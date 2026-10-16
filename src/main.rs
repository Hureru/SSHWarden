use std::sync::Arc;

use anyhow::Context;
#[cfg(windows)]
use base64::Engine;
use clap::Parser;
use tokio::sync::RwLock;
use tracing::info;

mod cache;
mod cli;
mod commands;
mod control;
mod daemon;
mod naming;
mod notifications;
mod path_util;
mod process;
mod runtime;
mod shell;
mod ssh_target;
mod sshconfig;
mod status;
mod sync;
mod unlock;

#[cfg(windows)]
use cache::{current_hello_unlock_info, decrypt_envelope_local_key_cache_with_hello};
use cache::{
    current_native_unlock_slot, decrypt_envelope_local_key_cache_with_native,
    decrypt_envelope_local_key_cache_with_pin, enroll_device_platform_slots_if_missing,
    load_managed_keys_from_cache, write_envelope_local_key_cache,
};
use cli::{Cli, Commands, KeysAction, SshConfigAction, StartupAction, UnlockMethod};
use commands::env::cmd_env;
use commands::keys::cmd_keys;
use commands::login::{cmd_login, cmd_set_pin, create_client, prompt_password};
use commands::sshconfig::{
    cmd_sshcfg_show, cmd_sshcfg_status, cmd_sshcfg_uninstall, cmd_sshcfg_write,
};
use control::{cmd_control, cmd_restart, cmd_stop, PinFailureHandle};
use daemon::run_foreground;
#[cfg(windows)]
use process::detach_console;
use process::{
    claim_pid_file, cmd_daemon_install, cmd_daemon_uninstall, log_file_path, remove_pid_file,
};
use runtime::{
    AuthorizationMemorySet, CachedKeyTuples, LocalCacheKeyHandle, RuntimeEvent, UIRequestTx,
};
use ssh_target::{parse_ssh_target, SSH_VALUE_TAKING_FLAGS};
use sshconfig::{
    load_host_bindings_importing_managed, managed_sshwarden_include_path,
    sync_managed_ssh_config_inner, user_ssh_config_path, write_sshwarden_include_line,
};
use status::{cmd_doctor, cmd_status};
#[cfg(windows)]
use unlock::try_hello_unlock;
use unlock::{
    gate_pin_validator, get_pin_encrypted_data, make_pin_validator, save_device_session,
    DecryptedCache, PinValidator,
};

fn main() -> anyhow::Result<()> {
    // Set Per-Monitor DPI Awareness V2 before any UI calls.
    // This prevents Win32 dialogs (CredUI) from being blurry on high-DPI displays.
    sshwarden_ui::init();

    // Initialize rustls CryptoProvider for tokio-tungstenite (WebSocket TLS)
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

    // Daemon mode: log to file; otherwise log to stderr
    // Background mode = `run --background`; foreground `run` and the bare
    // invocation log to stderr.
    let is_daemon = matches!(cli.command, Some(Commands::Run { background: true }));

    if is_daemon {
        let log_path = log_file_path()?;
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .with_context(|| format!("Failed to open log file: {}", log_path.display()))?;

        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_writer(std::sync::Mutex::new(log_file))
            .with_ansi(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .init();
    }

    let config = sshwarden_config::Config::load().context("Failed to load configuration")?;

    // The Slint UI event loop is needed whenever we start the agent: the bare
    // invocation (defaults to `run`) and `run [--background]` both serve SSH and
    // may pop unlock/bind dialogs.
    let needs_ui = matches!(cli.command, None | Some(Commands::Run { .. }));

    if needs_ui {
        // Create UI request channel for tokio <-> Slint communication
        let (ui_request_tx, ui_request_rx) =
            tokio::sync::mpsc::channel::<sshwarden_ui::UIRequest>(1);
        let ui_request_tx = Arc::new(ui_request_tx);

        // Build the tokio runtime manually (not on main thread)
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?;

        // Spawn the async logic on the tokio runtime thread
        let is_daemon_mode = is_daemon;
        let ui_tx = ui_request_tx.clone();
        let tokio_handle = std::thread::spawn(move || -> anyhow::Result<()> {
            rt.block_on(async move {
                // RT-02: single-instance guard for ANY run_foreground entry —
                // both `sshwarden daemon` and a bare foreground `sshwarden` are
                // the one singleton daemon (one agent + one control server + one
                // OpenSSH endpoint); two cannot coexist. Claim the PID file
                // atomically so two near-simultaneous starters cannot both pass a
                // check-then-write gate and spin up competing agents/pipes.
                match claim_pid_file() {
                    Ok(true) => {}
                    Ok(false) => {
                        info!("SSHWarden is already running");
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                }
                #[cfg(windows)]
                if is_daemon_mode {
                    detach_console();
                }
                #[cfg(not(windows))]
                let _ = is_daemon_mode;

                info!("SSHWarden started (PID: {})", std::process::id());
                let result = run_foreground(config, ui_tx).await;
                remove_pid_file();
                result
            })
        });

        // Main thread: run Slint event loop and handle UI requests
        run_slint_event_loop(ui_request_rx);

        // Wait for tokio thread to finish
        match tokio_handle.join() {
            Ok(result) => result,
            Err(_) => anyhow::bail!("Tokio runtime thread panicked"),
        }
    } else {
        // Non-UI commands: use a simple tokio runtime
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?;

        rt.block_on(async move {
            match cli.command {
                // Agent-starting variants are handled in the needs_ui branch.
                None | Some(Commands::Run { .. }) => unreachable!(),
                Some(Commands::Stop) => cmd_stop().await,
                Some(Commands::Restart) => cmd_restart().await,
                Some(Commands::Login { base_url, email }) => {
                    cmd_login(&config, base_url.as_deref(), email.as_deref()).await
                }
                Some(Commands::Lock) => cmd_control("lock").await,
                Some(Commands::Unlock { method }) => match method {
                    UnlockMethod::Pin => {
                        let pin_value = prompt_password("Enter PIN: ")?;
                        cmd_control(&format!("unlock-pin:{}", &*pin_value)).await
                    }
                    UnlockMethod::Hello => cmd_control("unlock-hello").await,
                    UnlockMethod::Native => cmd_control("unlock-native").await,
                    UnlockMethod::Auto => cmd_control("unlock").await,
                },
                Some(Commands::Status { json }) => cmd_status(json).await,
                Some(Commands::Doctor { json, fix }) => cmd_doctor(&config, json, fix).await,
                Some(Commands::Keys { action }) => {
                    cmd_keys(action.unwrap_or(KeysAction::List)).await
                }
                Some(Commands::SshConfig { action }) => match action {
                    Some(SshConfigAction::Show) => cmd_sshcfg_show().await,
                    Some(SshConfigAction::Write) => cmd_sshcfg_write().await,
                    Some(SshConfigAction::Remove) => cmd_sshcfg_uninstall().await,
                    None => cmd_sshcfg_status().await,
                },
                Some(Commands::Startup { action }) => match action {
                    StartupAction::Enable => cmd_startup_enable().await,
                    StartupAction::Disable => cmd_daemon_uninstall().await,
                },
                Some(Commands::Config) => {
                    let path = sshwarden_config::config_path()?;
                    if !path.exists() {
                        config.save()?;
                        out_line(format!("Created default config at: {}", path.display()));
                    } else {
                        out_line(format!("Config file: {}", path.display()));
                    }
                    Ok(())
                }
                Some(Commands::SetPin) => cmd_set_pin().await,
                Some(Commands::Sync) => cmd_control("sync").await,
                Some(Commands::Forget { shared_cache }) => {
                    if shared_cache {
                        cmd_control("forget-shared").await
                    } else {
                        cmd_control("forget").await
                    }
                }
                Some(Commands::Env { shell }) => cmd_env(&config, &shell),
            }
        })
    }
}

/// Run the Slint event loop on the main thread, processing UI requests.
///
/// This function blocks until `slint::quit_event_loop()` is called (triggered
/// when the tokio thread finishes and drops ui_request_tx).
fn run_slint_event_loop(mut ui_request_rx: tokio::sync::mpsc::Receiver<sshwarden_ui::UIRequest>) {
    // Bridge thread: receive UI requests synchronously and forward to Slint main event loop.
    std::thread::spawn(move || {
        while let Some(request) = ui_request_rx.blocking_recv() {
            match request {
                sshwarden_ui::UIRequest::PinDialog {
                    response_tx,
                    validator,
                    context,
                } => {
                    let result = slint::invoke_from_event_loop(move || {
                        sshwarden_ui::unlock::show_pin_dialog(response_tx, validator, context);
                    });

                    if result.is_err() {
                        tracing::error!("Slint event loop is not running, cannot show PIN dialog");
                    }
                }
                sshwarden_ui::UIRequest::AuthDialog { info, response_tx } => {
                    let auth_request =
                        sshwarden_ui::notify::AuthDialogRequest { info, response_tx };
                    let result = slint::invoke_from_event_loop(move || {
                        sshwarden_ui::notify::show_auth_dialog(auth_request);
                    });

                    if result.is_err() {
                        tracing::error!("Slint event loop is not running, cannot show auth dialog");
                    }
                }
                sshwarden_ui::UIRequest::BindHostsDialog {
                    request,
                    response_tx,
                } => {
                    let bind_request = sshwarden_ui::bind_hosts::BindHostsDialogRequest {
                        request,
                        response_tx,
                    };
                    let result = slint::invoke_from_event_loop(move || {
                        sshwarden_ui::bind_hosts::show_bind_hosts_dialog(bind_request);
                    });

                    if result.is_err() {
                        tracing::error!(
                            "Slint event loop is not running, cannot show bind-hosts dialog"
                        );
                    }
                }
            }
        }

        // Channel closed — tokio thread has finished, quit Slint event loop.
        let _ = slint::quit_event_loop();
    });

    // Keep event loop alive even if all windows are closed.
    let _ = slint::run_event_loop_until_quit();
}
/// Send a control command to the running daemon via IPC.
/// Print a line of command *result* output to stdout so it can be piped and
/// grepped (`sshwarden keys | grep ...`). Diagnostic/daemon logging stays on
/// stderr via `tracing`; only user-facing results go here (UX-1).
#[allow(clippy::print_stdout)]
fn out_line(msg: impl std::fmt::Display) {
    println!("{msg}");
}

/// Print a user-facing error line to stderr.
#[allow(clippy::print_stderr)]
fn err_line(msg: impl std::fmt::Display) {
    eprintln!("{msg}");
}

/// True when a Remembered Device exists on disk (local key cache or legacy vault
/// file) — the offline equivalent of run_foreground's startup check.
fn has_remembered_device_on_disk() -> bool {
    matches!(
        sshwarden_config::cache::LocalKeyCacheFile::load(),
        Ok(Some(_))
    ) || matches!(sshwarden_config::vault::VaultFile::load(), Ok(Some(_)))
}

/// `startup enable`: refuse unless a Remembered Device exists, then install the
/// platform auto-start entry (so the agent can unlock at login).
async fn cmd_startup_enable() -> anyhow::Result<()> {
    if !has_remembered_device_on_disk() {
        anyhow::bail!(
            "No Remembered Device yet, so an agent started at login could not unlock. \
             Run `sshwarden login` first, then `sshwarden startup enable`."
        );
    }
    cmd_daemon_install().await
}

/// Inspect the argv of the process at `pid` and, if it looks like an SSH client
/// command, extract the target host (without `user@` prefix).
///
/// Best-effort: returns `None` when the process has gone, when permission is
/// denied, when argv[0] doesn't look like an SSH client binary, or when the
/// positional target can't be confidently located.
fn infer_ssh_target_from_pid(pid: u32) -> Option<String> {
    if pid == 0 {
        tracing::debug!("Unable to infer SSH target: peer pid is zero");
        return None;
    }
    let argv = sshwarden_agent::peerinfo::gather::get_peer_cmd(pid)?;
    if argv.is_empty() {
        tracing::debug!(pid, "Unable to infer SSH target: peer argv is empty");
        return None;
    }
    let basename = std::path::Path::new(&argv[0])
        .file_name()
        .and_then(|s| s.to_str())?
        .to_ascii_lowercase();
    let basename = basename.strip_suffix(".exe").unwrap_or(&basename);
    if !matches!(
        basename,
        "ssh" | "scp" | "sftp" | "ssh-keyscan" | "ssh-copy-id"
    ) {
        tracing::debug!(pid, process = %basename, "Unable to infer SSH target: peer is not a recognized SSH client");
        return None;
    }

    let mut iter = argv.iter().skip(1).peekable();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            return iter.next().map(|s| parse_ssh_target(s));
        }
        if let Some(rest) = arg.strip_prefix('-') {
            if rest.is_empty() {
                continue;
            }
            // Walk combined short opts; once we hit a value-taking flag,
            // either inline value is present (rest of chars) or next argv is consumed.
            let chars: Vec<char> = rest.chars().collect();
            let mut consume_next = false;
            for (i, c) in chars.iter().enumerate() {
                if SSH_VALUE_TAKING_FLAGS.contains(*c) {
                    if i + 1 >= chars.len() {
                        consume_next = true;
                    }
                    break;
                }
            }
            if consume_next {
                iter.next();
            }
            continue;
        }
        return Some(parse_ssh_target(arg));
    }
    tracing::debug!(pid, process = %basename, "Unable to infer SSH target: no positional target found");
    None
}

/// Resolve the human-friendly key name for an SSH UI request, given the
/// freshly-decrypted key list. Falls back to "Unknown key" when no `cipher_id`
/// match is found.
fn key_name_for_request(
    request: &sshwarden_agent::SshAgentUIRequest,
    keys: &[(String, String, String)],
) -> String {
    request
        .cipher_id
        .as_ref()
        .and_then(|cid| keys.iter().find(|(_, _, id)| id == cid))
        .map(|(_, name, _)| name.clone())
        .unwrap_or_else(|| "Unknown key".to_string())
}

/// Apply freshly-decrypted keys to the shared state (key_names map + cached tuples).
/// Does **not** touch the in-memory agent — that is the caller's responsibility.
async fn apply_decrypted_keys_state(
    key_names: &Arc<RwLock<std::collections::HashMap<String, String>>>,
    cached_key_tuples: &CachedKeyTuples,
    keys: &[(String, String, String)],
) {
    {
        let mut names = key_names.write().await;
        names.clear();
        for (_, name, cipher_id) in keys {
            names.insert(cipher_id.clone(), name.clone());
        }
    }
    cached_key_tuples.write().await.set(keys.to_vec());
}

/// Run the authorization prompt if required by the request and configured
/// prompt behaviour. Agent forwarding always forces a prompt regardless of
/// the global setting.
async fn run_authorization_prompt(
    request: &sshwarden_agent::SshAgentUIRequest,
    key_name: String,
    prompt_behavior: sshwarden_config::PromptBehavior,
    ui_request_tx: &UIRequestTx,
) -> bool {
    let needs_prompt = request.is_forwarding
        || match prompt_behavior {
            sshwarden_config::PromptBehavior::Always => true,
            sshwarden_config::PromptBehavior::Never => false,
            sshwarden_config::PromptBehavior::RememberUntilLock => true,
        };
    if !needs_prompt {
        return true;
    }
    let sign_info = sshwarden_ui::SignRequestInfo {
        key_name,
        process_name: request.process_name.clone(),
        namespace: request.namespace.clone(),
        operation_kind: operation_kind_for_request(request).to_string(),
        is_forwarding: request.is_forwarding,
    };
    prompt_authorization_with_bind_flow(
        ui_request_tx,
        sign_info,
        request.pid,
        request.cipher_id.as_deref(),
    )
    .await
}

/// Handle a single UI request from the SSH agent (runs in a spawned task).
#[allow(clippy::too_many_arguments)]
#[allow(unused_variables)]
async fn handle_ui_request(
    request: sshwarden_agent::SshAgentUIRequest,
    response_tx: tokio::sync::broadcast::Sender<(u32, bool)>,
    vault_locked: Arc<std::sync::atomic::AtomicBool>,
    cached_key_tuples: CachedKeyTuples,
    agent: sshwarden_agent::SshWardenAgent,
    key_names: Arc<RwLock<std::collections::HashMap<String, String>>>,
    pin_encrypted_keys: Arc<RwLock<Option<String>>>,
    vault_file_data: Arc<RwLock<Option<sshwarden_config::vault::VaultFile>>>,
    local_key_cache_data: Arc<RwLock<Option<sshwarden_config::cache::LocalKeyCacheFile>>>,
    local_cache_key_state: LocalCacheKeyHandle,
    prompt_behavior: sshwarden_config::PromptBehavior,
    auto_unlock: bool,
    ui_request_tx: UIRequestTx,
    runtime_event_tx: tokio::sync::mpsc::Sender<RuntimeEvent>,
    authorization_memory: AuthorizationMemorySet,
    pin_failures: PinFailureHandle,
) {
    if request.is_list {
        if vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
            info!(
                request_id = request.request_id,
                process = %request.process_name,
                "Key list request while vault locked - listing public identities without unlock"
            );
        }

        agent.clear_needs_unlock();
        info!(
            request_id = request.request_id,
            process = %request.process_name,
            "Key list request - auto-approving"
        );
        let _ = response_tx.send((request.request_id, true));
        return;
    }

    // Check if vault is locked; if so, try to unlock
    if vault_locked.load(std::sync::atomic::Ordering::Relaxed) && auto_unlock {
        info!(
            request_id = request.request_id,
            "Vault is locked, attempting auto-unlock"
        );

        // 1. Native envelope unlock (platform Keychain / Secret Service / DPAPI).
        //    No UI prompt; if the slot is present and unlock succeeds, use it.
        {
            let cache_opt = local_key_cache_data.read().await.clone();
            if let Some(cache) = cache_opt.filter(|c| current_native_unlock_slot(c).is_some()) {
                let cache_for_unlock = cache.clone();
                let native_result = tokio::task::spawn_blocking(move || {
                    decrypt_envelope_local_key_cache_with_native(&cache_for_unlock)
                })
                .await;
                match native_result {
                    Ok(Ok((keys_json, lck))) => {
                        if let Ok(keys) =
                            serde_json::from_str::<Vec<(String, String, String)>>(&keys_json)
                        {
                            let key_name = key_name_for_request(&request, &keys);
                            apply_decrypted_keys_state(&key_names, &cached_key_tuples, &keys).await;
                            let mut agent_for_unlock = agent.clone();
                            if agent_for_unlock.set_keys(keys).is_ok() {
                                local_cache_key_state.write().await.set(lck);
                                vault_locked.store(false, std::sync::atomic::Ordering::Relaxed);
                                info!("Auto-unlocked via native local key cache");
                                let _ = runtime_event_tx
                                    .send(RuntimeEvent::AutoUnlockedNative)
                                    .await;
                                let approved = run_authorization_prompt(
                                    &request,
                                    key_name,
                                    prompt_behavior,
                                    &ui_request_tx,
                                )
                                .await;
                                let _ = response_tx.send((request.request_id, approved));
                                return;
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        info!(
                            "Native local key cache auto-unlock failed: {}; trying next method",
                            e
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Native unlock task join failed: {}", e);
                    }
                }
            }
        }

        // 2. Windows Hello envelope (preferred) → legacy vault.enc Hello sign-path.
        #[cfg(windows)]
        {
            // 2a. Envelope-based Hello unlock from local-key-cache.json.
            let cache_opt = local_key_cache_data.read().await.clone();
            if let Some(cache) = cache_opt.filter(|c| current_hello_unlock_info(c).is_some()) {
                let cache_for_unlock = cache.clone();
                let hello_result = tokio::task::spawn_blocking(move || {
                    decrypt_envelope_local_key_cache_with_hello(&cache_for_unlock)
                })
                .await;
                match hello_result {
                    Ok(Ok((keys_json, lck))) => {
                        if let Ok(keys) =
                            serde_json::from_str::<Vec<(String, String, String)>>(&keys_json)
                        {
                            let key_name = key_name_for_request(&request, &keys);
                            apply_decrypted_keys_state(&key_names, &cached_key_tuples, &keys).await;
                            let mut agent_for_unlock = agent.clone();
                            if agent_for_unlock.set_keys(keys).is_ok() {
                                local_cache_key_state.write().await.set(lck);
                                vault_locked.store(false, std::sync::atomic::Ordering::Relaxed);
                                info!("Auto-unlocked via Windows Hello envelope");
                                let _ = runtime_event_tx
                                    .send(RuntimeEvent::AutoUnlockedWindowsHello)
                                    .await;
                                let approved = run_authorization_prompt(
                                    &request,
                                    key_name,
                                    prompt_behavior,
                                    &ui_request_tx,
                                )
                                .await;
                                let _ = response_tx.send((request.request_id, approved));
                                return;
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        info!(
                            "Hello envelope auto-unlock failed: {}; trying legacy sign-path",
                            e
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Hello envelope task join failed: {}", e);
                    }
                }
            }

            // 2b. Legacy Hello sign-path from vault.enc (backward compatibility).
            let hello_info = {
                let vf = vault_file_data.read().await;
                vf.as_ref().and_then(|v| {
                    let challenge = v.hello_challenge.as_ref()?;
                    let encrypted = v.hello_encrypted.as_ref()?;
                    Some((challenge.clone(), encrypted.clone()))
                })
            };

            if let Some((challenge_b64, hello_encrypted)) = hello_info {
                if let Ok(challenge_bytes) =
                    base64::engine::general_purpose::STANDARD.decode(&challenge_b64)
                {
                    if challenge_bytes.len() == 16 {
                        let mut challenge = [0u8; 16];
                        challenge.copy_from_slice(&challenge_bytes);
                        let hello_result = tokio::task::spawn_blocking(move || {
                            try_hello_unlock(&challenge, &hello_encrypted)
                        })
                        .await;
                        if let Ok(Ok(keys_json)) = hello_result {
                            if let Ok(keys) =
                                serde_json::from_str::<Vec<(String, String, String)>>(&keys_json)
                            {
                                let key_name = key_name_for_request(&request, &keys);
                                apply_decrypted_keys_state(&key_names, &cached_key_tuples, &keys)
                                    .await;
                                let mut agent_for_unlock = agent.clone();
                                if agent_for_unlock.set_keys(keys).is_ok() {
                                    vault_locked.store(false, std::sync::atomic::Ordering::Relaxed);
                                    info!("Auto-unlocked via Windows Hello sign-path (legacy)");
                                    let _ = runtime_event_tx
                                        .send(RuntimeEvent::AutoUnlockedWindowsHello)
                                        .await;
                                    let approved = run_authorization_prompt(
                                        &request,
                                        key_name,
                                        prompt_behavior,
                                        &ui_request_tx,
                                    )
                                    .await;
                                    let _ = response_tx.send((request.request_id, approved));
                                    return;
                                }
                            }
                        } else {
                            info!("Hello sign-path auto-unlock failed, trying PIN dialog fallback");
                        }
                    }
                }
            }
        }

        // 3. PIN dialog: envelope-first validator with legacy fallback.
        //    The validator runs synchronously inside the dialog and captures the
        //    decrypted payload (and SymmetricKey, for envelope) into shared cells.
        let envelope_cache = {
            let guard = local_key_cache_data.read().await;
            guard
                .as_ref()
                .filter(|c| c.local_cache_key.pin_encrypted.is_some())
                .cloned()
        };

        let (validator, decrypted_cache, lck_holder): (PinValidator, DecryptedCache, _) =
            if let Some(cache) = envelope_cache {
                let dc: DecryptedCache = Arc::new(std::sync::Mutex::new(None));
                let kh: Arc<std::sync::Mutex<Option<sshwarden_api::crypto::SymmetricKey>>> =
                    Arc::new(std::sync::Mutex::new(None));
                let dc_inner = dc.clone();
                let kh_inner = kh.clone();
                let v: PinValidator = Arc::new(move |pin: &str| -> bool {
                    match decrypt_envelope_local_key_cache_with_pin(&cache, pin) {
                        Ok((keys_json, lck)) => {
                            *dc_inner.lock().unwrap_or_else(|e| e.into_inner()) = Some(keys_json);
                            *kh_inner.lock().unwrap_or_else(|e| e.into_inner()) = Some(lck);
                            true
                        }
                        Err(_) => false,
                    }
                });
                (v, dc, Some(kh))
            } else if let Some(enc_data) =
                get_pin_encrypted_data(&pin_encrypted_keys, &vault_file_data).await
            {
                let (v, dc) = make_pin_validator(enc_data);
                (v, dc, None)
            } else {
                // No PIN credentials of any kind — bail out.
                info!(
                    request_id = request.request_id,
                    "Auto-unlock failed: no PIN credentials available"
                );
                let _ = response_tx.send((request.request_id, false));
                return;
            };

        // SEC-03: share the daemon-wide PIN brute-force lockout with the control
        // channel so repeated wrong PINs in the SSH-request dialog also count.
        let validator = gate_pin_validator(validator, &pin_failures);

        let context_key_name = {
            let names = key_names.read().await;
            request
                .cipher_id
                .as_ref()
                .and_then(|cid| names.get(cid))
                .cloned()
                .unwrap_or_else(|| "Unknown key".to_string())
        };
        let pin_result = sshwarden_ui::unlock::request_pin_dialog_with_context(
            &ui_request_tx,
            validator,
            Some(unlock_context_for_request(&request, context_key_name)),
        )
        .await;

        if let Some(pin) = pin_result {
            let keys_json = match decrypted_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                Some(j) => j,
                None => {
                    tracing::warn!("PIN validator reported success but cache was empty");
                    let _ = response_tx.send((request.request_id, false));
                    return;
                }
            };
            if let Ok(keys) = serde_json::from_str::<Vec<(String, String, String)>>(&keys_json) {
                let key_name = key_name_for_request(&request, &keys);
                apply_decrypted_keys_state(&key_names, &cached_key_tuples, &keys).await;
                let mut agent_for_unlock = agent.clone();
                if agent_for_unlock.set_keys(keys).is_ok() {
                    if let Some(kh) = lck_holder {
                        let maybe_lck = kh.lock().unwrap_or_else(|e| e.into_inner()).take();
                        if let Some(lck) = maybe_lck {
                            // Multi-device: seed this device's own platform unlock
                            // slot from the freshly recovered key, mirroring the
                            // explicit unlock-pin control path (no-op in
                            // single-device mode or if a slot already exists).
                            enroll_device_platform_slots_if_missing(&lck);
                            local_cache_key_state.write().await.set(lck);
                        }
                    }
                    vault_locked.store(false, std::sync::atomic::Ordering::Relaxed);
                    info!("Auto-unlocked via PIN dialog");
                    let _ = runtime_event_tx
                        .send(RuntimeEvent::AutoUnlockedPin { pin })
                        .await;
                    let approved = run_authorization_prompt(
                        &request,
                        key_name,
                        prompt_behavior,
                        &ui_request_tx,
                    )
                    .await;
                    let _ = response_tx.send((request.request_id, approved));
                    return;
                }
            }
        }

        // PIN cancelled or every path failed → deny the request.
        let _ = response_tx.send((request.request_id, false));
        return;
    }

    // LOGIC-2: reaching here with the vault still locked means the auto-unlock
    // block above was skipped (auto_unlock disabled). The loaded entries have no
    // private material, so deny cleanly rather than auto-approving under
    // prompt_behavior=Never — otherwise ssh sees an "approval" followed by a
    // broken signature with no way to recover.
    if vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
        info!(
            request_id = request.request_id,
            process = %request.process_name,
            "Sign request denied: vault is locked and auto-unlock is disabled. \
             Run `sshwarden unlock`, or enable [unlock] auto_unlock_on_request."
        );
        let _ = response_tx.send((request.request_id, false));
        return;
    }

    let operation_kind = operation_kind_for_request(&request).to_string();
    let memory_key = request
        .cipher_id
        .as_ref()
        .map(|vault_item_id| (vault_item_id.clone(), operation_kind.clone()));

    if !request.is_forwarding
        && matches!(
            prompt_behavior,
            sshwarden_config::PromptBehavior::RememberUntilLock
        )
        && memory_key.as_ref().is_some_and(|key| {
            authorization_memory
                .try_read()
                .is_ok_and(|memory| memory.contains(key))
        })
    {
        info!(
            request_id = request.request_id,
            process = %request.process_name,
            operation = %operation_kind,
            "Sign request - auto-approved from authorization memory"
        );
        let _ = response_tx.send((request.request_id, true));
        return;
    }

    // Sign request - check prompt behavior.
    // Agent forwarding always requires explicit approval, regardless of prompt_behavior.
    let should_prompt = request.is_forwarding
        || match prompt_behavior {
            sshwarden_config::PromptBehavior::Always => true,
            sshwarden_config::PromptBehavior::Never => false,
            sshwarden_config::PromptBehavior::RememberUntilLock => true,
        };

    if !should_prompt {
        info!(
            request_id = request.request_id,
            process = %request.process_name,
            "Sign request - auto-approved (prompt_behavior=never)"
        );
        let _ = response_tx.send((request.request_id, true));
        return;
    }

    // Build request info for UI — use try_read to avoid blocking on write lock
    let key_name = match key_names.try_read() {
        Ok(names) => request
            .cipher_id
            .as_ref()
            .and_then(|id| names.get(id))
            .cloned()
            .unwrap_or_else(|| "Unknown key".to_string()),
        Err(_) => "Unknown key".to_string(),
    };

    let sign_info = sshwarden_ui::SignRequestInfo {
        key_name,
        process_name: request.process_name.clone(),
        namespace: request.namespace.clone(),
        operation_kind: operation_kind.clone(),
        is_forwarding: request.is_forwarding,
    };

    info!(
        request_id = request.request_id,
        process = %request.process_name,
        key = %sign_info.key_name,
        "Sign request - prompting user"
    );

    let result_pid = request.pid;
    let result_cipher_id = request.cipher_id.clone();
    let approved = prompt_authorization_with_bind_flow(
        &ui_request_tx,
        sign_info,
        result_pid,
        result_cipher_id.as_deref(),
    )
    .await;
    if approved
        && !request.is_forwarding
        && matches!(
            prompt_behavior,
            sshwarden_config::PromptBehavior::RememberUntilLock
        )
    {
        if let Some(key) = memory_key {
            authorization_memory.write().await.insert(key);
        }
    }
    let _ = response_tx.send((request.request_id, approved));
}

fn unlock_context_for_request(
    request: &sshwarden_agent::SshAgentUIRequest,
    key_name: String,
) -> sshwarden_ui::UnlockRequestContext {
    sshwarden_ui::UnlockRequestContext {
        key_name,
        process_name: request.process_name.clone(),
        operation_kind: operation_kind_for_request(request).to_string(),
        is_forwarding: request.is_forwarding,
    }
}

fn operation_kind_for_request(request: &sshwarden_agent::SshAgentUIRequest) -> &'static str {
    request.operation_kind.as_str()
}

/// Prompt the user to authorize a sign request, supporting the
/// "Bind & Approve…" secondary action. Returns true if the request was
/// approved (either directly or after a successful binding save).
async fn prompt_authorization_with_bind_flow(
    ui_request_tx: &UIRequestTx,
    sign_info: sshwarden_ui::SignRequestInfo,
    pid: u32,
    cipher_id: Option<&str>,
) -> bool {
    match sshwarden_ui::notify::request_authorization(ui_request_tx, &sign_info).await {
        sshwarden_ui::AuthorizationResult::Approved => true,
        sshwarden_ui::AuthorizationResult::Denied | sshwarden_ui::AuthorizationResult::Timeout => {
            false
        }
        sshwarden_ui::AuthorizationResult::BindRequested => {
            run_bind_hosts_flow(ui_request_tx, pid, cipher_id).await
        }
    }
}

/// Show the host-binding dialog, persist on save, and return whether the
/// original sign request should be approved.
async fn run_bind_hosts_flow(
    ui_request_tx: &UIRequestTx,
    pid: u32,
    initial_cipher_id: Option<&str>,
) -> bool {
    let keys = match load_managed_keys_from_cache() {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(
                "Bind dialog requested but local key cache is unavailable: {}",
                e
            );
            return false;
        }
    };
    let bindings = load_host_bindings_importing_managed(&keys).unwrap_or_else(|e| {
        tracing::warn!("Failed to load host bindings: {}", e);
        sshwarden_config::bindings::HostBindingsFile::default()
    });
    let entries: Vec<sshwarden_ui::BindHostsKeyEntry> = keys
        .iter()
        .map(|k| sshwarden_ui::BindHostsKeyEntry {
            cipher_id: k.cipher_id.clone(),
            name: k.name.clone(),
            hosts: bindings
                .bindings
                .get(&k.cipher_id)
                .map(|b| b.hosts.clone())
                .unwrap_or_default(),
        })
        .collect();

    if entries.is_empty() {
        tracing::warn!("Bind dialog requested but no keys are available to bind");
        return false;
    }

    let prefill_host = infer_ssh_target_from_pid(pid);
    let bind_request = sshwarden_ui::BindHostsRequest {
        keys: entries,
        initial_selection: initial_cipher_id.map(String::from),
        prefill_host,
        approve_on_save: true,
    };

    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    if ui_request_tx
        .send(sshwarden_ui::UIRequest::BindHostsDialog {
            request: bind_request,
            response_tx,
        })
        .await
        .is_err()
    {
        tracing::error!("Failed to dispatch bind-hosts dialog request");
        return false;
    }

    let bind_result =
        match tokio::time::timeout(std::time::Duration::from_secs(600), response_rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => {
                tracing::error!("Bind dialog response channel closed unexpectedly");
                return false;
            }
            Err(_) => {
                tracing::warn!("Bind dialog timed out after 600s");
                return false;
            }
        };

    match bind_result {
        sshwarden_ui::BindHostsResult::Cancelled => false,
        sshwarden_ui::BindHostsResult::Saved { bindings: payload } => {
            if let Err(e) = persist_bind_payload(&payload).await {
                tracing::error!("Failed to persist host bindings: {}", e);
                return false;
            }
            true
        }
    }
}

/// Persist the user's final binding decisions and regenerate the managed snippet.
///
/// Runs the blocking file I/O inside `spawn_blocking` to keep the tokio
/// runtime responsive.
async fn persist_bind_payload(
    payload: &std::collections::BTreeMap<String, Vec<String>>,
) -> anyhow::Result<()> {
    let payload = payload.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let keys = load_managed_keys_from_cache().unwrap_or_default();
        let mut bindings = load_host_bindings_importing_managed(&keys)?;
        for (cipher_id, hosts) in &payload {
            bindings.set_hosts(cipher_id, hosts.clone())?;
        }
        bindings.save()?;

        sync_managed_ssh_config_inner(&keys, true)?;

        // CFG-2: a binding is inert unless ~/.ssh/config Includes the managed
        // snippet. Mirror cmd_bindings_add so UI/sign-flow bindings install the
        // Include line too (idempotent). Non-fatal — the snippet is already saved.
        let include_path = managed_sshwarden_include_path()?;
        let config_path = user_ssh_config_path()?;
        if let Err(e) = write_sshwarden_include_line(&config_path, &include_path) {
            tracing::warn!(
                "Bindings saved, but failed to ensure the Include line in {}: {e}",
                config_path.display()
            );
        }
        Ok(())
    })
    .await
    .map_err(|e| anyhow::anyhow!("Bindings persist task panicked: {}", e))?
}

/// Open the BindHostsDialog standalone (no in-flight sign request).
/// Returns true if the user saved, false if they cancelled.
async fn dispatch_standalone_bind_hosts_dialog(
    ui_request_tx: &UIRequestTx,
) -> anyhow::Result<bool> {
    let keys = load_managed_keys_from_cache()?;
    let bindings = load_host_bindings_importing_managed(&keys).unwrap_or_else(|e| {
        tracing::warn!("Failed to load host bindings: {}", e);
        sshwarden_config::bindings::HostBindingsFile::default()
    });
    let entries: Vec<sshwarden_ui::BindHostsKeyEntry> = keys
        .iter()
        .map(|k| sshwarden_ui::BindHostsKeyEntry {
            cipher_id: k.cipher_id.clone(),
            name: k.name.clone(),
            hosts: bindings
                .bindings
                .get(&k.cipher_id)
                .map(|b| b.hosts.clone())
                .unwrap_or_default(),
        })
        .collect();
    if entries.is_empty() {
        anyhow::bail!("No SSH keys available — run `sshwarden sync` or login first");
    }

    let bind_request = sshwarden_ui::BindHostsRequest {
        keys: entries,
        initial_selection: None,
        prefill_host: None,
        approve_on_save: false,
    };

    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    ui_request_tx
        .send(sshwarden_ui::UIRequest::BindHostsDialog {
            request: bind_request,
            response_tx,
        })
        .await
        .map_err(|_| anyhow::anyhow!("UI request channel closed"))?;

    // CONC-1: this dialog response is awaited inline in the main select! loop
    // (via the BindHostsDialog control command), so an unbounded wait would
    // freeze auto-lock, token refresh and notification handling. Bound it.
    match tokio::time::timeout(std::time::Duration::from_secs(600), response_rx).await {
        Ok(Ok(sshwarden_ui::BindHostsResult::Saved { bindings: payload })) => {
            persist_bind_payload(&payload).await?;
            Ok(true)
        }
        Ok(Ok(sshwarden_ui::BindHostsResult::Cancelled)) => Ok(false),
        Ok(Err(_)) => anyhow::bail!("Dialog response channel closed unexpectedly"),
        Err(_) => anyhow::bail!("Host-binding dialog timed out after 600s"),
    }
}

/// Login to the vault and fetch SSH keys, returning both keys and the authenticated client.
async fn fetch_vault_keys_with_client(
    config: &sshwarden_config::Config,
) -> anyhow::Result<(
    Vec<sshwarden_api::DecryptedSshKey>,
    sshwarden_api::BitwardenClient,
)> {
    let password = prompt_password("Master password: ")?;

    let mut client = create_client(config, None);
    client.login_password(&config.auth.email, &password).await?;

    let keys = client.sync_ssh_keys().await?;
    Ok((keys, client))
}

/// After first login, ask the user if they want to set a PIN for persistent unlock.
///
/// This avoids requiring the master password on every restart.
async fn prompt_setup_pin(
    cached_key_tuples: &CachedKeyTuples,
    pin_encrypted_keys: &Arc<RwLock<Option<String>>>,
    vault_file_data: &Arc<RwLock<Option<sshwarden_config::vault::VaultFile>>>,
    local_key_cache_data: &Arc<RwLock<Option<sshwarden_config::cache::LocalKeyCacheFile>>>,
    local_cache_key_state: &LocalCacheKeyHandle,
    config: &sshwarden_config::Config,
    api_client: &Arc<RwLock<Option<sshwarden_api::BitwardenClient>>>,
) {
    #[allow(clippy::print_stderr)]
    {
        eprint!("Set up a PIN to unlock without master password next time? [Y/n] ");
    }
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return;
    }
    let input = input.trim().to_lowercase();
    if !input.is_empty() && input != "y" && input != "yes" {
        info!("Skipped PIN setup. You can set it later with 'sshwarden set-pin'.");
        return;
    }

    let pin = match prompt_password("Enter new PIN (>= 4 chars): ") {
        Ok(p) => p,
        Err(_) => return,
    };
    if pin.len() < 4 {
        info!("PIN must be at least 4 characters. Skipped.");
        return;
    }
    let pin_confirm = match prompt_password("Confirm PIN: ") {
        Ok(p) => p,
        Err(_) => return,
    };
    if pin != pin_confirm {
        info!("PINs do not match. Skipped.");
        return;
    }

    let keys = cached_key_tuples.read().await.clone_inner();
    match write_envelope_local_key_cache(&keys, &config.auth.email, &config.server.base_url, &pin) {
        Ok((cache, local_cache_key)) => {
            *local_key_cache_data.write().await = Some(cache);
            local_cache_key_state.write().await.set(local_cache_key);
            *pin_encrypted_keys.write().await = None;
            *vault_file_data.write().await = None;
            if let Err(e) = sshwarden_config::vault::VaultFile::delete() {
                tracing::warn!(
                    "Failed to delete legacy vault file after envelope cache write: {}",
                    e
                );
            }
            info!("PIN set. Envelope local key cache saved.");
        }
        Err(e) => {
            tracing::warn!("Failed to save envelope local key cache: {}", e);
            return;
        }
    }

    // Save device session with PIN-encrypted refresh token
    {
        let client_guard = api_client.read().await;
        if let Some(ref client) = *client_guard {
            save_device_session(client, config, Some(&pin)).await;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::path_util::{ensure_managed_ssh_config_path_is_safe, paths_equivalent_for_safety};
    use crate::sshconfig::{
        import_host_bindings_from_managed_file, remove_sshwarden_include_line, ManagedKey,
    };

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    /// Helper that runs only the argv-parsing portion of host inference,
    /// bypassing the live PID lookup.
    fn infer_from_argv(parts: &[&str]) -> Option<String> {
        let argv = argv(parts);
        if argv.is_empty() {
            return None;
        }
        let basename = std::path::Path::new(&argv[0])
            .file_name()
            .and_then(|s| s.to_str())?
            .to_ascii_lowercase();
        let basename = basename.strip_suffix(".exe").unwrap_or(&basename);
        if !matches!(
            basename,
            "ssh" | "scp" | "sftp" | "ssh-keyscan" | "ssh-copy-id"
        ) {
            return None;
        }
        let mut iter = argv.iter().skip(1).peekable();
        while let Some(arg) = iter.next() {
            if arg == "--" {
                return iter.next().map(|s| parse_ssh_target(s));
            }
            if let Some(rest) = arg.strip_prefix('-') {
                if rest.is_empty() {
                    continue;
                }
                let chars: Vec<char> = rest.chars().collect();
                let mut consume_next = false;
                for (i, c) in chars.iter().enumerate() {
                    if SSH_VALUE_TAKING_FLAGS.contains(*c) {
                        if i + 1 >= chars.len() {
                            consume_next = true;
                        }
                        break;
                    }
                }
                if consume_next {
                    iter.next();
                }
                continue;
            }
            return Some(parse_ssh_target(arg));
        }
        None
    }

    #[test]
    fn parses_plain_hostname() {
        assert_eq!(
            infer_from_argv(&["ssh", "github.com"]).as_deref(),
            Some("github.com")
        );
    }

    #[test]
    fn strips_user_prefix() {
        assert_eq!(
            infer_from_argv(&["ssh", "git@github.com"]).as_deref(),
            Some("github.com")
        );
    }

    #[test]
    fn skips_value_taking_flags_with_separate_value() {
        // -p 2222 -i ~/.ssh/id -l user host
        assert_eq!(
            infer_from_argv(&[
                "ssh",
                "-p",
                "2222",
                "-i",
                "/tmp/id",
                "-l",
                "user",
                "bastion.example.com"
            ])
            .as_deref(),
            Some("bastion.example.com")
        );
    }

    #[test]
    fn handles_inline_short_flag_value() {
        // -p2222 host  → -p has value "2222" inline, host is positional
        assert_eq!(
            infer_from_argv(&["ssh", "-p2222", "host.example"]).as_deref(),
            Some("host.example")
        );
    }

    #[test]
    fn handles_combined_short_flags() {
        // -vv host  (v is non-value-taking; combined)
        assert_eq!(
            infer_from_argv(&["ssh", "-vv", "host.example"]).as_deref(),
            Some("host.example")
        );
    }

    #[test]
    fn double_dash_terminator() {
        assert_eq!(
            infer_from_argv(&["ssh", "-v", "--", "weird-host"]).as_deref(),
            Some("weird-host")
        );
    }

    #[test]
    fn accepts_ipv4() {
        assert_eq!(
            infer_from_argv(&["ssh", "192.168.1.10"]).as_deref(),
            Some("192.168.1.10")
        );
    }

    #[test]
    fn accepts_scp_basename() {
        assert_eq!(
            infer_from_argv(&["scp", "file.txt", "user@host.example:/tmp"]).as_deref(),
            Some("file.txt")
        );
        // Note: scp's positional is the source — caller should be aware. We still
        // return the first positional; this is best-effort UX, not authoritative.
    }

    #[test]
    fn rejects_non_ssh_clients() {
        assert!(infer_from_argv(&["git", "push", "origin", "main"]).is_none());
        assert!(infer_from_argv(&["bash"]).is_none());
    }

    #[test]
    fn windows_exe_suffix_ok() {
        assert_eq!(
            infer_from_argv(&["ssh.exe", "host"]).as_deref(),
            Some("host")
        );
    }

    #[test]
    fn no_target_returns_none() {
        assert!(infer_from_argv(&["ssh"]).is_none());
        assert!(infer_from_argv(&["ssh", "-v"]).is_none());
    }

    #[test]
    fn strips_only_last_at() {
        // SSH allows weird usernames; we strip only the last '@'.
        assert_eq!(
            infer_from_argv(&["ssh", "weird@user@host.example"]).as_deref(),
            Some("host.example")
        );
    }

    fn temp_test_path(name: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "sshwarden-test-{}-{}-{name}",
            std::process::id(),
            unique
        ))
    }

    #[test]
    fn imports_manually_edited_host_lines_from_managed_file() {
        let path = temp_test_path("managed.conf");
        let content = "# SSHWarden managed SSH config\n\
# sshwarden:key id-1\n\
# Github (id-1)\n\
Host github.com gitlab.com\n\
    IdentityFile \"/tmp/github.pub\"\n\
    IdentitiesOnly yes\n";
        std::fs::write(&path, content).unwrap();

        let keys = vec![ManagedKey {
            name: "Github".to_string(),
            cipher_id: "id-1".to_string(),
        }];
        let mut bindings = sshwarden_config::bindings::HostBindingsFile::default();
        let changed = import_host_bindings_from_managed_file(&path, &keys, &mut bindings).unwrap();

        assert!(changed);
        assert_eq!(
            bindings.bindings.get("id-1").unwrap().hosts,
            vec!["github.com".to_string(), "gitlab.com".to_string()]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn managed_ssh_config_safety_rejects_nonexistent_alias_of_user_config() {
        let dir = temp_test_path("managed-safety-alias");
        let ssh_dir = dir.join(".ssh");
        let user_config = ssh_dir.join("config");
        let managed_path = ssh_dir.join("..").join(".ssh").join("config");

        assert!(paths_equivalent_for_safety(&managed_path, &user_config));
        assert!(ensure_managed_ssh_config_path_is_safe(&managed_path, &user_config).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn include_write_replaces_marked_include_line() {
        let dir = temp_test_path("include-replace");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config");
        let include_path = dir.join("sshwarden_config");
        std::fs::write(
            &config_path,
            "Host *\n    AddKeysToAgent yes\n\n# SSHWarden managed key selector snippets\nInclude \"/old/sshwarden_config\"\n",
        )
        .unwrap();

        write_sshwarden_include_line(&config_path, &include_path).unwrap();
        let updated = std::fs::read_to_string(&config_path).unwrap();

        assert!(updated.contains(&sshwarden_config::ssh_config::include_line(&include_path)));
        assert!(!updated.contains("/old/sshwarden_config"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn include_remove_drops_marked_include_line() {
        let dir = temp_test_path("include-remove");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config");
        let include_path = dir.join("sshwarden_config");
        let include_line = sshwarden_config::ssh_config::include_line(&include_path);
        std::fs::write(
            &config_path,
            format!(
                "Host *\n    AddKeysToAgent yes\n\n# SSHWarden managed key selector snippets\n{include_line}\n"
            ),
        )
        .unwrap();

        assert!(remove_sshwarden_include_line(&config_path, &include_path).unwrap());
        let updated = std::fs::read_to_string(&config_path).unwrap();

        assert!(updated.contains("Host *"));
        assert!(!updated.contains("SSHWarden managed key selector snippets"));
        assert!(!updated.contains(&include_line));
        let _ = std::fs::remove_dir_all(dir);
    }
}
