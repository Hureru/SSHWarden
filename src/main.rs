use std::sync::Arc;

use anyhow::Context;
#[cfg(windows)]
use base64::Engine;
use clap::Parser;
use tokio::sync::RwLock;
use tracing::info;

mod cache;
mod cli;
mod control;
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
use cache::{
    current_hello_challenge_b64, current_hello_unlock_info,
    decrypt_envelope_local_key_cache_with_hello,
};
use cache::{
    current_native_unlock_slot, decrypt_envelope_local_key_cache_with_native,
    decrypt_envelope_local_key_cache_with_pin, enroll_device_platform_slots_if_missing,
    key_material_fingerprints_from_tuples, key_tuples_from_cache_header,
    load_managed_keys_from_cache, persist_device_unlock_slots_from_cache,
    write_envelope_local_key_cache,
};
use cli::{Cli, Commands, KeysAction, SshConfigAction, StartupAction, UnlockMethod};
use control::{
    cmd_control, cmd_restart, cmd_stop, handle_control_command, lock_vault, PinFailureHandle,
    PinFailureState,
};
use notifications::connect_notification_client;
#[cfg(windows)]
use process::detach_console;
use process::{
    claim_pid_file, cmd_daemon_install, cmd_daemon_uninstall, is_daemon_running, log_file_path,
    remove_pid_file,
};
use runtime::{
    AuthorizationMemorySet, CachedKeyTuples, KeyMaterialFingerprints, LocalCacheKeyHandle,
    LocalCacheKeyState, NotificationConnectionState, NotificationRuntimeState, RuntimeEvent,
    SecureKeyCache, UIRequestTx,
};
use shell::{powershell_single_quote, shell_single_quote};
use ssh_target::{parse_ssh_target, SSH_VALUE_TAKING_FLAGS};
use sshconfig::{
    load_host_bindings_importing_managed, managed_sshwarden_include_path,
    remove_sshwarden_include_line, selector_path_for_key, sync_managed_ssh_config_inner,
    sync_managed_ssh_config_with_bindings, user_ssh_config_path, write_key_selector_files,
    write_sshwarden_include_line, ManagedKey,
};
use status::{cmd_doctor, cmd_status};
use sync::{do_sync, resolve_pending_sync};
use unlock::{
    gate_pin_validator, get_pin_encrypted_data, make_pin_validator, save_device_session,
    try_restore_api_session, DecryptedCache, PinValidator,
};
#[cfg(windows)]
use unlock::{try_hello_unlock, try_restore_api_session_hello};

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

/// Set PIN command: prompt for PIN and send to daemon.
async fn cmd_set_pin() -> anyhow::Result<()> {
    let pin = prompt_password("Enter new PIN: ")?;
    if pin.len() < 4 {
        err_line("PIN must be at least 4 characters");
        return Ok(());
    }
    let pin_confirm = prompt_password("Confirm PIN: ")?;
    if pin != pin_confirm {
        info!("PINs do not match");
        return Ok(());
    }

    let cmd = format!("set-pin:{}", &*pin);
    cmd_control(&cmd).await
}

/// Prompt for a password from the terminal (hides input).
/// Returns `Zeroizing<String>` to ensure the password is wiped from memory when dropped.
fn prompt_password(prompt: &str) -> anyhow::Result<zeroize::Zeroizing<String>> {
    Ok(zeroize::Zeroizing::new(
        rpassword::prompt_password(prompt).context("Failed to read password")?,
    ))
}

/// Prompt for an email from the terminal.
fn prompt_email(prompt: &str) -> anyhow::Result<String> {
    #[allow(clippy::print_stderr)]
    {
        eprint!("{}", prompt);
    }
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("Failed to read email")?;
    Ok(input.trim().to_string())
}

/// Create a BitwardenClient from config, with optional overrides.
fn create_client(
    config: &sshwarden_config::Config,
    base_url_override: Option<&str>,
) -> sshwarden_api::BitwardenClient {
    let base = base_url_override.unwrap_or(&config.server.base_url);
    let api_url = config
        .server
        .api_url
        .as_deref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}/api", base));
    let identity_url = config
        .server
        .identity_url
        .as_deref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}/identity", base));
    sshwarden_api::BitwardenClient::new(base, &api_url, &identity_url)
}

/// Login command: authenticate and load keys into the running agent.
///
/// UX-2: routes through the running daemon (via the control channel) so a
/// successful login actually loads keys into the agent serving SSH clients.
/// Falls back to a standalone login that only lists keys if no daemon is up.
async fn cmd_login(
    config: &sshwarden_config::Config,
    base_url: Option<&str>,
    email: Option<&str>,
) -> anyhow::Result<()> {
    // UX-2: a running daemon logs in with its OWN configured server/account; the
    // control protocol carries only the password. If the caller supplied
    // --email/--base-url, reject up front — BEFORE prompting — rather than
    // silently logging into the wrong account/server (and without wasting a
    // password/email prompt the caller can't use).
    if (email.is_some() || base_url.is_some()) && is_daemon_running() {
        anyhow::bail!(
            "A daemon is already running and logs in with its own configured account/server; \
             --email/--base-url cannot be applied to it. Stop the daemon to log in standalone, \
             or omit these flags."
        );
    }

    let password = prompt_password("Master password: ")?;

    // Prefer the running daemon: it performs the login + sync and loads keys
    // into the live agent. The control protocol carries only the password, so
    // the daemon uses its own configured server/email.
    match sshwarden_agent::control::send_control_command(&format!("unlock-password:{}", &*password))
        .await
    {
        Ok(response) => {
            if response.ok {
                if base_url.is_some() {
                    info!("Note: the running agent uses its own configured server; --base-url is ignored.");
                }
                out_line(
                    response
                        .message
                        .as_deref()
                        .unwrap_or("Logged in; keys loaded into the running agent."),
                );
                // Onboarding: if this device has no Remembered Device yet, offer to
                // set a PIN so future unlocks skip the master password. The PIN is
                // entered here (client side) and persisted by the agent's SetPin
                // handler, so it works even when the agent runs detached.
                if !has_remembered_device_on_disk() {
                    offer_pin_setup().await?;
                }
            } else {
                err_line(format!(
                    "Login failed: {}",
                    response.error.as_deref().unwrap_or("unknown error")
                ));
                std::process::exit(1);
            }
            return Ok(());
        }
        Err(_) => {
            info!(
                "No agent running; logging in for listing only (start `sshwarden run --background` to serve keys)."
            );
        }
    }

    // Standalone fallback: authenticate and list keys without touching an agent.
    // Resolve the email here (prompting only now) — the daemon path never needs it.
    let email = match email {
        Some(e) => e.to_string(),
        None if !config.auth.email.is_empty() => config.auth.email.clone(),
        None => prompt_email("Email: ")?,
    };
    let mut client = create_client(config, base_url);
    info!("Logging in as {}...", email);
    client.login_password(&email, &password).await?;

    let keys = client.sync_ssh_keys().await?;
    if keys.is_empty() {
        out_line("No SSH keys found in vault. Add SSH keys in Bitwarden to use them.");
    } else {
        out_line("Login successful. Vault SSH keys:");
        for key in &keys {
            out_line(format!(
                "  SSH Key: {} (cipher: {})",
                key.name, key.cipher_id
            ));
        }
        out_line(
            "\nNote: no agent was running, so keys were not loaded. Start `sshwarden run --background`, then run `sshwarden login` again.",
        );
    }

    Ok(())
}

/// Offer to set a quick-unlock PIN after a successful daemon login. The PIN is
/// read on this (client) terminal and sent to the agent's SetPin handler, which
/// writes the envelope Local Key Cache — completing the Remembered Device. Works
/// even when the agent runs detached, since the prompt is client-side.
async fn offer_pin_setup() -> anyhow::Result<()> {
    use std::io::Write;
    #[allow(clippy::print_stderr)]
    {
        eprint!("Set up a PIN to unlock without your master password next time? [Y/n] ");
    }
    let _ = std::io::stderr().flush();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return Ok(());
    }
    let input = input.trim().to_lowercase();
    if !input.is_empty() && input != "y" && input != "yes" {
        out_line("Skipped PIN setup. You can set it later with `sshwarden set-pin`.");
        return Ok(());
    }
    let pin = prompt_password("Enter new PIN (>= 4 chars): ")?;
    if pin.len() < 4 {
        err_line("PIN must be at least 4 characters. Skipped — run `sshwarden set-pin` later.");
        return Ok(());
    }
    let confirm = prompt_password("Confirm PIN: ")?;
    if *pin != *confirm {
        err_line("PINs do not match. Skipped — run `sshwarden set-pin` later.");
        return Ok(());
    }
    match sshwarden_agent::control::send_control_command(&format!("set-pin:{}", &*pin)).await {
        Ok(resp) if resp.ok => out_line("PIN set — this device is now remembered."),
        Ok(resp) => err_line(format!(
            "Could not set PIN: {}",
            resp.error.as_deref().unwrap_or("unknown error")
        )),
        Err(e) => err_line(format!("Could not set PIN: {e}")),
    }
    Ok(())
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

fn cmd_env(config: &sshwarden_config::Config, shell: &str) -> anyhow::Result<()> {
    // UX-5: Windows OpenSSH uses the fixed pipe and ignores SSH_AUTH_SOCK, so
    // these exports are usually only relevant for a custom [socket] endpoint or
    // third-party clients that honour SSH_AUTH_SOCK. Note goes to stderr so it
    // doesn't break `eval`.
    #[cfg(windows)]
    err_line(
        r"# Note: Windows OpenSSH talks to the fixed pipe \\.\pipe\openssh-ssh-agent and ignores SSH_AUTH_SOCK; these exports only matter for a custom [socket] endpoint or clients that honour SSH_AUTH_SOCK.",
    );

    let endpoint = config
        .socket
        .path
        .as_deref()
        .map(std::path::PathBuf::from)
        .unwrap_or(sshwarden_config::default_agent_socket_path()?);
    let endpoint = endpoint.display().to_string();

    #[allow(clippy::print_stdout)]
    match shell {
        "sh" | "bash" | "zsh" | "posix" => {
            println!("export SSH_AUTH_SOCK='{}'", shell_single_quote(&endpoint));
            println!(
                "export SSHWARDEN_SSH_AUTH_SOCK='{}'",
                shell_single_quote(&endpoint)
            );
        }
        "fish" => {
            println!("set -gx SSH_AUTH_SOCK '{}';", shell_single_quote(&endpoint));
            println!(
                "set -gx SSHWARDEN_SSH_AUTH_SOCK '{}';",
                shell_single_quote(&endpoint)
            );
        }
        "powershell" | "pwsh" | "ps" => {
            println!(
                "$env:SSH_AUTH_SOCK = '{}'",
                powershell_single_quote(&endpoint)
            );
            println!(
                "$env:SSHWARDEN_SSH_AUTH_SOCK = '{}'",
                powershell_single_quote(&endpoint)
            );
        }
        "cmd" => {
            println!("set SSH_AUTH_SOCK={endpoint}");
            println!("set SSHWARDEN_SSH_AUTH_SOCK={endpoint}");
        }
        other => {
            anyhow::bail!("Unsupported shell syntax '{other}'. Use sh, fish, powershell, or cmd.")
        }
    }

    Ok(())
}

/// Resolve a user-supplied `key` argument to a cipher_uuid.
///
/// Accepts an exact cipher_uuid match or a case-insensitive exact name match.
/// If no local cache exists, the input is treated as a cipher_uuid verbatim
/// (no validation) so users can bind ahead of first sync.
fn resolve_cipher_id(query: &str) -> anyhow::Result<String> {
    let keys = match sshwarden_config::cache::LocalKeyCacheFile::load()? {
        Some(cache) => cache.header.keys,
        None => return Ok(query.to_string()),
    };
    if keys.iter().any(|k| k.vault_item_id == query) {
        return Ok(query.to_string());
    }
    let name_matches: Vec<&sshwarden_config::cache::KeyIdentity> = keys
        .iter()
        .filter(|k| k.name.eq_ignore_ascii_case(query))
        .collect();
    match name_matches.len() {
        0 => anyhow::bail!(
            "No key matches '{}'. Run `sshwarden keys` to see available keys.",
            query
        ),
        1 => Ok(name_matches[0].vault_item_id.clone()),
        n => anyhow::bail!(
            "'{}' matches {} keys by name — pass the cipher uuid instead.",
            query,
            n
        ),
    }
}

/// Dispatch the `keys` command group: an offline list plus host-binding
/// management (the former `bindings` subcommands).
async fn cmd_keys(action: KeysAction) -> anyhow::Result<()> {
    match action {
        KeysAction::List => cmd_keys_list().await,
        KeysAction::Bind { key, hosts } => cmd_bindings_add(&key, &hosts).await,
        KeysAction::Unbind { key, host, all } => cmd_keys_unbind(&key, host.as_deref(), all).await,
        KeysAction::Ui => cmd_control("bind-hosts-dialog").await,
    }
}

/// Merge of the former `bindings remove` + `bindings clear`: `--all` clears
/// every host for the key; otherwise a host pattern is required.
async fn cmd_keys_unbind(key: &str, host: Option<&str>, all: bool) -> anyhow::Result<()> {
    if all {
        cmd_bindings_clear(key).await
    } else {
        cmd_bindings_remove(key, host, false).await
    }
}

/// Offline unified key view: each cached key with its bound hosts and whether a
/// public-key selector file exists, plus a one-line ssh-config Include summary
/// and a best-effort live lock state. Reads only local files (no network); the
/// daemon is contacted opportunistically and its absence is not an error.
async fn cmd_keys_list() -> anyhow::Result<()> {
    let cache = sshwarden_config::cache::LocalKeyCacheFile::load()?;

    let Some(cache) = cache else {
        out_line("No keys cached yet. Run `sshwarden login` (or `sshwarden sync`) first.");
        return Ok(());
    };
    if cache.header.keys.is_empty() {
        out_line(
            "No SSH keys in the local cache. Add SSH keys in Bitwarden, then `sshwarden sync`.",
        );
        return Ok(());
    }

    let managed_keys = ManagedKey::from_cache_header(&cache.header.keys);
    let bindings = load_host_bindings_importing_managed(&managed_keys).unwrap_or_else(|e| {
        tracing::warn!("Failed to load host bindings: {}", e);
        sshwarden_config::bindings::HostBindingsFile::default()
    });

    // Best-effort live lock state; omit silently when the daemon is down.
    let locked: Option<bool> =
        match sshwarden_agent::control::send_control_command("status-json").await {
            Ok(resp) => resp
                .details
                .as_ref()
                .and_then(|d| d.get("locked"))
                .and_then(|v| v.as_bool()),
            Err(_) => None,
        };
    let state = match locked {
        Some(true) => " — vault locked",
        Some(false) => " — vault unlocked",
        None => "",
    };

    out_line(format!(
        "Cached SSH keys ({}){}:",
        cache.header.keys.len(),
        state
    ));
    for key in &cache.header.keys {
        let selector_ok = selector_path_for_key(&key.name, &key.vault_item_id)
            .map(|p| p.exists())
            .unwrap_or(false);
        out_line(format!(
            "  • {} ({})  [{}]",
            key.name,
            key.vault_item_id,
            if selector_ok {
                "selector ready"
            } else {
                "selector missing — run `sshwarden ssh-config write`"
            }
        ));
        match bindings.bindings.get(&key.vault_item_id) {
            Some(b) if !b.hosts.is_empty() => {
                for host in &b.hosts {
                    out_line(format!("      host: {host}"));
                }
            }
            _ => out_line("      hosts: none — `sshwarden keys bind <key> <host>`".to_string()),
        }
    }

    // One-line Include summary so the user knows whether `ssh` will route via
    // these selectors.
    let include_path = managed_sshwarden_include_path()?;
    let config_path = user_ssh_config_path()?;
    let has_include = std::fs::read_to_string(&config_path)
        .map(|s| {
            s.lines().any(|l| {
                sshwarden_config::ssh_config::line_matches_sshwarden_include(l, &include_path)
            })
        })
        .unwrap_or(false);
    if has_include {
        out_line("\nssh-config: Include active (ssh will use the bound keys).");
    } else {
        out_line(format!(
            "\nssh-config: not included — run `sshwarden ssh-config write` to wire {}.",
            config_path.display()
        ));
    }
    Ok(())
}

async fn cmd_bindings_add(key: &str, hosts: &[String]) -> anyhow::Result<()> {
    let cipher_id = resolve_cipher_id(key)?;
    let keys = load_managed_keys_from_cache().unwrap_or_default();
    let mut bindings = load_host_bindings_importing_managed(&keys)?;
    for host in hosts {
        if is_catch_all_host_pattern(host) {
            tracing::warn!(
                "Binding a key to '{}' may cause SSH to offer this key for many hosts and can reintroduce MaxAuthTries failures.",
                host
            );
        }
        bindings.add_host(&cipher_id, host)?;
    }
    bindings.save()?;

    // UX-7: a failed snippet regeneration means `ssh host` would route to the
    // wrong key (or none), so fail loudly rather than warn-and-continue.
    sync_managed_ssh_config_inner(&keys, true)
        .context("Bindings saved but managed snippet regeneration failed")?;

    // CFG-2: a binding does nothing unless ~/.ssh/config Includes the managed
    // snippet. Auto-install the Include line so `bindings add` is never a silent
    // no-op (idempotent — only writes when the line is missing).
    let include_path = managed_sshwarden_include_path()?;
    let config_path = user_ssh_config_path()?;
    if let Err(e) = write_sshwarden_include_line(&config_path, &include_path) {
        err_line(format!(
            "Binding saved, but failed to ensure the Include line in {}: {e}. Run `sshwarden ssh-config write`.",
            config_path.display()
        ));
    }

    out_line(format!(
        "Added {} host pattern(s) to key {}.",
        hosts.len(),
        cipher_id
    ));
    Ok(())
}

fn is_catch_all_host_pattern(host: &str) -> bool {
    matches!(host.trim(), "*" | "!*")
}

async fn cmd_bindings_remove(key: &str, host: Option<&str>, all: bool) -> anyhow::Result<()> {
    let cipher_id = resolve_cipher_id(key)?;
    let keys = load_managed_keys_from_cache().unwrap_or_default();
    let mut bindings = load_host_bindings_importing_managed(&keys)?;

    let changed = match (host, all) {
        (Some(_), true) => anyhow::bail!("Pass either a host argument or `--all`, not both."),
        (None, false) => anyhow::bail!(
            "Specify a host pattern to remove, or pass `--all` to clear every host for this key."
        ),
        (None, true) => bindings.clear_key(&cipher_id),
        (Some(h), false) => bindings.remove_host(&cipher_id, h),
    };

    if !changed {
        anyhow::bail!("No matching host binding found for key {}", cipher_id);
    }
    bindings.save()?;

    sync_managed_ssh_config_inner(&keys, true)
        .context("Bindings saved but managed snippet regeneration failed")?;

    out_line(format!("Updated bindings for key {cipher_id}."));
    Ok(())
}

async fn cmd_bindings_clear(key: &str) -> anyhow::Result<()> {
    cmd_bindings_remove(key, None, true).await
}

/// `ssh-config write`: regenerate the managed snippet from the local cache +
/// bindings and ensure the Include line in ~/.ssh/config (offline). Selector
/// `.pub` files are written during `login`/`sync`. Merges the former
/// `ssh-config --write` / `install` / `regenerate`.
async fn cmd_sshcfg_write() -> anyhow::Result<()> {
    let keys = load_managed_keys_from_cache()?;
    sync_managed_ssh_config_inner(&keys, true)?;

    let include_path = managed_sshwarden_include_path()?;
    let config_path = user_ssh_config_path()?;
    write_sshwarden_include_line(&config_path, &include_path)?;

    out_line(format!("Wrote managed snippet: {}", include_path.display()));
    out_line(format!(
        "Include line ensured in: {}",
        config_path.display()
    ));
    Ok(())
}

async fn cmd_sshcfg_uninstall() -> anyhow::Result<()> {
    let include_path = managed_sshwarden_include_path()?;
    let config_path = user_ssh_config_path()?;
    let removed = remove_sshwarden_include_line(&config_path, &include_path)?;

    #[allow(clippy::print_stdout)]
    {
        if removed {
            println!("Removed Include line from {}", config_path.display());
        } else {
            println!(
                "No sshwarden Include line found in {}",
                config_path.display()
            );
        }
        println!(
            "Note: snippet file {} is preserved. Delete it manually if you want a clean uninstall.",
            include_path.display()
        );
    }
    Ok(())
}

async fn cmd_sshcfg_status() -> anyhow::Result<()> {
    let include_path = managed_sshwarden_include_path()?;
    let config_path = user_ssh_config_path()?;
    let cache = sshwarden_config::cache::LocalKeyCacheFile::load()?;
    let bindings = cache
        .as_ref()
        .map(|cache| ManagedKey::from_cache_header(&cache.header.keys))
        .map(|keys| load_host_bindings_importing_managed(&keys))
        .transpose()?
        .unwrap_or_default();

    let user_config_has_include = std::fs::read_to_string(&config_path)
        .map(|s| {
            s.lines().any(|l| {
                sshwarden_config::ssh_config::line_matches_sshwarden_include(l, &include_path)
            })
        })
        .unwrap_or(false);

    let snippet_size = std::fs::metadata(&include_path).map(|m| m.len()).ok();

    #[allow(clippy::print_stdout)]
    {
        println!(
            "Bindings file:   {}",
            sshwarden_config::bindings::HostBindingsFile::path()?.display()
        );
        println!("Managed snippet: {}", include_path.display());
        if let Some(size) = snippet_size {
            println!("  → exists ({size} bytes)");
        } else {
            println!("  → not present");
        }
        println!("User ssh config: {}", config_path.display());
        println!(
            "  → Include line {}",
            if user_config_has_include {
                "present"
            } else {
                "missing"
            }
        );
        println!(
            "Key cache:       {} keys",
            cache.as_ref().map(|c| c.header.keys.len()).unwrap_or(0)
        );
        let total_hosts: usize = bindings.bindings.values().map(|b| b.hosts.len()).sum();
        println!(
            "Bindings:        {} key(s) bound to {} host pattern(s)",
            bindings.bindings.len(),
            total_hosts
        );
    }
    Ok(())
}

async fn cmd_sshcfg_show() -> anyhow::Result<()> {
    let include_path = managed_sshwarden_include_path()?;
    let content = std::fs::read_to_string(&include_path)
        .with_context(|| format!("Failed to read {}", include_path.display()))?;
    #[allow(clippy::print_stdout)]
    {
        print!("{}", content);
        if !content.ends_with('\n') {
            println!();
        }
    }
    Ok(())
}

async fn run_foreground(
    mut config: sshwarden_config::Config,
    ui_request_tx: UIRequestTx,
) -> anyhow::Result<()> {
    info!("Starting SSHWarden SSH Agent...");
    info!("Server: {}", config.server.base_url);

    // Check for persisted cache/vault files BEFORE prompting for master password.
    let local_key_cache = sshwarden_config::cache::LocalKeyCacheFile::load()
        .unwrap_or_else(|e| {
            tracing::warn!("Failed to load local key cache: {}", e);
            None
        })
        .inspect(|cache| {
            // Multi-device migration aid: if an older shared cache still carries
            // platform unlock slots, copy them into this device's private
            // unlock-slots file. Future cache writes strip platform slots from
            // the shared file so devices stop overwriting each other.
            if let Err(e) = persist_device_unlock_slots_from_cache(cache) {
                tracing::warn!("Failed to persist device unlock slots: {}", e);
            }
        });
    let vault_file = sshwarden_config::vault::VaultFile::load().unwrap_or_else(|e| {
        tracing::warn!("Failed to load vault file: {}", e);
        None
    });

    let has_local_key_cache = local_key_cache.is_some();
    let has_vault_file = vault_file.is_some();
    let has_remembered_device = has_local_key_cache || has_vault_file;

    // Login and fetch keys BEFORE starting the agent server (so password prompt works cleanly)
    // Skip if we have a remembered device — user will unlock with PIN/Hello/password later.
    let mut api_client: Option<sshwarden_api::BitwardenClient> = None;
    let mut first_login = false;
    let vault_keys = if has_remembered_device {
        if has_local_key_cache {
            info!("Local key cache found. Starting locked with listable key identities.");
        } else {
            info!("Legacy vault file found. Use Hello/PIN/password to unlock.");
        }
        None
    } else {
        // No vault file — need to login with master password
        // If email is not configured, ask interactively and save to config
        if config.auth.email.is_empty() {
            let email = prompt_email("Email: ")?;
            if email.is_empty() {
                info!("No email provided. Agent will start with no keys.");
                None
            } else {
                config.auth.email = email;
                if let Err(e) = config.save() {
                    tracing::warn!("Failed to save config: {}", e);
                } else {
                    info!("Email saved to config.toml");
                }
                first_login = true;
                match fetch_vault_keys_with_client(&config).await {
                    Ok((keys, client)) => {
                        info!("Fetched {} SSH key(s) from vault", keys.len());
                        api_client = Some(client);
                        Some(keys)
                    }
                    Err(e) => {
                        tracing::warn!("Failed to fetch vault keys: {}.", e);
                        None
                    }
                }
            }
        } else {
            first_login = true;
            match fetch_vault_keys_with_client(&config).await {
                Ok((keys, client)) => {
                    info!("Fetched {} SSH key(s) from vault", keys.len());
                    api_client = Some(client);
                    Some(keys)
                }
                Err(e) => {
                    tracing::warn!("Failed to fetch vault keys: {}.", e);
                    None
                }
            }
        }
    };

    // Create channels for UI communication
    let (request_tx, mut request_rx) =
        tokio::sync::mpsc::channel::<sshwarden_agent::SshAgentUIRequest>(32);
    // CONC-4 mitigation: a generous capacity makes a broadcast `Lagged` (which
    // would otherwise be treated as a denial in confirm()/can_list()) effectively
    // impossible under realistic concurrency. The fully race-free fix (per-request
    // oneshot registry) needs runtime verification of the signing path and is
    // tracked as a follow-up.
    let (response_tx, _response_rx) = tokio::sync::broadcast::channel::<(u32, bool)>(256);
    let response_tx = Arc::new(response_tx);
    let (runtime_event_tx, mut runtime_event_rx) = tokio::sync::mpsc::channel::<RuntimeEvent>(32);

    // Start the SSH agent server
    let agent_endpoint = config.socket.path.as_deref().map(std::path::PathBuf::from);
    let mut agent = sshwarden_agent::SshWardenAgent::start_server_with_endpoint(
        request_tx,
        response_tx.clone(),
        agent_endpoint,
    )
    .context("Failed to start SSH agent server")?;

    // RT-01: watch for a fatal agent-transport failure (e.g. the OpenSSH pipe
    // could not be claimed) so the daemon shuts down instead of running as a
    // zombie that still answers status/unlock while serving no SSH client.
    let mut agent_fatal_rx = agent.fatal_rx();

    // Build a map of cipher_id -> key_name for UI display
    let key_names: Arc<std::collections::HashMap<String, String>> = Arc::new(
        vault_keys
            .as_ref()
            .map(|keys| {
                keys.iter()
                    .map(|k| (k.cipher_id.clone(), k.name.clone()))
                    .collect()
            })
            .unwrap_or_default(),
    );

    // Cache key tuples for re-loading after unlock, track public key identities,
    // and track vault lock state.
    let cached_key_tuples: CachedKeyTuples = Arc::new(RwLock::new(SecureKeyCache::new()));
    let public_key_identity_tuples: CachedKeyTuples = Arc::new(RwLock::new(SecureKeyCache::new()));
    let vault_locked = Arc::new(std::sync::atomic::AtomicBool::new(has_remembered_device));
    let api_client: Arc<RwLock<Option<sshwarden_api::BitwardenClient>>> =
        Arc::new(RwLock::new(api_client));
    let pin_encrypted_keys: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(
        vault_file.as_ref().map(|v| v.pin_encrypted.clone()),
    ));
    let vault_file_data: Arc<RwLock<Option<sshwarden_config::vault::VaultFile>>> =
        Arc::new(RwLock::new(vault_file));
    let local_key_cache_data: Arc<RwLock<Option<sshwarden_config::cache::LocalKeyCacheFile>>> =
        Arc::new(RwLock::new(local_key_cache));
    let local_cache_key_state: LocalCacheKeyHandle =
        Arc::new(RwLock::new(LocalCacheKeyState::default()));
    let authorization_memory: AuthorizationMemorySet =
        Arc::new(RwLock::new(std::collections::HashSet::new()));
    let key_material_fingerprints: KeyMaterialFingerprints =
        Arc::new(RwLock::new(std::collections::HashMap::new()));
    let pending_sync = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let pin_failures: PinFailureHandle =
        Arc::new(std::sync::Mutex::new(PinFailureState::default()));
    // CONC-6: count in-flight UI requests (sign/unlock prompts) so the inactivity
    // auto-lock does not fire while a prompt is open (last_activity is only
    // refreshed at request arrival, not while the user is deciding).
    let in_flight_prompts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let key_names = Arc::new(RwLock::new((*key_names).clone()));

    // Load vault keys into agent
    if let Some(keys) = vault_keys {
        let key_tuples: Vec<(String, String, String)> = keys
            .iter()
            .map(|k| {
                (
                    (*k.private_key_pem).clone(),
                    k.name.clone(),
                    k.cipher_id.clone(),
                )
            })
            .collect();
        let count = key_tuples.len();
        if count > 0 {
            if let Err(e) = write_key_selector_files(&keys) {
                tracing::warn!("Failed to write key selector files: {}", e);
            }
            if let Err(e) = sync_managed_ssh_config_with_bindings(&keys) {
                tracing::warn!("Failed to sync managed SSH config: {}", e);
            }
            public_key_identity_tuples
                .write()
                .await
                .set(key_tuples.clone());
            cached_key_tuples.write().await.set(key_tuples.clone());
            *key_material_fingerprints.write().await =
                key_material_fingerprints_from_tuples(&key_tuples);
            agent.set_keys(key_tuples)?;
            info!("Loaded {} SSH key(s) into agent", count);

            // After first login with keys loaded, offer to set up PIN for persistence
            if first_login {
                prompt_setup_pin(
                    &cached_key_tuples,
                    &pin_encrypted_keys,
                    &vault_file_data,
                    &local_key_cache_data,
                    &local_cache_key_state,
                    &config,
                    &api_client,
                )
                .await;
            }
        }
    } else if let Some(cache) = local_key_cache_data.read().await.as_ref() {
        let identities = key_tuples_from_cache_header(cache);
        let count = identities.len();
        if count > 0 {
            public_key_identity_tuples
                .write()
                .await
                .set(identities.clone());
            {
                let mut names = key_names.write().await;
                names.clear();
                for (_, name, vault_item_id) in &identities {
                    names.insert(vault_item_id.clone(), name.clone());
                }
            }
            if let Err(e) = agent.set_public_identities(identities) {
                tracing::warn!(
                    "Failed to load public key identities from local cache: {}",
                    e
                );
            } else {
                info!(
                    "Loaded {} public key identity/identities from local key cache",
                    count
                );
            }
        } else {
            info!("Local key cache has no key identities.");
        }
    } else if !has_vault_file {
        info!("Agent running with no keys.");
    }

    // Start the IPC control server
    #[allow(unused_variables)]
    let (control_tx, mut control_rx) =
        tokio::sync::mpsc::channel::<sshwarden_agent::ControlRequest>(16);
    let cancel_token = tokio_util::sync::CancellationToken::new();

    {
        let cancel_clone = cancel_token.clone();
        tokio::spawn(async move {
            sshwarden_agent::control::start_control_server(control_tx, cancel_clone).await;
        });
    }

    info!("SSH Agent is running. Press Ctrl+C to stop.");

    // Main loop configuration
    let prompt_behavior = config.agent.prompt_behavior;
    let auto_unlock = config.unlock.auto_unlock_on_request;
    let lock_timeout = config.agent.lock_timeout;
    let config = Arc::new(config);
    let mut last_activity = tokio::time::Instant::now();
    let mut lock_check_interval = tokio::time::interval(std::time::Duration::from_secs(60));
    let mut token_refresh_interval = tokio::time::interval(std::time::Duration::from_secs(30 * 60));
    // Skip the first immediate tick for token refresh
    token_refresh_interval.tick().await;

    // Notification hub state
    let mut notification_rx: Option<tokio::sync::mpsc::Receiver<sshwarden_api::SyncEvent>> = None;
    let mut _notification_client: Option<sshwarden_api::NotificationClient> = None;
    let notification_state = Arc::new(RwLock::new(NotificationRuntimeState::default()));

    // Connect to notification hub if we already have an API session (first login)
    {
        let client_guard = api_client.read().await;
        if let Some(ref client) = *client_guard {
            if let Some(token) = client.access_token() {
                connect_notification_client(
                    &config,
                    Some(client),
                    token,
                    &mut notification_rx,
                    &mut _notification_client,
                    &notification_state,
                )
                .await;

                // Save device session for this host
                save_device_session(client, &config, None).await;
            }
        }
    }

    loop {
        tokio::select! {
            // Control commands from IPC
            Some(ctrl_req) = control_rx.recv() => {
                last_activity = tokio::time::Instant::now();
                // `stop` shuts the daemon down cleanly: ack, then break the loop
                // so the cancel-token cleanup below runs (same path as Ctrl-C).
                if matches!(ctrl_req.action, sshwarden_agent::ControlAction::Stop) {
                    let _ = ctrl_req
                        .reply
                        .send(sshwarden_agent::ControlResponse::ok("Stopping agent"));
                    info!("Received stop command, shutting down...");
                    break;
                }
                let response = handle_control_command(
                    ctrl_req.action,
                    &mut agent,
                    &vault_locked,
                    &cached_key_tuples,
                    &public_key_identity_tuples,
                    &api_client,
                    &pin_encrypted_keys,
                    &vault_file_data,
                    &local_key_cache_data,
                    &local_cache_key_state,
                    &key_material_fingerprints,
                    &key_names,
                    &config,
                    auto_unlock,
                    &ui_request_tx,
                    &mut notification_rx,
                    &mut _notification_client,
                    &pending_sync,
                    &notification_state,
                    &authorization_memory,
                    &pin_failures,
                ).await;
                let _ = ctrl_req.reply.send(response);
            }
            // UI requests from SSH agent
            Some(request) = request_rx.recv() => {
                last_activity = tokio::time::Instant::now();

                // CONC-6: mark a request in flight for the duration of the
                // handler (which may open a long sign/unlock prompt).
                in_flight_prompts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let in_flight_done = in_flight_prompts.clone();

                // Spawn a task to handle each request so we don't block the main loop
                let response_tx_clone = (*response_tx).clone();
                let vault_locked_clone = vault_locked.clone();
                let cached_keys_clone = cached_key_tuples.clone();
                let agent_clone = agent.clone();
                let key_names_clone = key_names.clone();
                let pin_encrypted_clone = pin_encrypted_keys.clone();
                let vault_file_clone = vault_file_data.clone();
                let local_key_cache_clone = local_key_cache_data.clone();
                let local_cache_key_state_clone = local_cache_key_state.clone();
                let runtime_event_tx_clone = runtime_event_tx.clone();
                let authorization_memory_clone = authorization_memory.clone();
                let pin_failures_clone = pin_failures.clone();

                let ui_tx_clone = ui_request_tx.clone();

                tokio::spawn(async move {
                    handle_ui_request(
                        request,
                        response_tx_clone,
                        vault_locked_clone,
                        cached_keys_clone,
                        agent_clone,
                        key_names_clone,
                        pin_encrypted_clone,
                        vault_file_clone,
                        local_key_cache_clone,
                        local_cache_key_state_clone,
                        prompt_behavior,
                        auto_unlock,
                        ui_tx_clone,
                        runtime_event_tx_clone,
                        authorization_memory_clone,
                        pin_failures_clone,
                    ).await;
                    in_flight_done.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                });
            }
            // Runtime events from spawned SSH request handlers
            Some(event) = runtime_event_rx.recv() => {
                match event {
                    #[cfg(windows)]
                    RuntimeEvent::AutoUnlockedWindowsHello => {
                        try_restore_api_session_hello(
                            &api_client,
                            &config,
                            &mut notification_rx,
                            &mut _notification_client,
                            &notification_state,
                        )
                        .await;
                        resolve_pending_sync(
                            &pending_sync,
                            &api_client,
                            &cached_key_tuples,
                            &public_key_identity_tuples,
                            &local_key_cache_data,
                            &local_cache_key_state,
                            &authorization_memory,
                            &key_material_fingerprints,
                            &vault_locked,
                            &mut agent,
                            &key_names,
                            &notification_state,
                        )
                        .await;
                    }
                    RuntimeEvent::AutoUnlockedPin { pin } => {
                        try_restore_api_session(
                            &api_client,
                            &config,
                            &pin,
                            &mut notification_rx,
                            &mut _notification_client,
                            &notification_state,
                        )
                        .await;
                        resolve_pending_sync(
                            &pending_sync,
                            &api_client,
                            &cached_key_tuples,
                            &public_key_identity_tuples,
                            &local_key_cache_data,
                            &local_cache_key_state,
                            &authorization_memory,
                            &key_material_fingerprints,
                            &vault_locked,
                            &mut agent,
                            &key_names,
                            &notification_state,
                        )
                        .await;
                    }
                    RuntimeEvent::AutoUnlockedNative => {
                        // Native (Keychain / Secret Service / DPAPI) unlock cannot
                        // currently restore an API session — SessionFile has no
                        // native_encrypted_token slot — so we only resolve any
                        // sync that was deferred while the vault was locked.
                        resolve_pending_sync(
                            &pending_sync,
                            &api_client,
                            &cached_key_tuples,
                            &public_key_identity_tuples,
                            &local_key_cache_data,
                            &local_cache_key_state,
                            &authorization_memory,
                            &key_material_fingerprints,
                            &vault_locked,
                            &mut agent,
                            &key_names,
                            &notification_state,
                        )
                        .await;
                    }
                }
            }
            // Notification hub events
            Some(event) = async {
                match notification_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match event {
                    sshwarden_api::SyncEvent::CipherChanged => {
                        if vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
                            pending_sync.store(true, std::sync::atomic::Ordering::Relaxed);
                            info!("Notification: cipher changed while locked; sync pending until unlock");
                        } else {
                            info!("Notification: cipher changed, syncing...");
                            match do_sync(&api_client, &cached_key_tuples, &public_key_identity_tuples, &local_key_cache_data, &local_cache_key_state, &authorization_memory, &key_material_fingerprints, &vault_locked, &mut agent, &key_names, &notification_state).await {
                                Ok(count) => {
                                    notification_state.write().await.last_event_at = Some(std::time::Instant::now());
                                    info!("Auto-synced: {} SSH keys", count)
                                },
                                Err(e) => {
                                    pending_sync.store(true, std::sync::atomic::Ordering::Relaxed);
                                    tracing::warn!("Auto-sync failed: {}; sync remains pending", e);
                                }
                            }
                        }
                    }
                    sshwarden_api::SyncEvent::LogOut => {
                        notification_state.write().await.last_event_at = Some(std::time::Instant::now());
                        info!("Notification: remote logout");
                        let _ = lock_vault(&mut agent, &vault_locked, &cached_key_tuples, Some(&local_cache_key_state), Some(&authorization_memory)).await;
                    }
                    sshwarden_api::SyncEvent::FallbackSyncDue => {
                        if vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
                            pending_sync.store(true, std::sync::atomic::Ordering::Relaxed);
                            info!("Notification degraded while locked; sync pending until unlock");
                        } else {
                            info!("Notification degraded, running fallback sync...");
                            match do_sync(&api_client, &cached_key_tuples, &public_key_identity_tuples, &local_key_cache_data, &local_cache_key_state, &authorization_memory, &key_material_fingerprints, &vault_locked, &mut agent, &key_names, &notification_state).await {
                                Ok(count) => {
                                    let mut state = notification_state.write().await;
                                    state.last_event_at = Some(std::time::Instant::now());
                                    state.last_fallback_sync_at = Some(std::time::Instant::now());
                                    info!("Fallback-synced: {} SSH keys", count)
                                },
                                Err(e) => {
                                    pending_sync.store(true, std::sync::atomic::Ordering::Relaxed);
                                    tracing::warn!("Fallback sync failed: {}; sync remains pending", e);
                                }
                            }
                        }
                    }
                }
            }
            // Token auto-refresh
            _ = token_refresh_interval.tick() => {
                let mut client_guard = api_client.write().await;
                if let Some(ref mut client) = *client_guard {
                    if client.is_token_expiring_soon() {
                        match client.refresh_access_token().await {
                            Ok(()) => {
                                info!("Access token refreshed");
                                // Update session file with new refresh token
                                save_device_session(client, &config, None).await;
                                if let Some(token) = client.access_token().map(str::to_string) {
                                    connect_notification_client(
                                        &config,
                                        Some(&*client),
                                        &token,
                                        &mut notification_rx,
                                        &mut _notification_client,
                                        &notification_state,
                                    ).await;
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Token refresh failed: {}", e);
                            }
                        }
                    }
                }
            }
            // Auto-lock check
            _ = lock_check_interval.tick() => {
                if lock_timeout > 0
                    && !vault_locked.load(std::sync::atomic::Ordering::Relaxed)
                    && in_flight_prompts.load(std::sync::atomic::Ordering::Relaxed) == 0
                    && last_activity.elapsed().as_secs() >= lock_timeout
                {
                    info!("Auto-locking vault due to inactivity ({} seconds)", lock_timeout);
                    let _ = lock_vault(&mut agent, &vault_locked, &cached_key_tuples, Some(&local_cache_key_state), Some(&authorization_memory)).await;
                }
            }
            // SSH agent transport failed (e.g. could not claim the OpenSSH pipe).
            // Shut down rather than run as a zombie that answers status/unlock
            // while serving no SSH client (RT-01).
            changed = agent_fatal_rx.changed() => {
                if changed.is_err() {
                    tracing::error!("SSH agent signal channel closed; shutting down");
                    break;
                }
                let reason = agent_fatal_rx.borrow().clone();
                if let Some(reason) = reason {
                    tracing::error!(%reason, "SSH agent transport failed; shutting down daemon");
                    break;
                }
            }
            // Shutdown signal
            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl+C, shutting down...");
                break;
            }
        }
    }

    cancel_token.cancel();
    notification_state.write().await.state = NotificationConnectionState::Stopped;
    agent.stop();
    info!("SSHWarden stopped.");
    Ok(())
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
    use crate::sshconfig::import_host_bindings_from_managed_file;

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
