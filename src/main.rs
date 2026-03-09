use std::sync::Arc;

use anyhow::Context;
#[cfg(windows)]
use base64::Engine;
use clap::{Parser, Subcommand};
use tokio::sync::RwLock;
use tracing::info;

// Type alias for cached key tuples (name, public_key, private_key)
type CachedKeyTuples = Arc<RwLock<Vec<(String, String, String)>>>;

#[derive(Parser)]
#[command(
    name = "sshwarden",
    version,
    about = "SSH Agent backed by Bitwarden vault"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run daemon in background
    Daemon {
        /// Create startup shortcut for auto-start on login
        #[arg(long)]
        install: bool,
        /// Remove startup shortcut
        #[arg(long)]
        uninstall: bool,
    },
    /// Login to Bitwarden server and start agent with vault keys
    Login {
        /// Bitwarden server base URL (overrides config)
        #[arg(long)]
        base_url: Option<String>,
        /// Email address
        #[arg(long)]
        email: Option<String>,
    },
    /// Unlock the vault
    Unlock {
        /// Use PIN instead of Windows Hello
        #[arg(long)]
        pin: bool,
        /// Use master password to re-login and unlock
        #[arg(long)]
        password: bool,
        /// Use Windows Hello sign-path to unlock
        #[arg(long)]
        hello: bool,
    },
    /// Lock the vault (clear private keys from memory)
    Lock,
    /// Set or update PIN for quick unlock
    SetPin,
    /// Show agent status
    Status,
    /// List available SSH keys from vault (requires login)
    Keys {
        /// Bitwarden server base URL (overrides config)
        #[arg(long)]
        base_url: Option<String>,
        /// Email address
        #[arg(long)]
        email: Option<String>,
    },
    /// Manually trigger vault sync
    Sync,
    /// Edit configuration
    Config,
}

/// Type alias for the UI request sender passed through the system.
type UIRequestTx = Arc<tokio::sync::mpsc::Sender<sshwarden_ui::UIRequest>>;

fn main() -> anyhow::Result<()> {
    // Set Per-Monitor DPI Awareness V2 before any UI calls.
    // This prevents Win32 dialogs (CredUI) from being blurry on high-DPI displays.
    sshwarden_ui::init();

    let cli = Cli::parse();

    // Daemon mode: log to file; otherwise log to stderr
    let is_daemon = matches!(
        cli.command,
        Some(Commands::Daemon {
            install: false,
            uninstall: false
        })
    );

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

    // Determine if we need the Slint UI event loop (foreground/daemon modes)
    let needs_ui = matches!(
        cli.command,
        None | Some(Commands::Daemon {
            install: false,
            uninstall: false
        })
    );

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
                if is_daemon_mode {
                    if is_daemon_running() {
                        info!("SSHWarden daemon is already running");
                        return Ok(());
                    }
                    #[cfg(windows)]
                    detach_console();

                    write_pid_file()?;
                    info!("SSHWarden daemon started (PID: {})", std::process::id());
                    let result = run_foreground(config, ui_tx).await;
                    remove_pid_file();
                    result
                } else {
                    run_foreground(config, ui_tx).await
                }
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
                None => unreachable!(),
                Some(Commands::Daemon { install, uninstall }) => {
                    if install {
                        cmd_daemon_install().await
                    } else if uninstall {
                        cmd_daemon_uninstall().await
                    } else {
                        unreachable!()
                    }
                }
                Some(Commands::Login { base_url, email }) => {
                    cmd_login(&config, base_url.as_deref(), email.as_deref()).await
                }
                Some(Commands::Keys { base_url, email }) => {
                    cmd_keys(&config, base_url.as_deref(), email.as_deref()).await
                }
                Some(Commands::Lock) => cmd_control("lock").await,
                Some(Commands::Unlock {
                    pin,
                    password,
                    hello,
                }) => {
                    if pin {
                        let pin_value = prompt_password("Enter PIN: ")?;
                        let cmd = format!("unlock-pin:{}", pin_value);
                        cmd_control(&cmd).await
                    } else if password {
                        let pw = prompt_password("Master password: ")?;
                        let cmd = format!("unlock-password:{}", pw);
                        cmd_control(&cmd).await
                    } else if hello {
                        cmd_control("unlock-hello").await
                    } else {
                        cmd_control("unlock").await
                    }
                }
                Some(Commands::Status) => cmd_control("status").await,
                Some(Commands::Config) => {
                    let path = sshwarden_config::config_path()?;
                    if !path.exists() {
                        config.save()?;
                        info!("Created default config at: {}", path.display());
                    } else {
                        info!("Config file: {}", path.display());
                    }
                    Ok(())
                }
                Some(Commands::SetPin) => cmd_set_pin().await,
                Some(Commands::Sync) => cmd_control("sync").await,
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
                } => {
                    let result = slint::invoke_from_event_loop(move || {
                        sshwarden_ui::unlock::show_pin_dialog(response_tx, validator);
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
            }
        }

        // Channel closed — tokio thread has finished, quit Slint event loop.
        let _ = slint::quit_event_loop();
    });

    // Keep event loop alive even if all windows are closed.
    let _ = slint::run_event_loop_until_quit();
}
/// Send a control command to the running daemon via IPC.
#[cfg(windows)]
async fn cmd_control(cmd: &str) -> anyhow::Result<()> {
    match sshwarden_agent::control::send_control_command(cmd).await {
        Ok(response) => {
            if response.ok {
                if let Some(msg) = &response.message {
                    info!("{}", msg);
                }
                if let Some(locked) = response.locked {
                    info!("  Locked: {}", locked);
                }
                if let Some(count) = response.key_count {
                    info!("  Keys: {}", count);
                }
            } else {
                let err = response.error.as_deref().unwrap_or("Unknown error");
                info!("Error: {}", err);
            }
            Ok(())
        }
        Err(e) => {
            info!("Could not connect to SSHWarden daemon: {}", e);
            info!("Is the daemon running? Start it with: sshwarden");
            Ok(())
        }
    }
}

#[cfg(not(windows))]
async fn cmd_control(_cmd: &str) -> anyhow::Result<()> {
    info!("IPC control is only supported on Windows currently");
    Ok(())
}

/// Set PIN command: prompt for PIN and send to daemon.
async fn cmd_set_pin() -> anyhow::Result<()> {
    let pin = prompt_password("Enter new PIN: ")?;
    if pin.len() < 4 {
        info!("PIN must be at least 4 characters");
        return Ok(());
    }
    let pin_confirm = prompt_password("Confirm PIN: ")?;
    if pin != pin_confirm {
        info!("PINs do not match");
        return Ok(());
    }

    let cmd = format!("set-pin:{}", pin);
    cmd_control(&cmd).await
}

/// Prompt for a password from the terminal (hides input).
fn prompt_password(prompt: &str) -> anyhow::Result<String> {
    rpassword::prompt_password(prompt).context("Failed to read password")
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

/// Login command: authenticate and list SSH keys.
async fn cmd_login(
    config: &sshwarden_config::Config,
    base_url: Option<&str>,
    email: Option<&str>,
) -> anyhow::Result<()> {
    let email = match email {
        Some(e) => e.to_string(),
        None if !config.auth.email.is_empty() => config.auth.email.clone(),
        None => prompt_email("Email: ")?,
    };
    let password = prompt_password("Master password: ")?;

    let mut client = create_client(config, base_url);

    info!("Logging in as {}...", email);
    client.login_password(&email, &password).await?;
    info!("Login successful!");

    let keys = client.sync_ssh_keys().await?;
    for key in &keys {
        info!("  SSH Key: {} (cipher: {})", key.name, key.cipher_id);
    }

    if keys.is_empty() {
        info!("No SSH keys found in vault. Add SSH keys in Bitwarden to use them.");
    }

    Ok(())
}

/// Keys command: login, sync, and list SSH keys.
async fn cmd_keys(
    config: &sshwarden_config::Config,
    base_url: Option<&str>,
    email: Option<&str>,
) -> anyhow::Result<()> {
    let email = match email {
        Some(e) => e.to_string(),
        None if !config.auth.email.is_empty() => config.auth.email.clone(),
        None => prompt_email("Email: ")?,
    };
    let password = prompt_password("Master password: ")?;

    let mut client = create_client(config, base_url);

    info!("Logging in as {}...", email);
    client.login_password(&email, &password).await?;

    let keys = client.sync_ssh_keys().await?;
    if keys.is_empty() {
        info!("No SSH keys found in vault.");
    } else {
        info!("Found {} SSH key(s):", keys.len());
        for key in &keys {
            // Show first line of PEM to identify key type
            let key_type = if key.private_key_pem.contains("ed25519") {
                "ED25519"
            } else if key.private_key_pem.contains("BEGIN RSA") {
                "RSA"
            } else {
                "SSH"
            };
            info!("  [{}] {} ({})", key_type, key.name, key.cipher_id);
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

    // Check for persisted vault file BEFORE prompting for master password
    let vault_file = sshwarden_config::vault::VaultFile::load().unwrap_or_else(|e| {
        tracing::warn!("Failed to load vault file: {}", e);
        None
    });

    let has_vault_file = vault_file.is_some();

    // Login and fetch keys BEFORE starting the agent server (so password prompt works cleanly)
    // Skip if we have a vault file — user will unlock with PIN/Hello/password later
    let mut api_client: Option<sshwarden_api::BitwardenClient> = None;
    let mut first_login = false;
    let vault_keys = if has_vault_file {
        info!("Vault file found. Use Hello/PIN/password to unlock.");
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
    let (response_tx, _response_rx) = tokio::sync::broadcast::channel::<(u32, bool)>(32);
    let response_tx = Arc::new(response_tx);

    // Start the SSH agent server
    let mut agent = sshwarden_agent::SshWardenAgent::start_server(request_tx, response_tx.clone())
        .context("Failed to start SSH agent server")?;

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

    // Cache key tuples for re-loading after unlock, and track vault lock state
    let cached_key_tuples: CachedKeyTuples = Arc::new(RwLock::new(Vec::new()));
    let vault_locked = Arc::new(std::sync::atomic::AtomicBool::new(has_vault_file));
    let api_client: Arc<RwLock<Option<sshwarden_api::BitwardenClient>>> =
        Arc::new(RwLock::new(api_client));
    let pin_encrypted_keys: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(
        vault_file.as_ref().map(|v| v.pin_encrypted.clone()),
    ));
    let vault_file_data: Arc<RwLock<Option<sshwarden_config::vault::VaultFile>>> =
        Arc::new(RwLock::new(vault_file));
    let key_names = Arc::new(RwLock::new((*key_names).clone()));

    // Load vault keys into agent
    if let Some(keys) = vault_keys {
        let key_tuples: Vec<(String, String, String)> = keys
            .iter()
            .map(|k| {
                (
                    k.private_key_pem.clone(),
                    k.name.clone(),
                    k.cipher_id.clone(),
                )
            })
            .collect();
        let count = key_tuples.len();
        if count > 0 {
            *cached_key_tuples.write().await = key_tuples.clone();
            agent.set_keys(key_tuples)?;
            info!("Loaded {} SSH key(s) into agent", count);

            // After first login with keys loaded, offer to set up PIN for persistence
            if first_login {
                prompt_setup_pin(
                    &cached_key_tuples,
                    &pin_encrypted_keys,
                    &vault_file_data,
                    &config,
                )
                .await;
            }
        }
    } else if !has_vault_file {
        info!("Agent running with no keys.");
    }

    // Start the IPC control server
    #[allow(unused_variables)]
    let (control_tx, mut control_rx) =
        tokio::sync::mpsc::channel::<sshwarden_agent::ControlRequest>(16);
    let cancel_token = tokio_util::sync::CancellationToken::new();

    #[cfg(windows)]
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

    loop {
        tokio::select! {
            // Control commands from IPC
            Some(ctrl_req) = control_rx.recv() => {
                last_activity = tokio::time::Instant::now();
                let response = handle_control_command(
                    ctrl_req.action,
                    &mut agent,
                    &vault_locked,
                    &cached_key_tuples,
                    &api_client,
                    &pin_encrypted_keys,
                    &vault_file_data,
                    &key_names,
                    &config,
                    auto_unlock,
                    &ui_request_tx,
                ).await;
                let _ = ctrl_req.reply.send(response);
            }
            // UI requests from SSH agent
            Some(request) = request_rx.recv() => {
                last_activity = tokio::time::Instant::now();

                // Spawn a task to handle each request so we don't block the main loop
                let response_tx_clone = (*response_tx).clone();
                let vault_locked_clone = vault_locked.clone();
                let cached_keys_clone = cached_key_tuples.clone();
                let agent_clone = agent.clone();
                let key_names_clone = key_names.clone();
                let pin_encrypted_clone = pin_encrypted_keys.clone();
                let vault_file_clone = vault_file_data.clone();

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
                        prompt_behavior,
                        auto_unlock,
                        ui_tx_clone,
                    ).await;
                });
            }
            // Auto-lock check
            _ = lock_check_interval.tick() => {
                if lock_timeout > 0
                    && !vault_locked.load(std::sync::atomic::Ordering::Relaxed)
                    && last_activity.elapsed().as_secs() >= lock_timeout
                {
                    info!("Auto-locking vault due to inactivity ({} seconds)", lock_timeout);
                    if agent.lock().is_ok() {
                        vault_locked.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
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
    agent.stop();
    info!("SSHWarden stopped.");
    Ok(())
}

/// Handle a control command from the IPC channel.
#[allow(clippy::too_many_arguments)]
async fn handle_control_command(
    action: sshwarden_agent::ControlAction,
    agent: &mut sshwarden_agent::SshWardenAgent,
    vault_locked: &Arc<std::sync::atomic::AtomicBool>,
    cached_key_tuples: &CachedKeyTuples,
    api_client: &Arc<RwLock<Option<sshwarden_api::BitwardenClient>>>,
    pin_encrypted_keys: &Arc<RwLock<Option<String>>>,
    vault_file_data: &Arc<RwLock<Option<sshwarden_config::vault::VaultFile>>>,
    key_names: &Arc<RwLock<std::collections::HashMap<String, String>>>,
    config: &Arc<sshwarden_config::Config>,
    auto_unlock: bool,
    ui_request_tx: &UIRequestTx,
) -> sshwarden_agent::ControlResponse {
    use sshwarden_agent::ControlAction;

    match action {
        ControlAction::Lock => {
            if vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
                sshwarden_agent::ControlResponse::ok("Vault is already locked")
            } else {
                match agent.lock() {
                    Ok(()) => {
                        vault_locked.store(true, std::sync::atomic::Ordering::Relaxed);
                        info!("Vault locked via control command");
                        sshwarden_agent::ControlResponse::ok("Vault locked")
                    }
                    Err(e) => {
                        sshwarden_agent::ControlResponse::err(&format!("Failed to lock: {}", e))
                    }
                }
            }
        }
        ControlAction::Unlock => {
            if !vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
                return sshwarden_agent::ControlResponse::ok("Vault is already unlocked");
            }

            // Try Hello sign-path first (if hello_challenge available)
            #[cfg(windows)]
            {
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

                            // Try Hello sign-path unlock
                            let hello_result = tokio::task::spawn_blocking(move || {
                                try_hello_unlock(&challenge, &hello_encrypted)
                            })
                            .await;

                            if let Ok(Ok(keys_json)) = hello_result {
                                return finish_unlock_with_json(
                                    &keys_json,
                                    agent,
                                    vault_locked,
                                    cached_key_tuples,
                                    key_names,
                                    "Vault unlocked via Windows Hello",
                                )
                                .await;
                            }
                            info!("Hello unlock failed or cancelled, trying fallback");
                        }
                    }
                }
            }

            // Fall back to PIN dialog when Hello sign-path fails
            if auto_unlock {
                info!("Hello sign-path failed, trying PIN dialog fallback");
                let enc_data =
                    get_pin_encrypted_data(pin_encrypted_keys, vault_file_data).await;

                if let Some(enc_data) = enc_data {
                    let (validator, decrypted_cache) = make_pin_validator(enc_data);
                    let pin_result =
                        sshwarden_ui::unlock::request_pin_dialog(ui_request_tx, validator)
                            .await;

                    if pin_result.is_some() {
                        let keys_json =
                            decrypted_cache.lock().unwrap().take().unwrap();
                        return finish_unlock_with_json(
                            &keys_json,
                            agent,
                            vault_locked,
                            cached_key_tuples,
                            key_names,
                            "Vault unlocked via PIN dialog",
                        )
                        .await;
                    }
                }
                return sshwarden_agent::ControlResponse::err(
                    "Unlock cancelled. Try: unlock --pin or unlock --password",
                );
            }

            sshwarden_agent::ControlResponse::err(
                "Auto-unlock is disabled. Use: unlock --pin or unlock --password",
            )
        }
        ControlAction::UnlockHello => {
            if !vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
                return sshwarden_agent::ControlResponse::ok("Vault is already unlocked");
            }

            #[cfg(windows)]
            {
                let vf = vault_file_data.read().await;
                let (challenge_b64, hello_encrypted) = match *vf {
                    Some(ref v) => (v.hello_challenge.clone(), v.hello_encrypted.clone()),
                    None => {
                        return sshwarden_agent::ControlResponse::err(
                            "No vault file found. Set PIN first.",
                        )
                    }
                };
                drop(vf);

                let challenge_b64 =
                    match challenge_b64 {
                        Some(c) => c,
                        None => return sshwarden_agent::ControlResponse::err(
                            "Windows Hello not enrolled. Set PIN with Hello available to enroll.",
                        ),
                    };

                let hello_encrypted =
                    match hello_encrypted {
                        Some(e) => e,
                        None => return sshwarden_agent::ControlResponse::err(
                            "Windows Hello not enrolled. Set PIN with Hello available to enroll.",
                        ),
                    };

                let challenge_bytes =
                    match base64::engine::general_purpose::STANDARD.decode(&challenge_b64) {
                        Ok(b) if b.len() == 16 => {
                            let mut arr = [0u8; 16];
                            arr.copy_from_slice(&b);
                            arr
                        }
                        _ => {
                            return sshwarden_agent::ControlResponse::err(
                                "Invalid hello_challenge in vault file",
                            )
                        }
                    };

                let hello_result = tokio::task::spawn_blocking(move || {
                    try_hello_unlock(&challenge_bytes, &hello_encrypted)
                })
                .await;

                match hello_result {
                    Ok(Ok(keys_json)) => {
                        finish_unlock_with_json(
                            &keys_json,
                            agent,
                            vault_locked,
                            cached_key_tuples,
                            key_names,
                            "Vault unlocked via Windows Hello",
                        )
                        .await
                    }
                    Ok(Err(e)) => sshwarden_agent::ControlResponse::err(&format!(
                        "Hello unlock failed: {}",
                        e
                    )),
                    Err(e) => sshwarden_agent::ControlResponse::err(&format!(
                        "Hello unlock task failed: {}",
                        e
                    )),
                }
            }

            #[cfg(not(windows))]
            sshwarden_agent::ControlResponse::err("Windows Hello is only supported on Windows")
        }
        ControlAction::Status => {
            let locked = vault_locked.load(std::sync::atomic::Ordering::Relaxed);
            let count = agent.key_count();
            let has_pin = pin_encrypted_keys.read().await.is_some();
            let has_vault = vault_file_data.read().await.is_some();
            let mut resp = sshwarden_agent::ControlResponse::status(locked, count);
            let mut extras = Vec::new();
            if has_pin {
                extras.push("PIN configured");
            }
            if has_vault {
                extras.push("vault.enc present");
            }
            if !extras.is_empty() {
                resp.message = Some(format!(
                    "{} ({})",
                    resp.message.unwrap_or_default(),
                    extras.join(", ")
                ));
            }
            resp
        }
        ControlAction::UnlockPin { pin } => {
            if !vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
                return sshwarden_agent::ControlResponse::ok("Vault is already unlocked");
            }

            // Try in-memory first, then vault file
            let encrypted = {
                let mem = pin_encrypted_keys.read().await.clone();
                if mem.is_some() {
                    mem
                } else {
                    vault_file_data
                        .read()
                        .await
                        .as_ref()
                        .map(|v| v.pin_encrypted.clone())
                }
            };

            match encrypted {
                Some(enc_data) => match sshwarden_api::crypto::pin_decrypt(&enc_data, &pin) {
                    Ok(keys_json) => {
                        finish_unlock_with_json(
                            &keys_json,
                            agent,
                            vault_locked,
                            cached_key_tuples,
                            key_names,
                            "Vault unlocked via PIN",
                        )
                        .await
                    }
                    Err(_) => sshwarden_agent::ControlResponse::err("Invalid PIN"),
                },
                None => sshwarden_agent::ControlResponse::err(
                    "No PIN configured. Use 'sshwarden set-pin' first.",
                ),
            }
        }
        ControlAction::UnlockPassword { password } => {
            if !vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
                return sshwarden_agent::ControlResponse::ok("Vault is already unlocked");
            }

            // Get email from vault file or config
            let email = {
                let vf = vault_file_data.read().await;
                vf.as_ref()
                    .map(|v| v.email.clone())
                    .unwrap_or_else(|| config.auth.email.clone())
            };

            if email.is_empty() {
                return sshwarden_agent::ControlResponse::err(
                    "No email configured. Cannot re-login.",
                );
            }

            let mut client = create_client(config.as_ref(), None);
            match client.login_password(&email, &password).await {
                Ok(()) => {}
                Err(e) => {
                    return sshwarden_agent::ControlResponse::err(&format!("Login failed: {}", e))
                }
            }

            match client.sync_ssh_keys().await {
                Ok(keys) => {
                    let key_tuples: Vec<(String, String, String)> = keys
                        .iter()
                        .map(|k| {
                            (
                                k.private_key_pem.clone(),
                                k.name.clone(),
                                k.cipher_id.clone(),
                            )
                        })
                        .collect();
                    let count = key_tuples.len();
                    *cached_key_tuples.write().await = key_tuples.clone();

                    // Update key_names
                    {
                        let mut names = key_names.write().await;
                        names.clear();
                        for k in &keys {
                            names.insert(k.cipher_id.clone(), k.name.clone());
                        }
                    }

                    if let Err(e) = agent.set_keys(key_tuples) {
                        return sshwarden_agent::ControlResponse::err(&format!(
                            "Login succeeded but failed to load keys: {}",
                            e
                        ));
                    }
                    vault_locked.store(false, std::sync::atomic::Ordering::Relaxed);
                    *api_client.write().await = Some(client);

                    // Update vault.enc if PIN is configured
                    let pin_enc = pin_encrypted_keys.read().await.clone();
                    if pin_enc.is_some() {
                        // Vault file already has the old pin_encrypted; update it with re-encrypted keys
                        // We can't re-encrypt without knowing the PIN, so just keep the vault file as-is.
                        // The user can run set-pin again if they want to update.
                    }

                    info!("Vault unlocked via master password, {} keys loaded", count);
                    sshwarden_agent::ControlResponse::ok(&format!(
                        "Vault unlocked, {} SSH keys loaded",
                        count
                    ))
                }
                Err(e) => sshwarden_agent::ControlResponse::err(&format!(
                    "Sync failed after login: {}",
                    e
                )),
            }
        }
        ControlAction::Sync => {
            let client_guard = api_client.read().await;
            if let Some(ref client) = *client_guard {
                match client.sync_ssh_keys().await {
                    Ok(keys) => {
                        let key_tuples: Vec<(String, String, String)> = keys
                            .iter()
                            .map(|k| {
                                (
                                    k.private_key_pem.clone(),
                                    k.name.clone(),
                                    k.cipher_id.clone(),
                                )
                            })
                            .collect();
                        let count = key_tuples.len();
                        *cached_key_tuples.write().await = key_tuples.clone();
                        drop(client_guard);

                        if !vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
                            if let Err(e) = agent.set_keys(key_tuples) {
                                return sshwarden_agent::ControlResponse::err(&format!(
                                    "Sync succeeded but failed to reload keys: {}",
                                    e
                                ));
                            }
                        }
                        info!("Vault synced: {} SSH keys", count);
                        sshwarden_agent::ControlResponse::ok(&format!("Synced {} SSH keys", count))
                    }
                    Err(e) => sshwarden_agent::ControlResponse::err(&format!("Sync failed: {}", e)),
                }
            } else {
                sshwarden_agent::ControlResponse::err(
                    "Not authenticated. Use 'unlock --password' to login.",
                )
            }
        }
        ControlAction::SetPin { pin } => {
            if pin.len() < 4 {
                return sshwarden_agent::ControlResponse::err("PIN must be at least 4 characters");
            }

            let keys = cached_key_tuples.read().await.clone();
            if keys.is_empty() {
                return sshwarden_agent::ControlResponse::err("No keys loaded. Login first.");
            }

            // Serialize key tuples and encrypt with PIN
            let keys_json = match serde_json::to_string(&keys) {
                Ok(j) => j,
                Err(e) => {
                    return sshwarden_agent::ControlResponse::err(&format!(
                        "Failed to serialize keys: {}",
                        e
                    ))
                }
            };

            match sshwarden_api::crypto::pin_encrypt(&keys_json, &pin) {
                Ok(encrypted) => {
                    // Store in memory
                    *pin_encrypted_keys.write().await = Some(encrypted.clone());

                    // Persist to vault.enc
                    let email = config.auth.email.clone();
                    let server_url = config.server.base_url.clone();

                    #[allow(unused_mut)]
                    let mut vault = sshwarden_config::vault::VaultFile {
                        version: 1,
                        pin_encrypted: encrypted,
                        hello_challenge: None,
                        hello_encrypted: None,
                        email,
                        server_url,
                    };

                    // Try to register Windows Hello sign-path
                    #[cfg(windows)]
                    {
                        if sshwarden_ui::unlock::hello_crypto::hello_available() {
                            info!("Windows Hello available, attempting to register sign-path");
                            let challenge: [u8; 16] = rand::random();
                            let keys_json_clone = keys_json.clone();
                            let challenge_clone = challenge;

                            let hello_result = tokio::task::spawn_blocking(move || {
                                sshwarden_ui::unlock::hello_crypto::hello_encrypt_keys(
                                    &keys_json_clone,
                                    &challenge_clone,
                                )
                            })
                            .await;

                            match hello_result {
                                Ok(Ok(hello_enc)) => {
                                    vault.hello_encrypted = Some(hello_enc);
                                    vault.hello_challenge = Some(
                                        base64::engine::general_purpose::STANDARD.encode(challenge),
                                    );
                                    info!("Windows Hello sign-path registered");
                                }
                                Ok(Err(e)) => {
                                    tracing::warn!("Hello encrypt failed: {}", e);
                                }
                                Err(e) => {
                                    tracing::warn!("Hello encrypt task failed: {}", e);
                                }
                            }
                        }
                    }

                    if let Err(e) = vault.save() {
                        tracing::warn!("Failed to save vault file: {}", e);
                        // Still return success since in-memory encryption worked
                    } else {
                        info!(
                            "Vault file saved to {}",
                            sshwarden_config::vault::VaultFile::path()
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|_| "unknown".to_string())
                        );
                    }

                    *vault_file_data.write().await = Some(vault);

                    info!("PIN set successfully, keys encrypted with PIN");
                    sshwarden_agent::ControlResponse::ok(
                        "PIN set successfully (persisted to vault.enc)",
                    )
                }
                Err(e) => sshwarden_agent::ControlResponse::err(&format!(
                    "Failed to encrypt with PIN: {}",
                    e
                )),
            }
        }
    }
}

/// Try to unlock using Windows Hello sign-path.
/// Must be called from spawn_blocking.
#[cfg(windows)]
fn try_hello_unlock(challenge: &[u8; 16], hello_encrypted: &str) -> anyhow::Result<String> {
    sshwarden_ui::unlock::hello_crypto::hello_decrypt_keys(hello_encrypted, challenge)
}

/// Read PIN-encrypted data from in-memory cache or vault file.
async fn get_pin_encrypted_data(
    pin_encrypted_keys: &Arc<RwLock<Option<String>>>,
    vault_file_data: &Arc<RwLock<Option<sshwarden_config::vault::VaultFile>>>,
) -> Option<String> {
    {
        let mem = pin_encrypted_keys.read().await;
        if let Some(ref s) = *mem {
            return Some(s.clone());
        }
    }
    let vf = vault_file_data.read().await;
    vf.as_ref().map(|v| v.pin_encrypted.clone())
}

/// Create a PIN validator closure and a shared cache for the decrypted result.
///
/// The validator performs Argon2id-based decryption, caching the result on success
/// so the caller can retrieve the decrypted keys without re-running the KDF.
fn make_pin_validator(
    enc_data: String,
) -> (
    Arc<dyn Fn(&str) -> bool + Send + Sync>,
    Arc<std::sync::Mutex<Option<String>>>,
) {
    let decrypted_cache: Arc<std::sync::Mutex<Option<String>>> =
        Arc::new(std::sync::Mutex::new(None));
    let cache_clone = decrypted_cache.clone();

    let validator: Arc<dyn Fn(&str) -> bool + Send + Sync> =
        Arc::new(move |pin: &str| -> bool {
            match sshwarden_api::crypto::pin_decrypt(&enc_data, pin) {
                Ok(keys_json) => {
                    *cache_clone.lock().unwrap() = Some(keys_json);
                    true
                }
                Err(_) => false,
            }
        });

    (validator, decrypted_cache)
}

/// Finish an unlock by parsing keys JSON and loading into agent.
async fn finish_unlock_with_json(
    keys_json: &str,
    agent: &mut sshwarden_agent::SshWardenAgent,
    vault_locked: &Arc<std::sync::atomic::AtomicBool>,
    cached_key_tuples: &CachedKeyTuples,
    key_names: &Arc<RwLock<std::collections::HashMap<String, String>>>,
    success_msg: &str,
) -> sshwarden_agent::ControlResponse {
    let keys: Vec<(String, String, String)> = match serde_json::from_str(keys_json) {
        Ok(k) => k,
        Err(e) => {
            return sshwarden_agent::ControlResponse::err(&format!(
                "Failed to parse decrypted keys: {}",
                e
            ))
        }
    };

    // Update key_names map
    {
        let mut names = key_names.write().await;
        names.clear();
        for (_, name, cipher_id) in &keys {
            names.insert(cipher_id.clone(), name.clone());
        }
    }

    *cached_key_tuples.write().await = keys.clone();
    if let Err(e) = agent.set_keys(keys) {
        return sshwarden_agent::ControlResponse::err(&format!("Failed to reload keys: {}", e));
    }
    vault_locked.store(false, std::sync::atomic::Ordering::Relaxed);
    info!("{}", success_msg);
    sshwarden_agent::ControlResponse::ok(success_msg)
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
    prompt_behavior: sshwarden_config::PromptBehavior,
    auto_unlock: bool,
    ui_request_tx: UIRequestTx,
) {
    if request.is_list {
        // If vault is locked, try to auto-unlock before listing keys
        if vault_locked.load(std::sync::atomic::Ordering::Relaxed) && auto_unlock {
            info!(
                request_id = request.request_id,
                process = %request.process_name,
                "Key list request while vault locked, attempting auto-unlock"
            );

            let mut unlocked = false;

            // Try Hello sign-path first
            #[cfg(windows)]
            if !unlocked {
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
                                let finish = finish_unlock_with_json(
                                    &keys_json,
                                    &mut agent.clone(),
                                    &vault_locked,
                                    &cached_key_tuples,
                                    &key_names,
                                    "Auto-unlocked via Windows Hello sign-path (list request)",
                                )
                                .await;
                                if finish.ok {
                                    unlocked = true;
                                }
                            } else {
                                info!("Hello sign-path failed for list unlock, trying UV fallback");
                            }
                        }
                    }
                }
            }

            // Fall back to PIN dialog
            if !unlocked {
                info!("Hello sign-path failed for list unlock, trying PIN dialog fallback");
                let enc_data =
                    get_pin_encrypted_data(&pin_encrypted_keys, &vault_file_data).await;

                if let Some(enc_data) = enc_data {
                    let (validator, decrypted_cache) = make_pin_validator(enc_data);
                    let pin_result =
                        sshwarden_ui::unlock::request_pin_dialog(&ui_request_tx, validator)
                            .await;

                    if pin_result.is_some() {
                        let keys_json =
                            decrypted_cache.lock().unwrap().take().unwrap();
                        let finish = finish_unlock_with_json(
                            &keys_json,
                            &mut agent.clone(),
                            &vault_locked,
                            &cached_key_tuples,
                            &key_names,
                            "Auto-unlocked via PIN dialog (list request)",
                        )
                        .await;
                        if finish.ok {
                            unlocked = true;
                        }
                    }
                }
            }

            if !unlocked {
                info!(
                    request_id = request.request_id,
                    "Vault still locked, denying list request"
                );
                let _ = response_tx.send((request.request_id, false));
                return;
            }
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

        let unlocked = false;

        // 1. Try Hello sign-path first (if challenge exists)
        #[cfg(windows)]
        if !unlocked {
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

                        // spawn_blocking: Hello unlock only
                        let hello_result = tokio::task::spawn_blocking(move || {
                            try_hello_unlock(&challenge, &hello_encrypted)
                        })
                        .await;

                        if let Ok(Ok(keys_json)) = hello_result {
                            let keys: Result<Vec<(String, String, String)>, _> =
                                serde_json::from_str(&keys_json);
                            if let Ok(keys) = keys {
                                // Extract key name for the authorization prompt
                                let key_name = request
                                    .cipher_id
                                    .as_ref()
                                    .and_then(|cid| keys.iter().find(|(_, _, id)| id == cid))
                                    .map(|(_, name, _)| name.clone())
                                    .unwrap_or_else(|| "Unknown key".to_string());

                                // Update state after successful unlock
                                {
                                    let mut names = key_names.write().await;
                                    names.clear();
                                    for (_, name, cipher_id) in &keys {
                                        names.insert(cipher_id.clone(), name.clone());
                                    }
                                }
                                *cached_key_tuples.write().await = keys.clone();
                                let mut agent_for_unlock = agent.clone();
                                if agent_for_unlock.set_keys(keys).is_ok() {
                                    vault_locked.store(false, std::sync::atomic::Ordering::Relaxed);
                                    info!("Auto-unlocked via Windows Hello sign-path");
                                }

                                // Authorization via Slint dialog (async)
                                let needs_prompt = match prompt_behavior {
                                    sshwarden_config::PromptBehavior::Always => true,
                                    sshwarden_config::PromptBehavior::Never => false,
                                    sshwarden_config::PromptBehavior::RememberUntilLock => true,
                                };
                                let approved = if needs_prompt {
                                    let sign_info = sshwarden_ui::SignRequestInfo {
                                        key_name,
                                        process_name: request.process_name.clone(),
                                        namespace: request.namespace.clone(),
                                        is_forwarding: request.is_forwarding,
                                    };
                                    sshwarden_ui::notify::request_authorization(
                                        &ui_request_tx,
                                        &sign_info,
                                    )
                                    .await
                                        == sshwarden_ui::AuthorizationResult::Approved
                                } else {
                                    true
                                };
                                let _ = response_tx.send((request.request_id, approved));
                                return;
                            }
                        } else {
                            info!("Hello sign-path auto-unlock failed, trying PIN dialog fallback");
                        }
                    }
                }
            }
        }

        // 2. Fall back to PIN dialog
        if !unlocked {
            info!("Hello sign-path auto-unlock failed, trying PIN dialog fallback");
            let enc_data =
                get_pin_encrypted_data(&pin_encrypted_keys, &vault_file_data).await;

            if let Some(enc_data) = enc_data {
                let (validator, decrypted_cache) = make_pin_validator(enc_data);
                let pin_result =
                    sshwarden_ui::unlock::request_pin_dialog(&ui_request_tx, validator)
                        .await;

                if pin_result.is_some() {
                    let keys_json =
                        decrypted_cache.lock().unwrap().take().unwrap();
                    let keys: Result<Vec<(String, String, String)>, _> =
                        serde_json::from_str(&keys_json);
                    if let Ok(keys) = keys {
                        // Update state
                        {
                            let mut names = key_names.write().await;
                            names.clear();
                            for (_, name, cid) in &keys {
                                names.insert(cid.clone(), name.clone());
                            }
                        }
                        *cached_key_tuples.write().await = keys.clone();

                        // Get key name for authorization prompt
                        let key_name = request
                            .cipher_id
                            .as_ref()
                            .and_then(|cid| keys.iter().find(|(_, _, id)| id == cid))
                            .map(|(_, name, _)| name.clone())
                            .unwrap_or_else(|| "Unknown key".to_string());

                        let mut agent_for_unlock = agent.clone();
                        if agent_for_unlock.set_keys(keys).is_ok() {
                            vault_locked.store(false, std::sync::atomic::Ordering::Relaxed);
                            info!("Auto-unlocked via PIN dialog");

                            // Check if we need authorization prompt
                            let needs_prompt = match prompt_behavior {
                                sshwarden_config::PromptBehavior::Always => true,
                                sshwarden_config::PromptBehavior::Never => false,
                                sshwarden_config::PromptBehavior::RememberUntilLock => true,
                            };

                            if needs_prompt {
                                let sign_info = sshwarden_ui::SignRequestInfo {
                                    key_name,
                                    process_name: request.process_name.clone(),
                                    namespace: request.namespace.clone(),
                                    is_forwarding: request.is_forwarding,
                                };
                                let approved = sshwarden_ui::notify::request_authorization(
                                    &ui_request_tx,
                                    &sign_info,
                                )
                                .await
                                    == sshwarden_ui::AuthorizationResult::Approved;
                                let _ = response_tx.send((request.request_id, approved));
                                return;
                            }
                            // No prompt needed, approve directly
                            let _ = response_tx.send((request.request_id, true));
                            return;
                        }
                    }
                }
            }
        }

        if !unlocked {
            let _ = response_tx.send((request.request_id, false));
            return;
        }
    }

    // Sign request - check prompt behavior
    let should_prompt = match prompt_behavior {
        sshwarden_config::PromptBehavior::Always => true,
        sshwarden_config::PromptBehavior::Never => false,
        sshwarden_config::PromptBehavior::RememberUntilLock => {
            // TODO: implement authorization cache, for now always prompt
            true
        }
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
        is_forwarding: request.is_forwarding,
    };

    info!(
        request_id = request.request_id,
        process = %request.process_name,
        key = %sign_info.key_name,
        "Sign request - prompting user"
    );

    let result = sshwarden_ui::notify::request_authorization(&ui_request_tx, &sign_info).await;
    let approved = result == sshwarden_ui::AuthorizationResult::Approved;
    let _ = response_tx.send((request.request_id, approved));
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
    config: &sshwarden_config::Config,
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

    let keys = cached_key_tuples.read().await.clone();
    let keys_json = match serde_json::to_string(&keys) {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!("Failed to serialize keys for PIN: {}", e);
            return;
        }
    };

    let encrypted = match sshwarden_api::crypto::pin_encrypt(&keys_json, &pin) {
        Ok(enc) => enc,
        Err(e) => {
            tracing::warn!("Failed to encrypt with PIN: {}", e);
            return;
        }
    };

    *pin_encrypted_keys.write().await = Some(encrypted.clone());

    #[allow(unused_mut)]
    let mut vault = sshwarden_config::vault::VaultFile {
        version: 1,
        pin_encrypted: encrypted,
        hello_challenge: None,
        hello_encrypted: None,
        email: config.auth.email.clone(),
        server_url: config.server.base_url.clone(),
    };

    // Try to register Windows Hello sign-path
    #[cfg(windows)]
    {
        if sshwarden_ui::unlock::hello_crypto::hello_available() {
            info!("Registering Windows Hello for quick unlock...");
            let challenge: [u8; 16] = rand::random();
            let keys_json_clone = keys_json.clone();
            let challenge_clone = challenge;

            let hello_result = tokio::task::spawn_blocking(move || {
                sshwarden_ui::unlock::hello_crypto::hello_encrypt_keys(
                    &keys_json_clone,
                    &challenge_clone,
                )
            })
            .await;

            match hello_result {
                Ok(Ok(hello_enc)) => {
                    vault.hello_encrypted = Some(hello_enc);
                    vault.hello_challenge =
                        Some(base64::engine::general_purpose::STANDARD.encode(challenge));
                    info!("Windows Hello registered for unlock");
                }
                Ok(Err(e)) => tracing::warn!("Hello registration failed: {}", e),
                Err(e) => tracing::warn!("Hello registration task failed: {}", e),
            }
        }
    }

    if let Err(e) = vault.save() {
        tracing::warn!("Failed to save vault file: {}", e);
    } else {
        info!("PIN set. Next time just use 'sshwarden unlock --pin' or Windows Hello.");
    }

    *vault_file_data.write().await = Some(vault);
}

/// Get the runtime data directory for SSHWarden (same as exe directory for portability).
fn data_dir() -> anyhow::Result<std::path::PathBuf> {
    sshwarden_config::config_dir()
}

/// Get the PID file path.
fn pid_file_path() -> anyhow::Result<std::path::PathBuf> {
    Ok(data_dir()?.join("sshwarden.pid"))
}

/// Get the log file path.
fn log_file_path() -> anyhow::Result<std::path::PathBuf> {
    Ok(data_dir()?.join("sshwarden.log"))
}

/// Check if daemon is already running by reading PID file and checking process.
fn is_daemon_running() -> bool {
    let pid_path = match pid_file_path() {
        Ok(p) => p,
        Err(_) => return false,
    };

    if !pid_path.exists() {
        return false;
    }

    let pid_str = match std::fs::read_to_string(&pid_path) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let pid: u32 = match pid_str.trim().parse() {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Check if the process is still running
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    sys.process(sysinfo::Pid::from_u32(pid)).is_some()
}

/// Write current PID to pid file.
fn write_pid_file() -> anyhow::Result<()> {
    let pid = std::process::id();
    let path = pid_file_path()?;
    std::fs::write(&path, pid.to_string())
        .with_context(|| format!("Failed to write PID file: {}", path.display()))
}

/// Remove pid file on shutdown.
fn remove_pid_file() {
    if let Ok(path) = pid_file_path() {
        let _ = std::fs::remove_file(path);
    }
}

/// Detach from the parent console (for daemon mode).
/// This frees the console so the parent terminal regains control,
/// while the process remains in the user's interactive desktop session.
/// UI dialogs (TaskDialog, Windows Hello, MessageBox) are unaffected
/// because they use the GUI subsystem, not the console.
#[cfg(windows)]
fn detach_console() {
    use windows::Win32::System::Console::FreeConsole;

    unsafe {
        let _ = FreeConsole();
    }
}

/// Get the path to the startup shortcut in the user's Startup folder.
#[cfg(windows)]
fn startup_shortcut_path() -> anyhow::Result<std::path::PathBuf> {
    let startup_dir = std::env::var("APPDATA").context("APPDATA environment variable not set")?;
    let startup_dir = std::path::Path::new(&startup_dir)
        .join("Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    Ok(startup_dir.join("SSHWarden.lnk"))
}

/// Install startup shortcut in the user's Startup folder.
#[cfg(windows)]
async fn cmd_daemon_install() -> anyhow::Result<()> {
    let exe = std::env::current_exe().context("Failed to get current executable path")?;
    let exe_str = exe.to_str().context("Executable path is not valid UTF-8")?;
    let working_dir = exe.parent().context("Failed to get executable directory")?;
    let working_dir_str = working_dir
        .to_str()
        .context("Directory path is not valid UTF-8")?;

    let shortcut_path = startup_shortcut_path()?;
    let shortcut_str = shortcut_path
        .to_str()
        .context("Shortcut path is not valid UTF-8")?;

    // Use PowerShell to create a .lnk shortcut file
    // WindowStyle 7 = Minimized, so the console window doesn't flash on startup
    // (hide_console_window() will hide it immediately after launch)
    let ps_script = format!(
        "$ws = New-Object -ComObject WScript.Shell; \
         $s = $ws.CreateShortcut('{}'); \
         $s.TargetPath = '{}'; \
         $s.Arguments = 'daemon'; \
         $s.WorkingDirectory = '{}'; \
         $s.WindowStyle = 7; \
         $s.Description = 'SSHWarden SSH Agent Daemon'; \
         $s.Save()",
        shortcut_str.replace('\'', "''"),
        exe_str.replace('\'', "''"),
        working_dir_str.replace('\'', "''"),
    );

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps_script])
        .output()
        .context("Failed to run powershell")?;

    if output.status.success() {
        info!("SSHWarden startup shortcut created at: {}", shortcut_str);
        info!("The daemon will start automatically on login");
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to create startup shortcut: {}", stderr.trim());
    }

    Ok(())
}

#[cfg(not(windows))]
async fn cmd_daemon_install() -> anyhow::Result<()> {
    info!("Startup installation is only supported on Windows currently");
    Ok(())
}

/// Remove startup shortcut from the user's Startup folder.
#[cfg(windows)]
async fn cmd_daemon_uninstall() -> anyhow::Result<()> {
    let shortcut_path = startup_shortcut_path()?;
    match std::fs::remove_file(&shortcut_path) {
        Ok(()) => {
            info!("SSHWarden startup shortcut removed");
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!("No startup shortcut found, nothing to remove");
        }
        Err(e) => {
            anyhow::bail!("Failed to remove startup shortcut: {}", e);
        }
    }
    Ok(())
}

#[cfg(not(windows))]
async fn cmd_daemon_uninstall() -> anyhow::Result<()> {
    info!("Startup uninstallation is only supported on Windows currently");
    Ok(())
}
