use std::sync::Arc;

use anyhow::Context;
#[cfg(windows)]
use base64::Engine;
use clap::{Parser, Subcommand};
use tokio::sync::RwLock;
use tracing::info;
use zeroize::Zeroize;

#[derive(Clone, Debug)]
struct NotificationRuntimeState {
    state: NotificationConnectionState,
    url: Option<String>,
    last_error: Option<String>,
    reconnect_attempts: usize,
    last_connected_at: Option<std::time::Instant>,
    last_event_at: Option<std::time::Instant>,
    last_fallback_sync_at: Option<std::time::Instant>,
    stale_cache: bool,
    stale_cache_error: Option<String>,
}

#[derive(Clone, Debug)]
enum NotificationConnectionState {
    NotStarted,
    Starting,
    Running,
    Stopped,
    Failed,
}

impl Default for NotificationRuntimeState {
    fn default() -> Self {
        Self {
            state: NotificationConnectionState::NotStarted,
            url: None,
            last_error: None,
            reconnect_attempts: 0,
            last_connected_at: None,
            last_event_at: None,
            last_fallback_sync_at: None,
            stale_cache: false,
            stale_cache_error: None,
        }
    }
}

impl NotificationRuntimeState {
    fn state_name(&self) -> &'static str {
        match self.state {
            NotificationConnectionState::NotStarted => "not_started",
            NotificationConnectionState::Starting => "starting",
            NotificationConnectionState::Running => "running",
            NotificationConnectionState::Stopped => "stopped",
            NotificationConnectionState::Failed => "failed",
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "state": self.state_name(),
            "url": self.url,
            "last_error": self.last_error,
            "reconnect_attempts": self.reconnect_attempts,
            "last_connected_age_secs": self.last_connected_at.map(|t| t.elapsed().as_secs()),
            "last_event_age_secs": self.last_event_at.map(|t| t.elapsed().as_secs()),
            "last_fallback_sync_age_secs": self.last_fallback_sync_at.map(|t| t.elapsed().as_secs()),
            "stale_cache": self.stale_cache,
            "stale_cache_error": self.stale_cache_error,
        })
    }
}

/// Secure key cache: automatically zeroes PEM private keys on drop/clear.
struct SecureKeyCache(Vec<(String, String, String)>);

type AuthorizationMemorySet = Arc<RwLock<std::collections::HashSet<(String, String)>>>;
type KeyMaterialFingerprints = Arc<RwLock<std::collections::HashMap<String, String>>>;

#[derive(Default)]
struct LocalCacheKeyState(Option<sshwarden_api::crypto::SymmetricKey>);

impl LocalCacheKeyState {
    fn set(&mut self, key: sshwarden_api::crypto::SymmetricKey) {
        self.0 = Some(key);
    }

    fn clone_key(&self) -> Option<sshwarden_api::crypto::SymmetricKey> {
        self.0.clone()
    }

    fn clear(&mut self) {
        self.0 = None;
    }
}

type LocalCacheKeyHandle = Arc<RwLock<LocalCacheKeyState>>;

impl SecureKeyCache {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn set(&mut self, keys: Vec<(String, String, String)>) {
        self.clear();
        self.0 = keys;
    }

    fn clear(&mut self) {
        for (pem, _, _) in &mut self.0 {
            pem.zeroize();
        }
        self.0.clear();
    }

    fn clone_inner(&self) -> Vec<(String, String, String)> {
        self.0.clone()
    }
}

impl Drop for SecureKeyCache {
    fn drop(&mut self) {
        self.clear();
    }
}

type CachedKeyTuples = Arc<RwLock<SecureKeyCache>>;

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
        /// Use platform-native unlock (macOS Keychain / Linux Secret Service)
        #[arg(long)]
        native: bool,
    },
    /// Lock the vault (clear private keys from memory)
    Lock,
    /// Set or update PIN for quick unlock
    SetPin,
    /// Show agent status
    Status {
        /// Print full machine-readable status JSON
        #[arg(long)]
        json: bool,
    },
    /// Run read-only diagnostics
    Doctor {
        /// Print machine-readable diagnostic JSON
        #[arg(long)]
        json: bool,
        /// Explicitly allow repairs (no repairs implemented yet)
        #[arg(long)]
        fix: bool,
    },
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
    /// Forget local remembered key/session material
    Forget,
    /// Print shell environment exports for SSHWarden agent discovery
    Env {
        /// Shell syntax to emit: sh, powershell, fish, or cmd
        #[arg(long, default_value = "sh")]
        shell: String,
    },
    /// Print SSH config snippets using selector files
    SshConfig {
        /// Bitwarden server base URL (overrides config)
        #[arg(long)]
        base_url: Option<String>,
        /// Email address
        #[arg(long)]
        email: Option<String>,
        /// Write selector files, a managed include file, and add it to ~/.ssh/config
        #[arg(long)]
        write: bool,
        /// Manage the include line and managed snippet locally (no network)
        #[command(subcommand)]
        action: Option<SshConfigAction>,
    },
    /// Manage host bindings for SSH keys (offline, uses local key cache)
    Bindings {
        #[command(subcommand)]
        action: BindingsAction,
    },
    /// Edit configuration
    Config,
}

#[derive(Subcommand, Clone)]
enum SshConfigAction {
    /// Regenerate the managed snippet and add Include to ~/.ssh/config
    Install,
    /// Remove the Include line from ~/.ssh/config (snippet file is preserved)
    Uninstall,
    /// Show paths, Include status, and binding counts
    Status,
    /// Rewrite the managed snippet from current bindings + local key cache
    Regenerate,
    /// Print the managed snippet to stdout
    Show,
}

#[derive(Subcommand, Clone)]
enum BindingsAction {
    /// List all bindings, cross-referenced with the local key cache
    List,
    /// Bind one or more host patterns to a key (by name or cipher id)
    Add {
        /// Key name (as shown in `sshwarden keys`) or cipher uuid
        key: String,
        /// Host patterns: hostnames, IPs, or globs (e.g. `*.prod.example.com`)
        #[arg(required = true)]
        hosts: Vec<String>,
    },
    /// Remove a single host from a key's bindings, or all if `--all`
    Remove {
        /// Key name or cipher uuid
        key: String,
        /// Host pattern to remove (omit with `--all` to clear)
        host: Option<String>,
        /// Remove every host for this key
        #[arg(long)]
        all: bool,
    },
    /// Remove every host pattern bound to a key
    Clear {
        /// Key name or cipher uuid
        key: String,
    },
    /// Open the graphical bindings manager (requires the daemon to be running)
    Ui,
}

/// Type alias for the UI request sender passed through the system.
type UIRequestTx = Arc<tokio::sync::mpsc::Sender<sshwarden_ui::UIRequest>>;

/// Internal events emitted by spawned SSH request handlers back to the main loop.
#[allow(clippy::enum_variant_names)]
enum RuntimeEvent {
    #[cfg(windows)]
    AutoUnlockedWindowsHello,
    AutoUnlockedPin {
        pin: String,
    },
    AutoUnlockedNative,
}

fn main() -> anyhow::Result<()> {
    // Set Per-Monitor DPI Awareness V2 before any UI calls.
    // This prevents Win32 dialogs (CredUI) from being blurry on high-DPI displays.
    sshwarden_ui::init();

    // Initialize rustls CryptoProvider for tokio-tungstenite (WebSocket TLS)
    let _ = rustls::crypto::ring::default_provider().install_default();

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
                // RT-02: single-instance guard for ANY run_foreground entry —
                // both `sshwarden daemon` and a bare foreground `sshwarden` are
                // the one singleton daemon (one agent + one control server + one
                // OpenSSH endpoint); two cannot coexist. Previously only the
                // daemon branch was guarded, so a bare `sshwarden` could spin up a
                // second agent and control server competing for the same pipes.
                if is_daemon_running() {
                    info!("SSHWarden is already running");
                    return Ok(());
                }
                #[cfg(windows)]
                if is_daemon_mode {
                    detach_console();
                }
                #[cfg(not(windows))]
                let _ = is_daemon_mode;

                write_pid_file()?;
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
                    native,
                }) => {
                    if pin {
                        let pin_value = prompt_password("Enter PIN: ")?;
                        let cmd = format!("unlock-pin:{}", &*pin_value);
                        cmd_control(&cmd).await
                    } else if password {
                        let pw = prompt_password("Master password: ")?;
                        let cmd = format!("unlock-password:{}", &*pw);
                        cmd_control(&cmd).await
                    } else if hello {
                        cmd_control("unlock-hello").await
                    } else if native {
                        cmd_control("unlock-native").await
                    } else {
                        cmd_control("unlock").await
                    }
                }
                Some(Commands::Status { json }) => {
                    if json {
                        cmd_control("status-json").await
                    } else {
                        cmd_control("status").await
                    }
                }
                Some(Commands::Doctor { json, fix }) => cmd_doctor(&config, json, fix).await,
                Some(Commands::SshConfig {
                    base_url,
                    email,
                    write,
                    action,
                }) => match action {
                    Some(SshConfigAction::Install) => cmd_sshcfg_install().await,
                    Some(SshConfigAction::Uninstall) => cmd_sshcfg_uninstall().await,
                    Some(SshConfigAction::Status) => cmd_sshcfg_status().await,
                    Some(SshConfigAction::Regenerate) => cmd_sshcfg_regenerate().await,
                    Some(SshConfigAction::Show) => cmd_sshcfg_show().await,
                    None => {
                        cmd_ssh_config(&config, base_url.as_deref(), email.as_deref(), write).await
                    }
                },
                Some(Commands::Bindings { action }) => cmd_bindings(action).await,
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
                Some(Commands::Forget) => cmd_control("forget").await,
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

async fn cmd_control(cmd: &str) -> anyhow::Result<()> {
    match sshwarden_agent::control::send_control_command(cmd).await {
        Ok(response) => {
            if response.ok {
                if cmd == "status-json" {
                    let value = response
                        .details
                        .as_ref()
                        .cloned()
                        .unwrap_or_else(|| serde_json::to_value(&response).unwrap_or_default());
                    out_line(serde_json::to_string_pretty(&value)?);
                    return Ok(());
                }
                if let Some(msg) = &response.message {
                    out_line(msg);
                }
                if let Some(locked) = response.locked {
                    out_line(format!("  Locked: {locked}"));
                }
                if let Some(count) = response.key_count {
                    out_line(format!("  Keys: {count}"));
                }
                if let Some(details) = &response.details {
                    if let Some(notification) = details.get("notification") {
                        out_line(format!("  Notification: {notification}"));
                    }
                    if let Some(pending) = details.get("pending_sync") {
                        out_line(format!("  Pending sync: {pending}"));
                    }
                    if let Some(authenticated) = details.get("authenticated") {
                        out_line(format!("  Authenticated: {authenticated}"));
                    }
                }
            } else {
                let err = response.error.as_deref().unwrap_or("Unknown error");
                err_line(format!("Error: {err}"));
            }
            Ok(())
        }
        Err(e) => {
            err_line(format!("Could not connect to SSHWarden daemon: {e}"));
            err_line("Is the daemon running? Start it with: sshwarden");
            Ok(())
        }
    }
}

#[derive(serde::Serialize)]
struct DoctorCheck {
    name: String,
    ok: bool,
    message: String,
}

impl DoctorCheck {
    fn ok(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ok: true,
            message: message.into(),
        }
    }

    fn warn(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ok: false,
            message: message.into(),
        }
    }
}

/// Fetch daemon status for the doctor report over the control channel. Works
/// on every platform — the Unix control client is fully implemented, so this is
/// no longer Windows-only (XP-1/UX-6/LOGIC-5).
async fn fetch_status_details_for_doctor() -> anyhow::Result<serde_json::Value> {
    let response = sshwarden_agent::control::send_control_command("status-json").await?;
    Ok(response
        .details
        .clone()
        .unwrap_or_else(|| serde_json::to_value(&response).unwrap_or_default()))
}

#[cfg(windows)]
fn windows_openssh_pipe_exists() -> bool {
    std::path::Path::new(r"\\.\pipe\openssh-ssh-agent").exists()
}

fn count_key_selector_files() -> anyhow::Result<(std::path::PathBuf, usize)> {
    let dir = key_selector_dir()?;
    let count = if dir.exists() {
        std::fs::read_dir(&dir)?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("pub"))
            .count()
    } else {
        0
    };
    Ok((dir, count))
}

async fn cmd_doctor(
    config: &sshwarden_config::Config,
    json: bool,
    fix: bool,
) -> anyhow::Result<()> {
    let mut checks = Vec::new();

    if fix {
        checks.push(DoctorCheck::ok(
            "doctor.fix",
            "doctor --fix requested; applying only explicit safe repairs implemented by doctor",
        ));
    }

    let discovery_client = create_client(config, None);
    match discovery_client.discover_notifications_url().await {
        Ok(Some(url)) => checks.push(DoctorCheck::ok(
            "server.discovery",
            format!("/api/config advertises notifications URL: {url}"),
        )),
        Ok(None) => checks.push(DoctorCheck::warn(
            "server.discovery",
            "/api/config is reachable but did not advertise environment.notifications",
        )),
        Err(e) => checks.push(DoctorCheck::warn(
            "server.discovery",
            format!("/api/config discovery failed; built-in URL rules will be used: {e}"),
        )),
    }

    checks.push(DoctorCheck::ok(
        "notification.resolved_url",
        format!(
            "Configured fallback notification URL resolves to {}",
            config.server.notifications_url()
        ),
    ));

    let status = match fetch_status_details_for_doctor().await {
        Ok(status) => {
            checks.push(DoctorCheck::ok(
                "daemon",
                "SSHWarden daemon control channel is reachable",
            ));
            Some(status)
        }
        Err(e) => {
            checks.push(DoctorCheck::warn(
                "daemon",
                format!("SSHWarden daemon control channel is not reachable: {e}"),
            ));
            None
        }
    };

    if let Some(status) = status.as_ref() {
        // RT-05/XP-4: detect the "zombie" case where the control channel answers
        // but the SSH agent task isn't actually serving the endpoint (e.g. on
        // Windows the OpenSSH ssh-agent service owns the pipe). Uses the
        // agent_running flag from status, so no extra platform FFI is needed.
        let agent_running = status
            .get("agent_running")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if agent_running {
            checks.push(DoctorCheck::ok(
                "agent.serving",
                "SSHWarden's SSH agent task is serving the endpoint",
            ));
        } else {
            checks.push(DoctorCheck::warn(
                "agent.serving",
                "The control channel answers but SSHWarden's SSH agent is NOT serving the endpoint — another agent likely owns it (on Windows, the OpenSSH 'ssh-agent' service: Stop-Service ssh-agent; Set-Service ssh-agent -StartupType Disabled). ssh/ssh-add will not see SSHWarden's keys until this is fixed.",
            ));
        }

        let authenticated = status
            .get("authenticated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if authenticated {
            checks.push(DoctorCheck::ok(
                "session",
                "Bitwarden API session is restored in the daemon",
            ));
        } else {
            checks.push(DoctorCheck::warn(
                "session",
                "Bitwarden API session is not restored; notifications and online sync will not run until login/unlock restores it",
            ));
        }

        let pending_sync = status
            .get("pending_sync")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if pending_sync {
            checks.push(DoctorCheck::warn(
                "sync.pending",
                "Pending Sync is recorded; unlock or restore connectivity to resolve it",
            ));
        } else {
            checks.push(DoctorCheck::ok(
                "sync.pending",
                "No Pending Sync is recorded",
            ));
        }

        let has_local_key_cache = status
            .get("has_local_key_cache")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let has_vault_file = status
            .get("has_vault_file")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let legacy_migration_available = status
            .get("legacy_migration_available")
            .and_then(|v| v.as_bool())
            .unwrap_or(has_vault_file && !has_local_key_cache);
        if has_local_key_cache {
            checks.push(DoctorCheck::ok(
                "local_key_cache",
                "Envelope Local Key Cache is present",
            ));
        } else if legacy_migration_available {
            checks.push(DoctorCheck::warn(
                "local_key_cache.migration",
                "Legacy vault.enc is present without envelope Local Key Cache; run `sshwarden unlock --pin` to migrate",
            ));
        } else {
            checks.push(DoctorCheck::warn(
                "local_key_cache",
                "No remembered Local Key Cache is present",
            ));
        }

        let notification = status.get("notification").cloned().unwrap_or_default();
        let notification_state = notification
            .get("state")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        if notification
            .get("stale_cache")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            checks.push(DoctorCheck::warn(
                "local_key_cache.stale",
                format!(
                    "Local Key Cache is stale: {}",
                    notification
                        .get("stale_cache_error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown refresh error")
                ),
            ));
        } else {
            checks.push(DoctorCheck::ok(
                "local_key_cache.stale",
                "Local Key Cache is not marked stale",
            ));
        }

        match notification_state {
            "running" => checks.push(DoctorCheck::ok(
                "notification",
                format!(
                    "Notification client is running ({})",
                    notification
                        .get("url")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown URL")
                ),
            )),
            "not_started" => checks.push(DoctorCheck::warn(
                "notification",
                "Notification client has not started; usually no API session/token is available yet",
            )),
            "failed" => checks.push(DoctorCheck::warn(
                "notification",
                format!(
                    "Notification client failed: {}",
                    notification
                        .get("last_error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown error")
                ),
            )),
            other => checks.push(DoctorCheck::warn(
                "notification",
                format!("Notification client state is {other}"),
            )),
        }
    }

    match count_key_selector_files() {
        Ok((dir, count)) if count > 0 => {
            checks.push(DoctorCheck::ok(
                "key_selectors",
                format!(
                    "Found {count} key selector .pub file(s) in {}",
                    dir.display()
                ),
            ));
            if count > 5 {
                checks.push(DoctorCheck::warn(
                    "ssh.max_auth_tries",
                    format!(
                        "{count} selector files/keys detected; without Host-specific IdentityFile + IdentitiesOnly yes, OpenSSH servers may fail with MaxAuthTries"
                    ),
                ));
            } else {
                checks.push(DoctorCheck::ok(
                    "ssh.max_auth_tries",
                    "Key count is not high enough to trigger the common MaxAuthTries failure by itself",
                ));
            }
        }
        Ok((dir, _)) if dir.exists() => checks.push(DoctorCheck::warn(
            "key_selectors",
            format!("No key selector .pub files found in {}", dir.display()),
        )),
        Ok((dir, _)) => checks.push(DoctorCheck::warn(
            "key_selectors",
            format!("Key selector directory does not exist: {}", dir.display()),
        )),
        Err(e) => checks.push(DoctorCheck::warn(
            "key_selectors",
            format!("Could not determine key selector directory: {e}"),
        )),
    }

    #[cfg(windows)]
    {
        if windows_openssh_pipe_exists() {
            checks.push(DoctorCheck::ok(
                "agent_endpoint.windows_pipe",
                r"OpenSSH agent pipe \\.\pipe\openssh-ssh-agent exists (it may be owned by SSHWarden or by the OS ssh-agent service — see the agent.serving check for which one is actually serving)",
            ));
        } else {
            checks.push(DoctorCheck::warn(
                "agent_endpoint.windows_pipe",
                r"No OpenSSH agent pipe at \\.\pipe\openssh-ssh-agent; SSH clients have no agent to talk to",
            ));
        }
    }

    #[cfg(not(windows))]
    {
        // XP-3: check the Unix agent socket exists with 0600 perms and that
        // SSH_AUTH_SOCK points at it.
        match sshwarden_config::default_agent_socket_path() {
            Ok(path) => {
                if path.exists() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        match std::fs::metadata(&path) {
                            Ok(meta) => {
                                let mode = meta.permissions().mode() & 0o777;
                                if mode == 0o600 {
                                    checks.push(DoctorCheck::ok(
                                        "agent_endpoint.unix_socket",
                                        format!(
                                            "Agent socket present with 0600 perms: {}",
                                            path.display()
                                        ),
                                    ));
                                } else {
                                    checks.push(DoctorCheck::warn(
                                        "agent_endpoint.unix_socket",
                                        format!(
                                            "Agent socket {} has mode {mode:o}, expected 0600",
                                            path.display()
                                        ),
                                    ));
                                }
                            }
                            Err(e) => checks.push(DoctorCheck::warn(
                                "agent_endpoint.unix_socket",
                                format!("Could not stat agent socket {}: {e}", path.display()),
                            )),
                        }
                    }
                    match std::env::var("SSH_AUTH_SOCK") {
                        Ok(sock) if std::path::PathBuf::from(&sock) == path => {
                            checks.push(DoctorCheck::ok(
                                "agent_endpoint.ssh_auth_sock",
                                "SSH_AUTH_SOCK points at the SSHWarden agent socket",
                            ));
                        }
                        Ok(sock) => checks.push(DoctorCheck::warn(
                            "agent_endpoint.ssh_auth_sock",
                            format!("SSH_AUTH_SOCK ({sock}) does not point at the SSHWarden agent socket ({}); run `eval \"$(sshwarden env)\"`", path.display()),
                        )),
                        Err(_) => checks.push(DoctorCheck::warn(
                            "agent_endpoint.ssh_auth_sock",
                            format!("SSH_AUTH_SOCK is not set; run `eval \"$(sshwarden env)\"` so ssh uses {}", path.display()),
                        )),
                    }
                } else {
                    checks.push(DoctorCheck::warn(
                        "agent_endpoint.unix_socket",
                        format!(
                            "Agent socket not present at {}; is the daemon running?",
                            path.display()
                        ),
                    ));
                }
            }
            Err(e) => checks.push(DoctorCheck::warn(
                "agent_endpoint.unix_socket",
                format!("Could not resolve agent socket path: {e}"),
            )),
        }
    }

    let include_path = managed_sshwarden_include_path().ok();
    let config_path = user_ssh_config_path().ok();
    match (include_path, config_path) {
        (Some(include_path), Some(config_path)) => {
            if include_path.exists() {
                checks.push(DoctorCheck::ok(
                    "ssh_config.include_file",
                    format!("Managed SSH config exists: {}", include_path.display()),
                ));
                let managed_content = std::fs::read_to_string(&include_path).unwrap_or_default();
                if managed_content.contains("IdentityFile")
                    && managed_content.contains("IdentitiesOnly yes")
                {
                    checks.push(DoctorCheck::ok(
                        "ssh_config.selector_rules",
                        "Managed SSH config contains IdentityFile and IdentitiesOnly yes selector rules",
                    ));
                } else {
                    checks.push(DoctorCheck::warn(
                        "ssh_config.selector_rules",
                        "Managed SSH config does not contain Host-specific IdentityFile + IdentitiesOnly yes rules; run `sshwarden ssh-config` to print examples or `sshwarden ssh-config --write` to replace the managed include",
                    ));
                }
            } else {
                checks.push(DoctorCheck::warn(
                    "ssh_config.include_file",
                    format!(
                        "Managed SSH config does not exist: {}",
                        include_path.display()
                    ),
                ));
            }

            let has_include = std::fs::read_to_string(&config_path)
                .map(|content| {
                    content.lines().any(|line| {
                        sshwarden_config::ssh_config::line_matches_sshwarden_include(
                            line,
                            &include_path,
                        )
                    })
                })
                .unwrap_or(false);

            if fix && !has_include {
                if let Some(parent) = include_path.parent() {
                    if let Err(e) = create_private_dir(parent) {
                        checks.push(DoctorCheck::warn(
                            "doctor.fix.ssh_config_dir",
                            format!(
                                "Failed to create SSH config directory {}: {e}",
                                parent.display()
                            ),
                        ));
                    }
                }
                if !include_path.exists() {
                    let managed = "# SSHWarden managed key selector snippets\n# Run `sshwarden ssh-config` to print Host-specific examples.\n";
                    match write_private_file(&include_path, managed) {
                        Ok(()) => checks.push(DoctorCheck::ok(
                            "doctor.fix.include_file",
                            format!(
                                "Created managed SSH config placeholder: {}",
                                include_path.display()
                            ),
                        )),
                        Err(e) => checks.push(DoctorCheck::warn(
                            "doctor.fix.include_file",
                            format!(
                                "Failed to create managed SSH config {}: {e}",
                                include_path.display()
                            ),
                        )),
                    }
                }
                match write_sshwarden_include_line(&config_path, &include_path) {
                    Ok(()) => checks.push(DoctorCheck::ok(
                        "doctor.fix.include",
                        format!("Added SSHWarden Include line to {}", config_path.display()),
                    )),
                    Err(e) => checks.push(DoctorCheck::warn(
                        "doctor.fix.include",
                        format!(
                            "Failed to add SSHWarden Include line to {}: {e}",
                            config_path.display()
                        ),
                    )),
                }
            }

            let has_include = std::fs::read_to_string(&config_path)
                .map(|content| {
                    content.lines().any(|line| {
                        sshwarden_config::ssh_config::line_matches_sshwarden_include(
                            line,
                            &include_path,
                        )
                    })
                })
                .unwrap_or(false);
            if has_include {
                checks.push(DoctorCheck::ok(
                    "ssh_config.include",
                    format!(
                        "{} includes SSHWarden managed config",
                        config_path.display()
                    ),
                ));
            } else {
                checks.push(DoctorCheck::warn(
                    "ssh_config.include",
                    format!(
                        "{} does not include SSHWarden managed config; run `sshwarden ssh-config --write` if desired",
                        config_path.display()
                    ),
                ));
            }
        }
        _ => checks.push(DoctorCheck::warn(
            "ssh_config",
            "Could not determine ~/.ssh/config or managed include path",
        )),
    }

    let all_ok = checks.iter().all(|check| check.ok);
    if json {
        #[allow(clippy::print_stdout)]
        {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": all_ok,
                    "checks": checks,
                }))?
            );
        }
    } else {
        for check in &checks {
            if check.ok {
                out_line(format!("[ok] {}: {}", check.name, check.message));
            } else {
                out_line(format!("[warn] {}: {}", check.name, check.message));
            }
        }
    }

    Ok(())
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
    let email = match email {
        Some(e) => e.to_string(),
        None if !config.auth.email.is_empty() => config.auth.email.clone(),
        None => prompt_email("Email: ")?,
    };
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
                    info!("Note: the running daemon uses its own configured server; --base-url is ignored.");
                }
                out_line(
                    response
                        .message
                        .as_deref()
                        .unwrap_or("Logged in; keys loaded into the running agent."),
                );
            } else {
                err_line(format!(
                    "Login failed: {}",
                    response.error.as_deref().unwrap_or("unknown error")
                ));
            }
            return Ok(());
        }
        Err(_) => {
            info!(
                "Daemon not running; logging in for listing only (start `sshwarden` to serve keys)."
            );
        }
    }

    // Standalone fallback: authenticate and list keys without touching an agent.
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
            "\nNote: no daemon was running, so the agent was not loaded. Start `sshwarden`, then `sshwarden unlock --password`.",
        );
    }

    Ok(())
}

fn key_selector_dir() -> anyhow::Result<std::path::PathBuf> {
    Ok(sshwarden_config::config_dir()?.join("keys"))
}

/// Short single-character SSH flags that consume the next argv element as a value.
///
/// Reference: `ssh(1)` OPTIONS section. We intentionally over-approximate to be
/// safe — any unknown flag is treated as value-taking only if the character
/// matches this set.
const SSH_VALUE_TAKING_FLAGS: &str = "BbcDEeFIiJLlmOopQRSWw";

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

fn parse_ssh_target(arg: &str) -> String {
    match arg.rsplit_once('@') {
        Some((_, host)) => host.to_string(),
        None => arg.to_string(),
    }
}

fn slugify_key_name(name: &str) -> String {
    let mut slug = String::new();
    let mut last_dash = false;

    for ch in name.chars().flat_map(char::to_lowercase) {
        let is_allowed = ch.is_ascii_alphanumeric() || ch == '_' || ch == '-';
        if is_allowed {
            slug.push(ch);
            last_dash = false;
        } else if !last_dash {
            slug.push('-');
            last_dash = true;
        }
    }

    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        "ssh-key".to_string()
    } else {
        slug.to_string()
    }
}

fn vault_item_id_prefix(cipher_id: &str) -> String {
    cipher_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(8)
        .collect::<String>()
}

fn selector_file_name(key_name: &str, cipher_id: &str) -> String {
    let prefix = vault_item_id_prefix(cipher_id);
    if prefix.is_empty() {
        format!("{}.pub", slugify_key_name(key_name))
    } else {
        format!("{}--{}.pub", slugify_key_name(key_name), prefix)
    }
}

fn selector_path_for_key(key_name: &str, cipher_id: &str) -> anyhow::Result<std::path::PathBuf> {
    Ok(key_selector_dir()?.join(selector_file_name(key_name, cipher_id)))
}

fn write_key_selector_files(keys: &[sshwarden_api::DecryptedSshKey]) -> anyhow::Result<()> {
    let dir = key_selector_dir()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create key selector directory: {}", dir.display()))?;

    let mut active_paths = std::collections::HashSet::new();
    for key in keys {
        let path = selector_path_for_key(&key.name, &key.cipher_id)?;
        active_paths.insert(path.clone());
        let content = format!("{}\n", key.public_key_openssh.trim());
        std::fs::write(&path, content)
            .with_context(|| format!("Failed to write key selector file: {}", path.display()))?;
    }

    // Remove selector files for deleted/archived/unavailable items. Rename aliases
    // are retained because they have a different path for the same Vault Item Id.
    if dir.exists() {
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("Failed to read key selector directory: {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("pub")
                && !active_paths.contains(&path)
            {
                let file_name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("");
                let active_key_for_alias = keys.iter().find(|key| {
                    let prefix = vault_item_id_prefix(&key.cipher_id);
                    !prefix.is_empty() && file_name.ends_with(&format!("--{prefix}.pub"))
                });
                if let Some(key) = active_key_for_alias {
                    let content = format!("{}\n", key.public_key_openssh.trim());
                    std::fs::write(&path, content).with_context(|| {
                        format!("Failed to update key selector alias: {}", path.display())
                    })?;
                } else {
                    std::fs::remove_file(&path).with_context(|| {
                        format!(
                            "Failed to remove stale key selector file: {}",
                            path.display()
                        )
                    })?;
                }
            }
        }
    }

    Ok(())
}

fn ssh_config_snippet_for_keys(keys: &[sshwarden_api::DecryptedSshKey]) -> anyhow::Result<String> {
    let mut lines = Vec::new();
    lines.push("# SSHWarden key selector snippets".to_string());
    lines.push("# Copy a Host block and replace <host> with the destination host.".to_string());
    lines.push("".to_string());

    for key in keys {
        let path = selector_path_for_key(&key.name, &key.cipher_id)?;
        lines.push(format!("# {} ({})", key.name, key.cipher_id));
        lines.push("Host <host>".to_string());
        lines.push(format!(
            "    IdentityFile {}",
            sshwarden_config::ssh_config::path_arg(&path)
        ));
        lines.push("    IdentitiesOnly yes".to_string());
        lines.push("".to_string());
    }

    Ok(lines.join("\n"))
}

/// Generate a managed `sshwarden_config` snippet driven by [`HostBindingsFile`].
///
/// Each key with one or more bound host patterns produces a real `Host` block
/// pointing at its `.pub` selector file, with `IdentitiesOnly yes`. Keys without
/// any binding are emitted as commented-out templates below, so the user can
/// see what is available to bind.
/// Slim key reference used by snippet generation — avoids touching `DecryptedSshKey`
/// (which holds the sensitive private PEM) when only metadata is needed.
#[derive(Debug, Clone)]
struct ManagedKey {
    name: String,
    cipher_id: String,
}

impl ManagedKey {
    fn from_decrypted(keys: &[sshwarden_api::DecryptedSshKey]) -> Vec<Self> {
        keys.iter()
            .map(|k| Self {
                name: k.name.clone(),
                cipher_id: k.cipher_id.clone(),
            })
            .collect()
    }

    fn from_cache_header(keys: &[sshwarden_config::cache::KeyIdentity]) -> Vec<Self> {
        keys.iter()
            .map(|k| Self {
                name: k.name.clone(),
                cipher_id: k.vault_item_id.clone(),
            })
            .collect()
    }
}

fn ssh_config_snippet_with_bindings(
    keys: &[ManagedKey],
    bindings: &sshwarden_config::bindings::HostBindingsFile,
) -> anyhow::Result<String> {
    let mut lines = vec![
        "# SSHWarden managed SSH config — DO NOT EDIT".to_string(),
        "# This file is regenerated on every vault sync.".to_string(),
        "# Manage bindings via `sshwarden bindings ...`.".to_string(),
        String::new(),
    ];

    let mut bound_keys: Vec<&ManagedKey> = Vec::new();
    let mut unbound_keys: Vec<&ManagedKey> = Vec::new();
    for key in keys {
        match bindings.bindings.get(&key.cipher_id) {
            Some(b) if !b.hosts.is_empty() => bound_keys.push(key),
            _ => unbound_keys.push(key),
        }
    }

    for key in &bound_keys {
        let path = selector_path_for_key(&key.name, &key.cipher_id)?;
        let binding = bindings
            .bindings
            .get(&key.cipher_id)
            .expect("bound_keys filtered for presence");
        lines.push(format!("# {} ({})", key.name, key.cipher_id));
        lines.push(format!("Host {}", binding.hosts.join(" ")));
        lines.push(format!(
            "    IdentityFile {}",
            sshwarden_config::ssh_config::path_arg(&path)
        ));
        lines.push("    IdentitiesOnly yes".to_string());
        lines.push(String::new());
    }

    if !unbound_keys.is_empty() {
        lines.push("# --- Unbound keys (uncomment + edit to use) ---".to_string());
        lines.push(String::new());
        for key in &unbound_keys {
            let path = selector_path_for_key(&key.name, &key.cipher_id)?;
            lines.push(format!("# {} ({})", key.name, key.cipher_id));
            lines.push("# Host <host>".to_string());
            lines.push(format!(
                "#     IdentityFile {}",
                sshwarden_config::ssh_config::path_arg(&path)
            ));
            lines.push("#     IdentitiesOnly yes".to_string());
            lines.push(String::new());
        }
    }

    Ok(lines.join("\n"))
}

/// Refresh the managed `sshwarden_config` file from current vault keys + bindings.
///
/// Behaviour:
/// - Loads [`HostBindingsFile`] (defaults to empty if missing).
/// - Prunes bindings whose `cipher_uuid` is no longer in `keys`, persists if changed.
/// - Writes the snippet only if there are bindings OR the managed file already
///   exists — never creates the file unsolicited for users who have not opted in.
/// - Does NOT modify `~/.ssh/config`; the `Include` line is installed separately.
fn sync_managed_ssh_config_with_bindings(
    keys: &[sshwarden_api::DecryptedSshKey],
) -> anyhow::Result<()> {
    let managed = ManagedKey::from_decrypted(keys);
    sync_managed_ssh_config_inner(&managed, false)
}

/// Inner sync: optionally force write even when no bindings + no existing file
/// (used by `ssh-config install` / `regenerate` explicit CLI commands).
fn sync_managed_ssh_config_inner(keys: &[ManagedKey], force_write: bool) -> anyhow::Result<()> {
    let mut bindings = sshwarden_config::bindings::HostBindingsFile::load()
        .context("Failed to load host bindings")?;
    let known_ids: Vec<&str> = keys.iter().map(|k| k.cipher_id.as_str()).collect();
    let pruned = bindings.prune_orphans(known_ids.iter().copied());
    if pruned > 0 {
        bindings
            .save()
            .context("Failed to save host bindings after pruning orphans")?;
        info!("Pruned {} orphan host binding(s)", pruned);
    }

    let include_path = managed_sshwarden_include_path()?;
    let has_bindings = !bindings.bindings.is_empty();
    if !force_write && !has_bindings && !include_path.exists() {
        return Ok(());
    }

    let snippet = ssh_config_snippet_with_bindings(keys, &bindings)?;
    write_private_file(&include_path, snippet).with_context(|| {
        format!(
            "Failed to write managed SSHWarden SSH config: {}",
            include_path.display()
        )
    })?;
    Ok(())
}

fn managed_sshwarden_include_path() -> anyhow::Result<std::path::PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .context("Could not determine home directory")?;
    Ok(home.join(".ssh").join("sshwarden_config"))
}

fn user_ssh_config_path() -> anyhow::Result<std::path::PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .context("Could not determine home directory")?;
    Ok(home.join(".ssh").join("config"))
}

fn create_private_dir(path: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path)?;
    sshwarden_config::ssh_config::ensure_ssh_dir_permissions(path)?;
    Ok(())
}

fn write_private_file(path: &std::path::Path, content: impl AsRef<[u8]>) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    std::fs::write(path, content)?;
    sshwarden_config::ssh_config::ensure_private_file_permissions(path)?;
    Ok(())
}

fn write_sshwarden_include_line(
    config_path: &std::path::Path,
    include_path: &std::path::Path,
) -> anyhow::Result<()> {
    if let Some(parent) = config_path.parent() {
        create_private_dir(parent).with_context(|| {
            format!(
                "Failed to create SSH config directory: {}",
                parent.display()
            )
        })?;
    }

    let include_line = sshwarden_config::ssh_config::include_line(include_path);
    let existing = std::fs::read_to_string(config_path).unwrap_or_default();
    if !existing.lines().any(|line| {
        sshwarden_config::ssh_config::line_matches_sshwarden_include(line, include_path)
    }) {
        let mut new_config = existing;
        if !new_config.is_empty() && !new_config.ends_with('\n') {
            new_config.push('\n');
        }
        new_config.push_str("\n# SSHWarden managed key selector snippets\n");
        new_config.push_str(&include_line);
        new_config.push('\n');
        write_private_file(config_path, &new_config)
            .with_context(|| format!("Failed to update SSH config: {}", config_path.display()))?;
    }

    Ok(())
}

/// Remove the sshwarden `Include` line and its preceding marker comment from
/// `~/.ssh/config`. Returns `true` if anything was changed.
fn remove_sshwarden_include_line(
    config_path: &std::path::Path,
    include_path: &std::path::Path,
) -> anyhow::Result<bool> {
    if !config_path.exists() {
        return Ok(false);
    }
    let existing = std::fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read SSH config: {}", config_path.display()))?;
    const MARKER: &str = sshwarden_config::ssh_config::SSHWARDEN_INCLUDE_MARKER;

    let mut kept: Vec<&str> = Vec::with_capacity(existing.lines().count());
    let mut removed_any = false;
    let mut skip_marker_for_next_include = false;
    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed == MARKER {
            // Defer the decision: drop only if the next non-empty line is our Include.
            skip_marker_for_next_include = true;
            kept.push(line);
            continue;
        }
        if sshwarden_config::ssh_config::line_matches_sshwarden_include(trimmed, include_path) {
            // Drop the include line and retroactively drop the marker if it was the previous kept entry.
            if skip_marker_for_next_include {
                while let Some(last) = kept.last() {
                    if last.trim().is_empty() {
                        kept.pop();
                    } else if last.trim() == MARKER {
                        kept.pop();
                        break;
                    } else {
                        break;
                    }
                }
            }
            skip_marker_for_next_include = false;
            removed_any = true;
            continue;
        }
        if !trimmed.is_empty() {
            skip_marker_for_next_include = false;
        }
        kept.push(line);
    }

    if !removed_any {
        return Ok(false);
    }

    let mut new_config = kept.join("\n");
    if !new_config.is_empty() && !new_config.ends_with('\n') {
        new_config.push('\n');
    }
    write_private_file(config_path, &new_config)
        .with_context(|| format!("Failed to update SSH config: {}", config_path.display()))?;
    Ok(true)
}

fn write_managed_ssh_config(snippet: &str) -> anyhow::Result<()> {
    let include_path = managed_sshwarden_include_path()?;
    write_private_file(&include_path, snippet).with_context(|| {
        format!(
            "Failed to write managed SSHWarden SSH config: {}",
            include_path.display()
        )
    })?;

    let config_path = user_ssh_config_path()?;
    write_sshwarden_include_line(&config_path, &include_path)?;

    info!("Wrote managed SSH config: {}", include_path.display());
    info!("Ensured Include line in: {}", config_path.display());
    Ok(())
}

fn cmd_env(config: &sshwarden_config::Config, shell: &str) -> anyhow::Result<()> {
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

fn shell_single_quote(value: &str) -> String {
    value.replace('\'', "'\\''")
}

fn powershell_single_quote(value: &str) -> String {
    value.replace('\'', "''")
}

fn key_identities_from_tuples(
    keys: &[(String, String, String)],
) -> Vec<sshwarden_config::cache::KeyIdentity> {
    keys.iter()
        .map(
            |(pem, name, vault_item_id)| sshwarden_config::cache::KeyIdentity {
                name: name.clone(),
                vault_item_id: vault_item_id.clone(),
                public_key_openssh: public_key_openssh_from_pem(pem).unwrap_or_default(),
            },
        )
        .collect()
}

fn public_key_openssh_from_pem(pem: &str) -> anyhow::Result<String> {
    let private_key = ssh_key::private::PrivateKey::from_openssh(pem)
        .map_err(|e| anyhow::anyhow!("Failed to parse private key for public identity: {e}"))?;
    private_key
        .public_key()
        .to_openssh()
        .map_err(|e| anyhow::anyhow!("Failed to encode public key: {e}"))
}

#[allow(clippy::too_many_arguments)]
fn build_envelope_local_key_cache(
    keys: &[(String, String, String)],
    email: &str,
    server_url: &str,
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
    pin_encrypted: Option<String>,
    pin_salt: Option<String>,
    hello_challenge: Option<String>,
    hello_encrypted: Option<String>,
    native_encrypted: Option<String>,
) -> anyhow::Result<sshwarden_config::cache::LocalKeyCacheFile> {
    let keys_json = serde_json::to_string(keys).context("Failed to serialize cache payload")?;
    let encrypted_payload =
        sshwarden_api::crypto::encrypt_enc_string(keys_json.as_bytes(), local_cache_key)?;
    let cache = sshwarden_config::cache::LocalKeyCacheFile {
        version: 3,
        header: sshwarden_config::cache::LocalKeyCacheHeader {
            email: email.to_string(),
            server_url: server_url.to_string(),
            keys: key_identities_from_tuples(keys),
        },
        encrypted_payload,
        local_cache_key: sshwarden_config::cache::LocalCacheKeySlots {
            pin_encrypted,
            pin_salt,
            hello_challenge,
            hello_encrypted,
            native_encrypted,
        },
    };
    Ok(cache)
}

fn write_envelope_local_key_cache(
    keys: &[(String, String, String)],
    email: &str,
    server_url: &str,
    pin: &str,
) -> anyhow::Result<(
    sshwarden_config::cache::LocalKeyCacheFile,
    sshwarden_api::crypto::SymmetricKey,
)> {
    let local_cache_key = sshwarden_api::crypto::random_symmetric_key();
    let (pin_encrypted, pin_salt) = encrypt_local_cache_key_with_pin(&local_cache_key, pin)?;
    let mut cache = build_envelope_local_key_cache(
        keys,
        email,
        server_url,
        &local_cache_key,
        Some(pin_encrypted),
        Some(pin_salt),
        None,
        None,
        None,
    )?;
    if let Err(e) = enroll_native_for_local_key_cache(&mut cache, &local_cache_key) {
        tracing::debug!("Native unlock enrollment skipped: {}", e);
    }
    #[cfg(windows)]
    {
        if sshwarden_ui::unlock::hello_crypto::hello_available() {
            if let Err(e) = enroll_hello_for_local_key_cache(&mut cache, &local_cache_key) {
                tracing::warn!("Failed to enroll Windows Hello for local key cache: {}", e);
            }
        }
    }
    cache.save()?;
    Ok((cache, local_cache_key))
}

fn refresh_envelope_local_key_cache(
    keys: &[(String, String, String)],
    existing: &sshwarden_config::cache::LocalKeyCacheFile,
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
) -> anyhow::Result<sshwarden_config::cache::LocalKeyCacheFile> {
    let cache = build_envelope_local_key_cache(
        keys,
        &existing.header.email,
        &existing.header.server_url,
        local_cache_key,
        existing.local_cache_key.pin_encrypted.clone(),
        existing.local_cache_key.pin_salt.clone(),
        existing.local_cache_key.hello_challenge.clone(),
        existing.local_cache_key.hello_encrypted.clone(),
        existing.local_cache_key.native_encrypted.clone(),
    )?;
    cache.save()?;
    Ok(cache)
}

fn enroll_native_for_local_key_cache(
    cache: &mut sshwarden_config::cache::LocalKeyCacheFile,
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
) -> anyhow::Result<()> {
    if !sshwarden_ui::unlock::native::native_available() {
        anyhow::bail!("native unlock is not available");
    }
    let encoded_local_cache_key = sshwarden_api::crypto::encode_symmetric_key(local_cache_key);
    let native_slot =
        sshwarden_ui::unlock::native::native_encrypt_local_cache_key(&encoded_local_cache_key)?;
    cache.local_cache_key.native_encrypted = Some(native_slot);
    Ok(())
}

#[cfg(windows)]
fn enroll_hello_for_local_key_cache(
    cache: &mut sshwarden_config::cache::LocalKeyCacheFile,
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
) -> anyhow::Result<()> {
    let challenge: [u8; 16] = rand::random();
    let hello_encrypted = encrypt_local_cache_key_with_hello(local_cache_key, &challenge)?;
    cache.local_cache_key.hello_challenge =
        Some(base64::engine::general_purpose::STANDARD.encode(challenge));
    cache.local_cache_key.hello_encrypted = Some(hello_encrypted);
    Ok(())
}

/// Encrypt the local cache key with a PIN, generating a fresh random salt.
/// Returns `(pin_encrypted, pin_salt_b64)` for the v3 cache format (SEC-04).
fn encrypt_local_cache_key_with_pin(
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
    pin: &str,
) -> anyhow::Result<(String, String)> {
    let encoded_local_cache_key = sshwarden_api::crypto::encode_symmetric_key(local_cache_key);
    let salt = sshwarden_api::crypto::random_pin_salt();
    let pin_encrypted =
        sshwarden_api::crypto::pin_encrypt_with_salt(&encoded_local_cache_key, pin, &salt)?;
    let pin_salt = base64::engine::general_purpose::STANDARD.encode(salt);
    Ok((pin_encrypted, pin_salt))
}

#[cfg(windows)]
fn encrypt_local_cache_key_with_hello(
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
    challenge: &[u8; 16],
) -> anyhow::Result<String> {
    let encoded_local_cache_key = sshwarden_api::crypto::encode_symmetric_key(local_cache_key);
    try_hello_encrypt(&encoded_local_cache_key, challenge)
}

fn decrypt_envelope_payload(
    cache: &sshwarden_config::cache::LocalKeyCacheFile,
    local_cache_key: sshwarden_api::crypto::SymmetricKey,
) -> anyhow::Result<(String, sshwarden_api::crypto::SymmetricKey)> {
    let payload =
        sshwarden_api::crypto::decrypt_enc_string(&cache.encrypted_payload, &local_cache_key)
            .context("Failed to decrypt local key cache payload")?;
    let keys_json =
        String::from_utf8(payload).context("Local key cache payload is not valid UTF-8")?;
    Ok((keys_json, local_cache_key))
}

#[allow(dead_code)]
fn decrypt_envelope_local_key_cache_with_native(
    cache: &sshwarden_config::cache::LocalKeyCacheFile,
) -> anyhow::Result<(String, sshwarden_api::crypto::SymmetricKey)> {
    let native_slot = cache
        .local_cache_key
        .native_encrypted
        .as_deref()
        .context("Local key cache has no native unlock slot")?;
    let encoded_lck = sshwarden_ui::unlock::native::native_decrypt_local_cache_key(native_slot)
        .context("Failed to unlock Local Cache Key with native unlock")?;
    let local_cache_key = sshwarden_api::crypto::decode_symmetric_key(&encoded_lck)
        .context("Failed to decode Local Cache Key")?;
    decrypt_envelope_payload(cache, local_cache_key)
}

async fn finish_native_unlock_response(
    cache: sshwarden_config::cache::LocalKeyCacheFile,
    agent: &mut sshwarden_agent::SshWardenAgent,
    vault_locked: &Arc<std::sync::atomic::AtomicBool>,
    cached_key_tuples: &CachedKeyTuples,
    key_names: &Arc<RwLock<std::collections::HashMap<String, String>>>,
    local_cache_key_state: &LocalCacheKeyHandle,
    success_msg: &str,
) -> sshwarden_agent::ControlResponse {
    match decrypt_envelope_local_key_cache_with_native(&cache) {
        Ok((keys_json, local_cache_key)) => {
            local_cache_key_state.write().await.set(local_cache_key);
            finish_unlock_with_json(
                &keys_json,
                agent,
                vault_locked,
                cached_key_tuples,
                key_names,
                success_msg,
            )
            .await
        }
        Err(e) => sshwarden_agent::ControlResponse::err(&format!("Native unlock failed: {}", e)),
    }
}

fn decrypt_envelope_local_key_cache_with_pin(
    cache: &sshwarden_config::cache::LocalKeyCacheFile,
    pin: &str,
) -> anyhow::Result<(String, sshwarden_api::crypto::SymmetricKey)> {
    let encrypted_lck = cache
        .local_cache_key
        .pin_encrypted
        .as_deref()
        .context("Local key cache has no PIN unlock slot")?;
    let encoded_lck = match cache.local_cache_key.pin_salt.as_deref() {
        Some(salt_b64) => {
            let salt = base64::engine::general_purpose::STANDARD
                .decode(salt_b64)
                .context("Invalid PIN salt in local key cache")?;
            sshwarden_api::crypto::pin_decrypt_with_salt(encrypted_lck, pin, &salt)
        }
        // Pre-v3 cache: the PIN slot was derived with the fixed legacy salt.
        None => sshwarden_api::crypto::pin_decrypt_with_salt(
            encrypted_lck,
            pin,
            &sshwarden_api::crypto::legacy_pin_salt(),
        ),
    }
    .context("Failed to unlock Local Cache Key with PIN")?;
    let local_cache_key = sshwarden_api::crypto::decode_symmetric_key(&encoded_lck)
        .context("Failed to decode Local Cache Key")?;
    decrypt_envelope_payload(cache, local_cache_key)
}

/// Transparently migrate a pre-v3 (fixed-salt) cache to v3 with a fresh random
/// PIN salt after a successful PIN unlock (SEC-04). Only the PIN slot is
/// re-wrapped; the local cache key and other slots (Hello/native) are preserved
/// so there is no biometric re-prompt. Best-effort: a failure is logged, not
/// fatal (the unlock itself already succeeded).
fn needs_pin_salt_migration(cache: &sshwarden_config::cache::LocalKeyCacheFile) -> bool {
    cache.local_cache_key.pin_encrypted.is_some()
        && (cache.version < 3 || cache.local_cache_key.pin_salt.is_none())
}

fn migrate_pin_salt_to_v3(
    cache: &sshwarden_config::cache::LocalKeyCacheFile,
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
    pin: &str,
) -> anyhow::Result<sshwarden_config::cache::LocalKeyCacheFile> {
    let (pin_encrypted, pin_salt) = encrypt_local_cache_key_with_pin(local_cache_key, pin)?;
    let mut migrated = cache.clone();
    migrated.version = 3;
    migrated.local_cache_key.pin_encrypted = Some(pin_encrypted);
    migrated.local_cache_key.pin_salt = Some(pin_salt);
    migrated.save()?;
    Ok(migrated)
}

#[cfg(windows)]
fn decrypt_envelope_local_key_cache_with_hello(
    cache: &sshwarden_config::cache::LocalKeyCacheFile,
) -> anyhow::Result<(String, sshwarden_api::crypto::SymmetricKey)> {
    let challenge_b64 = cache
        .local_cache_key
        .hello_challenge
        .as_deref()
        .context("Local key cache has no Windows Hello challenge")?;
    let hello_encrypted = cache
        .local_cache_key
        .hello_encrypted
        .as_deref()
        .context("Local key cache has no Windows Hello unlock slot")?;
    let challenge_bytes = base64::engine::general_purpose::STANDARD
        .decode(challenge_b64)
        .context("Failed to decode Windows Hello challenge")?;
    if challenge_bytes.len() != 16 {
        anyhow::bail!("Invalid Windows Hello challenge length");
    }
    let mut challenge = [0u8; 16];
    challenge.copy_from_slice(&challenge_bytes);
    let encoded_lck = try_hello_unlock(&challenge, hello_encrypted)
        .context("Failed to unlock Local Cache Key with Windows Hello")?;
    let local_cache_key = sshwarden_api::crypto::decode_symmetric_key(&encoded_lck)
        .context("Failed to decode Local Cache Key")?;
    decrypt_envelope_payload(cache, local_cache_key)
}

fn key_material_fingerprints_from_tuples(
    keys: &[(String, String, String)],
) -> std::collections::HashMap<String, String> {
    use sha2::{Digest, Sha256};

    keys.iter()
        .map(|(pem, _name, vault_item_id)| {
            let mut hasher = Sha256::new();
            hasher.update(pem.as_bytes());
            (vault_item_id.clone(), format!("{:x}", hasher.finalize()))
        })
        .collect()
}

async fn clear_authorization_memory_for_changed_keys_async(
    old_fingerprints: &std::collections::HashMap<String, String>,
    new_keys: &[(String, String, String)],
    authorization_memory: &AuthorizationMemorySet,
) -> (usize, std::collections::HashMap<String, String>) {
    let new_fingerprints = key_material_fingerprints_from_tuples(new_keys);
    let changed_or_removed: std::collections::HashSet<String> = old_fingerprints
        .iter()
        .filter_map(
            |(vault_item_id, old_fingerprint)| match new_fingerprints.get(vault_item_id) {
                Some(new_fingerprint) if new_fingerprint == old_fingerprint => None,
                _ => Some(vault_item_id.clone()),
            },
        )
        .chain(
            new_fingerprints
                .keys()
                .filter(|id| !old_fingerprints.contains_key(*id))
                .cloned(),
        )
        .collect();

    if changed_or_removed.is_empty() {
        return (0, new_fingerprints);
    }

    let mut memory = authorization_memory.write().await;
    let before = memory.len();
    memory.retain(|(vault_item_id, _operation)| !changed_or_removed.contains(vault_item_id));
    (before.saturating_sub(memory.len()), new_fingerprints)
}

fn key_tuples_from_cache_header(
    cache: &sshwarden_config::cache::LocalKeyCacheFile,
) -> Vec<(String, String, String)> {
    cache
        .header
        .keys
        .iter()
        .map(|key| {
            (
                key.public_key_openssh.clone(),
                key.name.clone(),
                key.vault_item_id.clone(),
            )
        })
        .collect()
}

async fn cmd_ssh_config(
    config: &sshwarden_config::Config,
    base_url: Option<&str>,
    email: Option<&str>,
    write: bool,
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
    write_key_selector_files(&keys)?;
    let snippet = ssh_config_snippet_for_keys(&keys)?;

    if write {
        write_managed_ssh_config(&snippet)?;
    } else {
        #[allow(clippy::print_stdout)]
        {
            println!("{}", snippet);
        }
    }

    Ok(())
}

/// Load `ManagedKey`s from the local key cache header (offline, no decryption).
///
/// Returns an error when no cache exists — callers should surface this as a
/// hint that the user needs to log in or sync first.
fn load_managed_keys_from_cache() -> anyhow::Result<Vec<ManagedKey>> {
    let cache = sshwarden_config::cache::LocalKeyCacheFile::load()
        .context("Failed to load local key cache")?
        .context("No local key cache found — run `sshwarden login` or `sshwarden sync` first")?;
    Ok(ManagedKey::from_cache_header(&cache.header.keys))
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

async fn cmd_bindings(action: BindingsAction) -> anyhow::Result<()> {
    match action {
        BindingsAction::List => cmd_bindings_list().await,
        BindingsAction::Add { key, hosts } => cmd_bindings_add(&key, &hosts).await,
        BindingsAction::Remove { key, host, all } => {
            cmd_bindings_remove(&key, host.as_deref(), all).await
        }
        BindingsAction::Clear { key } => cmd_bindings_clear(&key).await,
        BindingsAction::Ui => cmd_control("bind-hosts-dialog").await,
    }
}

async fn cmd_bindings_list() -> anyhow::Result<()> {
    let bindings = sshwarden_config::bindings::HostBindingsFile::load()?;
    let cache = sshwarden_config::cache::LocalKeyCacheFile::load()?;
    let name_for = |id: &str| -> Option<String> {
        cache.as_ref().and_then(|c| {
            c.header
                .keys
                .iter()
                .find(|k| k.vault_item_id == id)
                .map(|k| k.name.clone())
        })
    };

    #[allow(clippy::print_stdout)]
    {
        if bindings.bindings.is_empty() {
            println!("No host bindings configured.");
            println!(
                "Use `sshwarden bindings add <key> <host>...` to bind a key to one or more hosts."
            );
            return Ok(());
        }
        println!("Host bindings ({}):", bindings.bindings.len());
        for (cipher_id, binding) in &bindings.bindings {
            let label = name_for(cipher_id)
                .map(|n| format!("{n} ({cipher_id})"))
                .unwrap_or_else(|| cipher_id.clone());
            println!("  • {label}");
            for host in &binding.hosts {
                println!("      - {host}");
            }
        }
    }
    Ok(())
}

async fn cmd_bindings_add(key: &str, hosts: &[String]) -> anyhow::Result<()> {
    let cipher_id = resolve_cipher_id(key)?;
    let mut bindings = sshwarden_config::bindings::HostBindingsFile::load()?;
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

    let keys = load_managed_keys_from_cache().unwrap_or_default();
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
            "Binding saved, but failed to ensure the Include line in {}: {e}. Run `sshwarden ssh-config install`.",
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
    let mut bindings = sshwarden_config::bindings::HostBindingsFile::load()?;

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

    let keys = load_managed_keys_from_cache().unwrap_or_default();
    sync_managed_ssh_config_inner(&keys, true)
        .context("Bindings saved but managed snippet regeneration failed")?;

    out_line(format!("Updated bindings for key {cipher_id}."));
    Ok(())
}

async fn cmd_bindings_clear(key: &str) -> anyhow::Result<()> {
    cmd_bindings_remove(key, None, true).await
}

async fn cmd_sshcfg_install() -> anyhow::Result<()> {
    let keys = load_managed_keys_from_cache()?;
    sync_managed_ssh_config_inner(&keys, true)?;

    let include_path = managed_sshwarden_include_path()?;
    let config_path = user_ssh_config_path()?;
    write_sshwarden_include_line(&config_path, &include_path)?;

    #[allow(clippy::print_stdout)]
    {
        println!("Managed snippet: {}", include_path.display());
        println!("Include line ensured in: {}", config_path.display());
    }
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
    let bindings = sshwarden_config::bindings::HostBindingsFile::load().unwrap_or_default();
    let cache = sshwarden_config::cache::LocalKeyCacheFile::load()?;

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

async fn cmd_sshcfg_regenerate() -> anyhow::Result<()> {
    let keys = load_managed_keys_from_cache()?;
    sync_managed_ssh_config_inner(&keys, true)?;
    let include_path = managed_sshwarden_include_path()?;
    #[allow(clippy::print_stdout)]
    {
        println!("Regenerated: {}", include_path.display());
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
        out_line("No SSH keys found in vault.");
    } else {
        out_line(format!("Found {} SSH key(s):", keys.len()));
        for key in &keys {
            // Show first line of PEM to identify key type
            let key_type = if key.private_key_pem.as_str().contains("ed25519") {
                "ED25519"
            } else if key.private_key_pem.as_str().contains("BEGIN RSA") {
                "RSA"
            } else {
                "SSH"
            };
            out_line(format!("  [{}] {} ({})", key_type, key.name, key.cipher_id));
        }
        out_line("\nNote: this lists vault keys without changing the running agent. Use `sshwarden login` to load them.");
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
    let local_key_cache = sshwarden_config::cache::LocalKeyCacheFile::load().unwrap_or_else(|e| {
        tracing::warn!("Failed to load local key cache: {}", e);
        None
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
    let (response_tx, _response_rx) = tokio::sync::broadcast::channel::<(u32, bool)>(32);
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
                    ).await;
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

/// Lock the vault: clear private key tuples while retaining public key identities
/// in the SSH agent so locked remembered devices remain listable.
async fn lock_vault(
    agent: &mut sshwarden_agent::SshWardenAgent,
    vault_locked: &Arc<std::sync::atomic::AtomicBool>,
    cached_key_tuples: &CachedKeyTuples,
    local_cache_key_state: Option<&LocalCacheKeyHandle>,
    authorization_memory: Option<&AuthorizationMemorySet>,
) -> Result<(), anyhow::Error> {
    agent.lock()?;
    vault_locked.store(true, std::sync::atomic::Ordering::Relaxed);
    cached_key_tuples.write().await.clear();
    if let Some(state) = local_cache_key_state {
        state.write().await.clear();
    }
    if let Some(memory) = authorization_memory {
        memory.write().await.clear();
    }
    Ok(())
}

/// SEC-03: in-memory PIN brute-force protection. Kept per daemon run (not
/// persisted) so it cannot be reset by tampering with on-disk state.
#[derive(Default)]
struct PinFailureState {
    consecutive_failures: u32,
    locked_until: Option<tokio::time::Instant>,
}

type PinFailureHandle = Arc<std::sync::Mutex<PinFailureState>>;

/// Lock PIN unlock after this many consecutive wrong attempts.
const PIN_MAX_ATTEMPTS: u32 = 5;
/// Per-failure delay scales with the failure count, capped, to slow guessing.
const PIN_FAILURE_BASE_DELAY: std::time::Duration = std::time::Duration::from_millis(500);
const PIN_FAILURE_MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(5);
/// Lockout window once PIN_MAX_ATTEMPTS consecutive failures is reached.
const PIN_LOCKOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Reject a PIN attempt outright while a lockout is active. Returns the
/// remaining lockout duration if locked, clearing an expired lockout.
fn pin_lockout_remaining(pin_failures: &PinFailureHandle) -> Option<std::time::Duration> {
    let now = tokio::time::Instant::now();
    let mut st = pin_failures.lock().unwrap_or_else(|e| e.into_inner());
    match st.locked_until {
        Some(until) if until > now => Some(until - now),
        Some(_) => {
            st.locked_until = None;
            None
        }
        None => None,
    }
}

/// Record a PIN unlock outcome: reset on success, otherwise bump the failure
/// counter (arming a lockout at the threshold) and return the delay to apply.
fn record_pin_attempt(pin_failures: &PinFailureHandle, success: bool) -> std::time::Duration {
    let mut st = pin_failures.lock().unwrap_or_else(|e| e.into_inner());
    if success {
        st.consecutive_failures = 0;
        st.locked_until = None;
        return std::time::Duration::ZERO;
    }
    st.consecutive_failures = st.consecutive_failures.saturating_add(1);
    if st.consecutive_failures >= PIN_MAX_ATTEMPTS {
        st.locked_until = Some(tokio::time::Instant::now() + PIN_LOCKOUT);
    }
    std::cmp::min(
        PIN_FAILURE_BASE_DELAY * st.consecutive_failures,
        PIN_FAILURE_MAX_DELAY,
    )
}

#[allow(clippy::too_many_arguments)]
async fn build_status_response(
    json: bool,
    agent: &sshwarden_agent::SshWardenAgent,
    vault_locked: &Arc<std::sync::atomic::AtomicBool>,
    pin_encrypted_keys: &Arc<RwLock<Option<String>>>,
    vault_file_data: &Arc<RwLock<Option<sshwarden_config::vault::VaultFile>>>,
    api_client: &Arc<RwLock<Option<sshwarden_api::BitwardenClient>>>,
    pending_sync: &Arc<std::sync::atomic::AtomicBool>,
    notification_state: &Arc<RwLock<NotificationRuntimeState>>,
    local_key_cache_data: &Arc<RwLock<Option<sshwarden_config::cache::LocalKeyCacheFile>>>,
) -> sshwarden_agent::ControlResponse {
    let locked = vault_locked.load(std::sync::atomic::Ordering::Relaxed);
    let count = agent.key_count();
    let signable = agent.signable_key_count();
    let agent_running = agent.is_running();
    let has_pin = pin_encrypted_keys.read().await.is_some();
    let has_vault = vault_file_data.read().await.is_some();
    let has_local_key_cache = local_key_cache_data.read().await.is_some();
    let authenticated = api_client.read().await.is_some();
    let pending = pending_sync.load(std::sync::atomic::Ordering::Relaxed);
    let notification = notification_state.read().await.clone();
    // P1-3: surface the resolved data directory so users can tell where their
    // secrets actually live (docs historically disagreed on this).
    let data_dir = sshwarden_config::config_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unresolved>".to_string());

    let details = serde_json::json!({
        "locked": locked,
        "key_count": count,
        "signable_key_count": signable,
        "agent_running": agent_running,
        "has_pin": has_pin,
        "has_vault_file": has_vault,
        "has_local_key_cache": has_local_key_cache,
        "legacy_migration_available": has_vault && !has_local_key_cache,
        "authenticated": authenticated,
        "pending_sync": pending,
        "data_dir": data_dir,
        "notification": notification.to_json(),
    });

    let mut resp = sshwarden_agent::ControlResponse::status(locked, count).with_details(details);
    let mut extras = Vec::new();
    if !agent_running {
        // RT-01: surface the zombie state — the agent task is not serving SSH
        // clients even though the control channel still answers.
        extras.push("AGENT NOT SERVING (SSH endpoint unavailable)");
    }
    if count > 0 && signable < count {
        // lock-keystore: identities are listed (ssh-add -l) but have no private
        // material, so signing fails until unlock. Make that explicit.
        extras.push("keys listed but not signable until unlock");
    }
    if has_pin {
        extras.push("PIN configured");
    }
    if has_vault {
        extras.push("vault.enc present");
    }
    if has_local_key_cache {
        extras.push("local key cache present");
    }
    if has_vault && !has_local_key_cache {
        extras.push("legacy migration available");
    }
    if authenticated {
        extras.push("API session restored");
    }
    if pending {
        extras.push("pending sync");
    }
    if notification.stale_cache {
        extras.push("stale cache");
    }
    extras.push(notification.state_name());

    if json {
        resp.message = None;
    } else if !extras.is_empty() {
        resp.message = Some(format!(
            "{} ({})",
            resp.message.unwrap_or_default(),
            extras.join(", ")
        ));
    }

    resp
}

/// Handle a control command from the IPC channel.
#[allow(clippy::too_many_arguments)]
async fn handle_control_command(
    action: sshwarden_agent::ControlAction,
    agent: &mut sshwarden_agent::SshWardenAgent,
    vault_locked: &Arc<std::sync::atomic::AtomicBool>,
    cached_key_tuples: &CachedKeyTuples,
    public_key_identity_tuples: &CachedKeyTuples,
    api_client: &Arc<RwLock<Option<sshwarden_api::BitwardenClient>>>,
    pin_encrypted_keys: &Arc<RwLock<Option<String>>>,
    vault_file_data: &Arc<RwLock<Option<sshwarden_config::vault::VaultFile>>>,
    local_key_cache_data: &Arc<RwLock<Option<sshwarden_config::cache::LocalKeyCacheFile>>>,
    local_cache_key_state: &LocalCacheKeyHandle,
    key_material_fingerprints: &KeyMaterialFingerprints,
    key_names: &Arc<RwLock<std::collections::HashMap<String, String>>>,
    config: &Arc<sshwarden_config::Config>,
    auto_unlock: bool,
    ui_request_tx: &UIRequestTx,
    notification_rx: &mut Option<tokio::sync::mpsc::Receiver<sshwarden_api::SyncEvent>>,
    notification_client: &mut Option<sshwarden_api::NotificationClient>,
    pending_sync: &Arc<std::sync::atomic::AtomicBool>,
    notification_state: &Arc<RwLock<NotificationRuntimeState>>,
    authorization_memory: &AuthorizationMemorySet,
    pin_failures: &PinFailureHandle,
) -> sshwarden_agent::ControlResponse {
    use sshwarden_agent::ControlAction;

    match action {
        ControlAction::Lock => {
            if vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
                sshwarden_agent::ControlResponse::ok("Vault is already locked")
            } else {
                match lock_vault(
                    agent,
                    vault_locked,
                    cached_key_tuples,
                    Some(local_cache_key_state),
                    Some(authorization_memory),
                )
                .await
                {
                    Ok(()) => {
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

            // Try platform-native Local Key Cache first, then Windows Hello/legacy Hello.
            #[cfg(not(windows))]
            if let Some(cache) = local_key_cache_data.read().await.as_ref().cloned() {
                let resp = finish_native_unlock_response(
                    cache,
                    agent,
                    vault_locked,
                    cached_key_tuples,
                    key_names,
                    local_cache_key_state,
                    "Vault unlocked via platform-native local key cache",
                )
                .await;
                if resp.ok {
                    resolve_pending_sync(
                        pending_sync,
                        api_client,
                        cached_key_tuples,
                        public_key_identity_tuples,
                        local_key_cache_data,
                        local_cache_key_state,
                        authorization_memory,
                        key_material_fingerprints,
                        vault_locked,
                        agent,
                        key_names,
                        notification_state,
                    )
                    .await;
                    return resp;
                }
                tracing::warn!("Platform-native local key cache unlock failed");
            }

            // Try envelope Local Key Cache Windows Hello first, then legacy Hello.
            #[cfg(windows)]
            if let Some(cache) = local_key_cache_data.read().await.as_ref().cloned() {
                match decrypt_envelope_local_key_cache_with_hello(&cache) {
                    Ok((keys_json, local_cache_key)) => {
                        local_cache_key_state.write().await.set(local_cache_key);
                        let resp = finish_unlock_with_json(
                            &keys_json,
                            agent,
                            vault_locked,
                            cached_key_tuples,
                            key_names,
                            "Vault unlocked via Windows Hello local key cache",
                        )
                        .await;
                        if resp.ok {
                            try_restore_api_session_hello(
                                api_client,
                                config,
                                notification_rx,
                                notification_client,
                                notification_state,
                            )
                            .await;
                            resolve_pending_sync(
                                pending_sync,
                                api_client,
                                cached_key_tuples,
                                public_key_identity_tuples,
                                local_key_cache_data,
                                local_cache_key_state,
                                authorization_memory,
                                key_material_fingerprints,
                                vault_locked,
                                agent,
                                key_names,
                                notification_state,
                            )
                            .await;
                        }
                        return resp;
                    }
                    Err(e) => tracing::warn!("Windows Hello local key cache unlock failed: {}", e),
                }
            }

            // Try legacy Hello sign-path (if hello_challenge available).
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
                                let resp = finish_unlock_with_json(
                                    &keys_json,
                                    agent,
                                    vault_locked,
                                    cached_key_tuples,
                                    key_names,
                                    "Vault unlocked via Windows Hello",
                                )
                                .await;

                                if resp.ok {
                                    try_restore_api_session_hello(
                                        api_client,
                                        config,
                                        notification_rx,
                                        notification_client,
                                        notification_state,
                                    )
                                    .await;
                                    resolve_pending_sync(
                                        pending_sync,
                                        api_client,
                                        cached_key_tuples,
                                        public_key_identity_tuples,
                                        local_key_cache_data,
                                        local_cache_key_state,
                                        authorization_memory,
                                        key_material_fingerprints,
                                        vault_locked,
                                        agent,
                                        key_names,
                                        notification_state,
                                    )
                                    .await;
                                }

                                return resp;
                            }
                            info!("Hello unlock failed or cancelled, trying fallback");
                        }
                    }
                }
            }

            // Fall back to PIN dialog when Hello sign-path fails
            if auto_unlock {
                info!("Hello sign-path failed, trying PIN dialog fallback");
                let enc_data = get_pin_encrypted_data(pin_encrypted_keys, vault_file_data).await;

                if let Some(enc_data) = enc_data {
                    let (validator, decrypted_cache) = make_pin_validator(enc_data);
                    let pin_result =
                        sshwarden_ui::unlock::request_pin_dialog(ui_request_tx, validator).await;

                    if let Some(ref entered_pin) = pin_result {
                        let keys_json = match decrypted_cache
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .take()
                        {
                            Some(j) => j,
                            None => {
                                tracing::warn!(
                                    "PIN validator reported success but cache was empty"
                                );
                                return sshwarden_agent::ControlResponse::err(
                                    "PIN unlock failed: internal cache error",
                                );
                            }
                        };
                        let resp = finish_unlock_with_json(
                            &keys_json,
                            agent,
                            vault_locked,
                            cached_key_tuples,
                            key_names,
                            "Vault unlocked via PIN dialog",
                        )
                        .await;

                        if resp.ok {
                            try_restore_api_session(
                                api_client,
                                config,
                                entered_pin,
                                notification_rx,
                                notification_client,
                                notification_state,
                            )
                            .await;
                            resolve_pending_sync(
                                pending_sync,
                                api_client,
                                cached_key_tuples,
                                public_key_identity_tuples,
                                local_key_cache_data,
                                local_cache_key_state,
                                authorization_memory,
                                key_material_fingerprints,
                                vault_locked,
                                agent,
                                key_names,
                                notification_state,
                            )
                            .await;
                        }

                        return resp;
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
        ControlAction::UnlockNative => {
            if !vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
                return sshwarden_agent::ControlResponse::ok("Vault is already unlocked");
            }

            let cache = match local_key_cache_data.read().await.as_ref().cloned() {
                Some(cache) => cache,
                None => return sshwarden_agent::ControlResponse::err("No Local Key Cache found"),
            };

            let resp = finish_native_unlock_response(
                cache,
                agent,
                vault_locked,
                cached_key_tuples,
                key_names,
                local_cache_key_state,
                "Vault unlocked via platform-native local key cache",
            )
            .await;

            if resp.ok {
                resolve_pending_sync(
                    pending_sync,
                    api_client,
                    cached_key_tuples,
                    public_key_identity_tuples,
                    local_key_cache_data,
                    local_cache_key_state,
                    authorization_memory,
                    key_material_fingerprints,
                    vault_locked,
                    agent,
                    key_names,
                    notification_state,
                )
                .await;
            }

            resp
        }
        ControlAction::UnlockHello => {
            if !vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
                return sshwarden_agent::ControlResponse::ok("Vault is already unlocked");
            }

            #[cfg(windows)]
            {
                if let Some(cache) = local_key_cache_data.read().await.as_ref().cloned() {
                    match decrypt_envelope_local_key_cache_with_hello(&cache) {
                        Ok((keys_json, local_cache_key)) => {
                            local_cache_key_state.write().await.set(local_cache_key);
                            let resp = finish_unlock_with_json(
                                &keys_json,
                                agent,
                                vault_locked,
                                cached_key_tuples,
                                key_names,
                                "Vault unlocked via Windows Hello local key cache",
                            )
                            .await;
                            if resp.ok {
                                try_restore_api_session_hello(
                                    api_client,
                                    config,
                                    notification_rx,
                                    notification_client,
                                    notification_state,
                                )
                                .await;
                                resolve_pending_sync(
                                    pending_sync,
                                    api_client,
                                    cached_key_tuples,
                                    public_key_identity_tuples,
                                    local_key_cache_data,
                                    local_cache_key_state,
                                    authorization_memory,
                                    key_material_fingerprints,
                                    vault_locked,
                                    agent,
                                    key_names,
                                    notification_state,
                                )
                                .await;
                            }
                            return resp;
                        }
                        Err(e) => {
                            tracing::warn!("Windows Hello local key cache unlock failed: {}", e)
                        }
                    }
                }

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
                        let resp = finish_unlock_with_json(
                            &keys_json,
                            agent,
                            vault_locked,
                            cached_key_tuples,
                            key_names,
                            "Vault unlocked via Windows Hello",
                        )
                        .await;
                        if resp.ok {
                            try_restore_api_session_hello(
                                api_client,
                                config,
                                notification_rx,
                                notification_client,
                                notification_state,
                            )
                            .await;
                            resolve_pending_sync(
                                pending_sync,
                                api_client,
                                cached_key_tuples,
                                public_key_identity_tuples,
                                local_key_cache_data,
                                local_cache_key_state,
                                authorization_memory,
                                key_material_fingerprints,
                                vault_locked,
                                agent,
                                key_names,
                                notification_state,
                            )
                            .await;
                        }
                        resp
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
        ControlAction::Status { json } => {
            build_status_response(
                json,
                agent,
                vault_locked,
                pin_encrypted_keys,
                vault_file_data,
                api_client,
                pending_sync,
                notification_state,
                local_key_cache_data,
            )
            .await
        }
        ControlAction::UnlockPin { pin } => {
            let pin = zeroize::Zeroizing::new(pin);
            if !vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
                return sshwarden_agent::ControlResponse::ok("Vault is already unlocked");
            }

            // SEC-03: reject outright while a brute-force lockout is active (no
            // Argon2 work performed) so the control channel can't be hammered.
            if let Some(wait) = pin_lockout_remaining(pin_failures) {
                return sshwarden_agent::ControlResponse::err(&format!(
                    "Too many failed PIN attempts; locked for {}s",
                    wait.as_secs() + 1
                ));
            }

            let resp = 'unlock: {
                if let Some(cache) = local_key_cache_data.read().await.as_ref().cloned() {
                    match decrypt_envelope_local_key_cache_with_pin(&cache, &pin) {
                        Ok((keys_json, local_cache_key)) => {
                            // SEC-04: now that we hold the local cache key and a
                            // verified PIN, transparently upgrade a pre-v3 (fixed
                            // salt) cache to a random per-cache salt.
                            if needs_pin_salt_migration(&cache) {
                                match migrate_pin_salt_to_v3(&cache, &local_cache_key, &pin) {
                                    Ok(migrated) => {
                                        *local_key_cache_data.write().await = Some(migrated);
                                        info!(
                                            "Migrated local key cache PIN slot to v3 (random salt)"
                                        );
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "PIN salt v3 migration failed (non-fatal): {e}"
                                        )
                                    }
                                }
                            }
                            local_cache_key_state.write().await.set(local_cache_key);
                            let resp = finish_unlock_with_json(
                                &keys_json,
                                agent,
                                vault_locked,
                                cached_key_tuples,
                                key_names,
                                "Vault unlocked via PIN local key cache",
                            )
                            .await;

                            if resp.ok {
                                try_restore_api_session(
                                    api_client,
                                    config,
                                    &pin,
                                    notification_rx,
                                    notification_client,
                                    notification_state,
                                )
                                .await;
                                resolve_pending_sync(
                                    pending_sync,
                                    api_client,
                                    cached_key_tuples,
                                    public_key_identity_tuples,
                                    local_key_cache_data,
                                    local_cache_key_state,
                                    authorization_memory,
                                    key_material_fingerprints,
                                    vault_locked,
                                    agent,
                                    key_names,
                                    notification_state,
                                )
                                .await;
                            }

                            break 'unlock resp;
                        }
                        Err(e) => {
                            tracing::warn!("PIN unlock from local key cache failed: {}", e);
                        }
                    }
                }

                // Fall back to legacy in-memory/vault.enc cache.
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
                            if local_key_cache_data.read().await.is_none() {
                                let keys_for_migration: Result<Vec<(String, String, String)>, _> =
                                    serde_json::from_str(&keys_json);
                                if let Ok(keys_for_migration) = keys_for_migration {
                                    match write_envelope_local_key_cache(
                                    &keys_for_migration,
                                    &config.auth.email,
                                    &config.server.base_url,
                                    &pin,
                                ) {
                                    Ok((cache, local_cache_key)) => {
                                        *local_key_cache_data.write().await = Some(cache);
                                        local_cache_key_state.write().await.set(local_cache_key);
                                        *pin_encrypted_keys.write().await = None;
                                        *vault_file_data.write().await = None;
                                        if let Err(e) = sshwarden_config::vault::VaultFile::delete() {
                                            tracing::warn!("Failed to delete legacy vault file after migration: {}", e);
                                        }
                                        info!("Migrated legacy vault.enc to envelope local key cache");
                                    }
                                    Err(e) => tracing::warn!(
                                        "Failed to migrate legacy vault.enc to envelope local key cache: {}",
                                        e
                                    ),
                                }
                                }
                            }
                            let resp = finish_unlock_with_json(
                                &keys_json,
                                agent,
                                vault_locked,
                                cached_key_tuples,
                                key_names,
                                "Vault unlocked via PIN",
                            )
                            .await;

                            if resp.ok {
                                // Try to restore API session from device session file
                                try_restore_api_session(
                                    api_client,
                                    config,
                                    &pin,
                                    notification_rx,
                                    notification_client,
                                    notification_state,
                                )
                                .await;
                                resolve_pending_sync(
                                    pending_sync,
                                    api_client,
                                    cached_key_tuples,
                                    public_key_identity_tuples,
                                    local_key_cache_data,
                                    local_cache_key_state,
                                    authorization_memory,
                                    key_material_fingerprints,
                                    vault_locked,
                                    agent,
                                    key_names,
                                    notification_state,
                                )
                                .await;
                            }

                            resp
                        }
                        Err(_) => sshwarden_agent::ControlResponse::err("Invalid PIN"),
                    },
                    None => sshwarden_agent::ControlResponse::err(
                        "No PIN configured. Use 'sshwarden set-pin' first.",
                    ),
                }
            };

            // SEC-03: record the outcome — reset on success, otherwise apply an
            // escalating delay and arm a lockout once the threshold is reached.
            let delay = record_pin_attempt(pin_failures, resp.ok);
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            resp
        }
        ControlAction::UnlockPassword { password } => {
            let password = zeroize::Zeroizing::new(password);
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
                                (*k.private_key_pem).clone(),
                                k.name.clone(),
                                k.cipher_id.clone(),
                            )
                        })
                        .collect();
                    let count = key_tuples.len();
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

                    // Save device session + connect notifications
                    save_device_session(&client, config, None).await;

                    if let Some(token) = client.access_token() {
                        connect_notification_client(
                            config,
                            Some(&client),
                            token,
                            notification_rx,
                            notification_client,
                            notification_state,
                        )
                        .await;
                    }

                    *api_client.write().await = Some(client);
                    resolve_pending_sync(
                        pending_sync,
                        api_client,
                        cached_key_tuples,
                        public_key_identity_tuples,
                        local_key_cache_data,
                        local_cache_key_state,
                        authorization_memory,
                        key_material_fingerprints,
                        vault_locked,
                        agent,
                        key_names,
                        notification_state,
                    )
                    .await;

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
            // do_sync cannot load keys into the agent while the vault is locked
            // (no private material is held); it only refreshes the on-disk cache.
            // Report that honestly and mark a pending sync so the next unlock
            // applies the keys, instead of claiming the running agent was updated.
            let was_locked = vault_locked.load(std::sync::atomic::Ordering::Relaxed);
            match do_sync(
                api_client,
                cached_key_tuples,
                public_key_identity_tuples,
                local_key_cache_data,
                local_cache_key_state,
                authorization_memory,
                key_material_fingerprints,
                vault_locked,
                agent,
                key_names,
                notification_state,
            )
            .await
            {
                Ok(count) => {
                    if was_locked {
                        pending_sync.store(true, std::sync::atomic::Ordering::Relaxed);
                        sshwarden_agent::ControlResponse::ok(&format!(
                            "Synced {count} SSH keys to cache; they will load into the agent on next unlock"
                        ))
                    } else {
                        sshwarden_agent::ControlResponse::ok(&format!("Synced {count} SSH keys"))
                    }
                }
                Err(e) => sshwarden_agent::ControlResponse::err(&e),
            }
        }
        ControlAction::Forget => {
            if let Err(e) = sshwarden_config::cache::LocalKeyCacheFile::delete() {
                tracing::warn!("Failed to delete local key cache: {}", e);
            }
            if let Err(e) = sshwarden_config::vault::VaultFile::delete() {
                tracing::warn!("Failed to delete legacy vault file: {}", e);
            }
            let native_slot = local_key_cache_data
                .read()
                .await
                .as_ref()
                .and_then(|cache| cache.local_cache_key.native_encrypted.clone());
            if let Err(e) =
                sshwarden_ui::unlock::native::native_delete_local_cache_key(native_slot.as_deref())
            {
                tracing::warn!("Failed to delete native unlock material: {}", e);
            }
            if let Err(e) = sshwarden_config::session::SessionFile::delete() {
                tracing::warn!("Failed to delete device session file: {}", e);
            }

            *local_key_cache_data.write().await = None;
            *vault_file_data.write().await = None;
            *pin_encrypted_keys.write().await = None;
            local_cache_key_state.write().await.clear();
            authorization_memory.write().await.clear();
            cached_key_tuples.write().await.clear();
            public_key_identity_tuples.write().await.clear();
            key_names.write().await.clear();
            *api_client.write().await = None;
            pending_sync.store(false, std::sync::atomic::Ordering::Relaxed);
            {
                let mut state = notification_state.write().await;
                state.stale_cache = false;
                state.stale_cache_error = None;
            }
            if let Some(client) = notification_client.take() {
                client.stop();
            }
            *notification_rx = None;
            let _ = agent.clear_keys();
            vault_locked.store(true, std::sync::atomic::Ordering::Relaxed);

            sshwarden_agent::ControlResponse::ok(
                "Forgot local key cache, legacy vault file, and device session material",
            )
        }
        ControlAction::SetPin { pin } => {
            let pin = zeroize::Zeroizing::new(pin);
            if pin.len() < 4 {
                return sshwarden_agent::ControlResponse::err("PIN must be at least 4 characters");
            }

            let keys = cached_key_tuples.read().await.clone_inner();
            if keys.is_empty() {
                return sshwarden_agent::ControlResponse::err("No keys loaded. Login first.");
            }

            let email = config.auth.email.clone();
            let server_url = config.server.base_url.clone();

            match write_envelope_local_key_cache(&keys, &email, &server_url, &pin) {
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
                    info!("Envelope local key cache saved");

                    // Save device session with PIN-encrypted refresh token
                    {
                        let client_guard = api_client.read().await;
                        if let Some(ref client) = *client_guard {
                            save_device_session(client, config, Some(&pin)).await;
                        }
                    }

                    sshwarden_agent::ControlResponse::ok(
                        "PIN set successfully (persisted to local key cache)",
                    )
                }
                Err(e) => sshwarden_agent::ControlResponse::err(&format!(
                    "Failed to save envelope local key cache: {}",
                    e
                )),
            }
        }
        ControlAction::BindHostsDialog => {
            match dispatch_standalone_bind_hosts_dialog(ui_request_tx).await {
                Ok(saved) => {
                    if saved {
                        sshwarden_agent::ControlResponse::ok("Bindings updated")
                    } else {
                        sshwarden_agent::ControlResponse::ok("Dialog cancelled")
                    }
                }
                Err(e) => sshwarden_agent::ControlResponse::err(&format!(
                    "Failed to open bind-hosts dialog: {}",
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

#[cfg(windows)]
fn try_hello_encrypt(plaintext: &str, challenge: &[u8; 16]) -> anyhow::Result<String> {
    sshwarden_ui::unlock::hello_crypto::hello_encrypt_keys(plaintext, challenge)
}

fn notification_options(config: &sshwarden_config::Config) -> sshwarden_api::NotificationOptions {
    sshwarden_api::NotificationOptions {
        keepalive_interval: std::time::Duration::from_secs(
            config.agent.notification_keepalive_interval.max(1),
        ),
        idle_timeout: std::time::Duration::from_secs(config.agent.notification_idle_timeout.max(1)),
        reconnect_attempts_before_fallback: config
            .agent
            .notification_reconnect_attempts_before_fallback,
        reconnect_max_backoff: std::time::Duration::from_secs(
            config.agent.notification_reconnect_max_backoff.max(1),
        ),
        fallback_sync_interval: std::time::Duration::from_secs(config.agent.sync_interval),
    }
}

async fn connect_notification_client(
    config: &sshwarden_config::Config,
    api_client: Option<&sshwarden_api::BitwardenClient>,
    access_token: &str,
    notification_rx: &mut Option<tokio::sync::mpsc::Receiver<sshwarden_api::SyncEvent>>,
    notification_client: &mut Option<sshwarden_api::NotificationClient>,
    notification_state: &Arc<RwLock<NotificationRuntimeState>>,
) {
    if let Some(client) = notification_client.take() {
        client.stop();
    }
    *notification_rx = None;

    let notif_url = resolve_notifications_url(config, api_client).await;
    {
        let mut state = notification_state.write().await;
        state.state = NotificationConnectionState::Starting;
        state.url = Some(notif_url.clone());
        state.last_error = None;
    }
    info!("Attempting to connect to notification hub: {}", notif_url);
    match sshwarden_api::NotificationClient::connect_with_options(
        &notif_url,
        access_token,
        notification_options(config),
    )
    .await
    {
        Ok((notif_client, rx)) => {
            *notification_rx = Some(rx);
            *notification_client = Some(notif_client);
            let mut state = notification_state.write().await;
            state.state = NotificationConnectionState::Running;
            state.reconnect_attempts = 0;
            state.last_connected_at = Some(std::time::Instant::now());
            state.last_error = None;
        }
        Err(e) => {
            tracing::warn!("Failed to start notification client: {}", e);
            let mut state = notification_state.write().await;
            state.state = NotificationConnectionState::Failed;
            state.reconnect_attempts = state.reconnect_attempts.saturating_add(1);
            state.last_error = Some(e.to_string());
        }
    }
}

async fn resolve_notifications_url(
    config: &sshwarden_config::Config,
    api_client: Option<&sshwarden_api::BitwardenClient>,
) -> String {
    if let Some(explicit) = config.server.notifications_url.as_deref() {
        return explicit.to_string();
    }

    if let Some(client) = api_client {
        match client.discover_notifications_url().await {
            Ok(Some(url)) => return url,
            Ok(None) => tracing::debug!("Server config discovery omitted notifications URL"),
            Err(e) => tracing::debug!("Server config discovery failed: {}", e),
        }
    }

    config.server.notifications_url()
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

type PinValidator = Arc<dyn Fn(&str) -> bool + Send + Sync>;
type DecryptedCache = Arc<std::sync::Mutex<Option<String>>>;

/// Create a PIN validator closure and a shared cache for the decrypted result.
///
/// The validator performs Argon2id-based decryption, caching the result on success
/// so the caller can retrieve the decrypted keys without re-running the KDF.
fn make_pin_validator(enc_data: String) -> (PinValidator, DecryptedCache) {
    let decrypted_cache: Arc<std::sync::Mutex<Option<String>>> =
        Arc::new(std::sync::Mutex::new(None));
    let cache_clone = decrypted_cache.clone();

    let validator: Arc<dyn Fn(&str) -> bool + Send + Sync> = Arc::new(move |pin: &str| -> bool {
        match sshwarden_api::crypto::pin_decrypt(&enc_data, pin) {
            Ok(keys_json) => {
                *cache_clone.lock().unwrap_or_else(|e| e.into_inner()) = Some(keys_json);
                true
            }
            Err(_) => false,
        }
    });

    (validator, decrypted_cache)
}

/// Try to restore an API session from the device session file after Hello unlock.
///
/// Uses the Hello-encrypted refresh token stored in the session file.
#[cfg(windows)]
async fn try_restore_api_session_hello(
    api_client: &Arc<RwLock<Option<sshwarden_api::BitwardenClient>>>,
    config: &Arc<sshwarden_config::Config>,
    notification_rx: &mut Option<tokio::sync::mpsc::Receiver<sshwarden_api::SyncEvent>>,
    notification_client: &mut Option<sshwarden_api::NotificationClient>,
    notification_state: &Arc<RwLock<NotificationRuntimeState>>,
) {
    if api_client.read().await.is_some() {
        return;
    }

    let session = match sshwarden_config::session::SessionFile::load() {
        Ok(Some(s)) => s,
        _ => return,
    };

    // Need hello_encrypted_token and the vault's hello_challenge
    let hello_enc_token = match session.hello_encrypted_token {
        Some(ref t) => t.clone(),
        None => {
            info!("Session file has no Hello-encrypted token, skipping API restore");
            return;
        }
    };

    // Get challenge from vault file
    let vault_file = match sshwarden_config::vault::VaultFile::load() {
        Ok(Some(v)) => v,
        _ => return,
    };

    let challenge_b64 = match vault_file.hello_challenge {
        Some(ref c) => c.clone(),
        None => return,
    };

    let challenge_bytes = match base64::engine::general_purpose::STANDARD.decode(&challenge_b64) {
        Ok(b) if b.len() == 16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return,
    };

    // Decrypt with Hello
    let hello_result = tokio::task::spawn_blocking(move || {
        sshwarden_ui::unlock::hello_crypto::hello_decrypt_keys(&hello_enc_token, &challenge_bytes)
    })
    .await;

    let refresh_token = match hello_result {
        Ok(Ok(token)) => token,
        _ => {
            info!("Hello decrypt of session token failed");
            return;
        }
    };

    let base = &config.server.base_url;
    let api_url = config.server.api_url();
    let mut client = sshwarden_api::BitwardenClient::new_with_device_id(
        base,
        &api_url,
        &session.identity_url,
        &session.device_id,
    );
    client.set_refresh_token(refresh_token);

    match client.refresh_access_token().await {
        Ok(()) => {
            info!("Restored API session from device session file (Hello)");

            if let Some(token) = client.access_token() {
                connect_notification_client(
                    config,
                    Some(&client),
                    token,
                    notification_rx,
                    notification_client,
                    notification_state,
                )
                .await;
            }

            *api_client.write().await = Some(client);
        }
        Err(e) => {
            tracing::warn!("Hello session restore failed: {}", e);
        }
    }
}

/// Sync SSH keys from the Bitwarden API and reload into the agent.
#[allow(clippy::too_many_arguments)]
async fn do_sync(
    api_client: &Arc<RwLock<Option<sshwarden_api::BitwardenClient>>>,
    cached_key_tuples: &CachedKeyTuples,
    public_key_identity_tuples: &CachedKeyTuples,
    local_key_cache_data: &Arc<RwLock<Option<sshwarden_config::cache::LocalKeyCacheFile>>>,
    local_cache_key_state: &LocalCacheKeyHandle,
    authorization_memory: &AuthorizationMemorySet,
    key_material_fingerprints: &KeyMaterialFingerprints,
    vault_locked: &Arc<std::sync::atomic::AtomicBool>,
    agent: &mut sshwarden_agent::SshWardenAgent,
    key_names: &Arc<RwLock<std::collections::HashMap<String, String>>>,
    notification_state: &Arc<RwLock<NotificationRuntimeState>>,
) -> Result<usize, String> {
    let client_guard = api_client.read().await;
    let client = match *client_guard {
        Some(ref c) => c,
        None => return Err("Not authenticated. Use 'unlock --password' to login.".to_string()),
    };

    let keys = client
        .sync_ssh_keys()
        .await
        .map_err(|e| format!("Sync failed: {}", e))?;

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
    if let Err(e) = write_key_selector_files(&keys) {
        tracing::warn!("Failed to write key selector files: {}", e);
    }
    if let Err(e) = sync_managed_ssh_config_with_bindings(&keys) {
        tracing::warn!("Failed to sync managed SSH config: {}", e);
    }
    let old_fingerprints = key_material_fingerprints.read().await.clone();
    let (cleared_memory, new_fingerprints) = clear_authorization_memory_for_changed_keys_async(
        &old_fingerprints,
        &key_tuples,
        authorization_memory,
    )
    .await;
    if cleared_memory > 0 {
        tracing::info!(
            count = cleared_memory,
            "Cleared authorization memory after key material change"
        );
    }

    public_key_identity_tuples
        .write()
        .await
        .set(key_tuples.clone());
    cached_key_tuples.write().await.set(key_tuples.clone());
    *key_material_fingerprints.write().await = new_fingerprints;

    if let (Some(existing_cache), Some(local_cache_key)) = (
        local_key_cache_data.read().await.as_ref().cloned(),
        local_cache_key_state.read().await.clone_key(),
    ) {
        match refresh_envelope_local_key_cache(&key_tuples, &existing_cache, &local_cache_key) {
            Ok(cache) => {
                *local_key_cache_data.write().await = Some(cache);
                tracing::info!("Local key cache refreshed after sync");
            }
            Err(e) => {
                let error = e.to_string();
                {
                    let mut state = notification_state.write().await;
                    state.stale_cache = true;
                    state.stale_cache_error = Some(error.clone());
                }
                tracing::warn!(
                    "Sync succeeded but local key cache refresh failed: {}",
                    error
                );
            }
        }
    }

    // Update key_names
    {
        let mut names = key_names.write().await;
        names.clear();
        for k in &keys {
            names.insert(k.cipher_id.clone(), k.name.clone());
        }
    }

    drop(client_guard);

    if !vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
        if let Err(e) = agent.set_keys(key_tuples) {
            return Err(format!("Sync succeeded but failed to reload keys: {}", e));
        }
    }
    info!("Vault synced: {} SSH keys", count);
    Ok(count)
}

#[allow(clippy::too_many_arguments)]
async fn resolve_pending_sync(
    pending_sync: &Arc<std::sync::atomic::AtomicBool>,
    api_client: &Arc<RwLock<Option<sshwarden_api::BitwardenClient>>>,
    cached_key_tuples: &CachedKeyTuples,
    public_key_identity_tuples: &CachedKeyTuples,
    local_key_cache_data: &Arc<RwLock<Option<sshwarden_config::cache::LocalKeyCacheFile>>>,
    local_cache_key_state: &LocalCacheKeyHandle,
    authorization_memory: &AuthorizationMemorySet,
    key_material_fingerprints: &KeyMaterialFingerprints,
    vault_locked: &Arc<std::sync::atomic::AtomicBool>,
    agent: &mut sshwarden_agent::SshWardenAgent,
    key_names: &Arc<RwLock<std::collections::HashMap<String, String>>>,
    notification_state: &Arc<RwLock<NotificationRuntimeState>>,
) -> bool {
    if !pending_sync.swap(false, std::sync::atomic::Ordering::Relaxed) {
        return false;
    }

    info!("Resolving pending sync after unlock...");
    match do_sync(
        api_client,
        cached_key_tuples,
        public_key_identity_tuples,
        local_key_cache_data,
        local_cache_key_state,
        authorization_memory,
        key_material_fingerprints,
        vault_locked,
        agent,
        key_names,
        notification_state,
    )
    .await
    {
        Ok(count) => {
            info!("Pending sync resolved: {} SSH keys", count);
            true
        }
        Err(e) => {
            pending_sync.store(true, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!("Pending sync failed: {}; sync remains pending", e);
            false
        }
    }
}

/// Try to restore an API session from the device session file after PIN unlock.
///
/// Decrypts the stored refresh_token using the PIN, refreshes the access token,
/// and connects to the notification hub.
async fn try_restore_api_session(
    api_client: &Arc<RwLock<Option<sshwarden_api::BitwardenClient>>>,
    config: &Arc<sshwarden_config::Config>,
    pin: &str,
    notification_rx: &mut Option<tokio::sync::mpsc::Receiver<sshwarden_api::SyncEvent>>,
    notification_client: &mut Option<sshwarden_api::NotificationClient>,
    notification_state: &Arc<RwLock<NotificationRuntimeState>>,
) {
    // Only restore if we don't already have an API client
    if api_client.read().await.is_some() {
        return;
    }

    let session = match sshwarden_config::session::SessionFile::load() {
        Ok(Some(s)) => s,
        Ok(None) => {
            info!("No device session file found, skipping API session restore");
            return;
        }
        Err(e) => {
            tracing::warn!("Failed to load session file: {}", e);
            return;
        }
    };

    // Decrypt refresh token using PIN
    let refresh_token = match session.pin_encrypted_token {
        Some(ref enc) => match sshwarden_api::crypto::pin_decrypt(enc, pin) {
            Ok(token) => token,
            Err(e) => {
                tracing::warn!("Failed to decrypt session refresh token: {}", e);
                return;
            }
        },
        None => {
            info!("Session file has no PIN-encrypted token");
            return;
        }
    };

    // Create client with stored device_id and try to refresh
    let base = &config.server.base_url;
    let api_url = config.server.api_url();
    let mut client = sshwarden_api::BitwardenClient::new_with_device_id(
        base,
        &api_url,
        &session.identity_url,
        &session.device_id,
    );
    client.set_refresh_token(refresh_token);

    match client.refresh_access_token().await {
        Ok(()) => {
            info!("Restored API session from device session file");

            // Connect to notification hub
            if let Some(token) = client.access_token() {
                connect_notification_client(
                    config,
                    Some(&client),
                    token,
                    notification_rx,
                    notification_client,
                    notification_state,
                )
                .await;
            }

            // Update session file with new refresh token
            save_device_session(&client, config, Some(pin)).await;

            *api_client.write().await = Some(client);
        }
        Err(e) => {
            tracing::warn!("API session restore failed (token refresh): {}", e);
            // Session file may have an expired refresh token — clean it up
            if let Err(e) = sshwarden_config::session::SessionFile::delete() {
                tracing::warn!("Failed to delete stale session file: {}", e);
            }
        }
    }
}

/// Save the current API client's device session to disk.
///
/// If `pin` is provided, the refresh token is encrypted with it.
/// Otherwise, the existing session file's encrypted tokens are preserved.
async fn save_device_session(
    client: &sshwarden_api::BitwardenClient,
    _config: &sshwarden_config::Config,
    pin: Option<&str>,
) {
    let refresh_token = match client.refresh_token() {
        Some(t) => t.to_string(),
        None => return, // No refresh token to save
    };

    // Load existing session to preserve hello_encrypted_token if present
    let existing = sshwarden_config::session::SessionFile::load()
        .ok()
        .flatten();

    let pin_encrypted_token = if let Some(pin) = pin {
        match sshwarden_api::crypto::pin_encrypt(&refresh_token, pin) {
            Ok(enc) => Some(enc),
            Err(e) => {
                tracing::warn!("Failed to encrypt refresh token with PIN: {}", e);
                // Fall back to existing
                existing
                    .as_ref()
                    .and_then(|s| s.pin_encrypted_token.clone())
            }
        }
    } else {
        // Re-encrypt with existing PIN is not possible without the PIN.
        // Keep existing encrypted token if available.
        existing
            .as_ref()
            .and_then(|s| s.pin_encrypted_token.clone())
    };

    let hello_encrypted_token = create_or_preserve_hello_encrypted_token(
        &refresh_token,
        existing
            .as_ref()
            .and_then(|s| s.hello_encrypted_token.clone()),
    );

    let session = sshwarden_config::session::SessionFile {
        version: 1,
        device_id: client.device_id().to_string(),
        pin_encrypted_token,
        hello_encrypted_token,
        identity_url: client.identity_url().to_string(),
    };

    if let Err(e) = session.save() {
        tracing::warn!("Failed to save device session: {}", e);
    } else {
        info!(
            "Device session saved to {}",
            sshwarden_config::session::SessionFile::path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "unknown".to_string())
        );
    }
}

fn create_or_preserve_hello_encrypted_token(
    refresh_token: &str,
    existing: Option<String>,
) -> Option<String> {
    #[cfg(windows)]
    {
        let vault = match sshwarden_config::vault::VaultFile::load() {
            Ok(Some(v)) => v,
            _ => return existing,
        };
        let challenge_b64 = match vault.hello_challenge {
            Some(challenge) => challenge,
            None => return existing,
        };
        let challenge_bytes = match base64::engine::general_purpose::STANDARD.decode(&challenge_b64)
        {
            Ok(bytes) if bytes.len() == 16 => {
                let mut challenge = [0u8; 16];
                challenge.copy_from_slice(&bytes);
                challenge
            }
            _ => return existing,
        };

        match try_hello_encrypt(refresh_token, &challenge_bytes) {
            Ok(encrypted) => Some(encrypted),
            Err(e) => {
                tracing::warn!("Failed to encrypt refresh token with Windows Hello: {}", e);
                existing
            }
        }
    }

    #[cfg(not(windows))]
    {
        let _ = refresh_token;
        existing
    }
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

    cached_key_tuples.write().await.set(keys.clone());
    if let Err(e) = agent.set_keys(keys) {
        return sshwarden_agent::ControlResponse::err(&format!("Failed to reload keys: {}", e));
    }
    vault_locked.store(false, std::sync::atomic::Ordering::Relaxed);
    info!("{}", success_msg);
    sshwarden_agent::ControlResponse::ok(success_msg)
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
            if let Some(cache) = cache_opt.filter(|c| c.local_cache_key.native_encrypted.is_some())
            {
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
            if let Some(cache) = cache_opt.filter(|c| c.local_cache_key.hello_encrypted.is_some()) {
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
                            *dc_inner.lock().unwrap() = Some(keys_json);
                            *kh_inner.lock().unwrap() = Some(lck);
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
            let keys_json = match decrypted_cache.lock().unwrap().take() {
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
                        let maybe_lck = kh.lock().unwrap().take();
                        if let Some(lck) = maybe_lck {
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
    let bindings = sshwarden_config::bindings::HostBindingsFile::load().unwrap_or_default();
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
        let mut bindings = sshwarden_config::bindings::HostBindingsFile::load()?;
        for (cipher_id, hosts) in &payload {
            bindings.set_hosts(cipher_id, hosts.clone())?;
        }
        bindings.save()?;

        let keys = load_managed_keys_from_cache().unwrap_or_default();
        sync_managed_ssh_config_inner(&keys, true)?;
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
    let bindings = sshwarden_config::bindings::HostBindingsFile::load().unwrap_or_default();
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

    match response_rx.await {
        Ok(sshwarden_ui::BindHostsResult::Saved { bindings: payload }) => {
            persist_bind_payload(&payload).await?;
            Ok(true)
        }
        Ok(sshwarden_ui::BindHostsResult::Cancelled) => Ok(false),
        Err(_) => anyhow::bail!("Dialog response channel closed unexpectedly"),
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

#[cfg(target_os = "linux")]
async fn cmd_daemon_install() -> anyhow::Result<()> {
    let path = linux_autostart_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("Failed to create autostart directory: {}", parent.display())
        })?;
    }

    let exe = std::env::current_exe().context("Failed to get current executable path")?;
    let content = format!(
        "[Desktop Entry]\nType=Application\nName=SSHWarden\nComment=SSHWarden SSH Agent Daemon\nExec={} daemon\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
        desktop_exec_escape(&exe.display().to_string())
    );
    std::fs::write(&path, content)
        .with_context(|| format!("Failed to write autostart file: {}", path.display()))?;
    info!(
        "SSHWarden XDG autostart file created at: {}",
        path.display()
    );
    Ok(())
}

#[cfg(target_os = "macos")]
async fn cmd_daemon_install() -> anyhow::Result<()> {
    let path = macos_launch_agent_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create LaunchAgents directory: {}",
                parent.display()
            )
        })?;
    }

    let exe = std::env::current_exe().context("Failed to get current executable path")?;
    let working_dir = exe.parent().context("Failed to get executable directory")?;
    let content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>works.earendil.sshwarden</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>daemon</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{}</string>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"#,
        xml_escape(&exe.display().to_string()),
        xml_escape(&working_dir.display().to_string())
    );
    std::fs::write(&path, content)
        .with_context(|| format!("Failed to write LaunchAgent: {}", path.display()))?;
    info!("SSHWarden LaunchAgent created at: {}", path.display());
    Ok(())
}

#[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
async fn cmd_daemon_install() -> anyhow::Result<()> {
    info!("Startup installation is not supported on this platform currently");
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

#[cfg(target_os = "linux")]
async fn cmd_daemon_uninstall() -> anyhow::Result<()> {
    remove_startup_file(linux_autostart_path()?, "SSHWarden XDG autostart file")
}

#[cfg(target_os = "macos")]
async fn cmd_daemon_uninstall() -> anyhow::Result<()> {
    remove_startup_file(macos_launch_agent_path()?, "SSHWarden LaunchAgent")
}

#[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
async fn cmd_daemon_uninstall() -> anyhow::Result<()> {
    info!("Startup uninstallation is not supported on this platform currently");
    Ok(())
}

#[cfg(not(windows))]
fn remove_startup_file(path: std::path::PathBuf, label: &str) -> anyhow::Result<()> {
    match std::fs::remove_file(&path) {
        Ok(()) => info!("{} removed: {}", label, path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!("No {} found, nothing to remove", label)
        }
        Err(e) => anyhow::bail!("Failed to remove {}: {}", path.display(), e),
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_autostart_path() -> anyhow::Result<std::path::PathBuf> {
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".config"))
        })
        .context("HOME or XDG_CONFIG_HOME environment variable not set")?;
    Ok(config_home.join("autostart").join("sshwarden.desktop"))
}

#[cfg(target_os = "macos")]
fn macos_launch_agent_path() -> anyhow::Result<std::path::PathBuf> {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .context("HOME environment variable not set")?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join("works.earendil.sshwarden.plist"))
}

#[cfg(target_os = "linux")]
fn desktop_exec_escape(value: &str) -> String {
    if value.chars().any(|ch| ch.is_whitespace()) {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('\"', "\\\""))
    } else {
        value.to_string()
    }
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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
}
