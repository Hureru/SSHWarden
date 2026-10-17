use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use tracing::info;

mod bindings_cli;
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
mod ui;
mod unlock;

use cli::{Cli, Commands, KeysAction, SshConfigAction, StartupAction, UnlockMethod};
use commands::env::cmd_env;
use commands::keys::cmd_keys;
use commands::login::{cmd_login, cmd_set_pin, prompt_password};
use commands::sshconfig::{
    cmd_sshcfg_show, cmd_sshcfg_status, cmd_sshcfg_uninstall, cmd_sshcfg_write,
};
use control::{cmd_control, cmd_restart, cmd_stop};
use daemon::run_foreground;
#[cfg(windows)]
use process::detach_console;
use process::{
    claim_pid_file, cmd_daemon_install, cmd_daemon_uninstall, ensure_local_state_dir,
    log_file_path, migrate_legacy_log, remove_pid_file, LogMigration,
};
use ssh_target::{parse_ssh_target, SSH_VALUE_TAKING_FLAGS};
use status::{cmd_doctor, cmd_status};

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
        // PID/log/sockets live in the machine-local state directory, never in the
        // (possibly cloud-synced) shared data root.
        ensure_local_state_dir()?;
        let log_migration = migrate_legacy_log();
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

        // Reported only now: log setup necessarily runs before the subscriber
        // exists, so the migration itself cannot log.
        match log_migration {
            LogMigration::NotNeeded => {}
            LogMigration::Moved { from } => info!(
                "Moved legacy log {} -> {}",
                from.display(),
                log_path.display()
            ),
            LogMigration::LeftInPlace { from } => tracing::warn!(
                "Could not move legacy log {} to {}; it was left in place and a fresh log started",
                from.display(),
                log_path.display()
            ),
        }
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

/// True when a Remembered Device exists on disk (envelope Local Key Cache) —
/// the offline equivalent of run_foreground's startup check.
fn has_remembered_device_on_disk() -> bool {
    matches!(
        sshwarden_config::cache::LocalKeyCacheFile::load(),
        Ok(Some(_))
    )
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::path_util::{ensure_managed_ssh_config_path_is_safe, paths_equivalent_for_safety};
    use crate::sshconfig::{
        import_host_bindings_from_managed_file, remove_sshwarden_include_line,
        write_sshwarden_include_line, ManagedKey,
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
