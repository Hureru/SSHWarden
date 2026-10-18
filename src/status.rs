//! `status` and `doctor` commands: legible/machine-readable status output and
//! diagnostics (with safe `--fix` repairs).
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 5b).

use crate::commands::login::create_client;
use crate::path_util::{create_parent_dir, write_private_file};
use crate::sshconfig::{
    key_selector_dir, managed_sshwarden_include_path, user_ssh_config_path,
    write_sshwarden_include_line,
};
use crate::{has_remembered_device_on_disk, out_line};
/// `status`: a legible one-screen summary plus a suggested next step. With
/// `--json`, prints the agent's machine-readable status. Works even when the
/// agent is down (falls back to local file inspection).
///
/// Both views come from one model (see `status_report`), and both stay honestly
/// incomplete when a fact cannot be observed (agent down, no session, hub never
/// connected) instead of printing a healthy-looking default.
pub(crate) async fn cmd_status(json: bool) -> anyhow::Result<()> {
    // Machine-local state never sits in the (possibly cloud-synced) data dir, so
    // point users at the real log location — including when the agent is up,
    // which is exactly when they go looking for it.
    let local_state_dir = sshwarden_config::local_state_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unresolved>".to_string());
    let log_path = crate::process::log_file_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unresolved>".to_string());
    let device_remembered = has_remembered_device_on_disk();

    let details = match sshwarden_agent::control::send_control_command("status-json").await {
        Ok(response) => match response.details {
            Some(details) => details,
            None => serde_json::to_value(&response)?,
        },
        Err(_) => {
            // Agent unreachable: emit the same shape with nothing known.
            if json {
                out_line(serde_json::to_string_pretty(
                    &crate::status_report::offline_details_json(
                        device_remembered,
                        &log_path,
                        &local_state_dir,
                    ),
                )?);
                return Ok(());
            }
            for line in crate::status_report::StatusReport::offline(device_remembered, log_path)
                .render_lines()
            {
                out_line(line);
            }
            return Ok(());
        }
    };

    let missing = crate::status_report::missing_detail_keys(&details);
    if !missing.is_empty() {
        // A live daemon answered with fewer keys than the schema documents:
        // surface it in the log instead of letting a script find out the hard way.
        tracing::debug!(?missing, "status-json is missing documented keys");
    }

    if json {
        out_line(serde_json::to_string_pretty(&details)?);
        return Ok(());
    }

    for line in crate::status_report::StatusReport::from_details(&details).render_lines() {
        out_line(line);
    }
    Ok(())
}

#[derive(serde::Serialize)]
pub(crate) struct DoctorCheck {
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
pub(crate) async fn fetch_status_details_for_doctor() -> anyhow::Result<serde_json::Value> {
    let response = sshwarden_agent::control::send_control_command("status-json").await?;
    Ok(response
        .details
        .clone()
        .unwrap_or_else(|| serde_json::to_value(&response).unwrap_or_default()))
}

#[cfg(windows)]
pub(crate) fn windows_openssh_pipe_exists() -> bool {
    std::path::Path::new(r"\\.\pipe\openssh-ssh-agent").exists()
}

pub(crate) fn count_key_selector_files() -> anyhow::Result<(std::path::PathBuf, usize)> {
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

/// Join paths into a single comma-separated, human-readable list.
fn describe_paths(paths: &[std::path::PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) async fn cmd_doctor(
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
        if has_local_key_cache {
            checks.push(DoctorCheck::ok(
                "local_key_cache",
                "Envelope Local Key Cache is present",
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
                    "Local Key Cache is out of date because the refresh after a sync failed: {}",
                    notification
                        .get("stale_cache_error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown refresh error")
                ),
            ));
        } else {
            checks.push(DoctorCheck::ok(
                "local_key_cache.stale",
                "Local Key Cache is not marked out of date",
            ));
        }

        let notification_health =
            crate::status_report::json_health_label(&notification, authenticated);
        match notification_state {
            "running" => checks.push(DoctorCheck::ok(
                "notification",
                format!(
                    "Notification hub {} ({})",
                    notification_health,
                    notification
                        .get("url")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown URL")
                ),
            )),
            // Without an API session the hub has nothing to subscribe with, so
            // this is the expected state rather than a fault to fix.
            "not_started" if !authenticated => checks.push(DoctorCheck::ok(
                "notification",
                "Notification hub not started yet: no Bitwarden API session (unlock or login first)",
            )),
            "not_started" => checks.push(DoctorCheck::warn(
                "notification",
                "Notification hub has not started even though a Bitwarden API session exists; live sync is not running",
            )),
            _ => checks.push(DoctorCheck::warn(
                "notification",
                format!("Notification hub {notification_health}"),
            )),
        }
    }

    // Machine-local runtime state (PID file, log, sockets) is deliberately kept
    // out of the shared data dir: that dir may be cloud-synced, where PID/log
    // churn is pure noise and a foreign PID can confuse the liveness check.
    // Report the real paths (users look for sshwarden.log beside the exe) and any
    // leftovers from the pre-migration layout under the shared root.
    match crate::process::local_state_dir() {
        Ok(dir) => {
            let log = crate::process::log_file_path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<unknown>".to_string());
            let legacy_remaining = || {
                crate::process::legacy_pid_file_paths()
                    .into_iter()
                    .chain(crate::process::legacy_log_file_paths())
                    .filter(|path| path.exists())
                    .collect::<Vec<_>>()
            };
            let legacy = legacy_remaining();
            let base = format!(
                "PID/log/socket state lives in {} (log: {}); machine-local, never cloud-synced",
                dir.display(),
                log
            );
            if legacy.is_empty() {
                checks.push(DoctorCheck::ok("runtime_state", base));
            } else if fix {
                crate::process::cleanup_legacy_runtime_files();
                crate::process::migrate_legacy_log();
                let still_there = legacy_remaining();
                if still_there.is_empty() {
                    checks.push(DoctorCheck::ok(
                        "runtime_state",
                        format!("{base}; removed legacy runtime file(s) from the shared data dir"),
                    ));
                } else {
                    checks.push(DoctorCheck::warn(
                        "runtime_state",
                        format!(
                            "{base}; legacy runtime file(s) could not be cleaned up: {}",
                            describe_paths(&still_there)
                        ),
                    ));
                }
            } else {
                checks.push(DoctorCheck::warn(
                    "runtime_state",
                    format!(
                        "{base}; legacy runtime file(s) are still in the shared data dir: {} — run `sshwarden doctor --fix` to move/remove them",
                        describe_paths(&legacy)
                    ),
                ));
            }
        }
        Err(e) => checks.push(DoctorCheck::warn(
            "runtime_state",
            format!("Could not determine the machine-local state directory: {e}"),
        )),
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
                        Ok(sock) if path.as_path() == std::path::Path::new(&sock) => {
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
                        "Managed SSH config does not contain Host-specific IdentityFile + IdentitiesOnly yes rules; run `sshwarden ssh-config show` to print it or `sshwarden ssh-config write` to regenerate the managed include",
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
                    if let Err(e) = create_parent_dir(parent) {
                        checks.push(DoctorCheck::warn(
                            "doctor.fix.ssh_config_dir",
                            format!(
                                "Failed to create managed SSH config directory {}: {e}",
                                parent.display()
                            ),
                        ));
                    }
                }
                if !include_path.exists() {
                    let managed = "# SSHWarden managed key selector snippets\n# Run `sshwarden ssh-config write` to populate this from your bound keys.\n";
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
                        "{} does not include SSHWarden managed config; run `sshwarden ssh-config write` if desired",
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
