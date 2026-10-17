//! Process lifecycle: PID file, daemon detection, background spawn,
//! detach-console, and platform auto-start (startup) integration.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 3c).

use anyhow::Context;
use tracing::info;

/// Resolve the running agent's PID from the PID file, if a live owner exists.
///
/// The machine-local PID file is authoritative. During an upgrade from a build
/// that still wrote the PID under the shared data root, the legacy locations are
/// checked read-only so a new CLI cannot start a second daemon beside one that
/// is still running the old layout.
pub(crate) fn running_agent_pid() -> Option<u32> {
    let mut candidates = Vec::new();
    if let Ok(path) = pid_file_path() {
        candidates.push(path);
    }
    candidates.extend(legacy_pid_file_paths());
    for path in candidates {
        if !pid_file_owner_alive(&path) {
            continue;
        }
        if let Some(pid) = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
        {
            return Some(pid);
        }
    }
    None
}

/// Spawn a detached background agent process (`<exe> run --background`).
pub(crate) fn spawn_background_agent(exe: &std::path::Path) -> anyhow::Result<()> {
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["run", "--background"]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP so the child outlives this
        // CLI invocation and does not share its console.
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    cmd.spawn()
        .with_context(|| format!("Failed to start background agent: {}", exe.display()))?;
    Ok(())
}

/// Get the machine-local runtime state directory (PID file, log file, sockets).
///
/// This is deliberately *not* the shared data directory: the shared root may be
/// a cloud-synced folder (OneDrive/Dropbox), and PID/log/socket state is
/// device-local. See [`sshwarden_config::local_state_dir`].
pub(crate) fn local_state_dir() -> anyhow::Result<std::path::PathBuf> {
    sshwarden_config::local_state_dir()
}

/// Create the machine-local state directory if it does not exist yet.
pub(crate) fn ensure_local_state_dir() -> anyhow::Result<std::path::PathBuf> {
    let dir = local_state_dir()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create local state directory: {}", dir.display()))?;
    Ok(dir)
}

/// Get the PID file path.
pub(crate) fn pid_file_path() -> anyhow::Result<std::path::PathBuf> {
    Ok(local_state_dir()?.join("sshwarden.pid"))
}

/// Get the log file path.
pub(crate) fn log_file_path() -> anyhow::Result<std::path::PathBuf> {
    Ok(local_state_dir()?.join("sshwarden.log"))
}

/// Locations that held the PID file before runtime state moved to
/// [`local_state_dir`] (multi-device runs kept it under `devices/<id>/`).
pub(crate) fn legacy_pid_file_paths() -> Vec<std::path::PathBuf> {
    legacy_state_paths("sshwarden.pid")
}

/// Locations that held the log file before runtime state moved to
/// [`local_state_dir`].
pub(crate) fn legacy_log_file_paths() -> Vec<std::path::PathBuf> {
    legacy_state_paths("sshwarden.log")
}

/// Pre-migration candidates for a runtime file name, de-duplicated and with the
/// current (authoritative) path removed so callers never "migrate" onto themselves.
fn legacy_state_paths(file_name: &str) -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    let current = local_state_dir().ok().map(|dir| dir.join(file_name));
    for dir in [
        sshwarden_config::device_data_dir().ok(),
        sshwarden_config::shared_data_dir().ok(),
    ]
    .into_iter()
    .flatten()
    {
        let candidate = dir.join(file_name);
        if Some(&candidate) == current.as_ref() || paths.contains(&candidate) {
            continue;
        }
        paths.push(candidate);
    }
    paths
}

/// One-time cleanup of runtime files left in the shared data root by older
/// builds, so cloud sync stops mirroring machine-local state.
///
/// A legacy PID file whose recorded process is still alive is left alone: that
/// means an older-version daemon is still running from the old layout.
pub(crate) fn cleanup_legacy_runtime_files() {
    for path in legacy_pid_file_paths() {
        if pid_file_owner_alive(&path) {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => info!("Removed legacy PID file: {}", path.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(
                path = %path.display(),
                error = %e,
                "Failed to remove legacy PID file"
            ),
        }
    }

    // Sockets are recreated at runtime; drop the leftover empty directories.
    for dir in [
        sshwarden_config::device_data_dir()
            .ok()
            .map(|dir| dir.join("run")),
        sshwarden_config::shared_data_dir()
            .ok()
            .map(|dir| dir.join("run")),
    ]
    .into_iter()
    .flatten()
    {
        if dir == local_state_dir().unwrap_or_default().join("run") {
            continue;
        }
        // `remove_dir` only succeeds for empty directories; a non-empty one is
        // left untouched.
        let _ = std::fs::remove_dir(&dir);
    }
}

/// Outcome of [`migrate_legacy_log`], reported by the caller *after* the tracing
/// subscriber is installed (log setup runs before logging exists, so an `info!`
/// inside the migration itself would be dropped).
pub(crate) enum LogMigration {
    /// No pre-migration log was found; nothing to do.
    NotNeeded,
    /// The legacy log was moved to the machine-local location.
    Moved { from: std::path::PathBuf },
    /// The legacy log could not be moved and was left in place (a fresh log was
    /// started instead).
    LeftInPlace { from: std::path::PathBuf },
}

/// Move the pre-migration log to the machine-local location on first daemon
/// start after an upgrade.
///
/// Best effort: on a cross-filesystem move (or any other failure) the legacy
/// file is left in place and a fresh log is started, so log content is never
/// truncated or lost.
pub(crate) fn migrate_legacy_log() -> LogMigration {
    let Ok(new_path) = log_file_path() else {
        return LogMigration::NotNeeded;
    };
    if new_path.exists() {
        return LogMigration::NotNeeded;
    }
    for legacy in legacy_log_file_paths() {
        if !legacy.exists() {
            continue;
        }
        if let Some(parent) = new_path.parent() {
            if std::fs::create_dir_all(parent).is_err() {
                return LogMigration::LeftInPlace { from: legacy };
            }
        }
        return match std::fs::rename(&legacy, &new_path) {
            Ok(()) => LogMigration::Moved { from: legacy },
            Err(_) => LogMigration::LeftInPlace { from: legacy },
        };
    }
    LogMigration::NotNeeded
}

/// Return true if `path` holds a PID whose recorded process is still alive.
pub(crate) fn pid_file_owner_alive(path: &std::path::Path) -> bool {
    let pid_str = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let pid: u32 = match pid_str.trim().parse() {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Verify the PID is not just alive but actually our daemon: a recycled PID
    // (after a crash without clean shutdown) could belong to an unrelated process
    // and would otherwise falsely block a healthy restart.
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    match sys.process(sysinfo::Pid::from_u32(pid)) {
        Some(proc) => process_is_sshwarden(proc),
        None => false,
    }
}

/// Confirm a process is this SSHWarden binary, not an unrelated process that
/// recycled the PID. Prefer an exact exe-path match; fall back to the executable
/// file name when `exe()` is empty/restricted (common on macOS) or the daemon was
/// launched from a since-moved binary.
pub(crate) fn process_is_sshwarden(proc: &sysinfo::Process) -> bool {
    let self_exe = std::env::current_exe().ok();
    if let (Some(proc_exe), Some(self_path)) = (proc.exe(), self_exe.as_deref()) {
        if proc_exe == self_path {
            return true;
        }
    }
    match self_exe.as_deref().and_then(|p| p.file_name()) {
        Some(name) => proc.name() == name,
        None => false,
    }
}

/// Check if daemon is already running by reading PID file and checking process.
pub(crate) fn is_daemon_running() -> bool {
    let live = |path: &std::path::Path| path.exists() && pid_file_owner_alive(path);
    if pid_file_path().map(|p| live(&p)).unwrap_or(false) {
        return true;
    }
    // Upgrade path: a daemon started by an older build may still own the PID file
    // in the shared data directory.
    legacy_pid_file_paths().iter().any(|p| live(p))
}

/// Atomically claim the singleton PID file (RT-02). Returns `Ok(true)` if this
/// process is now the owner, `Ok(false)` if a live daemon already owns it.
///
/// Replaces the previous check-then-write (which let two near-simultaneous
/// starters both pass the `is_daemon_running()` check). `create_new` is an atomic
/// O_EXCL/CREATE_NEW open, so exactly one racing process wins the create. A
/// leftover file whose owner is gone (crash without clean shutdown) is treated as
/// stale and reclaimed.
pub(crate) fn claim_pid_file() -> anyhow::Result<bool> {
    use std::io::Write;
    let path = pid_file_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("Failed to create PID file directory: {}", parent.display())
        })?;
    }
    loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                // `create_new` guarantees we won this race, but an older build
                // still running from the shared data root would not be visible in
                // the machine-local PID path. Yield to it so two daemons cannot
                // coexist across the storage-layout upgrade.
                if let Some(legacy) = legacy_pid_file_paths()
                    .into_iter()
                    .find(|p| p.exists() && pid_file_owner_alive(p))
                {
                    drop(f);
                    let _ = std::fs::remove_file(&path);
                    tracing::info!(
                        legacy = %legacy.display(),
                        "A daemon from an older layout is still running; not starting a second one"
                    );
                    return Ok(false);
                }
                f.write_all(std::process::id().to_string().as_bytes())
                    .with_context(|| format!("Failed to write PID file: {}", path.display()))?;
                // We are the sole owner: it is now safe to drop stale legacy state
                // so cloud sync stops mirroring it.
                cleanup_legacy_runtime_files();
                return Ok(true);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if pid_file_owner_alive(&path) {
                    return Ok(false);
                }
                // Stale: the recorded owner is gone. Remove and retry the atomic
                // create; if another starter wins in between, the next iteration
                // sees a live owner and yields.
                match std::fs::remove_file(&path) {
                    Ok(()) => continue,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => {
                        return Err(e).with_context(|| {
                            format!("Failed to remove stale PID file: {}", path.display())
                        })
                    }
                }
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("Failed to create PID file: {}", path.display()))
            }
        }
    }
}

/// Remove pid file on shutdown.
pub(crate) fn remove_pid_file() {
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
pub(crate) fn detach_console() {
    use windows::Win32::System::Console::FreeConsole;

    unsafe {
        let _ = FreeConsole();
    }
}

/// Get the path to the startup shortcut in the user's Startup folder.
#[cfg(windows)]
pub(crate) fn startup_shortcut_path() -> anyhow::Result<std::path::PathBuf> {
    let startup_dir = std::env::var("APPDATA").context("APPDATA environment variable not set")?;
    let startup_dir = std::path::Path::new(&startup_dir)
        .join("Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    Ok(startup_dir.join("SSHWarden.lnk"))
}

/// Install startup shortcut in the user's Startup folder.
#[cfg(windows)]
pub(crate) async fn cmd_daemon_install() -> anyhow::Result<()> {
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
         $s.Arguments = 'run --background'; \
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
pub(crate) async fn cmd_daemon_install() -> anyhow::Result<()> {
    let path = linux_autostart_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("Failed to create autostart directory: {}", parent.display())
        })?;
    }

    let exe = std::env::current_exe().context("Failed to get current executable path")?;
    let content = format!(
        "[Desktop Entry]\nType=Application\nName=SSHWarden\nComment=SSHWarden SSH Agent Daemon\nExec={} run --background\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
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
pub(crate) async fn cmd_daemon_install() -> anyhow::Result<()> {
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
        <string>run</string>
        <string>--background</string>
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
pub(crate) async fn cmd_daemon_install() -> anyhow::Result<()> {
    info!("Startup installation is not supported on this platform currently");
    Ok(())
}

/// Remove startup shortcut from the user's Startup folder.
#[cfg(windows)]
pub(crate) async fn cmd_daemon_uninstall() -> anyhow::Result<()> {
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
pub(crate) async fn cmd_daemon_uninstall() -> anyhow::Result<()> {
    remove_startup_file(linux_autostart_path()?, "SSHWarden XDG autostart file")
}

#[cfg(target_os = "macos")]
pub(crate) async fn cmd_daemon_uninstall() -> anyhow::Result<()> {
    remove_startup_file(macos_launch_agent_path()?, "SSHWarden LaunchAgent")
}

#[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
pub(crate) async fn cmd_daemon_uninstall() -> anyhow::Result<()> {
    info!("Startup uninstallation is not supported on this platform currently");
    Ok(())
}

#[cfg(not(windows))]
pub(crate) fn remove_startup_file(path: std::path::PathBuf, label: &str) -> anyhow::Result<()> {
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
pub(crate) fn linux_autostart_path() -> anyhow::Result<std::path::PathBuf> {
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".config"))
        })
        .context("HOME or XDG_CONFIG_HOME environment variable not set")?;
    Ok(config_home.join("autostart").join("sshwarden.desktop"))
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_launch_agent_path() -> anyhow::Result<std::path::PathBuf> {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .context("HOME environment variable not set")?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join("works.earendil.sshwarden.plist"))
}

#[cfg(target_os = "linux")]
pub(crate) fn desktop_exec_escape(value: &str) -> String {
    if value.chars().any(|ch| ch.is_whitespace()) {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('\"', "\\\""))
    } else {
        value.to_string()
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
