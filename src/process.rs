//! Process lifecycle: PID file, daemon detection, background spawn,
//! detach-console, and platform auto-start (startup) integration.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 3c).

use anyhow::Context;
use tracing::info;

/// Resolve the running agent's PID from the PID file, if a live owner exists.
pub(crate) fn running_agent_pid() -> Option<u32> {
    let path = pid_file_path().ok()?;
    if !pid_file_owner_alive(&path) {
        return None;
    }
    std::fs::read_to_string(&path).ok()?.trim().parse().ok()
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

/// Get the runtime data directory for SSHWarden (same as exe directory for portability).
pub(crate) fn data_dir() -> anyhow::Result<std::path::PathBuf> {
    sshwarden_config::device_data_dir()
}

/// Get the PID file path.
pub(crate) fn pid_file_path() -> anyhow::Result<std::path::PathBuf> {
    Ok(data_dir()?.join("sshwarden.pid"))
}

/// Get the log file path.
pub(crate) fn log_file_path() -> anyhow::Result<std::path::PathBuf> {
    Ok(data_dir()?.join("sshwarden.log"))
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
    match pid_file_path() {
        Ok(p) => p.exists() && pid_file_owner_alive(&p),
        Err(_) => false,
    }
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
                f.write_all(std::process::id().to_string().as_bytes())
                    .with_context(|| format!("Failed to write PID file: {}", path.display()))?;
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
