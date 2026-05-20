use sysinfo::{Pid, System};

use super::models::PeerInfo;

pub fn get_peer_info(peer_pid: u32) -> Result<PeerInfo, String> {
    let mut system = System::new();
    system.refresh_processes(
        sysinfo::ProcessesToUpdate::Some(&[Pid::from_u32(peer_pid)]),
        true,
    );
    if let Some(process) = system.process(Pid::from_u32(peer_pid)) {
        let peer_process_name = match process.name().to_str() {
            Some(name) => name.to_string(),
            None => {
                return Err("Failed to get process name".to_string());
            }
        };

        return Ok(PeerInfo::new(
            peer_pid,
            process.pid().as_u32(),
            peer_process_name,
        ));
    }

    Err("Failed to get process".to_string())
}

/// Read the argv of the process with the given PID.
///
/// Returns `None` if the process is gone, the OS denies access, or any argv
/// entry isn't valid UTF-8. Intended for best-effort UX inference (e.g.
/// extracting the SSH target host) — never for security-relevant decisions.
pub fn get_peer_cmd(peer_pid: u32) -> Option<Vec<String>> {
    let mut system = System::new();
    system.refresh_processes(
        sysinfo::ProcessesToUpdate::Some(&[Pid::from_u32(peer_pid)]),
        true,
    );
    let Some(process) = system.process(Pid::from_u32(peer_pid)) else {
        tracing::debug!(
            peer_pid,
            "Unable to infer SSH target: peer process not found"
        );
        return None;
    };
    let argv = process
        .cmd()
        .iter()
        .map(|s| s.to_str().map(String::from))
        .collect::<Option<Vec<String>>>();
    if argv.is_none() {
        tracing::debug!(
            peer_pid,
            "Unable to infer SSH target: process argv is not valid UTF-8 or is unavailable"
        );
    }
    argv
}
