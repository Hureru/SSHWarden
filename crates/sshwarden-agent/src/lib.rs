pub mod agent;
pub mod control;
pub mod peerinfo;
mod request_parser;

#[cfg_attr(target_os = "windows", path = "windows.rs")]
#[cfg_attr(target_os = "macos", path = "unix.rs")]
#[cfg_attr(target_os = "linux", path = "unix.rs")]
mod platform_ssh_agent;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod peercred_unix_listener_stream;

#[cfg(windows)]
pub mod named_pipe_listener_stream;

pub use agent::{SshAgentUIRequest, SshWardenAgent, SshWardenKey};
pub use control::{ControlAction, ControlRequest, ControlResponse, CONTROL_PIPE_NAME};
