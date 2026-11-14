// Vendored from https://github.com/bitwarden/bitwarden-russh at a641316 (upstream is
// deprecated). Kept close to upstream, so its lints are not chased here; the
// SSHWarden change is `Agent::identities` in `ssh_agent.rs`.
#![allow(warnings, clippy::all)]

pub mod encoding;
pub mod msg;
pub mod session_bind;
pub mod ssh_agent;
