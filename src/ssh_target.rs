//! SSH client argv parsing helpers (used for best-effort host inference).
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 1).

/// Short single-character SSH flags that consume the next argv element as a value.
///
/// Reference: `ssh(1)` OPTIONS section. We intentionally over-approximate to be
/// safe — any unknown flag is treated as value-taking only if the character
/// matches this set.
pub(crate) const SSH_VALUE_TAKING_FLAGS: &str = "BbcDEeFIiJLlmOopQRSWw";

pub(crate) fn parse_ssh_target(arg: &str) -> String {
    match arg.rsplit_once('@') {
        Some((_, host)) => host.to_string(),
        None => arg.to_string(),
    }
}
