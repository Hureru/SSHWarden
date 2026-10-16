//! Shell-quoting helpers for `sshwarden env` output.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 1).

pub(crate) fn shell_single_quote(value: &str) -> String {
    value.replace('\'', "'\\''")
}

pub(crate) fn powershell_single_quote(value: &str) -> String {
    value.replace('\'', "''")
}
