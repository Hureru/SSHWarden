pub mod notify;
pub mod unlock;

/// Information about an SSH sign request, used to display to the user.
#[derive(Debug, Clone)]
pub struct SignRequestInfo {
    pub key_name: String,
    pub process_name: String,
    pub namespace: Option<String>,
    pub is_forwarding: bool,
}

/// Result of an authorization prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationResult {
    Approved,
    Denied,
    Timeout,
}

/// Initialize platform-specific UI settings.
///
/// On Windows, this sets Per-Monitor DPI Awareness V2 so that Win32
/// dialogs (CredUI, MessageBox) render sharply on high-DPI displays.
/// Must be called before any UI prompts are shown.
#[cfg(windows)]
pub fn init() {
    use windows::Win32::UI::HiDpi::{
        SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
    };
    unsafe {
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }
}

/// Initialize platform-specific UI settings (no-op on non-Windows).
#[cfg(not(windows))]
pub fn init() {}
