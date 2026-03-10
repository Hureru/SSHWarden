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

/// Unified UI request type for cross-thread communication.
///
/// The tokio thread sends these requests to the Slint main thread via an mpsc channel.
/// The bridge thread dispatches to the appropriate Slint dialog.
pub enum UIRequest {
    /// Request a PIN input dialog.
    PinDialog {
        response_tx: tokio::sync::oneshot::Sender<Option<String>>,
        validator: std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>,
    },
    /// Request an SSH sign authorization dialog.
    AuthDialog {
        info: SignRequestInfo,
        response_tx: tokio::sync::oneshot::Sender<AuthorizationResult>,
    },
}

/// Initialize platform-specific UI settings.
///
/// On Windows, this sets Per-Monitor DPI Awareness V2 so that Win32
/// dialogs (Windows Hello CredUI) render sharply on high-DPI displays.
/// Slint handles DPI for its own windows automatically.
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
