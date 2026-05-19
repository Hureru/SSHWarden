pub mod bind_hosts;
pub mod notify;
pub mod unlock;

use std::collections::BTreeMap;

/// Information about an SSH sign request, used to display to the user.
#[derive(Debug, Clone)]
pub struct SignRequestInfo {
    pub key_name: String,
    pub process_name: String,
    pub namespace: Option<String>,
    pub operation_kind: String,
    pub is_forwarding: bool,
}

/// Context shown when an unlock is caused by a signing request.
#[derive(Debug, Clone)]
pub struct UnlockRequestContext {
    pub key_name: String,
    pub process_name: String,
    pub operation_kind: String,
    pub is_forwarding: bool,
}

/// Result of an authorization prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationResult {
    Approved,
    Denied,
    Timeout,
    /// User clicked the "Bind this key…" secondary action. The main loop is
    /// expected to follow up with a [`UIRequest::BindHostsDialog`] and, on
    /// successful save, treat the original sign request as approved.
    BindRequested,
}

/// One key shown in the host-binding dialog.
#[derive(Debug, Clone)]
pub struct BindHostsKeyEntry {
    pub cipher_id: String,
    pub name: String,
    /// Current host patterns bound to this key (may be empty).
    pub hosts: Vec<String>,
}

/// Request payload for [`UIRequest::BindHostsDialog`].
#[derive(Debug, Clone)]
pub struct BindHostsRequest {
    /// All vault keys available for binding.
    pub keys: Vec<BindHostsKeyEntry>,
    /// Pre-select this `cipher_id` if present (otherwise first entry).
    pub initial_selection: Option<String>,
    /// Pre-fill this host pattern in the "Add" field for the initial key.
    pub prefill_host: Option<String>,
    /// If true, the primary button reads "Save & Approve" — used when this
    /// dialog was triggered from an in-flight sign authorization.
    pub approve_on_save: bool,
}

/// Result returned by the host-binding dialog.
#[derive(Debug, Clone)]
pub enum BindHostsResult {
    /// User saved. The map contains the final desired state for each key the
    /// user touched: `cipher_id -> hosts`. An empty vec means clear that key.
    /// Keys not present in the map were not modified.
    Saved { bindings: BTreeMap<String, Vec<String>> },
    /// User cancelled or closed the dialog.
    Cancelled,
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
        context: Option<UnlockRequestContext>,
    },
    /// Request an SSH sign authorization dialog.
    AuthDialog {
        info: SignRequestInfo,
        response_tx: tokio::sync::oneshot::Sender<AuthorizationResult>,
    },
    /// Request the host-binding management dialog.
    BindHostsDialog {
        request: BindHostsRequest,
        response_tx: tokio::sync::oneshot::Sender<BindHostsResult>,
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
