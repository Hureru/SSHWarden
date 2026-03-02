#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub mod hello_crypto;

#[cfg(windows)]
pub use self::windows::prompt_windows_hello;

pub mod slint_dialog;

pub use slint_dialog::{show_pin_dialog, request_pin_dialog};

#[cfg(not(windows))]
mod fallback;

#[cfg(not(windows))]
pub use fallback::prompt_windows_hello;

/// Result of an unlock attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockResult {
    /// User successfully verified identity.
    Verified,
    /// User cancelled the prompt.
    Cancelled,
    /// The unlock method is not available on this device.
    NotAvailable,
    /// Verification failed.
    Failed,
}
