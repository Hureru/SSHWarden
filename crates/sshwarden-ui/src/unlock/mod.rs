#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub mod hello_crypto;

pub mod native;
pub mod slint_dialog;

pub use slint_dialog::{request_pin_dialog, request_pin_dialog_with_context, show_pin_dialog};
