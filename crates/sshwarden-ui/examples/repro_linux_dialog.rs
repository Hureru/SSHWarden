#![allow(clippy::print_stdout, clippy::unwrap_used)]
//! Temporary repro: show the auth dialog on Linux and keep the event loop
//! alive so the window state can be inspected with `niri msg windows`.

fn main() {
    tracing_subscriber::fmt::init();

    // Mimic the daemon flow: the Slint event loop runs first (no windows),
    // and the dialog is created later via invoke_from_event_loop.
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let (response_tx, _response_rx) = tokio::sync::oneshot::channel();
        slint::invoke_from_event_loop(move || {
            sshwarden_ui::notify::show_auth_dialog(sshwarden_ui::notify::AuthDialogRequest {
                info: sshwarden_ui::SignRequestInfo {
                    key_name: "US-Phoenix-Arm-4c24G".to_string(),
                    process_name: "ssh".to_string(),
                    namespace: None,
                    operation_kind: "ssh_authentication".to_string(),
                    is_forwarding: false,
                },
                response_tx,
            });
        })
        .unwrap();
        // Leak the receiver so the dialog stays up for inspection.
        std::mem::forget(_response_rx);
    });

    slint::run_event_loop_until_quit().unwrap();
}
