use tracing::info;

slint::slint! {
    import { Button, VerticalBox, LineEdit, Palette } from "std-widgets.slint";

    export component PinDialog inherits Window {
        title: "SSHWarden - Unlock Vault";
        icon: @image-url("../../assets/Square44x44Logo.png");
        width: 380px;
        height: 195px;
        background: Palette.background;
        always-on-top: true;

        forward-focus: pin-input;

        in-out property <bool> show-error: false;
        in-out property <length> shake-offset: 0px;
        in-out property <string> error-message: "PIN cannot be empty";
        in-out property <bool> verifying: false;
        in-out property <string> pin-text: "";

        callback submit-pin(string);
        callback cancel();
        callback empty-submit();

        function try-submit() {
            if root.verifying { return; }
            if pin-input.text == "" {
                root.error-message = "PIN cannot be empty";
                show-error = true;
                root.empty-submit();
            } else {
                show-error = false;
                root.submit-pin(pin-input.text);
            }
        }

        VerticalBox {
            padding: 24px;
            spacing: 12px;

            Text {
                text: "Enter PIN to unlock SSHWarden";
                color: Palette.foreground;
                font-size: 14px;
            }

            VerticalLayout {
                spacing: 4px;

                Rectangle {
                    clip: false;
                    height: pin-input.preferred-height;

                    pin-input := LineEdit {
                        text <=> root.pin-text;
                        x: root.shake-offset;
                        width: parent.width;
                        input-type: password;
                        font-size: 16px;
                        enabled: !root.verifying;
                        edited => {
                            root.show-error = false;
                        }
                        accepted => { root.try-submit(); }
                    }
                }

                Text {
                    text: root.show-error ? root.error-message : "";
                    color: #e74c3c;
                    font-size: 12px;
                    height: 16px;
                }
            }

            HorizontalLayout {
                alignment: end;
                spacing: 12px;

                Button {
                    text: "Cancel";
                    clicked => { root.cancel(); }
                }

                Button {
                    text: root.verifying ? "Verifying..." : "Unlock";
                    primary: true;
                    enabled: !root.verifying;
                    clicked => { root.try-submit(); }
                }
            }
        }
    }
}

fn center_and_focus_dialog(dialog: &PinDialog) {
    let window = dialog.window();
    slint_center_win::center_window(window);
    use slint::winit_030::WinitWindowAccessor;
    let _ = window.with_winit_window(|winit_window: &slint::winit_030::winit::window::Window| {
        winit_window.focus_window();
        None::<()>
    });
}

fn trigger_shake(weak: &slint::Weak<PinDialog>) {
    let offsets: &[f32] = &[10.0, -8.0, 6.0, -4.0, 2.0, 0.0];
    for (i, &offset) in offsets.iter().enumerate() {
        let w = weak.clone();
        slint::Timer::single_shot(
            std::time::Duration::from_millis(i as u64 * 60),
            move || {
                if let Some(d) = w.upgrade() {
                    d.set_shake_offset(offset);
                }
            },
        );
    }
}

/// Show a PIN dialog on the Slint event loop thread.
///
/// This must be called from within the Slint event loop (e.g. via `slint::invoke_from_event_loop`).
/// The validator closure is invoked in a background thread to avoid blocking the UI.
/// On success, the PIN is sent back through the oneshot channel and the dialog closes.
/// On failure, the dialog stays open with an error message and shake animation.
pub fn show_pin_dialog(
    response_tx: tokio::sync::oneshot::Sender<Option<String>>,
    validator: std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>,
) {
    let dialog = match PinDialog::new() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create PIN dialog");
            let _ = response_tx.send(None);
            return;
        }
    };

    // Shared sender: Arc<Mutex> so it can be accessed from invoke_from_event_loop
    let tx_cell = std::sync::Arc::new(std::sync::Mutex::new(Some(response_tx)));
    let tx_for_show_error = tx_cell.clone();

    // Shake animation on empty submit
    let weak = dialog.as_weak();
    dialog.on_empty_submit(move || {
        trigger_shake(&weak);
    });

    // Submit PIN: spawn validation in background thread
    let weak = dialog.as_weak();
    let tx = tx_cell.clone();
    dialog.on_submit_pin(move |pin| {
        let pin_str = pin.to_string();

        // Set verifying state (disables input + changes button text)
        if let Some(d) = weak.upgrade() {
            d.set_verifying(true);
        }

        let validator = validator.clone();
        let tx = tx.clone();
        let weak = weak.clone();

        std::thread::spawn(move || {
            let is_valid = validator(&pin_str);

            let _ = slint::invoke_from_event_loop(move || {
                if is_valid {
                    if let Ok(mut guard) = tx.lock() {
                        if let Some(sender) = guard.take() {
                            let _ = sender.send(Some(pin_str));
                        }
                    }
                    if let Some(d) = weak.upgrade() {
                        let _ = d.hide();
                    }
                } else {
                    if let Some(d) = weak.upgrade() {
                        d.set_pin_text("".into());
                        d.set_error_message("Incorrect PIN, please try again".into());
                        d.set_show_error(true);
                        d.set_verifying(false);
                    }
                    trigger_shake(&weak);
                }
            });
        });
    });

    let weak = dialog.as_weak();
    let tx = tx_cell.clone();
    dialog.on_cancel(move || {
        if let Ok(mut guard) = tx.lock() {
            if let Some(sender) = guard.take() {
                let _ = sender.send(None);
            }
        }
        if let Some(d) = weak.upgrade() {
            let _ = d.hide();
        }
    });

    let tx = tx_cell;
    dialog.window().on_close_requested(move || {
        if let Ok(mut guard) = tx.lock() {
            if let Some(sender) = guard.take() {
                let _ = sender.send(None);
            }
        }
        slint::CloseRequestResponse::HideWindow
    });

    if let Err(e) = dialog.show() {
        tracing::error!(error = %e, "Failed to show PIN dialog");
        if let Ok(mut guard) = tx_for_show_error.lock() {
            if let Some(sender) = guard.take() {
                let _ = sender.send(None);
            }
        }
    } else {
        let weak = dialog.as_weak();
        slint::Timer::single_shot(std::time::Duration::from_millis(30), move || {
            if let Some(d) = weak.upgrade() {
                center_and_focus_dialog(&d);
            }
        });
    }
}

/// Request a PIN dialog from the tokio async context.
///
/// Sends a request to the Slint main thread and awaits the result.
/// The validator is called in a background thread for each PIN attempt.
/// Returns `Some(pin)` if validation succeeded, or `None` if cancelled.
pub async fn request_pin_dialog(
    request_tx: &tokio::sync::mpsc::Sender<crate::UIRequest>,
    validator: std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>,
) -> Option<String> {
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();

    let request = crate::UIRequest::PinDialog {
        response_tx,
        validator,
    };

    if request_tx.send(request).await.is_err() {
        tracing::error!("Failed to send PIN dialog request to UI thread");
        return None;
    }

    info!("Waiting for PIN dialog response...");

    match tokio::time::timeout(std::time::Duration::from_secs(300), response_rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => {
            tracing::error!("PIN dialog response channel closed unexpectedly");
            None
        }
        Err(_) => {
            tracing::error!("PIN dialog timed out after 300s");
            None
        }
    }
}
