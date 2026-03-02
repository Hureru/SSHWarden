use tracing::info;

slint::slint! {
    import { Button, VerticalBox, LineEdit, Palette } from "std-widgets.slint";

    export component PinDialog inherits Window {
        title: "SSHWarden - Unlock Vault";
        icon: @image-url("../../assets/shhwarden-32x32.png");
        width: 380px;
        height: 180px;
        background: Palette.background;
        always-on-top: true;

        forward-focus: pin-input;

        callback submit-pin(string);
        callback cancel();

        VerticalBox {
            padding: 24px;
            spacing: 16px;

            Text {
                text: "Enter PIN to unlock SSHWarden";
                color: Palette.foreground;
                font-size: 14px;
            }

            pin-input := LineEdit {
                input-type: password;
                font-size: 16px;
                accepted => { root.submit-pin(self.text); }
            }

            HorizontalLayout {
                alignment: end;
                spacing: 12px;

                Button {
                    text: "Cancel";
                    clicked => { root.cancel(); }
                }

                Button {
                    text: "Unlock";
                    primary: true;
                    clicked => { root.submit-pin(pin-input.text); }
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

/// Show a PIN dialog on the Slint event loop thread.
///
/// This must be called from within the Slint event loop (e.g. via `slint::invoke_from_event_loop`).
/// The result is sent back through the provided oneshot channel.
pub fn show_pin_dialog(response_tx: tokio::sync::oneshot::Sender<Option<String>>) {
    let dialog = match PinDialog::new() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create PIN dialog");
            let _ = response_tx.send(None);
            return;
        }
    };

    // Shared mutable cell for the oneshot sender (consumed once on submit/cancel/close/show-fail)
    let tx_cell = std::rc::Rc::new(std::cell::RefCell::new(Some(response_tx)));
    let tx_for_show_error = tx_cell.clone();

    let weak = dialog.as_weak();
    let tx = tx_cell.clone();
    dialog.on_submit_pin(move |pin| {
        let pin_str = pin.to_string();
        if let Some(sender) = tx.borrow_mut().take() {
            let _ = sender.send(if pin_str.is_empty() { None } else { Some(pin_str) });
        }
        if let Some(d) = weak.upgrade() {
            let _ = d.hide();
        }
    });

    let weak = dialog.as_weak();
    let tx = tx_cell.clone();
    dialog.on_cancel(move || {
        if let Some(sender) = tx.borrow_mut().take() {
            let _ = sender.send(None);
        }
        if let Some(d) = weak.upgrade() {
            let _ = d.hide();
        }
    });

    let tx = tx_cell;
    dialog.window().on_close_requested(move || {
        if let Some(sender) = tx.borrow_mut().take() {
            let _ = sender.send(None);
        }
        slint::CloseRequestResponse::HideWindow
    });

    if let Err(e) = dialog.show() {
        tracing::error!(error = %e, "Failed to show PIN dialog");
        if let Some(sender) = tx_for_show_error.borrow_mut().take() {
            let _ = sender.send(None);
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
/// Returns `Some(pin)` if the user entered a PIN, or `None` if cancelled.
pub async fn request_pin_dialog(
    request_tx: &tokio::sync::mpsc::Sender<crate::UIRequest>,
) -> Option<String> {
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();

    let request = crate::UIRequest::PinDialog { response_tx };

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

