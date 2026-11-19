use tracing::info;

slint::slint! {
    import { Button, LineEdit, Palette } from "std-widgets.slint";
    import { Theme, TipButton } from "../theme.slint";

    export component PinDialog inherits Window {
        title: "SSHWarden - Unlock Vault";
        icon: @image-url("../../assets/Square44x44Logo.png");
        default-font-family: Theme.font-family;
        width: 380px;
        // Fixed size, sized to the content: also what makes tiling compositors float it.
        height: content.preferred-height;
        background: Palette.background;
        always-on-top: true;

        forward-focus: pin-input;

        in-out property <bool> show-error: false;
        in-out property <length> shake-offset: 0px;
        in-out property <string> error-message: "PIN cannot be empty";
        in-out property <bool> verifying: false;
        in-out property <string> pin-text: "";
        in property <string> context-text: "";
        out property <length> content-height: content.preferred-height;

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

        // Parent of the content, and capturing: Esc cancels even while typing.
        // It never takes the focus itself: a click beside the field leaves it there.
        FocusScope {
            focus-on-tab-navigation: false;
            focus-on-click: false;
            capture-key-pressed(event) => {
                if event.text == Key.Escape {
                    root.cancel();
                    return accept;
                }
                return reject;
            }

            content := VerticalLayout {
                padding: Theme.pad;
                spacing: Theme.gap;

                Text {
                    text: "Enter PIN to unlock SSHWarden";
                    color: Palette.foreground;
                    font-size: Theme.title-size;
                    font-weight: 600;
                }

                if context-text != "": Text {
                    text: context-text;
                    color: Theme.muted;
                    font-size: Theme.body-size;
                    wrap: word-wrap;
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
                            accessible-label: "PIN";
                            accessible-description: root.show-error ? root.error-message : "";
                            edited => {
                                root.show-error = false;
                            }
                            accepted => { root.try-submit(); }
                        }
                    }

                    // Always one line high, so the window keeps its height.
                    HorizontalLayout {
                        height: 16px;

                        if root.show-error: Text {
                            text: root.error-message;
                            color: Theme.error;
                            font-size: Theme.small-size;
                        }
                    }
                }

                HorizontalLayout {
                    alignment: end;
                    spacing: 8px;

                    TipButton {
                        text: "Cancel";
                        shortcut: "Esc";
                        clicked => { root.cancel(); }
                    }

                    TipButton {
                        text: root.verifying ? "Verifying\u{2026}" : "Unlock";
                        shortcut: "Enter";
                        primary: true;
                        enabled: !root.verifying;
                        clicked => { root.try-submit(); }
                    }
                }
            }
        }
    }
}

fn unlock_context_text(context: &crate::UnlockRequestContext) -> String {
    let operation = match context.operation_kind.as_str() {
        "git_signing" => "Git Signing",
        "file_signing" => "File Signing",
        "ssh_signature" => "SSH Signature",
        "ssh_authentication" => "SSH Authentication",
        other => other,
    };
    let forwarding = if context.is_forwarding {
        " via agent forwarding"
    } else {
        ""
    };
    format!(
        "{} requests {} with {}{}",
        context.process_name, operation, context.key_name, forwarding
    )
}

fn trigger_shake(weak: &slint::Weak<PinDialog>) {
    let offsets: &[f32] = &[10.0, -8.0, 6.0, -4.0, 2.0, 0.0];
    for (i, &offset) in offsets.iter().enumerate() {
        let w = weak.clone();
        slint::Timer::single_shot(std::time::Duration::from_millis(i as u64 * 60), move || {
            if let Some(d) = w.upgrade() {
                d.set_shake_offset(offset);
            }
        });
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
    context: Option<crate::UnlockRequestContext>,
) {
    let Some(dialog) = build_pin_dialog(response_tx, validator, context) else {
        return;
    };
    let height = dialog.get_content_height();
    if let Err(e) = crate::window_placement::show_dialog(&dialog, 380.0, height) {
        tracing::error!(error = %e, "Failed to show PIN dialog");
        dialog.invoke_cancel();
    }
}

/// The dialog, wired to answer `response_tx`; `None` (already answered) if it cannot be created.
pub(crate) fn build_pin_dialog(
    response_tx: tokio::sync::oneshot::Sender<Option<String>>,
    validator: std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>,
    context: Option<crate::UnlockRequestContext>,
) -> Option<PinDialog> {
    let dialog = match PinDialog::new() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create PIN dialog");
            let _ = response_tx.send(None);
            return None;
        }
    };

    if let Some(context) = context {
        dialog.set_context_text(unlock_context_text(&context).into());
    }

    // Shared sender: Arc<Mutex> so it can be accessed from invoke_from_event_loop
    let tx_cell = std::sync::Arc::new(std::sync::Mutex::new(Some(response_tx)));
    // Answers `None` at most once.
    let cancel = {
        let tx = tx_cell.clone();
        move || {
            if let Ok(mut guard) = tx.lock() {
                if let Some(sender) = guard.take() {
                    let _ = sender.send(None);
                }
            }
        }
    };

    // Shake animation on empty submit
    let weak = dialog.as_weak();
    dialog.on_empty_submit(move || {
        trigger_shake(&weak);
    });

    // Submit PIN: spawn validation in background thread
    let weak = dialog.as_weak();
    let tx = tx_cell;
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
    let cancel_clicked = cancel.clone();
    dialog.on_cancel(move || {
        cancel_clicked();
        if let Some(d) = weak.upgrade() {
            let _ = d.hide();
        }
    });

    dialog.window().on_close_requested(move || {
        cancel();
        slint::CloseRequestResponse::HideWindow
    });

    Some(dialog)
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
    request_pin_dialog_with_context(request_tx, validator, None).await
}

pub async fn request_pin_dialog_with_context(
    request_tx: &tokio::sync::mpsc::Sender<crate::UIRequest>,
    validator: std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>,
    context: Option<crate::UnlockRequestContext>,
) -> Option<String> {
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();

    let request = crate::UIRequest::PinDialog {
        response_tx,
        validator,
        context,
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
