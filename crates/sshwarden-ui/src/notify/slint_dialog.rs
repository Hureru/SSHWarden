use crate::{AuthorizationResult, SignRequestInfo};

slint::slint! {
    import { Button, VerticalBox, HorizontalBox, Palette } from "std-widgets.slint";

    export component AuthDialog inherits Window {
        title: "SSHWarden - Authorization";
        icon: @image-url("../../assets/Square44x44Logo.png");
        default-font-family: "Segoe UI";
        width: 380px;
        height: 195px;
        background: Palette.background;
        always-on-top: true;

        in property <string> process-name: "Unknown";
        in property <string> key-name: "Unknown";
        in property <string> operation: "SSH Authentication";
        in property <bool> is-forwarding: false;

        callback approve();
        callback deny();

        // Ensure Enter/Esc are handled even when no button has focus.
        forward-focus: key-handler;
        key-handler := FocusScope {
            key-pressed(event) => {
                if event.text == "\n" {
                    root.approve();
                    return accept;
                }
                if event.text == "\u{1b}" {
                    root.deny();
                    return accept;
                }
                return reject;
            }
        }

        VerticalLayout {
            padding: 16px;
            padding-right: 16px;
            spacing: 8px;

            Text {
                text: process-name;
                color: Palette.foreground;
                font-size: 22px;
                font-weight: 700;
            }

            Text {
                text: "is requesting to use an SSH key";
                color: Palette.foreground;
                font-size: 13px;
            }

            VerticalLayout {
                spacing: 4px;
                padding-top: 4px;

                HorizontalLayout {
                    spacing: 6px;
                    Text {
                        text: "Key:";
                        color: Palette.foreground;
                        font-size: 13px;
                        font-weight: 600;
                        min-width: 70px;
                    }
                    Text {
                        text: key-name;
                        color: Palette.foreground;
                        font-size: 13px;
                    }
                }

                HorizontalLayout {
                    spacing: 6px;
                    Text {
                        text: "Operation:";
                        color: Palette.foreground;
                        font-size: 13px;
                        font-weight: 600;
                        min-width: 70px;
                    }
                    Text {
                        text: operation;
                        color: Palette.foreground;
                        font-size: 13px;
                    }
                }
            }

            if is-forwarding: Rectangle {
                background: #ff990033;
                border-radius: 4px;
                height: warning-text.preferred-height + 12px;

                warning-text := Text {
                    text: "\u{26A0} Agent forwarding (from remote host)";
                    color: #ff9900;
                    font-size: 13px;
                    x: 8px;
                    y: 6px;
                }
            }

            HorizontalLayout {
                alignment: end;
                spacing: 10px;

                Button {
                    text: "Deny";
                    height: 30px;
                    clicked => { root.deny(); }
                }

                Button {
                    text: "Approve";
                    height: 30px;
                    primary: true;
                    clicked => { root.approve(); }
                }
            }
        }
    }
}

pub struct AuthDialogRequest {
    pub info: SignRequestInfo,
    pub response_tx: tokio::sync::oneshot::Sender<AuthorizationResult>,
}

fn center_and_focus_dialog(dialog: &AuthDialog) {
    let window = dialog.window();
    slint_center_win::center_window(window);
    use slint::winit_030::WinitWindowAccessor;
    let _ = window.with_winit_window(|winit_window: &slint::winit_030::winit::window::Window| {
        winit_window.focus_window();
        None::<()>
    });
}

pub fn show_auth_dialog(request: AuthDialogRequest) {
    let dialog = match AuthDialog::new() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create auth dialog");
            let _ = request.response_tx.send(AuthorizationResult::Denied);
            return;
        }
    };

    let operation = match request.info.namespace.as_deref() {
        Some("git") => "Git Signing",
        Some(ns) => ns,
        None => "SSH Authentication",
    };

    dialog.set_process_name(request.info.process_name.as_str().into());
    dialog.set_key_name(request.info.key_name.as_str().into());
    dialog.set_operation(operation.into());
    dialog.set_is_forwarding(request.info.is_forwarding);

    let tx_cell = std::rc::Rc::new(std::cell::RefCell::new(Some(request.response_tx)));
    let tx_for_show_error = tx_cell.clone();

    let weak = dialog.as_weak();
    let tx = tx_cell.clone();
    dialog.on_approve(move || {
        if let Some(sender) = tx.borrow_mut().take() {
            let _ = sender.send(AuthorizationResult::Approved);
        }
        if let Some(d) = weak.upgrade() {
            let _ = d.hide();
        }
    });

    let weak = dialog.as_weak();
    let tx = tx_cell.clone();
    dialog.on_deny(move || {
        if let Some(sender) = tx.borrow_mut().take() {
            let _ = sender.send(AuthorizationResult::Denied);
        }
        if let Some(d) = weak.upgrade() {
            let _ = d.hide();
        }
    });

    let tx = tx_cell;
    dialog.window().on_close_requested(move || {
        if let Some(sender) = tx.borrow_mut().take() {
            let _ = sender.send(AuthorizationResult::Denied);
        }
        slint::CloseRequestResponse::HideWindow
    });

    if let Err(e) = dialog.show() {
        tracing::error!(error = %e, "Failed to show auth dialog");
        if let Some(sender) = tx_for_show_error.borrow_mut().take() {
            let _ = sender.send(AuthorizationResult::Denied);
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

pub async fn request_authorization(
    request_tx: &tokio::sync::mpsc::Sender<crate::UIRequest>,
    info: &SignRequestInfo,
) -> AuthorizationResult {
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();

    let request = crate::UIRequest::AuthDialog {
        info: info.clone(),
        response_tx,
    };

    if request_tx.send(request).await.is_err() {
        tracing::error!("Failed to send auth dialog request to UI thread");
        return AuthorizationResult::Denied;
    }

    tracing::info!("Waiting for authorization dialog response...");

    match tokio::time::timeout(std::time::Duration::from_secs(300), response_rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => {
            tracing::error!("Auth dialog response channel closed unexpectedly");
            AuthorizationResult::Denied
        }
        Err(_) => {
            tracing::error!("Authorization dialog timed out after 300s");
            AuthorizationResult::Timeout
        }
    }
}
