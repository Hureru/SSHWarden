use crate::{AuthorizationResult, SignRequestInfo};

slint::slint! {
    import { Button, Palette } from "std-widgets.slint";
    import { Theme, WarningBanner, DetailRow } from "../theme.slint";

    export component AuthDialog inherits Window {
        title: "SSHWarden - Authorization";
        icon: @image-url("../../assets/Square44x44Logo.png");
        default-font-family: Theme.font-family;
        width: 420px;
        // Fixed size, sized to the content: also what makes tiling compositors float it.
        height: content.preferred-height;
        background: Palette.background;
        always-on-top: true;

        in property <string> process-name: "Unknown";
        in property <string> process-detail: "Unknown";
        in property <string> key-name: "Unknown";
        in property <string> target: "";
        in property <string> operation: "SSH Authentication";
        in property <bool> is-forwarding: false;
        out property <length> content-height: content.preferred-height;
        // Set once the prompt has been up for `Theme.arm-delay`.
        property <bool> armed: false;

        callback approve();
        callback deny();
        callback bind();

        Timer {
            interval: Theme.arm-delay;
            running: !root.armed;
            triggered => { root.armed = true; }
        }

        // Parent of the content, so these keys work whichever widget has focus.
        forward-focus: scope;
        scope := FocusScope {
            // A fresh prompt takes no key but Esc: one typed for another window
            // must not answer it, nor move the focus in it.
            capture-key-pressed(event) => {
                if !root.armed && event.text != Key.Escape {
                    return accept;
                }
                return reject;
            }
            key-pressed(event) => {
                if event.text == Key.Escape {
                    root.deny();
                    return accept;
                }
                if event.text == Key.Return {
                    root.approve();
                    return accept;
                }
                if event.text == "b" || event.text == "B" {
                    root.bind();
                    return accept;
                }
                return reject;
            }

            content := VerticalLayout {
                padding: Theme.pad;
                spacing: Theme.gap;

                Text {
                    text: "Allow " + root.process-name + " to use \"" + root.key-name + "\"?";
                    color: Palette.foreground;
                    font-size: Theme.title-size;
                    font-weight: 600;
                    wrap: word-wrap;
                }

                VerticalLayout {
                    spacing: 4px;

                    if root.target != "": DetailRow { label: "Target"; value: root.target; }
                    DetailRow { label: "Operation"; value: root.operation; }
                    DetailRow { label: "Process"; value: root.process-detail; }
                }

                if root.is-forwarding: WarningBanner {
                    text: "Agent forwarding: the request comes from a remote host";
                }

                HorizontalLayout {
                    padding-top: 4px;
                    spacing: 8px;

                    Button {
                        text: "Bind\u{2026} (B)";
                        clicked => { root.bind(); }
                    }

                    Rectangle { horizontal-stretch: 1; }

                    Button {
                        text: "Deny (Esc)";
                        clicked => { root.deny(); }
                    }

                    Button {
                        text: "Approve (Enter)";
                        primary: true;
                        enabled: root.armed;
                        clicked => { root.approve(); }
                    }
                }
            }
        }
    }
}

pub struct AuthDialogRequest {
    pub info: SignRequestInfo,
    pub response_tx: tokio::sync::oneshot::Sender<AuthorizationResult>,
}

pub fn show_auth_dialog(request: AuthDialogRequest) {
    let Some(dialog) = build_auth_dialog(request) else {
        return;
    };
    let height = dialog.get_content_height();
    if let Err(e) = crate::window_placement::show_dialog(&dialog, 420.0, height) {
        tracing::error!(error = %e, "Failed to show auth dialog");
        dialog.invoke_deny();
    }
}

/// The dialog, wired to answer `request`; `None` (already answered) if it cannot be created.
pub(crate) fn build_auth_dialog(request: AuthDialogRequest) -> Option<AuthDialog> {
    let AuthDialogRequest { info, response_tx } = request;
    let dialog = match AuthDialog::new() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create auth dialog");
            let _ = response_tx.send(AuthorizationResult::Denied);
            return None;
        }
    };

    let operation = match info.operation_kind.as_str() {
        "git_signing" => "Git Signing",
        "file_signing" => "File Signing",
        "ssh_signature" => "SSH Signature",
        "ssh_authentication" => "SSH Authentication",
        other => other,
    };

    dialog.set_process_name(info.process_name.as_str().into());
    dialog.set_process_detail(format!("{} (pid {})", info.process_name, info.pid).into());
    dialog.set_key_name(info.key_name.as_str().into());
    dialog.set_target(info.target.as_deref().unwrap_or_default().into());
    dialog.set_operation(operation.into());
    dialog.set_is_forwarding(info.is_forwarding);

    let tx_cell = std::rc::Rc::new(std::cell::RefCell::new(Some(response_tx)));
    // Answers at most once, then hides the dialog.
    let answer = {
        let tx = tx_cell.clone();
        let weak = dialog.as_weak();
        move |result: AuthorizationResult| {
            if let Some(sender) = tx.borrow_mut().take() {
                let _ = sender.send(result);
            }
            if let Some(d) = weak.upgrade() {
                let _ = d.hide();
            }
        }
    };

    let approve = answer.clone();
    dialog.on_approve(move || approve(AuthorizationResult::Approved));
    let deny = answer.clone();
    dialog.on_deny(move || deny(AuthorizationResult::Denied));
    dialog.on_bind(move || answer(AuthorizationResult::BindRequested));

    dialog.window().on_close_requested(move || {
        if let Some(sender) = tx_cell.borrow_mut().take() {
            let _ = sender.send(AuthorizationResult::Denied);
        }
        slint::CloseRequestResponse::HideWindow
    });

    Some(dialog)
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
