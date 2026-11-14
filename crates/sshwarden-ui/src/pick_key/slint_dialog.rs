use std::cell::RefCell;
use std::rc::Rc;

use slint::{ModelRc, SharedString, VecModel};

use crate::PickKeyRequest;

slint::slint! {
    import { Button, ListView, Palette } from "std-widgets.slint";

    export component PickKeyDialog inherits Window {
        title: "SSHWarden - Choose Key";
        icon: @image-url("../../assets/Square44x44Logo.png");
        default-font-family: "Segoe UI";
        width: 420px;
        height: 360px;
        background: Palette.background;
        always-on-top: true;

        in property <string> process-name: "Unknown";
        in property <string> target: "";
        in property <bool> is-forwarding: false;
        in property <[string]> keys;
        in-out property <int> selected-index: 0;

        callback use-key(int);
        callback cancel();

        forward-focus: key-handler;
        key-handler := FocusScope {
            key-pressed(event) => {
                if event.text == "\n" {
                    root.use-key(root.selected-index);
                    return accept;
                }
                if event.text == "\u{1b}" {
                    root.cancel();
                    return accept;
                }
                if event.text == Key.UpArrow && root.selected-index > 0 {
                    root.selected-index -= 1;
                    return accept;
                }
                if event.text == Key.DownArrow && root.selected-index < root.keys.length - 1 {
                    root.selected-index += 1;
                    return accept;
                }
                return reject;
            }
        }

        VerticalLayout {
            padding: 16px;
            spacing: 8px;

            Text {
                text: process-name;
                color: Palette.foreground;
                font-size: 22px;
                font-weight: 700;
            }

            Text {
                text: "needs an SSH key for " + target;
                color: Palette.foreground;
                font-size: 13px;
                wrap: word-wrap;
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

            Rectangle {
                border-radius: 4px;
                border-width: 1px;
                border-color: Palette.foreground.with-alpha(0.15);

                ListView {
                    for name[i] in root.keys: Rectangle {
                        height: 32px;
                        background: i == root.selected-index ? Palette.accent-background : transparent;
                        border-radius: 3px;

                        TouchArea {
                            clicked => { root.selected-index = i; }
                            double-clicked => { root.use-key(i); }
                        }

                        Text {
                            x: 8px;
                            width: parent.width - 16px;
                            vertical-alignment: center;
                            text: name;
                            color: i == root.selected-index ? Palette.accent-foreground : Palette.foreground;
                            font-size: 13px;
                            overflow: elide;
                        }
                    }
                }
            }

            HorizontalLayout {
                alignment: end;
                spacing: 10px;

                Button {
                    text: "Cancel";
                    height: 30px;
                    clicked => { root.cancel(); }
                }

                Button {
                    text: "Use Key";
                    height: 30px;
                    primary: true;
                    clicked => { root.use-key(root.selected-index); }
                }
            }
        }
    }
}

pub struct PickKeyDialogRequest {
    pub request: PickKeyRequest,
    /// The chosen vault item id, or `None` when cancelled.
    pub response_tx: tokio::sync::oneshot::Sender<Option<String>>,
}

pub fn show_pick_key_dialog(request: PickKeyDialogRequest) {
    let PickKeyDialogRequest {
        request,
        response_tx,
    } = request;
    let dialog = match PickKeyDialog::new() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create key picker dialog");
            let _ = response_tx.send(None);
            return;
        }
    };

    dialog.set_process_name(request.process_name.as_str().into());
    dialog.set_target(request.target.as_str().into());
    dialog.set_is_forwarding(request.is_forwarding);
    let names: Vec<SharedString> = request
        .keys
        .iter()
        .map(|(_, name)| name.as_str().into())
        .collect();
    dialog.set_keys(ModelRc::from(Rc::new(VecModel::from(names))));

    let tx_cell = Rc::new(RefCell::new(Some(response_tx)));
    // Answers at most once, then hides the dialog.
    let answer = {
        let tx = tx_cell.clone();
        let weak = dialog.as_weak();
        move |choice: Option<String>| {
            if let Some(sender) = tx.borrow_mut().take() {
                let _ = sender.send(choice);
            }
            if let Some(d) = weak.upgrade() {
                let _ = d.hide();
            }
        }
    };

    let ids: Vec<String> = request.keys.into_iter().map(|(id, _)| id).collect();
    let answer_use = answer.clone();
    dialog.on_use_key(move |index| answer_use(ids.get(index as usize).cloned()));
    let answer_cancel = answer.clone();
    dialog.on_cancel(move || answer_cancel(None));
    let tx = tx_cell.clone();
    dialog.window().on_close_requested(move || {
        if let Some(sender) = tx.borrow_mut().take() {
            let _ = sender.send(None);
        }
        slint::CloseRequestResponse::HideWindow
    });

    // Must run before `show()`: see `window_placement::declare_fixed_size`.
    crate::window_placement::declare_fixed_size(dialog.window(), 420.0, 360.0);

    if let Err(e) = dialog.show() {
        tracing::error!(error = %e, "Failed to show key picker dialog");
        if let Some(sender) = tx_cell.borrow_mut().take() {
            let _ = sender.send(None);
        }
    } else {
        let weak = dialog.as_weak();
        slint::Timer::single_shot(std::time::Duration::from_millis(30), move || {
            if let Some(d) = weak.upgrade() {
                crate::window_placement::center_on_active_monitor_and_focus(d.window());
            }
        });
    }
}
