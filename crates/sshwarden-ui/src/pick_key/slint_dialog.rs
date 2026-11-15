use std::cell::RefCell;
use std::rc::Rc;

use slint::{ModelRc, StandardListViewItem, VecModel};

use crate::PickKeyRequest;

slint::slint! {
    import { Button, StandardListView, Palette } from "std-widgets.slint";
    import { Theme, WarningBanner } from "../theme.slint";

    export component PickKeyDialog inherits Window {
        title: "SSHWarden - Choose Key";
        icon: @image-url("../../assets/Square44x44Logo.png");
        default-font-family: Theme.font-family;
        width: 420px;
        // Fixed size, sized to the content: also what makes tiling compositors float it.
        height: content.preferred-height;
        background: Palette.background;
        always-on-top: true;

        in property <string> process-name: "Unknown";
        in property <string> target: "";
        in property <bool> is-forwarding: false;
        in property <[StandardListViewItem]> keys;
        out property <length> content-height: content.preferred-height;
        // Set once the prompt has been up for `Theme.arm-delay`.
        property <bool> armed: false;
        // Start time of the previous click on a row, for double-click detection.
        property <duration> last-click: -1s;
        property <int> last-click-item: -1;

        callback use-key(int);
        callback cancel();

        function use-current() {
            if list.current-item >= 0 {
                root.use-key(list.current-item);
            }
        }

        Timer {
            interval: Theme.arm-delay;
            running: !root.armed;
            triggered => { root.armed = true; }
        }

        // Parent of the content, so these keys work whichever widget has focus.
        // It never takes the focus itself: a click beside the list leaves it there.
        forward-focus: list;
        FocusScope {
            focus-on-tab-navigation: false;
            focus-on-click: false;
            // A fresh prompt takes no key but Esc: one typed for another window
            // must not choose a key, nor move the selection.
            capture-key-pressed(event) => {
                if !root.armed && event.text != Key.Escape {
                    return accept;
                }
                return reject;
            }
            key-pressed(event) => {
                if event.text == Key.Escape {
                    root.cancel();
                    return accept;
                }
                if event.text == Key.Return {
                    root.use-current();
                    return accept;
                }
                // 1-9 picks that row directly.
                if event.text.is-float() && event.text.to-float() >= 1
                    && event.text.to-float() <= min(9, root.keys.length) {
                    root.use-key(event.text.to-float() - 1);
                    return accept;
                }
                return reject;
            }

            content := VerticalLayout {
                padding: Theme.pad;
                spacing: Theme.gap;

                Text {
                    text: "Choose a key for " + root.process-name;
                    color: Palette.foreground;
                    font-size: Theme.title-size;
                    font-weight: 600;
                    wrap: word-wrap;
                }

                Text {
                    text: "Connecting to " + root.target + ". Only the key you choose is offered.";
                    color: Theme.muted;
                    font-size: Theme.body-size;
                    wrap: word-wrap;
                }

                if root.is-forwarding: WarningBanner {
                    text: "Agent forwarding: the request comes from a remote host";
                }

                list := StandardListView {
                    // Up to nine rows, so that every key a digit picks is in view.
                    height: clamp(root.keys.length, 2, 9) * Theme.list-row;
                    model: root.keys;
                    current-item: 0;
                    accessible-label: "SSH keys";
                    item-pointer-event(index, event, position) => {
                        if event.kind == PointerEventKind.down && event.button == PointerEventButton.left {
                            if root.armed && index == root.last-click-item && animation-tick() - root.last-click < 400ms {
                                root.use-key(index);
                            }
                            root.last-click = animation-tick();
                            root.last-click-item = index;
                        }
                    }
                }

                HorizontalLayout {
                    spacing: 8px;

                    Text {
                        text: "\u{2191}\u{2193} select \u{00B7} 1\u{2013}9 pick";
                        color: Theme.muted;
                        font-size: Theme.small-size;
                        vertical-alignment: center;
                        horizontal-stretch: 1;
                    }

                    Button {
                        text: "Cancel (Esc)";
                        clicked => { root.cancel(); }
                    }

                    Button {
                        text: "Use Key (Enter)";
                        primary: true;
                        enabled: root.armed && list.current-item >= 0;
                        clicked => { root.use-current(); }
                    }
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
    let Some(dialog) = build_pick_key_dialog(request) else {
        return;
    };
    let height = dialog.get_content_height();
    if let Err(e) = crate::window_placement::show_dialog(&dialog, 420.0, height) {
        tracing::error!(error = %e, "Failed to show key picker dialog");
        dialog.invoke_cancel();
    }
}

/// The dialog, wired to answer `request`; `None` (already answered) if it cannot be created.
pub(crate) fn build_pick_key_dialog(request: PickKeyDialogRequest) -> Option<PickKeyDialog> {
    let PickKeyDialogRequest {
        request,
        response_tx,
    } = request;
    let dialog = match PickKeyDialog::new() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create key picker dialog");
            let _ = response_tx.send(None);
            return None;
        }
    };

    dialog.set_process_name(request.process_name.as_str().into());
    dialog.set_target(request.target.as_str().into());
    dialog.set_is_forwarding(request.is_forwarding);
    // The first nine rows carry the digit that picks them.
    let rows: Vec<StandardListViewItem> = request
        .keys
        .iter()
        .enumerate()
        .map(|(i, (_, name))| match i {
            0..=8 => format!("{}  {name}", i + 1).as_str().into(),
            _ => format!("    {name}").as_str().into(),
        })
        .collect();
    dialog.set_keys(ModelRc::from(Rc::new(VecModel::from(rows))));

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
    dialog.on_use_key(move |index| {
        // An index outside the list must not cancel the prompt.
        if let Some(id) = usize::try_from(index).ok().and_then(|i| ids.get(i)) {
            answer_use(Some(id.clone()));
        }
    });
    dialog.on_cancel(move || answer(None));
    dialog.window().on_close_requested(move || {
        if let Some(sender) = tx_cell.borrow_mut().take() {
            let _ = sender.send(None);
        }
        slint::CloseRequestResponse::HideWindow
    });

    Some(dialog)
}
