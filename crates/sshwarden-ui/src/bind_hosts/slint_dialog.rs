use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};

use crate::{BindHostsRequest, BindHostsResult};

slint::slint! {
    import { Button, VerticalBox, HorizontalBox, LineEdit, ListView, ScrollView, Palette } from "std-widgets.slint";

    struct KeyEntry {
        cipher-id: string,
        name: string,
        bound-count: int,
    }

    export component BindHostsDialog inherits Window {
        title: "SSHWarden - Bind Hosts";
        icon: @image-url("../../assets/Square44x44Logo.png");
        default-font-family: "Segoe UI";
        width: 640px;
        height: 440px;
        background: Palette.background;
        always-on-top: true;

        in property <[KeyEntry]> keys;
        in-out property <int> selected-index: 0;
        in property <[string]> current-hosts;
        in-out property <string> new-host-text;
        in property <string> selected-key-label: "(no key)";
        in property <string> error-message: "";
        in property <bool> approve-on-save: false;

        callback key-selected(int);
        callback add-host();
        callback remove-host(int);
        callback save();
        callback cancel();

        forward-focus: key-handler;
        key-handler := FocusScope {
            key-pressed(event) => {
                if event.text == "\u{1b}" {
                    root.cancel();
                    return accept;
                }
                return reject;
            }
        }

        VerticalLayout {
            padding: 14px;
            spacing: 10px;

            Text {
                text: "Bind keys to SSH hosts";
                color: Palette.foreground;
                font-size: 18px;
                font-weight: 700;
            }

            Text {
                text: "Each key is offered to SSH only for the hosts listed here. Use hostnames, IPs, or globs like *.prod.example.com.";
                color: Palette.foreground;
                font-size: 12px;
                wrap: word-wrap;
            }

            HorizontalLayout {
                spacing: 12px;

                // Left pane: key list
                Rectangle {
                    width: 230px;
                    border-radius: 4px;
                    border-width: 1px;
                    border-color: Palette.foreground.with-alpha(0.15);

                    VerticalLayout {
                        padding: 4px;

                        keys-list := ListView {
                            for entry[i] in root.keys: Rectangle {
                                height: 38px;
                                background: i == root.selected-index ? Palette.accent-background : transparent;
                                border-radius: 3px;

                                TouchArea {
                                    clicked => { root.key-selected(i); }
                                }

                                HorizontalLayout {
                                    padding-left: 8px;
                                    padding-right: 8px;
                                    spacing: 6px;
                                    alignment: start;

                                    VerticalLayout {
                                        alignment: center;

                                        Text {
                                            text: entry.name;
                                            color: i == root.selected-index ? Palette.accent-foreground : Palette.foreground;
                                            font-size: 13px;
                                            font-weight: i == root.selected-index ? 600 : 500;
                                            overflow: elide;
                                        }

                                        Text {
                                            text: entry.bound-count == 0
                                                ? "no bindings"
                                                : entry.bound-count == 1
                                                    ? "1 host"
                                                    : entry.bound-count + " hosts";
                                            color: i == root.selected-index
                                                ? Palette.accent-foreground.with-alpha(0.75)
                                                : Palette.foreground.with-alpha(0.55);
                                            font-size: 11px;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Right pane: host editor
                VerticalLayout {
                    spacing: 8px;

                    Text {
                        text: root.selected-key-label;
                        color: Palette.foreground;
                        font-size: 13px;
                        font-weight: 600;
                        overflow: elide;
                    }

                    Rectangle {
                        border-radius: 4px;
                        border-width: 1px;
                        border-color: Palette.foreground.with-alpha(0.15);

                        VerticalLayout {
                            padding: 4px;

                            hosts-list := ListView {
                                for host[j] in root.current-hosts: Rectangle {
                                    height: 32px;
                                    border-radius: 3px;

                                    HorizontalLayout {
                                        padding-left: 8px;
                                        padding-right: 4px;
                                        spacing: 6px;

                                        VerticalLayout {
                                            alignment: center;
                                            Text {
                                                text: host;
                                                color: Palette.foreground;
                                                font-size: 13px;
                                                overflow: elide;
                                            }
                                        }

                                        Rectangle { horizontal-stretch: 1; }

                                        VerticalLayout {
                                            alignment: center;
                                            Button {
                                                text: "Remove";
                                                height: 26px;
                                                clicked => { root.remove-host(j); }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    HorizontalLayout {
                        spacing: 6px;

                        LineEdit {
                            placeholder-text: "Add host pattern (e.g. github.com, *.prod.example.com)";
                            text <=> root.new-host-text;
                            horizontal-stretch: 1;
                            accepted => { root.add-host(); }
                        }

                        Button {
                            text: "Add";
                            height: 30px;
                            clicked => { root.add-host(); }
                        }
                    }

                    if root.error-message != "": Text {
                        text: root.error-message;
                        color: #d94c4c;
                        font-size: 12px;
                        wrap: word-wrap;
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
                    text: approve-on-save ? "Save & Approve" : "Save";
                    height: 30px;
                    primary: true;
                    clicked => { root.save(); }
                }
            }
        }
    }
}

pub struct BindHostsDialogRequest {
    pub request: BindHostsRequest,
    pub response_tx: tokio::sync::oneshot::Sender<BindHostsResult>,
}

fn center_and_focus_dialog(dialog: &BindHostsDialog) {
    let window = dialog.window();
    slint_center_win::center_window(window);
    use slint::winit_030::WinitWindowAccessor;
    let _ = window.with_winit_window(|winit_window: &slint::winit_030::winit::window::Window| {
        winit_window.focus_window();
        None::<()>
    });
}

/// Cheap UI-side host pattern check. Final validation happens in the main loop
/// via `sshwarden_config::bindings::validate_host_pattern`.
fn quick_validate_host_pattern(pattern: &str) -> Result<(), &'static str> {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return Err("Host pattern is empty");
    }
    if trimmed.chars().any(|c| c.is_whitespace()) {
        return Err("Host pattern must not contain whitespace");
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err("Host pattern must not contain control characters");
    }
    if trimmed
        .chars()
        .any(|c| matches!(c, '"' | '\'' | '\\' | '#'))
    {
        return Err("Host pattern contains a character unsafe in ssh_config");
    }
    Ok(())
}

pub fn show_bind_hosts_dialog(request: BindHostsDialogRequest) {
    let dialog = match BindHostsDialog::new() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create bind-hosts dialog");
            let _ = request.response_tx.send(BindHostsResult::Cancelled);
            return;
        }
    };

    let BindHostsDialogRequest {
        request:
            BindHostsRequest {
                keys,
                initial_selection,
                prefill_host,
                approve_on_save,
            },
        response_tx,
    } = request;

    // Working state: cipher_id -> current edit Vec<String>. Pre-seeded from the request.
    let working: Rc<RefCell<HashMap<String, Vec<String>>>> = Rc::new(RefCell::new(
        keys.iter()
            .map(|k| (k.cipher_id.clone(), k.hosts.clone()))
            .collect(),
    ));
    let key_ids: Rc<Vec<String>> = Rc::new(keys.iter().map(|k| k.cipher_id.clone()).collect());
    let key_names: Rc<HashMap<String, String>> = Rc::new(
        keys.iter()
            .map(|k| (k.cipher_id.clone(), k.name.clone()))
            .collect(),
    );

    let initial_index = match initial_selection.as_deref() {
        Some(id) => key_ids
            .iter()
            .position(|k| k == id)
            .unwrap_or(0),
        None => 0,
    } as i32;

    // Build the Slint VecModel for the key list.
    let key_entries: VecModel<KeyEntry> = VecModel::default();
    for k in &keys {
        key_entries.push(KeyEntry {
            cipher_id: k.cipher_id.as_str().into(),
            name: k.name.as_str().into(),
            bound_count: k.hosts.len() as i32,
        });
    }
    let key_entries = Rc::new(key_entries);
    dialog.set_keys(ModelRc::from(key_entries.clone()));

    // Current-hosts model (shown for selected key).
    let hosts_model: Rc<VecModel<SharedString>> = Rc::new(VecModel::default());
    dialog.set_current_hosts(ModelRc::from(hosts_model.clone()));

    let refresh_hosts_for = {
        let working = working.clone();
        let key_ids = key_ids.clone();
        let hosts_model = hosts_model.clone();
        move |idx: i32| {
            hosts_model.set_vec(Vec::<SharedString>::new());
            let Some(cipher_id) = key_ids.get(idx as usize) else {
                return;
            };
            if let Some(hosts) = working.borrow().get(cipher_id) {
                for h in hosts {
                    hosts_model.push(SharedString::from(h.as_str()));
                }
            }
        }
    };

    let update_selected_label = {
        let key_names = key_names.clone();
        let key_ids = key_ids.clone();
        let weak = dialog.as_weak();
        move |idx: i32| {
            let Some(d) = weak.upgrade() else { return };
            let label = key_ids
                .get(idx as usize)
                .and_then(|id| key_names.get(id).map(|n| format!("Hosts for: {n}")))
                .unwrap_or_else(|| "(no key)".to_string());
            d.set_selected_key_label(label.into());
        }
    };

    let update_key_count = {
        let key_entries = key_entries.clone();
        move |idx: i32, count: i32| {
            if let Some(mut entry) = key_entries.row_data(idx as usize) {
                entry.bound_count = count;
                key_entries.set_row_data(idx as usize, entry);
            }
        }
    };

    let clear_error = {
        let weak = dialog.as_weak();
        move || {
            if let Some(d) = weak.upgrade() {
                d.set_error_message("".into());
            }
        }
    };

    dialog.set_selected_index(initial_index);
    if let Some(prefill) = prefill_host.as_deref() {
        dialog.set_new_host_text(prefill.into());
    }
    dialog.set_approve_on_save(approve_on_save);
    refresh_hosts_for(initial_index);
    update_selected_label(initial_index);

    let tx_cell: Rc<RefCell<Option<tokio::sync::oneshot::Sender<BindHostsResult>>>> =
        Rc::new(RefCell::new(Some(response_tx)));
    let tx_for_show_error = tx_cell.clone();

    // on_key_selected
    {
        let weak = dialog.as_weak();
        let refresh = refresh_hosts_for.clone();
        let label = update_selected_label.clone();
        let clear = clear_error.clone();
        dialog.on_key_selected(move |idx| {
            if let Some(d) = weak.upgrade() {
                d.set_selected_index(idx);
                d.set_new_host_text("".into());
            }
            refresh(idx);
            label(idx);
            clear();
        });
    }

    // on_add_host
    {
        let weak = dialog.as_weak();
        let working = working.clone();
        let key_ids = key_ids.clone();
        let hosts_model = hosts_model.clone();
        let update_count = update_key_count.clone();
        dialog.on_add_host(move || {
            let Some(d) = weak.upgrade() else { return };
            let raw = d.get_new_host_text().to_string();
            let trimmed = raw.trim().to_string();
            if let Err(msg) = quick_validate_host_pattern(&trimmed) {
                d.set_error_message(msg.into());
                return;
            }
            let idx = d.get_selected_index();
            let Some(cipher_id) = key_ids.get(idx as usize).cloned() else {
                return;
            };
            let already_present = {
                let map = working.borrow();
                map.get(&cipher_id)
                    .map(|v| v.iter().any(|h| h.eq_ignore_ascii_case(&trimmed)))
                    .unwrap_or(false)
            };
            if already_present {
                d.set_error_message("Host pattern already bound to this key".into());
                return;
            }
            working
                .borrow_mut()
                .entry(cipher_id)
                .or_default()
                .push(trimmed.clone());
            hosts_model.push(SharedString::from(trimmed.as_str()));
            update_count(idx, hosts_model.row_count() as i32);
            d.set_new_host_text("".into());
            d.set_error_message("".into());
        });
    }

    // on_remove_host
    {
        let weak = dialog.as_weak();
        let working = working.clone();
        let key_ids = key_ids.clone();
        let hosts_model = hosts_model.clone();
        let update_count = update_key_count.clone();
        dialog.on_remove_host(move |host_idx| {
            let Some(d) = weak.upgrade() else { return };
            let idx = d.get_selected_index();
            let Some(cipher_id) = key_ids.get(idx as usize).cloned() else {
                return;
            };
            if host_idx < 0 {
                return;
            }
            let host_idx = host_idx as usize;
            {
                let mut map = working.borrow_mut();
                if let Some(v) = map.get_mut(&cipher_id) {
                    if host_idx < v.len() {
                        v.remove(host_idx);
                    } else {
                        return;
                    }
                } else {
                    return;
                }
            }
            if host_idx < hosts_model.row_count() {
                hosts_model.remove(host_idx);
            }
            update_count(idx, hosts_model.row_count() as i32);
            d.set_error_message("".into());
        });
    }

    // on_save
    {
        let weak = dialog.as_weak();
        let tx = tx_cell.clone();
        let working = working.clone();
        dialog.on_save(move || {
            let payload: BTreeMap<String, Vec<String>> = working
                .borrow()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if let Some(sender) = tx.borrow_mut().take() {
                let _ = sender.send(BindHostsResult::Saved { bindings: payload });
            }
            if let Some(d) = weak.upgrade() {
                let _ = d.hide();
            }
        });
    }

    // on_cancel
    {
        let weak = dialog.as_weak();
        let tx = tx_cell.clone();
        dialog.on_cancel(move || {
            if let Some(sender) = tx.borrow_mut().take() {
                let _ = sender.send(BindHostsResult::Cancelled);
            }
            if let Some(d) = weak.upgrade() {
                let _ = d.hide();
            }
        });
    }

    // close button → cancel
    {
        let tx = tx_cell;
        dialog.window().on_close_requested(move || {
            if let Some(sender) = tx.borrow_mut().take() {
                let _ = sender.send(BindHostsResult::Cancelled);
            }
            slint::CloseRequestResponse::HideWindow
        });
    }

    if let Err(e) = dialog.show() {
        tracing::error!(error = %e, "Failed to show bind-hosts dialog");
        if let Some(sender) = tx_for_show_error.borrow_mut().take() {
            let _ = sender.send(BindHostsResult::Cancelled);
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
