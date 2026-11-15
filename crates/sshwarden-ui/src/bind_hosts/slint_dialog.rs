use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;

use slint::{ComponentHandle, Model, ModelRc, SharedString, StandardListViewItem, VecModel};

use crate::{BindHostsRequest, BindHostsResult};

slint::slint! {
    import { Button, LineEdit, ListView, StandardListView, Palette } from "std-widgets.slint";
    import { Theme } from "../theme.slint";

    export component BindHostsDialog inherits Window {
        title: "SSHWarden - Bind Hosts";
        icon: @image-url("../../assets/Square44x44Logo.png");
        default-font-family: Theme.font-family;
        width: 660px;
        // Fixed size, sized to the content: also what makes tiling compositors float it.
        height: content.preferred-height;
        background: Palette.background;
        always-on-top: true;

        in property <[StandardListViewItem]> keys;
        // The key whose hosts are shown.
        in-out property <int> selected-index: 0;
        in property <[string]> current-hosts;
        in-out property <string> new-host-text;
        in property <string> selected-key-label: "(no key)";
        in property <string> error-message: "";
        in property <bool> approve-on-save: false;
        out property <length> content-height: content.preferred-height;

        callback key-selected(int);
        callback add-host();
        callback remove-host(int);
        callback save();
        callback cancel();

        // Parent of the content, and capturing: these work while typing a host.
        // It never takes the focus itself: a click beside a field leaves it there.
        forward-focus: host-input;
        FocusScope {
            focus-on-tab-navigation: false;
            focus-on-click: false;
            capture-key-pressed(event) => {
                if event.text == Key.Escape {
                    root.cancel();
                    return accept;
                }
                if event.text == Key.Return && event.modifiers.control {
                    root.save();
                    return accept;
                }
                return reject;
            }

            content := VerticalLayout {
                padding: Theme.pad;
                spacing: Theme.gap;

                Text {
                    text: "Bind keys to SSH hosts";
                    color: Palette.foreground;
                    font-size: Theme.title-size;
                    font-weight: 600;
                }

                Text {
                    text: "Each key is offered to SSH only for the hosts listed here. Use hostnames, IPs, or globs like *.prod.example.com.";
                    color: Theme.muted;
                    font-size: Theme.body-size;
                    wrap: word-wrap;
                }

                HorizontalLayout {
                    spacing: 12px;

                    StandardListView {
                        width: 250px;
                        height: 8 * Theme.list-row;
                        model: root.keys;
                        current-item: root.selected-index;
                        accessible-label: "SSH keys";
                        // Selecting again once the rows have a height: only `set-current-item`
                        // also scrolls to the row and starts the arrow keys from it.
                        changed viewport-height => {
                            self.current-item = -1;
                            self.set-current-item(root.selected-index);
                        }
                        current-item-changed(index) => {
                            // Not for the call above, nor for reselecting the same key.
                            if index != root.selected-index {
                                root.selected-index = index;
                                root.key-selected(index);
                            }
                        }
                    }

                    VerticalLayout {
                        spacing: 8px;

                        Text {
                            text: root.selected-key-label;
                            color: Palette.foreground;
                            font-size: Theme.body-size;
                            font-weight: 600;
                            overflow: elide;
                        }

                        HorizontalLayout {
                            spacing: 6px;

                            host-input := LineEdit {
                                placeholder-text: "github.com, *.prod.example.com";
                                text <=> root.new-host-text;
                                horizontal-stretch: 1;
                                accessible-label: "Host pattern to add";
                                accepted => { root.add-host(); }
                            }

                            Button {
                                text: "Add (Enter)";
                                clicked => { root.add-host(); }
                            }
                        }

                        if root.error-message != "": Text {
                            text: root.error-message;
                            color: Theme.error;
                            font-size: Theme.small-size;
                            wrap: word-wrap;
                        }

                        Rectangle {
                            border-radius: 4px;
                            border-width: 1px;
                            border-color: Palette.border;
                            vertical-stretch: 1;

                            if root.current-hosts.length == 0: Text {
                                text: "No hosts bound to this key yet";
                                color: Theme.muted;
                                font-size: Theme.body-size;
                            }

                            ListView {
                                accessible-label: "Bound hosts";

                                for host[j] in root.current-hosts: HorizontalLayout {
                                    height: 36px;
                                    padding-left: 10px;
                                    padding-right: 4px;
                                    spacing: 6px;

                                    Text {
                                        text: host;
                                        color: Palette.foreground;
                                        font-size: Theme.body-size;
                                        vertical-alignment: center;
                                        overflow: elide;
                                        horizontal-stretch: 1;
                                    }

                                    VerticalLayout {
                                        alignment: center;

                                        Button {
                                            text: "Remove";
                                            accessible-label: "Remove " + host;
                                            clicked => { root.remove-host(j); }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                HorizontalLayout {
                    alignment: end;
                    spacing: 8px;

                    Button {
                        text: "Cancel (Esc)";
                        clicked => { root.cancel(); }
                    }

                    Button {
                        // Slint's `control` modifier is the Command key on macOS.
                        text: (root.approve-on-save ? "Save & Approve" : "Save")
                            + (Platform.os == OperatingSystemType.macos ? " (\u{2318}Enter)" : " (Ctrl+Enter)");
                        primary: true;
                        clicked => { root.save(); }
                    }
                }
            }
        }
    }
}

pub struct BindHostsDialogRequest {
    pub request: BindHostsRequest,
    pub response_tx: tokio::sync::oneshot::Sender<BindHostsResult>,
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

fn host_pattern_warning(pattern: &str) -> Option<&'static str> {
    match pattern.trim() {
        "*" | "!*" => Some(
            "Warning: this pattern can match many hosts and may reintroduce MaxAuthTries failures.",
        ),
        _ => None,
    }
}

fn is_bound(hosts: &[String], pattern: &str) -> bool {
    hosts.iter().any(|h| h.eq_ignore_ascii_case(pattern))
}

/// What saving should do with text still sitting in the host field: the
/// pattern to bind first, `None` when there is nothing new to bind, or why the
/// text is not a usable pattern. Typing a host and saving must not drop it.
fn pending_host(hosts: &[String], input: &str) -> Result<Option<String>, &'static str> {
    let pattern = input.trim();
    if pattern.is_empty() || is_bound(hosts, pattern) {
        return Ok(None);
    }
    quick_validate_host_pattern(pattern)?;
    Ok(Some(pattern.to_string()))
}

fn key_row(name: &str, host_count: usize) -> StandardListViewItem {
    let hosts = match host_count {
        0 => "no hosts".to_string(),
        1 => "1 host".to_string(),
        n => format!("{n} hosts"),
    };
    format!("{name} \u{2014} {hosts}").as_str().into()
}

pub fn show_bind_hosts_dialog(request: BindHostsDialogRequest) {
    let Some(dialog) = build_bind_hosts_dialog(request) else {
        return;
    };
    let height = dialog.get_content_height();
    if let Err(e) = crate::window_placement::show_dialog(&dialog, 660.0, height) {
        tracing::error!(error = %e, "Failed to show bind-hosts dialog");
        dialog.invoke_cancel();
    }
}

/// The dialog, wired to answer `request`; `None` (already answered) if it cannot be created.
pub(crate) fn build_bind_hosts_dialog(request: BindHostsDialogRequest) -> Option<BindHostsDialog> {
    let dialog = match BindHostsDialog::new() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create bind-hosts dialog");
            let _ = request.response_tx.send(BindHostsResult::Cancelled);
            return None;
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
    let key_names: Rc<Vec<String>> = Rc::new(keys.iter().map(|k| k.name.clone()).collect());
    let touched: Rc<RefCell<HashSet<String>>> = Rc::new(RefCell::new(HashSet::new()));

    let initial_index = match initial_selection.as_deref() {
        Some(id) => key_ids.iter().position(|k| k == id).unwrap_or(0),
        None => 0,
    } as i32;

    let key_rows: Rc<VecModel<StandardListViewItem>> = Rc::new(VecModel::from(
        keys.iter()
            .map(|k| key_row(&k.name, k.hosts.len()))
            .collect::<Vec<_>>(),
    ));
    dialog.set_keys(ModelRc::from(key_rows.clone()));

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
        let weak = dialog.as_weak();
        move |idx: i32| {
            let Some(d) = weak.upgrade() else { return };
            let label = key_names
                .get(idx as usize)
                .map(|n| format!("Hosts for: {n}"))
                .unwrap_or_else(|| "(no key)".to_string());
            d.set_selected_key_label(label.into());
        }
    };

    let update_key_count = {
        let key_rows = key_rows.clone();
        let key_names = key_names.clone();
        move |idx: i32, count: usize| {
            if let Some(name) = key_names.get(idx as usize) {
                key_rows.set_row_data(idx as usize, key_row(name, count));
            }
        }
    };

    // Binds `host` to the selected key in the working state.
    let commit_host = {
        let working = working.clone();
        let key_ids = key_ids.clone();
        let hosts_model = hosts_model.clone();
        let update_count = update_key_count.clone();
        let touched = touched.clone();
        move |d: &BindHostsDialog, host: String| {
            let idx = d.get_selected_index();
            let Some(cipher_id) = key_ids.get(idx as usize).cloned() else {
                return;
            };
            d.set_error_message(host_pattern_warning(&host).unwrap_or("").into());
            d.set_new_host_text("".into());
            hosts_model.push(SharedString::from(host.as_str()));
            update_count(idx, hosts_model.row_count());
            touched.borrow_mut().insert(cipher_id.clone());
            working
                .borrow_mut()
                .entry(cipher_id)
                .or_default()
                .push(host);
        }
    };

    let selected_hosts = {
        let working = working.clone();
        let key_ids = key_ids.clone();
        move |d: &BindHostsDialog| -> Vec<String> {
            key_ids
                .get(d.get_selected_index() as usize)
                .and_then(|id| working.borrow().get(id).cloned())
                .unwrap_or_default()
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

    // on_key_selected
    {
        let weak = dialog.as_weak();
        dialog.on_key_selected(move |idx| {
            if let Some(d) = weak.upgrade() {
                d.set_new_host_text("".into());
                d.set_error_message("".into());
            }
            refresh_hosts_for(idx);
            update_selected_label(idx);
        });
    }

    // on_add_host
    {
        let weak = dialog.as_weak();
        let commit = commit_host.clone();
        let hosts = selected_hosts.clone();
        dialog.on_add_host(move || {
            let Some(d) = weak.upgrade() else { return };
            let pattern = d.get_new_host_text().trim().to_string();
            if let Err(msg) = quick_validate_host_pattern(&pattern) {
                d.set_error_message(msg.into());
                return;
            }
            if is_bound(&hosts(&d), &pattern) {
                d.set_error_message("Host pattern already bound to this key".into());
                return;
            }
            commit(&d, pattern);
        });
    }

    // on_remove_host
    {
        let weak = dialog.as_weak();
        let working = working.clone();
        let key_ids = key_ids.clone();
        let hosts_model = hosts_model.clone();
        let update_count = update_key_count.clone();
        let touched = touched.clone();
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
                        touched.borrow_mut().insert(cipher_id.clone());
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
            update_count(idx, hosts_model.row_count());
            d.set_error_message("".into());
        });
    }

    // on_save
    {
        let weak = dialog.as_weak();
        let tx = tx_cell.clone();
        let working = working.clone();
        let touched = touched.clone();
        dialog.on_save(move || {
            let Some(d) = weak.upgrade() else { return };
            match pending_host(&selected_hosts(&d), &d.get_new_host_text()) {
                Ok(Some(host)) => commit_host(&d, host),
                Ok(None) => {}
                Err(msg) => {
                    d.set_error_message(msg.into());
                    return;
                }
            }
            let working = working.borrow();
            let payload: BTreeMap<String, Vec<String>> = touched
                .borrow()
                .iter()
                .filter_map(|id| working.get(id).map(|hosts| (id.clone(), hosts.clone())))
                .collect();
            if let Some(sender) = tx.borrow_mut().take() {
                let _ = sender.send(BindHostsResult::Saved { bindings: payload });
            }
            let _ = d.hide();
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
    dialog.window().on_close_requested(move || {
        if let Some(sender) = tx_cell.borrow_mut().take() {
            let _ = sender.send(BindHostsResult::Cancelled);
        }
        slint::CloseRequestResponse::HideWindow
    });

    Some(dialog)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saving_keeps_a_host_that_was_typed_but_not_added() {
        let bound = ["github.com".to_string()];

        assert_eq!(pending_host(&bound, "  "), Ok(None));
        assert_eq!(
            pending_host(&bound, " gitlab.com "),
            Ok(Some("gitlab.com".to_string()))
        );
        // Already bound: nothing to add, and no reason to refuse the save.
        assert_eq!(pending_host(&bound, "GitHub.com"), Ok(None));
        assert!(pending_host(&bound, "two hosts").is_err());
    }
}
