#![allow(clippy::print_stdout, clippy::print_stderr)]
//! Show one dialog with sample data, for checking layout, keys and the
//! accessibility tree by hand. Prints the dialog's answer and exits.
//!
//! Run with: cargo run -p sshwarden-ui --example preview_dialogs -- <which>
//! where <which> is one of: auth, auth-long, pin, pick, pick-short, bind

use sshwarden_ui::{
    bind_hosts, notify, pick_key, unlock, BindHostsKeyEntry, BindHostsRequest, PickKeyRequest,
    SignRequestInfo, UnlockRequestContext,
};
use tokio::sync::oneshot;

const LONG_KEY: &str = "US-Phoenix-Arm-4c24G production deploy key (rotated 2026-10)";

fn sign_info(long: bool) -> SignRequestInfo {
    SignRequestInfo {
        key_name: if long { LONG_KEY } else { "work-github" }.to_string(),
        process_name: if long {
            "git-remote-https-wrapper"
        } else {
            "ssh"
        }
        .to_string(),
        pid: 45844,
        target: Some(
            if long {
                "deploy@bastion-eu-central-1.internal.example.com:infrastructure/terraform-modules"
            } else {
                "git@github.com:acme/api"
            }
            .to_string(),
        ),
        namespace: None,
        operation_kind: "ssh_authentication".to_string(),
        is_forwarding: long,
    }
}

/// Print whatever the dialog answered, then stop the event loop.
fn report<T: std::fmt::Debug + Send + 'static>(rx: oneshot::Receiver<T>) {
    std::thread::spawn(move || {
        println!("result: {:?}", rx.blocking_recv());
        let _ = slint::quit_event_loop();
    });
}

fn show(which: &str) -> bool {
    match which {
        "auth" | "auth-long" => {
            let (response_tx, rx) = oneshot::channel();
            notify::show_auth_dialog(notify::AuthDialogRequest {
                info: sign_info(which == "auth-long"),
                response_tx,
            });
            report(rx);
        }
        "pin" => {
            let (response_tx, rx) = oneshot::channel();
            let context = UnlockRequestContext {
                key_name: "work-github".to_string(),
                process_name: "ssh".to_string(),
                operation_kind: "ssh_authentication".to_string(),
                is_forwarding: false,
            };
            // The sample PIN is 1234.
            let validator = std::sync::Arc::new(|pin: &str| pin == "1234");
            unlock::show_pin_dialog(response_tx, validator, Some(context));
            report(rx);
        }
        "pick" | "pick-short" => {
            let long = which == "pick";
            let (response_tx, rx) = oneshot::channel();
            let mut keys: Vec<(String, String)> = (1..=if long { 20 } else { 3 })
                .map(|i| (format!("id-{i}"), format!("server-key-{i:02}")))
                .collect();
            keys[2].1 = LONG_KEY.to_string();
            pick_key::show_pick_key_dialog(pick_key::PickKeyDialogRequest {
                request: PickKeyRequest {
                    keys,
                    process_name: "ssh".to_string(),
                    target: "git@github.com:acme/api".to_string(),
                    is_forwarding: long,
                },
                response_tx,
            });
            report(rx);
        }
        "bind" => {
            let (response_tx, rx) = oneshot::channel();
            let keys = (1..=30)
                .map(|i| BindHostsKeyEntry {
                    cipher_id: format!("id-{i}"),
                    name: if i == 3 {
                        LONG_KEY.to_string()
                    } else {
                        format!("server-key-{i:02}")
                    },
                    hosts: (0..i % 3).map(|h| format!("host{h}.example.com")).collect(),
                })
                .collect();
            bind_hosts::show_bind_hosts_dialog(bind_hosts::BindHostsDialogRequest {
                request: BindHostsRequest {
                    keys,
                    // Far down the list: the dialog has to open scrolled to it.
                    initial_selection: Some("id-27".to_string()),
                    prefill_host: Some("github.com".to_string()),
                    approve_on_save: true,
                },
                response_tx,
            });
            report(rx);
        }
        _ => return false,
    }
    true
}

fn main() {
    sshwarden_ui::init();
    tracing_subscriber::fmt::init();

    let which = std::env::args().nth(1).unwrap_or_default();
    // Same order as the daemon: the event loop runs first, dialogs come later.
    slint::Timer::single_shot(std::time::Duration::ZERO, move || {
        if !show(&which) {
            eprintln!("usage: preview_dialogs <auth|auth-long|pin|pick|pick-short|bind>");
            let _ = slint::quit_event_loop();
        }
    });
    if let Err(e) = slint::run_event_loop_until_quit() {
        eprintln!("event loop failed: {e}");
    }
}
