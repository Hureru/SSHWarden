//! Drives the dialogs' keyboard and mouse handling through Slint's own event
//! dispatch. Nothing is shown, but creating a dialog needs a display: skipped
//! without one.

use std::sync::Arc;
use std::time::Duration;

use slint::platform::{Key, PointerEventButton, WindowEvent};
use slint::{ComponentHandle, SharedString};
use tokio::sync::oneshot;

use crate::bind_hosts::slint_dialog::BindHostsDialog;
use crate::notify::slint_dialog::AuthDialog;
use crate::pick_key::slint_dialog::PickKeyDialog;
use crate::{
    AuthorizationResult, BindHostsKeyEntry, BindHostsRequest, BindHostsResult, PickKeyRequest,
    SignRequestInfo,
};

fn press(window: &slint::Window, key: impl Into<SharedString>) {
    let text = key.into();
    window.dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
    window.dispatch_event(WindowEvent::KeyReleased { text });
}

fn press_with_ctrl(window: &slint::Window, key: impl Into<SharedString>) {
    window.dispatch_event(WindowEvent::KeyPressed {
        text: Key::Control.into(),
    });
    press(window, key);
    window.dispatch_event(WindowEvent::KeyReleased {
        text: Key::Control.into(),
    });
}

fn click(window: &slint::Window, x: f32, y: f32) {
    let position = slint::LogicalPosition::new(x, y);
    let button = PointerEventButton::Left;
    window.dispatch_event(WindowEvent::PointerPressed { position, button });
    window.dispatch_event(WindowEvent::PointerReleased { position, button });
}

/// Let the delay that guards a fresh prompt run out.
fn wait_until_settled() {
    std::thread::sleep(Duration::from_millis(500));
    slint::platform::update_timers_and_animations();
}

/// Stands in for the first frame: nothing is drawn here, and a list only
/// learns the height of its rows when something visits them.
fn lay_out_list_at(window: &slint::Window, x: f32, y: f32) {
    let position = slint::LogicalPosition::new(x, y);
    window.dispatch_event(WindowEvent::PointerMoved { position });
    slint::platform::update_timers_and_animations();
}

fn auth_dialog() -> (AuthDialog, oneshot::Receiver<AuthorizationResult>) {
    let (response_tx, rx) = oneshot::channel();
    let info = SignRequestInfo {
        key_name: "work".to_string(),
        process_name: "ssh".to_string(),
        pid: 1,
        target: Some("example.com".to_string()),
        namespace: None,
        operation_kind: "ssh_authentication".to_string(),
        is_forwarding: false,
    };
    let request = crate::notify::AuthDialogRequest { info, response_tx };
    let dialog = crate::notify::slint_dialog::build_auth_dialog(request).expect("auth dialog");
    (dialog, rx)
}

/// The primary button sits in the bottom right corner of both prompts.
fn click_primary_button(window: &slint::Window, height: f32) {
    click(window, 360.0, height - 30.0);
}

/// Twelve keys, `id-1` to `id-12`.
fn pick_dialog() -> (PickKeyDialog, oneshot::Receiver<Option<String>>) {
    let (response_tx, rx) = oneshot::channel();
    let request = crate::pick_key::PickKeyDialogRequest {
        request: PickKeyRequest {
            keys: (1..=12)
                .map(|i| (format!("id-{i}"), format!("key {i}")))
                .collect(),
            process_name: "ssh".to_string(),
            target: "example.com".to_string(),
            is_forwarding: false,
        },
        response_tx,
    };
    let dialog =
        crate::pick_key::slint_dialog::build_pick_key_dialog(request).expect("pick dialog");
    (dialog, rx)
}

/// `keys` keys named `id-N`, each bound to `oldN.example.com`, with "github.com" typed in.
fn bind_dialog(
    keys: usize,
    initial_selection: Option<&str>,
) -> (BindHostsDialog, oneshot::Receiver<BindHostsResult>) {
    let (response_tx, rx) = oneshot::channel();
    let request = crate::bind_hosts::BindHostsDialogRequest {
        request: BindHostsRequest {
            keys: (1..=keys)
                .map(|i| BindHostsKeyEntry {
                    cipher_id: format!("id-{i}"),
                    name: format!("key {i}"),
                    hosts: vec![format!("old{i}.example.com")],
                })
                .collect(),
            initial_selection: initial_selection.map(str::to_string),
            prefill_host: Some("github.com".to_string()),
            approve_on_save: true,
        },
        response_tx,
    };
    let dialog =
        crate::bind_hosts::slint_dialog::build_bind_hosts_dialog(request).expect("bind dialog");
    (dialog, rx)
}

fn saved(rx: &mut oneshot::Receiver<BindHostsResult>) -> Vec<(String, Vec<String>)> {
    match rx.try_recv() {
        Ok(BindHostsResult::Saved { bindings }) => bindings.into_iter().collect(),
        other => panic!("expected a save, got {other:?}"),
    }
}

// One test: Slint binds its platform to the first thread that creates a window.
#[test]
fn dialogs_answer_to_keyboard_and_mouse() {
    if std::env::var_os("WAYLAND_DISPLAY").is_none() && std::env::var_os("DISPLAY").is_none() {
        return;
    }

    // A fresh authorization prompt takes nothing but Esc.
    let (dialog, mut rx) = auth_dialog();
    press(dialog.window(), Key::Escape);
    assert_eq!(rx.try_recv(), Ok(AuthorizationResult::Denied));

    let (fresh_auth, mut fresh_auth_rx) = auth_dialog();
    let auth_height = fresh_auth.get_content_height();
    for key in [Key::Return.into(), SharedString::from("b"), Key::Tab.into()] {
        press(fresh_auth.window(), key);
    }
    click_primary_button(fresh_auth.window(), auth_height);
    assert!(
        fresh_auth_rx.try_recv().is_err(),
        "answered before the delay"
    );

    // So does a fresh key picker, and a double click does not pick either.
    let (fresh_pick, mut fresh_pick_rx) = pick_dialog();
    let pick_height = fresh_pick.get_content_height();
    for key in [
        Key::Return.into(),
        SharedString::from("4"),
        Key::DownArrow.into(),
    ] {
        press(fresh_pick.window(), key);
    }
    click_primary_button(fresh_pick.window(), pick_height);
    assert!(fresh_pick_rx.try_recv().is_err(), "picked before the delay");

    let (dialog, mut rx) = pick_dialog();
    click(dialog.window(), 200.0, 230.0);
    click(dialog.window(), 200.0, 230.0);
    assert!(
        rx.try_recv().is_err(),
        "double click picked before the delay"
    );

    // The rest are driven after the delay; they are created here so that one wait covers them all.
    let mut auth: Vec<_> = (0..4).map(|_| auth_dialog()).collect();
    let mut pick: Vec<_> = (0..6).map(|_| pick_dialog()).collect();
    wait_until_settled();

    // Authorization: Enter approves, also on the prompt that ignored it at first.
    press(fresh_auth.window(), Key::Return);
    assert_eq!(fresh_auth_rx.try_recv(), Ok(AuthorizationResult::Approved));

    let (dialog, mut rx) = auth.pop().expect("auth dialog");
    click_primary_button(dialog.window(), auth_height);
    assert_eq!(rx.try_recv(), Ok(AuthorizationResult::Approved));

    let (dialog, mut rx) = auth.pop().expect("auth dialog");
    press(dialog.window(), "b");
    assert_eq!(rx.try_recv(), Ok(AuthorizationResult::BindRequested));

    // Tab moves the focus to the first button, where Space presses it ...
    let (dialog, mut rx) = auth.pop().expect("auth dialog");
    press(dialog.window(), Key::Tab);
    press(dialog.window(), " ");
    assert_eq!(rx.try_recv(), Ok(AuthorizationResult::BindRequested));

    // ... and Esc still denies from there.
    let (dialog, mut rx) = auth.pop().expect("auth dialog");
    press(dialog.window(), Key::Tab);
    press(dialog.window(), Key::Escape);
    assert_eq!(rx.try_recv(), Ok(AuthorizationResult::Denied));

    // Key picker: arrows move, Enter takes the current row. The Down pressed
    // while it was fresh did not move the selection, and a click beside the
    // list (here on the title) does not take the focus out of it.
    click(fresh_pick.window(), 200.0, 25.0);
    press(fresh_pick.window(), Key::DownArrow);
    press(fresh_pick.window(), Key::DownArrow);
    press(fresh_pick.window(), Key::Return);
    assert_eq!(fresh_pick_rx.try_recv(), Ok(Some("id-3".to_string())));

    let (dialog, mut rx) = pick.pop().expect("pick dialog");
    press(dialog.window(), Key::End);
    press(dialog.window(), Key::Return);
    assert_eq!(rx.try_recv(), Ok(Some("id-12".to_string())));

    // A digit takes its row.
    let (dialog, mut rx) = pick.pop().expect("pick dialog");
    press(dialog.window(), "4");
    assert_eq!(rx.try_recv(), Ok(Some("id-4".to_string())));

    let (dialog, mut rx) = pick.pop().expect("pick dialog");
    click_primary_button(dialog.window(), pick_height);
    assert_eq!(rx.try_recv(), Ok(Some("id-1".to_string())));

    // A double click takes the row; one click only selects it.
    let (dialog, mut rx) = pick.pop().expect("pick dialog");
    click(dialog.window(), 200.0, 230.0);
    assert!(rx.try_recv().is_err(), "a single click picked a key");
    click(dialog.window(), 200.0, 230.0);
    assert!(matches!(rx.try_recv(), Ok(Some(_))), "double click");

    // With nothing selected (Ctrl+Space) Enter picks nothing.
    let (dialog, mut rx) = pick.pop().expect("pick dialog");
    press_with_ctrl(dialog.window(), " ");
    press(dialog.window(), Key::Return);
    assert!(rx.try_recv().is_err(), "picked without a selection");

    let (dialog, mut rx) = pick.pop().expect("pick dialog");
    press(dialog.window(), Key::Tab);
    press(dialog.window(), Key::Escape);
    assert_eq!(rx.try_recv(), Ok(None));

    // PIN: typing still lands in the field after a click beside it, and Esc
    // cancels while the field has focus.
    let (response_tx, mut rx) = oneshot::channel();
    let dialog =
        crate::unlock::slint_dialog::build_pin_dialog(response_tx, Arc::new(|_: &str| true), None)
            .expect("pin dialog");
    click(dialog.window(), 300.0, 25.0);
    press(dialog.window(), "1");
    assert_eq!(dialog.get_pin_text(), "1");
    press(dialog.window(), Key::Escape);
    assert_eq!(rx.try_recv(), Ok(None));

    // Bind hosts: Ctrl+Enter saves, including the host still in the text field.
    let (dialog, mut rx) = bind_dialog(1, None);
    press_with_ctrl(dialog.window(), Key::Return);
    assert_eq!(
        saved(&mut rx),
        [(
            "id-1".to_string(),
            vec!["old1.example.com".to_string(), "github.com".to_string()]
        )]
    );

    // Without the mouse: the key list moves on from the preselected key, Enter adds a host.
    let (dialog, mut rx) = bind_dialog(5, Some("id-4"));
    let window = dialog.window();
    lay_out_list_at(window, 100.0, 200.0);
    press(window, Key::Backtab);
    press(window, Key::DownArrow);
    press(window, Key::Tab);
    for c in ["x", ".", "i", "o"] {
        press(window, c);
    }
    press(window, Key::Return);
    assert!(rx.try_recv().is_err(), "Enter in the host field saved");
    press_with_ctrl(window, Key::Return);
    assert_eq!(
        saved(&mut rx),
        [(
            "id-5".to_string(),
            vec!["old5.example.com".to_string(), "x.io".to_string()]
        )]
    );

    // Deselecting a row (Ctrl+Space) leaves the key being edited in place: the typed host is kept.
    let (dialog, mut rx) = bind_dialog(5, Some("id-4"));
    let window = dialog.window();
    lay_out_list_at(window, 100.0, 200.0);
    press(window, Key::Backtab);
    press_with_ctrl(window, " ");
    press_with_ctrl(window, Key::Return);
    assert_eq!(
        saved(&mut rx),
        [(
            "id-4".to_string(),
            vec!["old4.example.com".to_string(), "github.com".to_string()]
        )]
    );

    // Esc cancels while the host field has focus.
    let (dialog, mut rx) = bind_dialog(1, None);
    press(dialog.window(), Key::Escape);
    assert!(matches!(rx.try_recv(), Ok(BindHostsResult::Cancelled)));
}
