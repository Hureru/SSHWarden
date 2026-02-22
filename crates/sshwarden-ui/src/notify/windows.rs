use tracing::{error, info};
use windows::core::{HSTRING, PCWSTR};

use crate::{AuthorizationResult, SignRequestInfo};

/// Show a TaskDialog for SSH sign authorization.
///
/// Uses the simple `TaskDialog` API (not `TaskDialogIndirect`) to present
/// a UAC-style dialog with shield icon, blue main instruction, and Yes/No buttons.
/// Falls back to MessageBox if TaskDialog fails.
pub async fn prompt_authorization(info: &SignRequestInfo) -> AuthorizationResult {
    let info_for_dialog = info.clone();
    let info_for_fallback = info.clone();

    let result =
        tokio::task::spawn_blocking(move || show_task_dialog(&info_for_dialog)).await;

    match result {
        Ok(Ok(auth)) => auth,
        Ok(Err(e)) => {
            error!(error = %e, "TaskDialog failed, falling back to MessageBox");
            tokio::task::spawn_blocking(move || show_message_box_fallback(&info_for_fallback))
                .await
                .unwrap_or(AuthorizationResult::Denied)
        }
        Err(e) => {
            error!(error = %e, "Authorization prompt task panicked");
            AuthorizationResult::Denied
        }
    }
}

/// Show a simple TaskDialog with Yes/No buttons and shield icon.
fn show_task_dialog(info: &SignRequestInfo) -> anyhow::Result<AuthorizationResult> {
    use windows::Win32::UI::Controls::{
        TaskDialog, TDCBF_NO_BUTTON, TDCBF_YES_BUTTON,
    };
    use windows::Win32::UI::WindowsAndMessaging::IDYES;

    let operation = match info.namespace.as_deref() {
        Some("git") => "Git 签名",
        Some(ns) => ns,
        None => "SSH 认证",
    };

    // Main instruction (large blue text)
    let instruction = format!(
        "{} 正在请求使用 SSH 密钥",
        info.process_name
    );
    let instruction_h = HSTRING::from(&instruction);

    // Content body
    let mut content = format!(
        "密钥: {}\n操作: {}",
        info.key_name, operation
    );
    if info.is_forwarding {
        content.push_str("\n\n\u{26A0} 通过代理转发（来自远程主机）");
    }
    content.push_str("\n\n是否允许本次签名？");
    let content_h = HSTRING::from(&content);

    let title_h = HSTRING::from("SSHWarden");

    let mut pressed_button: i32 = 0;

    let hr = unsafe {
        TaskDialog(
            None,
            None,
            &title_h,
            &instruction_h,
            &content_h,
            TDCBF_YES_BUTTON | TDCBF_NO_BUTTON,
            PCWSTR(65532u16 as *const u16), // TD_SHIELD_ICON
            Some(&mut pressed_button),
        )
    };

    if let Err(e) = hr {
        return Err(anyhow::anyhow!("TaskDialog failed: {}", e));
    }

    if pressed_button == IDYES.0 {
        info!("User approved via TaskDialog");
        Ok(AuthorizationResult::Approved)
    } else {
        info!("User denied via TaskDialog (button={})", pressed_button);
        Ok(AuthorizationResult::Denied)
    }
}

/// Show a TaskDialog for SSH sign authorization (blocking version).
///
/// Same as `prompt_authorization` but synchronous — for use inside `spawn_blocking`
/// when already on a blocking thread (e.g., combined Hello unlock + authorization).
pub fn prompt_authorization_blocking(info: &SignRequestInfo) -> AuthorizationResult {
    match show_task_dialog(info) {
        Ok(auth) => auth,
        Err(e) => {
            error!(error = %e, "TaskDialog failed, falling back to MessageBox");
            show_message_box_fallback(info)
        }
    }
}

fn show_message_box_fallback(info: &SignRequestInfo) -> AuthorizationResult {
    use windows::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDYES, MB_DEFBUTTON2, MB_ICONQUESTION, MB_SETFOREGROUND, MB_TOPMOST,
        MB_YESNO,
    };

    let operation = match info.namespace.as_deref() {
        Some("git") => "Git 签名",
        Some(ns) => ns,
        None => "SSH 认证",
    };

    let mut message = format!(
        "SSHWarden - SSH 签名请求\n\n\
         密钥: {}\n\
         应用: {}\n\
         操作: {}",
        info.key_name, info.process_name, operation
    );

    if info.is_forwarding {
        message.push_str("\n\n\u{26A0} 通过代理转发（来自远程主机）");
    }

    message.push_str("\n\n是否授权此操作？");

    let title = HSTRING::from("SSHWarden");
    let text = HSTRING::from(message);

    let flags = MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST;

    let result = unsafe { MessageBoxW(None, &text, &title, flags) };

    if result == IDYES {
        info!("User approved (MessageBox fallback)");
        AuthorizationResult::Approved
    } else {
        info!("User denied (MessageBox fallback)");
        AuthorizationResult::Denied
    }
}
