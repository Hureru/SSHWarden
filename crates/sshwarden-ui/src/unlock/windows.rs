/// Public wrapper for hello_crypto module to call.
pub(super) fn focus_and_center_security_prompt_pub() {
    focus_and_center_security_prompt();
}

/// Find the Windows Hello security prompt window and center it on screen.
fn focus_and_center_security_prompt() {
    use windows::core::s;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        FindWindowA, GetForegroundWindow, GetSystemMetrics, GetWindowRect, MoveWindow,
        SetForegroundWindow, SM_CXSCREEN, SM_CYSCREEN,
    };

    let hwnd = match unsafe { FindWindowA(s!("Credential Dialog Xaml Host"), None) } {
        Ok(h) if h != HWND::default() => h,
        _ => return,
    };

    unsafe {
        // Get window dimensions
        let mut rect = std::mem::zeroed();
        if GetWindowRect(hwnd, &mut rect).is_err() {
            return;
        }

        let win_w = rect.right - rect.left;
        let win_h = rect.bottom - rect.top;
        let screen_w = GetSystemMetrics(SM_CXSCREEN);
        let screen_h = GetSystemMetrics(SM_CYSCREEN);

        // Center on screen
        let x = (screen_w - win_w) / 2;
        let y = (screen_h - win_h) / 2;

        let _ = MoveWindow(hwnd, x, y, win_w, win_h, true);

        // Also bring to foreground
        let fg = GetForegroundWindow();
        if fg != hwnd {
            let _ = SetForegroundWindow(hwnd);
        }
    }
}
