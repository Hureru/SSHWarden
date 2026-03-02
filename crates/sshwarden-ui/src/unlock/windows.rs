use tracing::info;
use windows::core::HSTRING;

use super::UnlockResult;

/// Windows Hello unlock prompt using WinRT UserConsentVerifier.
///
/// Shows the system biometric/PIN authentication dialog.
/// Returns NotAvailable/Failed directly when Hello is not available,
/// so the caller can try alternative unlock methods (e.g., PIN dialog).
pub async fn prompt_windows_hello() -> UnlockResult {
    match tokio::task::spawn_blocking(do_unlock).await {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(error = %e, "Unlock task panicked");
            UnlockResult::Failed
        }
    }
}

fn do_unlock() -> UnlockResult {
    try_windows_hello()
}

/// Attempt Windows Hello via UserConsentVerifier.
fn try_windows_hello() -> UnlockResult {
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    };

    // Check if Windows Hello is available on this device
    let availability = match UserConsentVerifier::CheckAvailabilityAsync() {
        Ok(op) => match op.get() {
            Ok(avail) => avail,
            Err(e) => {
                tracing::error!(error = %e, "Failed to check Windows Hello availability");
                return UnlockResult::NotAvailable;
            }
        },
        Err(e) => {
            tracing::error!(error = %e, "Failed to start availability check");
            return UnlockResult::NotAvailable;
        }
    };

    if availability != UserConsentVerifierAvailability::Available {
        info!(?availability, "Windows Hello not available");
        return UnlockResult::NotAvailable;
    }

    // Start a background thread to find and center the Windows Hello dialog
    let stop_centering = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_clone = stop_centering.clone();
    std::thread::spawn(move || {
        let mut interval_ms = 50u64;
        while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
            focus_and_center_security_prompt();
            std::thread::sleep(std::time::Duration::from_millis(interval_ms));
            // Gradual backoff: 50 → 100 → 200ms (cap)
            if interval_ms < 200 {
                interval_ms = (interval_ms * 2).min(200);
            }
        }
    });

    // Request verification
    let message = HSTRING::from("请通过 Windows Hello 验证您的身份以解锁 SSHWarden 密码库");
    let result = match UserConsentVerifier::RequestVerificationAsync(&message) {
        Ok(op) => {
            let r = op.get();
            // Stop the centering thread
            stop_centering.store(true, std::sync::atomic::Ordering::Relaxed);
            match r {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "Windows Hello verification failed");
                    return UnlockResult::Failed;
                }
            }
        }
        Err(e) => {
            stop_centering.store(true, std::sync::atomic::Ordering::Relaxed);
            tracing::error!(error = %e, "Failed to start verification");
            return UnlockResult::Failed;
        }
    };

    match result {
        UserConsentVerificationResult::Verified => {
            info!("Windows Hello verification successful");
            UnlockResult::Verified
        }
        UserConsentVerificationResult::Canceled => {
            info!("Windows Hello verification cancelled by user");
            UnlockResult::Cancelled
        }
        UserConsentVerificationResult::DeviceNotPresent => {
            info!("Windows Hello device not present");
            UnlockResult::NotAvailable
        }
        _ => {
            info!(?result, "Windows Hello verification failed");
            UnlockResult::Failed
        }
    }
}

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
