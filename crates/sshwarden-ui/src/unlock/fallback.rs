use tracing::info;

use super::UnlockResult;

/// Fallback Windows Hello prompt for non-Windows platforms.
/// Always returns NotAvailable since Windows Hello is Windows-only.
pub async fn prompt_windows_hello() -> UnlockResult {
    info!("Windows Hello not available on this platform");
    UnlockResult::NotAvailable
}
