use tracing::info;

use crate::{AuthorizationResult, SignRequestInfo};

/// Fallback authorization prompt for non-Windows platforms.
/// Auto-approves for now (Phase 3 will add platform-specific implementations).
pub async fn prompt_authorization(info: &SignRequestInfo) -> AuthorizationResult {
    info!(
        key = %info.key_name,
        process = %info.process_name,
        "Authorization auto-approved (no platform UI available)"
    );
    AuthorizationResult::Approved
}
