//! Notification-hub connection setup and URL resolution.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 3).

use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::info;

use crate::runtime::{NotificationConnectionState, NotificationRuntimeState};

/// Time budget for the `/api/config` notification-URL discovery request.
const NOTIFICATION_DISCOVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Time budget for establishing the notification-hub connection.
const NOTIFICATION_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

pub(crate) fn notification_options(
    config: &sshwarden_config::Config,
) -> sshwarden_api::NotificationOptions {
    sshwarden_api::NotificationOptions {
        keepalive_interval: std::time::Duration::from_secs(
            config.agent.notification_keepalive_interval.max(1),
        ),
        idle_timeout: std::time::Duration::from_secs(config.agent.notification_idle_timeout.max(1)),
        reconnect_attempts_before_fallback: config
            .agent
            .notification_reconnect_attempts_before_fallback,
        reconnect_max_backoff: std::time::Duration::from_secs(
            config.agent.notification_reconnect_max_backoff.max(1),
        ),
        fallback_sync_interval: std::time::Duration::from_secs(config.agent.sync_interval),
    }
}

pub(crate) async fn connect_notification_client(
    config: &sshwarden_config::Config,
    api_client: Option<&sshwarden_api::BitwardenClient>,
    access_token: &str,
    notification_rx: &mut Option<tokio::sync::mpsc::Receiver<sshwarden_api::SyncEvent>>,
    notification_client: &mut Option<sshwarden_api::NotificationClient>,
    notification_state: &Arc<RwLock<NotificationRuntimeState>>,
) {
    if let Some(client) = notification_client.take() {
        client.stop();
    }
    *notification_rx = None;

    let notif_url = resolve_notifications_url(config, api_client).await;
    {
        let mut state = notification_state.write().await;
        state.state = NotificationConnectionState::Starting;
        state.url = Some(notif_url.clone());
        state.last_error = None;
    }
    info!("Attempting to connect to notification hub: {}", notif_url);
    // Bounded: this runs inside a control action (and after unlock), so a hub
    // that accepts the connection but never completes the handshake must not
    // hold the caller forever.
    let connect_result = tokio::time::timeout(
        NOTIFICATION_CONNECT_TIMEOUT,
        sshwarden_api::NotificationClient::connect_with_options(
            &notif_url,
            access_token,
            notification_options(config),
        ),
    )
    .await;
    match connect_result {
        Ok(Ok((notif_client, rx))) => {
            *notification_rx = Some(rx);
            *notification_client = Some(notif_client);
            let mut state = notification_state.write().await;
            state.state = NotificationConnectionState::Running;
            state.reconnect_attempts = 0;
            state.last_connected_at = Some(std::time::Instant::now());
            state.last_error = None;
        }
        Ok(Err(e)) => {
            tracing::warn!("Failed to start notification client: {}", e);
            let mut state = notification_state.write().await;
            state.state = NotificationConnectionState::Failed;
            state.reconnect_attempts = state.reconnect_attempts.saturating_add(1);
            state.last_error = Some(e.to_string());
        }
        Err(_) => {
            let error = format!(
                "connecting to the notification hub timed out after {}s",
                NOTIFICATION_CONNECT_TIMEOUT.as_secs()
            );
            tracing::warn!("Failed to start notification client: {}", error);
            let mut state = notification_state.write().await;
            state.state = NotificationConnectionState::Failed;
            state.reconnect_attempts = state.reconnect_attempts.saturating_add(1);
            state.last_error = Some(error);
        }
    }
}

pub(crate) async fn resolve_notifications_url(
    config: &sshwarden_config::Config,
    api_client: Option<&sshwarden_api::BitwardenClient>,
) -> String {
    if let Some(explicit) = config.server.notifications_url.as_deref() {
        return explicit.to_string();
    }

    if let Some(client) = api_client {
        // Bounded: this runs before the hub connection and inside control
        // actions, so an unresponsive `/api/config` must fall back to the
        // built-in URL rules instead of stalling the caller.
        match tokio::time::timeout(
            NOTIFICATION_DISCOVERY_TIMEOUT,
            client.discover_notifications_url(),
        )
        .await
        {
            Ok(Ok(Some(url))) => return url,
            Ok(Ok(None)) => tracing::debug!("Server config discovery omitted notifications URL"),
            Ok(Err(e)) => tracing::debug!("Server config discovery failed: {}", e),
            Err(_) => tracing::debug!(
                "Server config discovery timed out after {}s",
                NOTIFICATION_DISCOVERY_TIMEOUT.as_secs()
            ),
        }
    }

    config.server.notifications_url()
}
