//! Shared runtime state types: notification state, secure key cache, local
//! cache key handle, and internal runtime events.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 2).

use std::sync::Arc;

use tokio::sync::RwLock;
use zeroize::Zeroize;

/// Aggregated notification-connection state rendered by `status`/`doctor`.
///
/// The API layer owns the connection itself and pushes
/// [`sshwarden_api::NotificationStatus`] snapshots on every transition; this
/// struct is the daemon's mirror of those snapshots plus the timing facts the
/// API layer cannot know (last delivered event, last successful sync, cache
/// staleness). It used to be written only once, at connect time, which made a
/// dropped socket look identical to a healthy one.
#[derive(Clone, Debug)]
pub(crate) struct NotificationRuntimeState {
    pub(crate) state: NotificationConnectionState,
    pub(crate) url: Option<String>,
    pub(crate) last_error: Option<String>,
    /// Consecutive failed connect attempts (0 while connected).
    pub(crate) consecutive_failures: u32,
    /// Failed connect attempts since this client was created.
    pub(crate) total_failures: u32,
    /// Delay before the next reconnect attempt, while degraded.
    pub(crate) next_retry_in_secs: Option<u64>,
    /// Successful connects since this client was created.
    pub(crate) connects: u64,
    pub(crate) last_connected_at: Option<std::time::Instant>,
    pub(crate) last_event_at: Option<std::time::Instant>,
    pub(crate) last_fallback_sync_at: Option<std::time::Instant>,
    /// Last successful sync of any kind (manual, auto, or fallback).
    pub(crate) last_sync_at: Option<std::time::Instant>,
    /// The last sync succeeded but refreshing the local key cache failed.
    pub(crate) stale_cache: bool,
    pub(crate) stale_cache_error: Option<String>,
}

/// Re-exported so the daemon and `status` share one vocabulary with the API
/// layer instead of maintaining a parallel enum.
pub(crate) use sshwarden_api::NotificationConnectionState;

impl Default for NotificationRuntimeState {
    fn default() -> Self {
        Self {
            state: NotificationConnectionState::NotStarted,
            url: None,
            last_error: None,
            consecutive_failures: 0,
            total_failures: 0,
            next_retry_in_secs: None,
            connects: 0,
            last_connected_at: None,
            last_event_at: None,
            last_fallback_sync_at: None,
            last_sync_at: None,
            stale_cache: false,
            stale_cache_error: None,
        }
    }
}

impl NotificationRuntimeState {
    pub(crate) fn state_name(&self) -> &'static str {
        self.state.name()
    }

    /// A connection attempt is starting.
    pub(crate) fn begin_connect(&mut self, url: &str) {
        self.state = NotificationConnectionState::Connecting;
        self.url = Some(url.to_string());
        self.last_error = None;
        self.next_retry_in_secs = None;
    }

    /// Mirror an API-layer connection snapshot.
    pub(crate) fn apply_status(&mut self, status: &sshwarden_api::NotificationStatus) {
        self.state = status.state;
        self.consecutive_failures = status.consecutive_failures;
        self.total_failures = status.total_failures;
        self.next_retry_in_secs = status.next_retry_in.map(|delay| delay.as_secs());
        self.last_error = status.last_error.clone();
        self.connects = status.connects;
        if status.state == NotificationConnectionState::Connected {
            // Every successful (re)connect, not just the first one.
            self.last_connected_at = Some(std::time::Instant::now());
        }
    }

    /// The client could not be created at all, so no status stream exists.
    pub(crate) fn mark_client_failed(&mut self, error: impl Into<String>) {
        self.state = NotificationConnectionState::Degraded;
        self.last_error = Some(error.into());
        self.total_failures = self.total_failures.saturating_add(1);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.next_retry_in_secs = None;
    }

    pub(crate) fn record_event(&mut self) {
        self.last_event_at = Some(std::time::Instant::now());
    }

    pub(crate) fn record_fallback_sync(&mut self) {
        let now = std::time::Instant::now();
        self.last_event_at = Some(now);
        self.last_fallback_sync_at = Some(now);
    }

    pub(crate) fn record_successful_sync(&mut self) {
        self.last_sync_at = Some(std::time::Instant::now());
    }

    /// A successful local-key-cache refresh clears the staleness it reported.
    pub(crate) fn mark_cache_refreshed(&mut self) {
        self.stale_cache = false;
        self.stale_cache_error = None;
    }

    pub(crate) fn mark_cache_stale(&mut self, error: impl Into<String>) {
        self.stale_cache = true;
        self.stale_cache_error = Some(error.into());
    }

    /// Drop everything: used when the device is forgotten or re-authenticated.
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }

    /// One-line, human-readable connection health.
    ///
    /// Shared by the `status` text view and the control-channel summary so both
    /// say the same thing. It never claims health it cannot observe: an idle
    /// socket reads as `connected`, a dropped one as `retrying (…)`.
    pub(crate) fn health_label(&self, authenticated: bool) -> String {
        notification_health_label(&NotificationHealth {
            state: self.state_name(),
            connects: self.connects,
            consecutive_failures: self.consecutive_failures,
            next_retry_in_secs: self.next_retry_in_secs,
            last_error: self.last_error.as_deref(),
            up_for_secs: self.last_connected_at.map(|at| at.elapsed().as_secs()),
            authenticated,
        })
    }

    pub(crate) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "state": self.state_name(),
            "url": self.url,
            "last_error": self.last_error,
            // Kept for compatibility; now means "consecutive failed attempts",
            // which is what consumers actually want to alert on.
            "reconnect_attempts": self.consecutive_failures,
            "consecutive_failures": self.consecutive_failures,
            "total_failures": self.total_failures,
            "next_retry_in_secs": self.next_retry_in_secs,
            "connects": self.connects,
            // Age of the most recent *successful* connection.
            "last_connected_age_secs": self.last_connected_at.map(|t| t.elapsed().as_secs()),
            "last_event_age_secs": self.last_event_at.map(|t| t.elapsed().as_secs()),
            "last_fallback_sync_age_secs": self.last_fallback_sync_at.map(|t| t.elapsed().as_secs()),
            "last_sync_age_secs": self.last_sync_at.map(|t| t.elapsed().as_secs()),
            "stale_cache": self.stale_cache,
            "stale_cache_error": self.stale_cache_error,
        })
    }
}

/// Compact, stable duration rendering ("45s", "12m", "3h07m").
pub(crate) fn humanize_age(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Keys of the `notification` object in `status --json`.
///
/// The agent-unreachable view builds its `notification` object from this list so
/// both views always expose the same keys (consumers used to have to special
/// case the offline shape).
pub(crate) const NOTIFICATION_JSON_KEYS: &[&str] = &[
    "state",
    "url",
    "last_error",
    "reconnect_attempts",
    "consecutive_failures",
    "total_failures",
    "next_retry_in_secs",
    "connects",
    "last_connected_age_secs",
    "last_event_age_secs",
    "last_fallback_sync_age_secs",
    "last_sync_age_secs",
    "stale_cache",
    "stale_cache_error",
];

/// Connection-health inputs, decoupled from [`NotificationRuntimeState`] so the
/// CLI can render the same wording from `status --json` fields without
/// reconstructing daemon-side types.
pub(crate) struct NotificationHealth<'a> {
    /// [`NotificationConnectionState::name`].
    pub(crate) state: &'a str,
    pub(crate) connects: u64,
    pub(crate) consecutive_failures: u32,
    pub(crate) next_retry_in_secs: Option<u64>,
    pub(crate) last_error: Option<&'a str>,
    /// Age of the most recent successful connection.
    pub(crate) up_for_secs: Option<u64>,
    pub(crate) authenticated: bool,
}

/// Render connection health from primitives.
///
/// Unknown states render as themselves rather than as "healthy".
pub(crate) fn notification_health_label(health: &NotificationHealth<'_>) -> String {
    match health.state {
        "not_started" if !health.authenticated => "off (no Bitwarden session)".to_string(),
        "not_started" => "off (not started)".to_string(),
        "starting" => "connecting…".to_string(),
        "running" => {
            let uptime = health
                .up_for_secs
                .map(|secs| format!(", up {}", humanize_age(secs)))
                .unwrap_or_default();
            if health.connects > 1 {
                format!("connected ({} reconnects{uptime})", health.connects - 1)
            } else {
                format!("connected{uptime}")
            }
        }
        "failed" => {
            let next = health
                .next_retry_in_secs
                .map(|delay| format!(", next attempt in {delay}s"))
                .unwrap_or_default();
            let error = health
                .last_error
                .map(|error| format!(": {error}"))
                .unwrap_or_default();
            if health.consecutive_failures == 0 {
                // An established connection was just lost, so no reconnect has
                // failed yet: say that rather than reporting "0 failed attempts".
                format!("lost connection, retrying{next}{error}")
            } else {
                format!(
                    "retrying ({} failed attempt(s){next}{error})",
                    health.consecutive_failures
                )
            }
        }
        "stopped" => "stopped".to_string(),
        // The daemon (or an older one) did not report a state at all.
        "unknown" => "unknown".to_string(),
        other => format!("unknown ({other})"),
    }
}

/// Secure key cache: automatically zeroes PEM private keys on drop/clear.
pub(crate) struct SecureKeyCache(pub(crate) Vec<(String, String, String)>);

pub(crate) type AuthorizationMemorySet = Arc<RwLock<std::collections::HashSet<(String, String)>>>;
pub(crate) type KeyMaterialFingerprints = Arc<RwLock<std::collections::HashMap<String, String>>>;

#[derive(Default)]
pub(crate) struct LocalCacheKeyState(pub(crate) Option<sshwarden_api::crypto::SymmetricKey>);

impl LocalCacheKeyState {
    pub(crate) fn set(&mut self, key: sshwarden_api::crypto::SymmetricKey) {
        self.0 = Some(key);
    }

    pub(crate) fn clone_key(&self) -> Option<sshwarden_api::crypto::SymmetricKey> {
        self.0.clone()
    }

    pub(crate) fn clear(&mut self) {
        self.0 = None;
    }
}

pub(crate) type LocalCacheKeyHandle = Arc<RwLock<LocalCacheKeyState>>;

impl SecureKeyCache {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn set(&mut self, keys: Vec<(String, String, String)>) {
        self.clear();
        self.0 = keys;
    }

    pub(crate) fn clear(&mut self) {
        for (pem, _, _) in &mut self.0 {
            pem.zeroize();
        }
        self.0.clear();
    }

    pub(crate) fn clone_inner(&self) -> Vec<(String, String, String)> {
        self.0.clone()
    }
}

impl Drop for SecureKeyCache {
    fn drop(&mut self) {
        self.clear();
    }
}

pub(crate) type CachedKeyTuples = Arc<RwLock<SecureKeyCache>>;

/// Type alias for the UI request sender passed through the system.
pub(crate) type UIRequestTx = Arc<tokio::sync::mpsc::Sender<sshwarden_ui::UIRequest>>;

/// Internal events emitted by spawned SSH request handlers back to the main loop.
#[allow(clippy::enum_variant_names)]
pub(crate) enum RuntimeEvent {
    #[cfg(windows)]
    AutoUnlockedWindowsHello,
    AutoUnlockedPin {
        pin: String,
    },
    AutoUnlockedNative,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sshwarden_api::{NotificationConnectionState, NotificationStatus};

    fn status(state: NotificationConnectionState) -> NotificationStatus {
        NotificationStatus {
            state,
            ..NotificationStatus::default()
        }
    }

    #[test]
    fn apply_status_tracks_every_reconnect_not_just_the_first() {
        let mut state = NotificationRuntimeState::default();
        for expected in 1..=3 {
            state.apply_status(&NotificationStatus {
                state: NotificationConnectionState::Connected,
                connects: expected,
                ..NotificationStatus::default()
            });
            assert_eq!(state.connects, expected);
            assert!(state.last_connected_at.is_some());
        }
        assert_eq!(state.state_name(), "running");
    }

    #[test]
    fn degraded_status_carries_the_retry_diagnostics() {
        let mut state = NotificationRuntimeState::default();
        state.apply_status(&NotificationStatus {
            state: NotificationConnectionState::Degraded,
            consecutive_failures: 2,
            total_failures: 7,
            next_retry_in: Some(std::time::Duration::from_secs(30)),
            last_error: Some("HTTP error: 401".to_string()),
            connects: 4,
        });
        assert_eq!(state.state_name(), "failed");
        assert_eq!(state.consecutive_failures, 2);
        assert_eq!(state.total_failures, 7);
        assert_eq!(state.next_retry_in_secs, Some(30));
        // A dropped connection must not erase the last successful connect.
        assert_eq!(state.connects, 4);
        let label = state.health_label(true);
        assert!(label.contains("retrying"), "{label}");
        assert!(label.contains("next attempt in 30s"), "{label}");
        assert!(label.contains("401"), "{label}");
    }

    #[test]
    fn a_just_lost_connection_is_not_reported_as_zero_failures() {
        let mut state = NotificationRuntimeState::default();
        // What the API layer publishes the moment an established socket drops:
        // counters reset by the successful connect, a reason, and a retry delay.
        state.apply_status(&NotificationStatus {
            state: NotificationConnectionState::Degraded,
            consecutive_failures: 0,
            total_failures: 1,
            next_retry_in: Some(std::time::Duration::from_secs(1)),
            last_error: Some("no hub traffic for 90s".to_string()),
            connects: 1,
        });
        let label = state.health_label(true);
        assert_eq!(
            label,
            "lost connection, retrying, next attempt in 1s: no hub traffic for 90s"
        );
    }

    #[test]
    fn client_failure_without_a_status_stream_is_reported() {
        let mut state = NotificationRuntimeState::default();
        state.mark_client_failed("invalid token");
        assert_eq!(state.state_name(), "failed");
        assert_eq!(state.consecutive_failures, 1);
        assert_eq!(state.last_error.as_deref(), Some("invalid token"));
    }

    #[test]
    fn health_label_distinguishes_offline_reasons() {
        let mut state = NotificationRuntimeState::default();
        assert_eq!(state.health_label(false), "off (no Bitwarden session)");
        assert_eq!(state.health_label(true), "off (not started)");

        state.apply_status(&status(NotificationConnectionState::Connecting));
        assert_eq!(state.health_label(true), "connecting…");

        state.apply_status(&NotificationStatus {
            state: NotificationConnectionState::Connected,
            connects: 3,
            ..NotificationStatus::default()
        });
        let label = state.health_label(true);
        assert!(label.starts_with("connected (2 reconnects"), "{label}");
    }

    #[test]
    fn cache_staleness_is_clearable_again() {
        let mut state = NotificationRuntimeState::default();
        state.mark_cache_stale("refresh blew up");
        assert!(state.stale_cache);
        state.mark_cache_refreshed();
        assert!(!state.stale_cache);
        assert!(state.stale_cache_error.is_none());
    }

    #[test]
    fn json_keeps_the_legacy_keys() {
        let mut state = NotificationRuntimeState::default();
        state.apply_status(&NotificationStatus {
            state: NotificationConnectionState::Degraded,
            consecutive_failures: 2,
            ..NotificationStatus::default()
        });
        let json = state.to_json();
        for key in [
            "state",
            "url",
            "last_error",
            "reconnect_attempts",
            "last_connected_age_secs",
            "last_event_age_secs",
            "last_fallback_sync_age_secs",
            "stale_cache",
            "stale_cache_error",
        ] {
            assert!(json.get(key).is_some(), "missing legacy key {key}");
        }
        assert_eq!(json["reconnect_attempts"], 2);
        assert_eq!(json["consecutive_failures"], 2);
    }

    #[test]
    fn humanize_age_is_compact() {
        assert_eq!(humanize_age(0), "0s");
        assert_eq!(humanize_age(59), "59s");
        assert_eq!(humanize_age(60), "1m");
        assert_eq!(humanize_age(3599), "59m");
        assert_eq!(humanize_age(3600), "1h00m");
        assert_eq!(humanize_age(7200 + 7 * 60), "2h07m");
    }
}
