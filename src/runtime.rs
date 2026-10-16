//! Shared runtime state types: notification state, secure key cache, local
//! cache key handle, and internal runtime events.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 2).

use std::sync::Arc;

use tokio::sync::RwLock;
use zeroize::Zeroize;

#[derive(Clone, Debug)]
pub(crate) struct NotificationRuntimeState {
    pub(crate) state: NotificationConnectionState,
    pub(crate) url: Option<String>,
    pub(crate) last_error: Option<String>,
    pub(crate) reconnect_attempts: usize,
    pub(crate) last_connected_at: Option<std::time::Instant>,
    pub(crate) last_event_at: Option<std::time::Instant>,
    pub(crate) last_fallback_sync_at: Option<std::time::Instant>,
    pub(crate) stale_cache: bool,
    pub(crate) stale_cache_error: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) enum NotificationConnectionState {
    NotStarted,
    Starting,
    Running,
    Stopped,
    Failed,
}

impl Default for NotificationRuntimeState {
    fn default() -> Self {
        Self {
            state: NotificationConnectionState::NotStarted,
            url: None,
            last_error: None,
            reconnect_attempts: 0,
            last_connected_at: None,
            last_event_at: None,
            last_fallback_sync_at: None,
            stale_cache: false,
            stale_cache_error: None,
        }
    }
}

impl NotificationRuntimeState {
    pub(crate) fn state_name(&self) -> &'static str {
        match self.state {
            NotificationConnectionState::NotStarted => "not_started",
            NotificationConnectionState::Starting => "starting",
            NotificationConnectionState::Running => "running",
            NotificationConnectionState::Stopped => "stopped",
            NotificationConnectionState::Failed => "failed",
        }
    }

    pub(crate) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "state": self.state_name(),
            "url": self.url,
            "last_error": self.last_error,
            "reconnect_attempts": self.reconnect_attempts,
            "last_connected_age_secs": self.last_connected_at.map(|t| t.elapsed().as_secs()),
            "last_event_age_secs": self.last_event_at.map(|t| t.elapsed().as_secs()),
            "last_fallback_sync_age_secs": self.last_fallback_sync_at.map(|t| t.elapsed().as_secs()),
            "stale_cache": self.stale_cache,
            "stale_cache_error": self.stale_cache_error,
        })
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
