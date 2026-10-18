//! Vault sync: reconciling freshly-synced keys, running a sync cycle, and
//! resolving a pending sync after unlock.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 4c).

use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::info;

use crate::cache::{
    clear_authorization_memory_for_changed_keys_async, refresh_envelope_local_key_cache,
};
use crate::runtime::{
    AuthorizationMemorySet, CachedKeyTuples, KeyMaterialFingerprints, LocalCacheKeyHandle,
    NotificationRuntimeState,
};
use crate::sshconfig::{sync_managed_ssh_config_with_bindings, write_key_selector_files};
#[allow(clippy::too_many_arguments)]
pub(crate) async fn reconcile_synced_key_state(
    key_tuples: &[(String, String, String)],
    cached_key_tuples: &CachedKeyTuples,
    public_key_identity_tuples: &CachedKeyTuples,
    local_key_cache_data: &Arc<RwLock<Option<sshwarden_config::cache::LocalKeyCacheFile>>>,
    local_cache_key_state: &LocalCacheKeyHandle,
    authorization_memory: &AuthorizationMemorySet,
    key_material_fingerprints: &KeyMaterialFingerprints,
    notification_state: &Arc<RwLock<NotificationRuntimeState>>,
) {
    let old_fingerprints = key_material_fingerprints.read().await.clone();
    let (cleared_memory, new_fingerprints) = clear_authorization_memory_for_changed_keys_async(
        &old_fingerprints,
        key_tuples,
        authorization_memory,
    )
    .await;
    if cleared_memory > 0 {
        tracing::info!(
            count = cleared_memory,
            "Cleared authorization memory after key material change"
        );
    }

    public_key_identity_tuples
        .write()
        .await
        .set(key_tuples.to_vec());
    cached_key_tuples.write().await.set(key_tuples.to_vec());
    *key_material_fingerprints.write().await = new_fingerprints;

    // Bind the guards' results to locals first: a `read().await` guard used as a
    // temporary inside the `if let` scrutinee would otherwise live until the end
    // of the whole statement and self-deadlock on the `write().await` below
    // (tokio's RwLock is not reentrant).
    let existing_cache = local_key_cache_data.read().await.as_ref().cloned();
    let local_cache_key = local_cache_key_state.read().await.clone_key();
    if let (Some(existing_cache), Some(local_cache_key)) = (existing_cache, local_cache_key) {
        match refresh_envelope_local_key_cache(key_tuples, &existing_cache, &local_cache_key) {
            Ok(cache) => {
                *local_key_cache_data.write().await = Some(cache);
                local_cache_key_state.write().await.set(local_cache_key);
                // Clears a staleness flag from an earlier failed refresh: the
                // flag describes the *current* cache, not a permanent defect.
                notification_state.write().await.mark_cache_refreshed();
                tracing::info!("Local key cache refreshed after sync");
            }
            Err(e) => {
                let error = e.to_string();
                notification_state.write().await.mark_cache_stale(&error);
                tracing::warn!(
                    "Sync succeeded but local key cache refresh failed: {}",
                    error
                );
            }
        }
    }
}

/// Sync SSH keys from the Bitwarden API and reload into the agent.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn do_sync(
    api_client: &Arc<RwLock<Option<sshwarden_api::BitwardenClient>>>,
    cached_key_tuples: &CachedKeyTuples,
    public_key_identity_tuples: &CachedKeyTuples,
    local_key_cache_data: &Arc<RwLock<Option<sshwarden_config::cache::LocalKeyCacheFile>>>,
    local_cache_key_state: &LocalCacheKeyHandle,
    authorization_memory: &AuthorizationMemorySet,
    key_material_fingerprints: &KeyMaterialFingerprints,
    vault_locked: &Arc<std::sync::atomic::AtomicBool>,
    agent: &mut sshwarden_agent::SshWardenAgent,
    key_names: &Arc<RwLock<std::collections::HashMap<String, String>>>,
    notification_state: &Arc<RwLock<NotificationRuntimeState>>,
) -> Result<usize, String> {
    let client_guard = api_client.read().await;
    let client = match *client_guard {
        Some(ref c) => c,
        None => return Err("Not authenticated. Run 'sshwarden login'.".to_string()),
    };

    if !client.has_user_key() {
        return Err(
            "Bitwarden session cannot decrypt vault data. Run `sshwarden login` to re-authenticate with your master password."
                .to_string(),
        );
    }

    let keys = client
        .sync_ssh_keys()
        .await
        .map_err(|e| format!("Sync failed: {}", e))?;

    let key_tuples: Vec<(String, String, String)> = keys
        .iter()
        .map(|k| {
            (
                (*k.private_key_pem).clone(),
                k.name.clone(),
                k.cipher_id.clone(),
            )
        })
        .collect();
    let count = key_tuples.len();
    if let Err(e) = write_key_selector_files(&keys) {
        tracing::warn!("Failed to write key selector files: {}", e);
    }
    if let Err(e) = sync_managed_ssh_config_with_bindings(&keys) {
        tracing::warn!("Failed to sync managed SSH config: {}", e);
    }
    reconcile_synced_key_state(
        &key_tuples,
        cached_key_tuples,
        public_key_identity_tuples,
        local_key_cache_data,
        local_cache_key_state,
        authorization_memory,
        key_material_fingerprints,
        notification_state,
    )
    .await;

    // Update key_names
    {
        let mut names = key_names.write().await;
        names.clear();
        for k in &keys {
            names.insert(k.cipher_id.clone(), k.name.clone());
        }
    }

    drop(client_guard);

    if !vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
        if let Err(e) = agent.set_keys(key_tuples) {
            return Err(format!("Sync succeeded but failed to reload keys: {}", e));
        }
    }
    // Baseline for `status`'s sync row: without it, "no pending sync" cannot be
    // distinguished from "never synced at all".
    notification_state.write().await.record_successful_sync();
    info!("Vault synced: {} SSH keys", count);
    Ok(count)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn resolve_pending_sync(
    pending_sync: &Arc<std::sync::atomic::AtomicBool>,
    api_client: &Arc<RwLock<Option<sshwarden_api::BitwardenClient>>>,
    cached_key_tuples: &CachedKeyTuples,
    public_key_identity_tuples: &CachedKeyTuples,
    local_key_cache_data: &Arc<RwLock<Option<sshwarden_config::cache::LocalKeyCacheFile>>>,
    local_cache_key_state: &LocalCacheKeyHandle,
    authorization_memory: &AuthorizationMemorySet,
    key_material_fingerprints: &KeyMaterialFingerprints,
    vault_locked: &Arc<std::sync::atomic::AtomicBool>,
    agent: &mut sshwarden_agent::SshWardenAgent,
    key_names: &Arc<RwLock<std::collections::HashMap<String, String>>>,
    notification_state: &Arc<RwLock<NotificationRuntimeState>>,
) -> bool {
    if !pending_sync.swap(false, std::sync::atomic::Ordering::Relaxed) {
        return false;
    }

    info!("Resolving pending sync after unlock...");
    match do_sync(
        api_client,
        cached_key_tuples,
        public_key_identity_tuples,
        local_key_cache_data,
        local_cache_key_state,
        authorization_memory,
        key_material_fingerprints,
        vault_locked,
        agent,
        key_names,
        notification_state,
    )
    .await
    {
        Ok(count) => {
            info!("Pending sync resolved: {} SSH keys", count);
            true
        }
        Err(e) => {
            pending_sync.store(true, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!("Pending sync failed: {}; sync remains pending", e);
            false
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cache::build_envelope_local_key_cache;
    use crate::runtime::{LocalCacheKeyState, SecureKeyCache};

    /// Set by the parent test run on the child process it spawns, so the child
    /// takes the branch that performs the actual check.
    const CHILD_ENV: &str = "SSHWARDEN_SYNC_DEADLOCK_TEST_CHILD";

    /// Unique temp directory under the OS temp root, so the test never writes
    /// into a real installation's config directory.
    fn temp_home(name: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "sshwarden-sync-test-{}-{unique}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Regression: `reconcile_synced_key_state` must not self-deadlock when the
    /// on-disk envelope cache is loaded AND an in-memory Local Cache Key exists
    /// (the state reached by `login` right after a native auto-unlock). The bug
    /// was a `read().await` guard bound as a temporary in the `if let`
    /// scrutinee, kept alive across the body's `write().await` on the same lock.
    ///
    /// The body runs in a child process of this test binary. `reconcile` calls
    /// `refresh_envelope_local_key_cache`, which re-saves `local-key-cache.json`
    /// into the shared data directory — and that directory is resolved through a
    /// process-wide `OnceLock`, so setting `SSHWARDEN_HOME` from inside the test
    /// is only honoured while no other test in this binary has resolved it yet
    /// (the SSH include-line tests already do). A fresh process makes the temp
    /// override deterministic and keeps the test from ever rewriting a real
    /// `local-key-cache.json`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_refreshes_cache_without_deadlock() {
        if std::env::var_os(CHILD_ENV).is_none() {
            let exe = std::env::current_exe().unwrap();
            let output = std::process::Command::new(exe)
                .args([
                    "--exact",
                    "--nocapture",
                    "sync::tests::reconcile_refreshes_cache_without_deadlock",
                ])
                .env(CHILD_ENV, "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            assert!(
                output.status.success(),
                "isolated child test failed (deadlock?)\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
            );
            return;
        }

        let home = temp_home("reconcile");
        std::env::set_var("SSHWARDEN_HOME", &home);
        let resolved = sshwarden_config::config_dir().unwrap();
        assert!(
            resolved.starts_with(&home),
            "child not isolated: config_dir resolved to {}",
            resolved.display()
        );

        let cached_key_tuples: CachedKeyTuples = Arc::new(RwLock::new(SecureKeyCache::new()));
        let public_key_identity_tuples: CachedKeyTuples =
            Arc::new(RwLock::new(SecureKeyCache::new()));
        let authorization_memory: AuthorizationMemorySet =
            Arc::new(RwLock::new(std::collections::HashSet::new()));
        let key_material_fingerprints: KeyMaterialFingerprints =
            Arc::new(RwLock::new(std::collections::HashMap::new()));
        let notification_state = Arc::new(RwLock::new(NotificationRuntimeState::default()));

        let key_tuples = vec![(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key\n-----END OPENSSH PRIVATE KEY-----\n"
                .to_string(),
            "test-key".to_string(),
            "cipher-1".to_string(),
        )];

        // Trigger condition: disk cache loaded + in-memory Local Cache Key.
        let local_cache_key = sshwarden_api::crypto::SymmetricKey {
            enc_key: vec![7u8; 32],
            mac_key: vec![9u8; 32],
        };
        let existing_cache = build_envelope_local_key_cache(
            &key_tuples,
            "user@example.com",
            "https://vault.example.com",
            &local_cache_key,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let local_key_cache_data = Arc::new(RwLock::new(Some(existing_cache)));
        let mut state = LocalCacheKeyState::default();
        state.set(local_cache_key);
        let local_cache_key_state = Arc::new(RwLock::new(state));

        let done = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            reconcile_synced_key_state(
                &key_tuples,
                &cached_key_tuples,
                &public_key_identity_tuples,
                &local_key_cache_data,
                &local_cache_key_state,
                &authorization_memory,
                &key_material_fingerprints,
                &notification_state,
            ),
        )
        .await;
        assert!(done.is_ok(), "reconcile_synced_key_state deadlocked");

        // The refresh really happened (Ok branch, not the "stale cache" error path).
        assert!(local_key_cache_data.read().await.is_some());
        assert!(local_cache_key_state.read().await.clone_key().is_some());
        assert!(!notification_state.read().await.stale_cache);

        let _ = std::fs::remove_dir_all(&home);
    }
}
