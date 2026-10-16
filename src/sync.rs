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

    if let (Some(existing_cache), Some(local_cache_key)) = (
        local_key_cache_data.read().await.as_ref().cloned(),
        local_cache_key_state.read().await.clone_key(),
    ) {
        match refresh_envelope_local_key_cache(key_tuples, &existing_cache, &local_cache_key) {
            Ok(cache) => {
                *local_key_cache_data.write().await = Some(cache);
                local_cache_key_state.write().await.set(local_cache_key);
                tracing::info!("Local key cache refreshed after sync");
            }
            Err(e) => {
                let error = e.to_string();
                {
                    let mut state = notification_state.write().await;
                    state.stale_cache = true;
                    state.stale_cache_error = Some(error.clone());
                }
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
