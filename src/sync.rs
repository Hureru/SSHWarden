//! Vault sync: reconciling freshly-synced keys, running a sync cycle, and
//! resolving a pending sync after unlock.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 4c).

use tracing::info;

use crate::cache::{
    clear_authorization_memory_for_changed_keys_async, refresh_envelope_local_key_cache,
};
use crate::runtime::DaemonState;
use crate::sshconfig::{sync_managed_ssh_config_with_bindings, write_key_selector_files};
pub(crate) const CACHE_KEY_NOT_LOADED: &str = "Local Cache Key not loaded; cache not refreshed";

pub(crate) async fn reconcile_synced_key_state(
    key_tuples: &[(String, String, String)],
    state: &DaemonState,
) {
    let old_fingerprints = state.key_material_fingerprints.read().await.clone();
    let (cleared_memory, new_fingerprints) = clear_authorization_memory_for_changed_keys_async(
        &old_fingerprints,
        key_tuples,
        &state.authorization_memory,
    )
    .await;
    if cleared_memory > 0 {
        tracing::info!(
            count = cleared_memory,
            "Cleared authorization memory after key material change"
        );
    }

    state
        .cached_key_tuples
        .write()
        .await
        .set(key_tuples.to_vec());
    *state.key_material_fingerprints.write().await = new_fingerprints;

    // Bind the guards' results to locals first: a `read().await` guard used as a
    // temporary inside the `if let` scrutinee would otherwise live until the end
    // of the whole statement and self-deadlock on the `write().await` below
    // (tokio's RwLock is not reentrant).
    let existing_cache = state.local_key_cache_data.read().await.as_ref().cloned();
    let local_cache_key = state.local_cache_key_state.read().await.clone_key();
    if existing_cache.is_some() && local_cache_key.is_none() {
        // The agent has the new keys but the file keeps the old ones; without
        // this flag a key deleted on the server would sign again after a restart.
        state
            .notification_state
            .write()
            .await
            .mark_cache_stale(CACHE_KEY_NOT_LOADED);
        tracing::warn!("{}", CACHE_KEY_NOT_LOADED);
    }
    if let (Some(existing_cache), Some(local_cache_key)) = (existing_cache, local_cache_key) {
        match refresh_envelope_local_key_cache(key_tuples, &existing_cache, &local_cache_key) {
            Ok(cache) => {
                *state.local_key_cache_data.write().await = Some(cache);
                state
                    .local_cache_key_state
                    .write()
                    .await
                    .set(local_cache_key);
                // Clears a staleness flag from an earlier failed refresh: the
                // flag describes the *current* cache, not a permanent defect.
                state
                    .notification_state
                    .write()
                    .await
                    .mark_cache_refreshed();
                tracing::info!("Local key cache refreshed after sync");
            }
            Err(e) => {
                let error = e.to_string();
                state
                    .notification_state
                    .write()
                    .await
                    .mark_cache_stale(&error);
                tracing::warn!(
                    "Sync succeeded but local key cache refresh failed: {}",
                    error
                );
            }
        }
    }
}

/// Sync SSH keys from the Bitwarden API and reload into the agent.
///
/// The fetch can wait 30 s on a silent server, so callers run this in its own
/// task, and it holds no lock that the main loop needs while it waits.
pub(crate) async fn do_sync(
    state: &DaemonState,
    agent: &mut sshwarden_agent::SshWardenAgent,
) -> Result<usize, String> {
    let _one_sync = state.sync_lock.lock().await;
    // A copy: the fetch must not hold the client's lock.
    let client = match state.api_client.read().await.as_ref() {
        Some(c) => c.clone(),
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

    // `lock` or `forget` may have run during the fetch: check again before any
    // key is loaded, and keep them out until the load is done.
    let _change = state.change_lock.lock().await;
    if state
        .vault_locked
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        state
            .pending_sync
            .store(true, std::sync::atomic::Ordering::Relaxed);
        return Err("Vault was locked during the sync; it will run on next unlock".to_string());
    }
    if state.api_client.read().await.is_none() {
        return Err("Logged out during the sync".to_string());
    }

    let key_tuples: crate::runtime::KeyTuples = zeroize::Zeroizing::new(
        keys.iter()
            .map(|k| {
                (
                    (*k.private_key_pem).clone(),
                    k.name.clone(),
                    k.cipher_id.clone(),
                )
            })
            .collect(),
    );
    let count = key_tuples.len();
    if let Err(e) = write_key_selector_files(&keys) {
        tracing::warn!("Failed to write key selector files: {}", e);
    }
    if let Err(e) = sync_managed_ssh_config_with_bindings(&keys) {
        tracing::warn!("Failed to sync managed SSH config: {}", e);
    }
    reconcile_synced_key_state(&key_tuples, state).await;

    // Update &state.key_names
    {
        let mut names = state.key_names.write().await;
        names.clear();
        for k in &keys {
            names.insert(k.cipher_id.clone(), k.name.clone());
        }
    }

    if let Err(e) = agent.set_keys(&key_tuples) {
        return Err(format!("Sync succeeded but failed to reload keys: {}", e));
    }
    // Baseline for `status`'s sync row: without it, "no pending sync" cannot be
    // distinguished from "never synced at all".
    state
        .notification_state
        .write()
        .await
        .record_successful_sync();
    info!("Vault synced: {} SSH keys", count);
    Ok(count)
}

/// Start the sync that waited for an unlock. It runs in its own task, so the
/// unlock reply and the main loop do not wait for the server.
pub(crate) fn resolve_pending_sync(state: &DaemonState, agent: &sshwarden_agent::SshWardenAgent) {
    if !state
        .pending_sync
        .swap(false, std::sync::atomic::Ordering::Relaxed)
    {
        return;
    }

    info!("Resolving pending sync after unlock...");
    let (state, mut agent) = (state.clone(), agent.clone());
    tokio::spawn(async move {
        match do_sync(&state, &mut agent).await {
            Ok(count) => info!("Pending sync resolved: {} SSH keys", count),
            Err(e) => {
                state
                    .pending_sync
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                tracing::warn!("Pending sync failed: {}; sync remains pending", e);
            }
        }
    });
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cache::build_envelope_local_key_cache;

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

        let state = DaemonState::for_tests();

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
        *state.local_key_cache_data.write().await = Some(existing_cache);
        state
            .local_cache_key_state
            .write()
            .await
            .set(local_cache_key);

        let done = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            reconcile_synced_key_state(&key_tuples, &state),
        )
        .await;
        assert!(done.is_ok(), "reconcile_synced_key_state deadlocked");

        // The refresh really happened (Ok branch, not the "stale cache" error path).
        assert!(state.local_key_cache_data.read().await.is_some());
        assert!(state
            .local_cache_key_state
            .read()
            .await
            .clone_key()
            .is_some());
        assert!(!state.notification_state.read().await.stale_cache);

        // A cache whose key is not in memory cannot be rewritten: say so.
        state.local_cache_key_state.write().await.clear();
        reconcile_synced_key_state(&key_tuples, &state).await;
        assert!(state.notification_state.read().await.stale_cache);

        let _ = std::fs::remove_dir_all(&home);
    }
}
