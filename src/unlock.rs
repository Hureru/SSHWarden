//! Vault unlock paths: PIN validators, manual-sync Local Key Cache refresh,
//! API session restore, device session save, and the
//! final unlock response plumbing.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 4b).

use std::sync::Arc;

use tracing::info;

use crate::cache::{
    decrypt_envelope_local_key_cache_with_pin, decrypt_envelope_payload,
    enroll_device_platform_slots_if_missing, migrate_pin_salt_to_v3, multi_device_mode,
    needs_pin_salt_migration, reload_shared_local_cache_from_disk_if_multi_device,
};
use crate::control::{pin_lockout_remaining, record_pin_attempt, PinFailureHandle};
use crate::notifications::connect_notification_client;
use crate::runtime::DaemonState;
/// Try to unlock using Windows Hello sign-path.
/// Must be called from spawn_blocking.
#[cfg(windows)]
pub(crate) fn try_hello_unlock(
    challenge: &[u8; 16],
    hello_encrypted: &str,
) -> anyhow::Result<String> {
    sshwarden_ui::unlock::hello_crypto::hello_decrypt_keys(hello_encrypted, challenge)
}

#[cfg(windows)]
pub(crate) fn try_hello_encrypt(plaintext: &str, challenge: &[u8; 16]) -> anyhow::Result<String> {
    sshwarden_ui::unlock::hello_crypto::hello_encrypt_keys(plaintext, challenge)
}

pub(crate) type PinValidator = Arc<dyn Fn(&str) -> bool + Send + Sync>;
/// What a correct PIN recovers: the decrypted key list and the Local Cache Key.
pub(crate) type PinDecrypted = (
    zeroize::Zeroizing<String>,
    sshwarden_api::crypto::SymmetricKey,
);

/// Wrap a PIN validator so every attempt shares the daemon-wide brute-force
/// accounting (SEC-03) with `ControlAction::UnlockPin`: reject outright while a
/// lockout is active, and record each outcome so UI/SSH dialog attempts count
/// toward the SAME lockout the control channel enforces — otherwise the dialog
/// path is an unthrottled brute-force bypass. The wrapper runs inside the
/// dialog's validation thread (not a tokio worker), so the failure accounting is
/// intentionally clock-agnostic (std::time::Instant).
fn gate_pin_validator(inner: PinValidator, pin_failures: &PinFailureHandle) -> PinValidator {
    let pin_failures = pin_failures.clone();
    Arc::new(move |pin: &str| -> bool {
        if pin_lockout_remaining(&pin_failures).is_some() {
            return false;
        }
        let ok = inner(pin);
        let _ = record_pin_attempt(&pin_failures, ok);
        ok
    })
}

/// The validator for a PIN dialog over `cache`. It counts attempts (SEC-03) and
/// keeps what the correct PIN decrypted, so the caller does not run Argon2 twice.
pub(crate) fn pin_dialog_validator(
    cache: sshwarden_config::cache::LocalKeyCacheFile,
    pin_failures: &PinFailureHandle,
) -> (PinValidator, Arc<std::sync::Mutex<Option<PinDecrypted>>>) {
    let holder = Arc::new(std::sync::Mutex::new(None));
    let holder_inner = holder.clone();
    let validator: PinValidator = Arc::new(move |pin: &str| -> bool {
        match decrypt_envelope_local_key_cache_with_pin(&cache, pin) {
            Ok(decrypted) => {
                *holder_inner.lock().unwrap_or_else(|e| e.into_inner()) = Some(decrypted);
                true
            }
            Err(_) => false,
        }
    });
    (gate_pin_validator(validator, pin_failures), holder)
}

/// Unlock the vault with a PIN. Every PIN path ends here: `unlock-pin`, the
/// `unlock` dialog and the dialog a sign request opens. `decrypted` is what the
/// dialog's validator already recovered; `None` decrypts here. Throttling, the
/// reply text and the session restore stay with the caller.
pub(crate) async fn unlock_with_pin(
    state: &DaemonState,
    agent: &mut sshwarden_agent::SshWardenAgent,
    pin: &str,
    decrypted: Option<PinDecrypted>,
) -> Result<(), String> {
    // A local copy, so no read guard is held across the writes below.
    let cache = state
        .local_key_cache_data
        .read()
        .await
        .as_ref()
        .cloned()
        .ok_or("No PIN configured. Use 'sshwarden set-pin' first.")?;
    let (keys_json, local_cache_key) = match decrypted {
        Some(decrypted) => decrypted,
        None => {
            let (cache, pin) = (cache.clone(), zeroize::Zeroizing::new(pin.to_string()));
            // Argon2 takes about 100 ms: keep it off the async workers.
            tokio::task::spawn_blocking(move || {
                decrypt_envelope_local_key_cache_with_pin(&cache, &pin)
            })
            .await
            .map_err(|e| format!("PIN unlock task failed: {e}"))?
            .map_err(|e| {
                tracing::warn!("PIN unlock from local key cache failed: {}", e);
                "Invalid PIN".to_string()
            })?
        }
    };

    // SEC-04: with the key and a verified PIN in hand, upgrade a pre-v3 (fixed
    // salt) cache to a random per-cache salt.
    if needs_pin_salt_migration(&cache) {
        match migrate_pin_salt_to_v3(&cache, &local_cache_key, pin) {
            Ok(migrated) => {
                *state.local_key_cache_data.write().await = Some(migrated);
                info!("Migrated local key cache PIN slot to v3 (random salt)");
            }
            Err(e) => tracing::warn!("PIN salt v3 migration failed (non-fatal): {e}"),
        }
    }
    // Multi-device: seed this device's own platform unlock slot, so a device
    // that joined later is not PIN-only for ever. No-op otherwise.
    enroll_device_platform_slots_if_missing(&local_cache_key);
    state
        .local_cache_key_state
        .write()
        .await
        .set(local_cache_key);
    let resp = finish_unlock_with_json(&keys_json, agent, state, "Vault unlocked via PIN").await;
    if !resp.ok {
        state.local_cache_key_state.write().await.clear();
        return Err(resp
            .error
            .unwrap_or_else(|| "PIN unlock failed".to_string()));
    }
    Ok(())
}

/// Manual `sync` is user-initiated and should not leave the live agent newer
/// than the encrypted Local Key Cache when the vault is already unlocked. If the
/// daemon has private keys loaded but no in-memory Local Cache Key, recover that
/// key via the user's PIN before syncing so `do_sync()` can refresh
/// `local-key-cache.json` with the newly pulled key set.
pub(crate) async fn ensure_local_cache_key_for_manual_sync(
    state: &DaemonState,
) -> Result<(), String> {
    if multi_device_mode() {
        reload_shared_local_cache_from_disk_if_multi_device(&state.local_key_cache_data).await;
    }

    let cache = match state.local_key_cache_data.read().await.as_ref().cloned() {
        Some(cache) => cache,
        None => return Ok(()),
    };

    // Bind to a local so the read guard is dropped before the `clear()` write on
    // the same lock below.
    let in_memory_key = state.local_cache_key_state.read().await.clone_key();
    if let Some(local_cache_key) = in_memory_key {
        if decrypt_envelope_payload(&cache, local_cache_key.clone()).is_ok() {
            return Ok(());
        }
        tracing::warn!(
            "In-memory Local Cache Key no longer decrypts the shared cache; PIN is required"
        );
        state.local_cache_key_state.write().await.clear();
    }

    if cache.local_cache_key.pin_encrypted.is_none() {
        return Ok(());
    }

    info!("Manual sync needs PIN to refresh the Local Key Cache");
    let (validator, holder) = pin_dialog_validator(cache, &state.pin_failures);

    match sshwarden_ui::unlock::request_pin_dialog(&state.ui_request_tx, validator).await {
        Some(_) => {
            // Take the recovered key OUT of the guard before awaiting, so no
            // std::sync::MutexGuard is held across the .await (clippy::await_holding_lock).
            let recovered = holder.lock().unwrap_or_else(|e| e.into_inner()).take();
            match recovered {
                Some((_keys_json, local_cache_key)) => {
                    state.local_cache_key_state.write().await.set(local_cache_key);
                    Ok(())
                }
                None => Err("PIN accepted but the Local Cache Key was not recovered".to_string()),
            }
        }
        None => Err(
            "Sync cancelled: PIN is required to refresh the Local Key Cache for this unlocked session"
                .to_string(),
        ),
    }
}

/// What a session needs to come back: the refresh token and the user key,
/// encrypted with the Local Cache Key (ADR 0028).
fn encrypt_session_secrets(
    refresh_token: &str,
    user_key: &sshwarden_api::crypto::SymmetricKey,
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
) -> anyhow::Result<String> {
    let json = zeroize::Zeroizing::new(
        serde_json::json!({
            "refresh_token": refresh_token,
            "user_key": sshwarden_api::crypto::encode_symmetric_key(user_key),
        })
        .to_string(),
    );
    sshwarden_api::crypto::encrypt_enc_string(json.as_bytes(), local_cache_key)
}

fn decrypt_session_secrets(
    encrypted: &str,
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
) -> anyhow::Result<(String, sshwarden_api::crypto::SymmetricKey)> {
    let json = zeroize::Zeroizing::new(sshwarden_api::crypto::decrypt_enc_string_to_string(
        encrypted,
        local_cache_key,
    )?);
    let secrets: serde_json::Value = serde_json::from_str(&json)?;
    let field = |name: &str| {
        secrets[name]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Session file has no {name}"))
    };
    Ok((
        field("refresh_token")?.to_string(),
        sshwarden_api::crypto::decode_symmetric_key(field("user_key")?)?,
    ))
}

/// Save the client's session for this device. It needs the Local Cache Key, a
/// refresh token and the user key; without all three the file is left alone.
pub(crate) async fn save_device_session(
    client: &sshwarden_api::BitwardenClient,
    local_cache_key: Option<&sshwarden_api::crypto::SymmetricKey>,
) {
    let (Some(local_cache_key), Some(refresh_token), Some(user_key)) =
        (local_cache_key, client.refresh_token(), client.user_key())
    else {
        return;
    };
    let lck_encrypted_session =
        match encrypt_session_secrets(refresh_token, user_key, local_cache_key) {
            Ok(encrypted) => Some(encrypted),
            Err(e) => {
                tracing::warn!("Failed to encrypt device session: {}", e);
                return;
            }
        };
    let session = sshwarden_config::session::SessionFile {
        version: 2,
        device_id: client.device_id().to_string(),
        identity_url: client.identity_url().to_string(),
        lck_encrypted_session,
    };
    match session.save() {
        Ok(()) => info!("Device session saved"),
        Err(e) => tracing::warn!("Failed to save device session: {}", e),
    }
}

/// Get the Bitwarden session back after an unlock, from the session file and
/// the Local Cache Key that the unlock just loaded. Every unlock path calls
/// this. After a restart it builds the client and refreshes the token; after a
/// lock it only gives the client its user key back. Returns a line for the
/// user when they have to act.
pub(crate) async fn restore_api_session(
    state: &DaemonState,
    notification_rx: &mut Option<tokio::sync::mpsc::Receiver<sshwarden_api::SyncEvent>>,
    notification_client: &mut Option<sshwarden_api::NotificationClient>,
) -> Option<String> {
    const LOGIN_HINT: &str =
        "The saved Bitwarden session cannot be used. Run `sshwarden login` once to turn sync back on.";

    if let Some(client) = state.api_client.read().await.as_ref() {
        if client.has_user_key() {
            return None;
        }
    }
    let local_cache_key = state.local_cache_key_state.read().await.clone_key()?;
    let session = match sshwarden_config::session::SessionFile::load() {
        Ok(Some(session)) => session,
        Ok(None) => return None,
        Err(e) => {
            tracing::warn!("Failed to load session file: {}", e);
            return None;
        }
    };
    let Some(encrypted) = session.lck_encrypted_session.as_deref() else {
        if session.version >= 2 {
            return None;
        }
        // A version 1 file: its tokens are not read any more. Write it back
        // without them, so that the device id survives for the next login.
        let stripped = sshwarden_config::session::SessionFile {
            version: 2,
            ..session
        };
        if let Err(e) = stripped.save() {
            tracing::warn!("Failed to rewrite the old session file: {}", e);
        }
        return Some(LOGIN_HINT.to_string());
    };
    let (refresh_token, user_key) = match decrypt_session_secrets(encrypted, &local_cache_key) {
        Ok(secrets) => secrets,
        Err(e) => {
            tracing::warn!("Session file does not open with the Local Cache Key: {}", e);
            return Some(LOGIN_HINT.to_string());
        }
    };

    if let Some(client) = state.api_client.write().await.as_mut() {
        // After a lock: the client and its tokens stayed, only the key went.
        client.set_user_key(user_key);
        save_device_session(client, Some(&local_cache_key)).await;
        return None;
    }

    let mut client = sshwarden_api::BitwardenClient::new_with_device_id(
        &state.config.server.base_url,
        &state.config.server.api_url(),
        &session.identity_url,
        &session.device_id,
    );
    client.set_refresh_token(refresh_token);
    client.set_user_key(user_key);
    match client.refresh_access_token().await {
        Ok(()) => {
            info!("Restored API session from device session file");
            if let Some(token) = client.access_token() {
                connect_notification_client(
                    &state.config,
                    Some(&client),
                    token,
                    notification_rx,
                    notification_client,
                    &state.notification_state,
                )
                .await;
            }
            save_device_session(&client, Some(&local_cache_key)).await;
        }
        Err(e) => {
            tracing::warn!("API session restore failed (token refresh): {}", e);
            if e.downcast_ref::<sshwarden_api::RefreshRejected>().is_some() {
                if let Err(e) = sshwarden_config::session::SessionFile::delete() {
                    tracing::warn!("Failed to delete stale session file: {}", e);
                }
                return Some(LOGIN_HINT.to_string());
            }
            // The server did not answer: keep the client, the token refresh
            // timer tries again.
        }
    }
    *state.api_client.write().await = Some(client);
    None
}

/// Finish an unlock by parsing keys JSON and loading into agent.
pub(crate) async fn finish_unlock_with_json(
    keys_json: &str,
    agent: &mut sshwarden_agent::SshWardenAgent,
    state: &DaemonState,
    success_msg: &str,
) -> sshwarden_agent::ControlResponse {
    let keys: crate::runtime::KeyTuples = match serde_json::from_str(keys_json) {
        Ok(k) => zeroize::Zeroizing::new(k),
        Err(e) => {
            return sshwarden_agent::ControlResponse::err(&format!(
                "Failed to parse decrypted keys: {}",
                e
            ))
        }
    };

    // Update &state.key_names map
    {
        let mut names = state.key_names.write().await;
        names.clear();
        for (_, name, cipher_id) in keys.iter() {
            names.insert(cipher_id.clone(), name.clone());
        }
    }

    state.cached_key_tuples.write().await.set(keys.to_vec());
    if let Err(e) = agent.set_keys(&keys) {
        return sshwarden_agent::ControlResponse::err(&format!("Failed to reload keys: {}", e));
    }
    state
        .vault_locked
        .store(false, std::sync::atomic::Ordering::Relaxed);
    info!("{}", success_msg);
    sshwarden_agent::ControlResponse::ok(success_msg)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn session_secrets_open_only_with_the_key_that_closed_them() {
        let key = |n: u8| sshwarden_api::crypto::SymmetricKey {
            enc_key: vec![n; 32],
            mac_key: vec![n + 1; 32],
        };
        let encrypted = encrypt_session_secrets("refresh-1", &key(1), &key(7)).unwrap();
        assert!(!encrypted.contains("refresh-1"));

        let (refresh_token, user_key) = decrypt_session_secrets(&encrypted, &key(7)).unwrap();
        assert_eq!(refresh_token, "refresh-1");
        assert_eq!(user_key.enc_key, key(1).enc_key);
        assert_eq!(user_key.mac_key, key(1).mac_key);

        assert!(decrypt_session_secrets(&encrypted, &key(8)).is_err());
    }

    #[test]
    fn pin_dialog_validator_keeps_what_the_right_pin_decrypted() {
        let lck = sshwarden_api::crypto::SymmetricKey {
            enc_key: vec![7u8; 32],
            mac_key: vec![9u8; 32],
        };
        let (pin_encrypted, pin_salt) =
            crate::cache::encrypt_local_cache_key_with_pin(&lck, "73915824").unwrap();
        let keys = vec![(
            "private".to_string(),
            "name".to_string(),
            "cipher-1".to_string(),
        )];
        let cache = crate::cache::build_envelope_local_key_cache(
            &keys,
            "user@example.com",
            "https://vault.example.com",
            &lck,
            Some(pin_encrypted),
            Some(pin_salt),
            None,
            None,
            None,
        )
        .unwrap();
        let failures = PinFailureHandle::default();
        let (validator, holder) = pin_dialog_validator(cache, &failures);

        assert!(!validator("00000000"));
        assert!(holder.lock().unwrap().is_none());
        assert!(validator("73915824"));
        let (keys_json, recovered) = holder.lock().unwrap().take().unwrap();
        assert!(keys_json.contains("cipher-1"));
        assert_eq!(recovered.enc_key, lck.enc_key);
    }
}
