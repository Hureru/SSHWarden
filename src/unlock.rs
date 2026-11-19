//! Vault unlock paths: PIN validators, manual-sync Local Key Cache refresh,
//! API session restore (PIN + Windows Hello), device session save, and the
//! final unlock response plumbing.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 4b).

use std::sync::Arc;

use tracing::info;

#[cfg(windows)]
use base64::Engine;

#[cfg(windows)]
use crate::cache::current_hello_challenge_b64;
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

/// Try to restore an API session from the device session file after Hello unlock.
///
/// Uses the Hello-encrypted refresh token stored in the session file.
#[cfg(windows)]
pub(crate) async fn try_restore_api_session_hello(
    state: &DaemonState,
    notification_rx: &mut Option<tokio::sync::mpsc::Receiver<sshwarden_api::SyncEvent>>,
    notification_client: &mut Option<sshwarden_api::NotificationClient>,
) {
    if state.api_client.read().await.is_some() {
        return;
    }

    let session = match sshwarden_config::session::SessionFile::load() {
        Ok(Some(s)) => s,
        _ => return,
    };

    // Need hello_encrypted_token and this device's Hello challenge.
    let hello_enc_token = match session.hello_encrypted_token {
        Some(ref t) => t.clone(),
        None => {
            info!("Session file has no Hello-encrypted token, skipping API restore");
            return;
        }
    };

    let challenge_b64 = match current_hello_challenge_b64() {
        Some(c) => c,
        None => return,
    };

    let challenge_bytes = match base64::engine::general_purpose::STANDARD.decode(&challenge_b64) {
        Ok(b) if b.len() == 16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return,
    };

    // Decrypt with Hello
    let hello_result = tokio::task::spawn_blocking(move || {
        sshwarden_ui::unlock::hello_crypto::hello_decrypt_keys(&hello_enc_token, &challenge_bytes)
    })
    .await;

    let refresh_token = match hello_result {
        Ok(Ok(token)) => token,
        _ => {
            info!("Hello decrypt of session token failed");
            return;
        }
    };

    let base = &state.config.server.base_url;
    let api_url = state.config.server.api_url();
    let mut client = sshwarden_api::BitwardenClient::new_with_device_id(
        base,
        &api_url,
        &session.identity_url,
        &session.device_id,
    );
    client.set_refresh_token(refresh_token);

    match client.refresh_access_token().await {
        Ok(()) => {
            info!("Restored API session from device session file (Hello)");

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

            *state.api_client.write().await = Some(client);
        }
        Err(e) => {
            tracing::warn!("Hello session restore failed: {}", e);
        }
    }
}

/// Try to restore an API session from the device session file after PIN unlock.
///
/// Decrypts the stored refresh_token using the PIN, refreshes the access token,
/// and connects to the notification hub.
pub(crate) async fn try_restore_api_session(
    state: &DaemonState,
    pin: &str,
    notification_rx: &mut Option<tokio::sync::mpsc::Receiver<sshwarden_api::SyncEvent>>,
    notification_client: &mut Option<sshwarden_api::NotificationClient>,
) {
    // Only restore if we don't already have an API client
    if state.api_client.read().await.is_some() {
        return;
    }

    let session = match sshwarden_config::session::SessionFile::load() {
        Ok(Some(s)) => s,
        Ok(None) => {
            info!("No device session file found, skipping API session restore");
            return;
        }
        Err(e) => {
            tracing::warn!("Failed to load session file: {}", e);
            return;
        }
    };

    // Decrypt refresh token using PIN
    let refresh_token = match session.pin_encrypted_token {
        Some(ref enc) => match sshwarden_api::crypto::pin_decrypt(enc, pin) {
            Ok(token) => token,
            Err(e) => {
                tracing::warn!("Failed to decrypt session refresh token: {}", e);
                return;
            }
        },
        None => {
            info!("Session file has no PIN-encrypted token");
            return;
        }
    };

    // Create client with stored device_id and try to refresh
    let base = &state.config.server.base_url;
    let api_url = state.config.server.api_url();
    let mut client = sshwarden_api::BitwardenClient::new_with_device_id(
        base,
        &api_url,
        &session.identity_url,
        &session.device_id,
    );
    client.set_refresh_token(refresh_token);

    match client.refresh_access_token().await {
        Ok(()) => {
            info!("Restored API session from device session file");

            // Connect to notification hub
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

            // Update session file with new refresh token
            save_device_session(&client, &state.config, Some(pin)).await;

            *state.api_client.write().await = Some(client);
        }
        Err(e) => {
            tracing::warn!("API session restore failed (token refresh): {}", e);
            // Session file may have an expired refresh token — clean it up
            if let Err(e) = sshwarden_config::session::SessionFile::delete() {
                tracing::warn!("Failed to delete stale session file: {}", e);
            }
        }
    }
}

/// Save the current API client's device session to disk.
///
/// If `pin` is provided, the refresh token is encrypted with it.
/// Otherwise, the existing session file's encrypted tokens are preserved.
pub(crate) async fn save_device_session(
    client: &sshwarden_api::BitwardenClient,
    _config: &sshwarden_config::Config,
    pin: Option<&str>,
) {
    let refresh_token = match client.refresh_token() {
        Some(t) => t.to_string(),
        None => return, // No refresh token to save
    };

    // Load existing session to preserve hello_encrypted_token if present
    let existing = sshwarden_config::session::SessionFile::load()
        .ok()
        .flatten();

    let pin_encrypted_token = if let Some(pin) = pin {
        match sshwarden_api::crypto::pin_encrypt(&refresh_token, pin) {
            Ok(enc) => Some(enc),
            Err(e) => {
                tracing::warn!("Failed to encrypt refresh token with PIN: {}", e);
                // Fall back to existing
                existing
                    .as_ref()
                    .and_then(|s| s.pin_encrypted_token.clone())
            }
        }
    } else {
        // Re-encrypt with existing PIN is not possible without the PIN.
        // Keep existing encrypted token if available.
        existing
            .as_ref()
            .and_then(|s| s.pin_encrypted_token.clone())
    };

    let hello_encrypted_token = create_or_preserve_hello_encrypted_token(
        &refresh_token,
        existing
            .as_ref()
            .and_then(|s| s.hello_encrypted_token.clone()),
    );

    let session = sshwarden_config::session::SessionFile {
        version: 1,
        device_id: client.device_id().to_string(),
        pin_encrypted_token,
        hello_encrypted_token,
        identity_url: client.identity_url().to_string(),
    };

    if let Err(e) = session.save() {
        tracing::warn!("Failed to save device session: {}", e);
    } else {
        info!(
            "Device session saved to {}",
            sshwarden_config::session::SessionFile::path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "unknown".to_string())
        );
    }
}

pub(crate) fn create_or_preserve_hello_encrypted_token(
    refresh_token: &str,
    existing: Option<String>,
) -> Option<String> {
    #[cfg(windows)]
    {
        let challenge_b64 = match current_hello_challenge_b64() {
            Some(challenge) => challenge,
            None => return existing,
        };
        let challenge_bytes = match base64::engine::general_purpose::STANDARD.decode(&challenge_b64)
        {
            Ok(bytes) if bytes.len() == 16 => {
                let mut challenge = [0u8; 16];
                challenge.copy_from_slice(&bytes);
                challenge
            }
            _ => return existing,
        };

        match try_hello_encrypt(refresh_token, &challenge_bytes) {
            Ok(encrypted) => Some(encrypted),
            Err(e) => {
                tracing::warn!("Failed to encrypt refresh token with Windows Hello: {}", e);
                existing
            }
        }
    }

    #[cfg(not(windows))]
    {
        let _ = refresh_token;
        existing
    }
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
