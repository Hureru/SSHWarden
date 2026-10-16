//! Envelope Local Key Cache model and per-device unlock slots.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 4a).

use std::sync::Arc;

use anyhow::Context;
use base64::Engine;
use tokio::sync::RwLock;
use tracing::info;

use crate::runtime::{AuthorizationMemorySet, CachedKeyTuples, LocalCacheKeyHandle};
use crate::sshconfig::ManagedKey;
use crate::unlock::finish_unlock_with_json;
#[cfg(windows)]
use crate::{try_hello_encrypt, try_hello_unlock};
pub(crate) fn key_identities_from_tuples(
    keys: &[(String, String, String)],
) -> Vec<sshwarden_config::cache::KeyIdentity> {
    keys.iter()
        .map(
            |(pem, name, vault_item_id)| sshwarden_config::cache::KeyIdentity {
                name: name.clone(),
                vault_item_id: vault_item_id.clone(),
                public_key_openssh: public_key_openssh_from_pem(pem).unwrap_or_default(),
            },
        )
        .collect()
}

pub(crate) fn public_key_openssh_from_pem(pem: &str) -> anyhow::Result<String> {
    let private_key = ssh_key::private::PrivateKey::from_openssh(pem)
        .map_err(|e| anyhow::anyhow!("Failed to parse private key for public identity: {e}"))?;
    private_key
        .public_key()
        .to_openssh()
        .map_err(|e| anyhow::anyhow!("Failed to encode public key: {e}"))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_envelope_local_key_cache(
    keys: &[(String, String, String)],
    email: &str,
    server_url: &str,
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
    pin_encrypted: Option<String>,
    pin_salt: Option<String>,
    hello_challenge: Option<String>,
    hello_encrypted: Option<String>,
    native_encrypted: Option<String>,
) -> anyhow::Result<sshwarden_config::cache::LocalKeyCacheFile> {
    let keys_json = serde_json::to_string(keys).context("Failed to serialize cache payload")?;
    let encrypted_payload =
        sshwarden_api::crypto::encrypt_enc_string(keys_json.as_bytes(), local_cache_key)?;
    let cache = sshwarden_config::cache::LocalKeyCacheFile {
        version: 3,
        header: sshwarden_config::cache::LocalKeyCacheHeader {
            email: email.to_string(),
            server_url: server_url.to_string(),
            keys: key_identities_from_tuples(keys),
        },
        encrypted_payload,
        local_cache_key: sshwarden_config::cache::LocalCacheKeySlots {
            pin_encrypted,
            pin_salt,
            hello_challenge,
            hello_encrypted,
            native_encrypted,
        },
    };
    Ok(cache)
}

pub(crate) fn write_envelope_local_key_cache(
    keys: &[(String, String, String)],
    email: &str,
    server_url: &str,
    pin: &str,
) -> anyhow::Result<(
    sshwarden_config::cache::LocalKeyCacheFile,
    sshwarden_api::crypto::SymmetricKey,
)> {
    let local_cache_key = sshwarden_api::crypto::random_symmetric_key();
    write_envelope_local_key_cache_with_key(keys, email, server_url, pin, &local_cache_key)
}

pub(crate) fn write_envelope_local_key_cache_with_key(
    keys: &[(String, String, String)],
    email: &str,
    server_url: &str,
    pin: &str,
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
) -> anyhow::Result<(
    sshwarden_config::cache::LocalKeyCacheFile,
    sshwarden_api::crypto::SymmetricKey,
)> {
    let (pin_encrypted, pin_salt) = encrypt_local_cache_key_with_pin(local_cache_key, pin)?;
    let mut cache = build_envelope_local_key_cache(
        keys,
        email,
        server_url,
        local_cache_key,
        Some(pin_encrypted),
        Some(pin_salt),
        None,
        None,
        None,
    )?;
    if let Err(e) = enroll_native_for_local_key_cache(&mut cache, local_cache_key) {
        tracing::debug!("Native unlock enrollment skipped: {}", e);
    }
    #[cfg(windows)]
    {
        if sshwarden_ui::unlock::hello_crypto::hello_available() {
            if let Err(e) = enroll_hello_for_local_key_cache(&mut cache, local_cache_key) {
                tracing::warn!("Failed to enroll Windows Hello for local key cache: {}", e);
            }
        }
    }
    cache.save()?;
    Ok((cache, local_cache_key.clone()))
}

pub(crate) fn refresh_envelope_local_key_cache(
    keys: &[(String, String, String)],
    existing: &sshwarden_config::cache::LocalKeyCacheFile,
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
) -> anyhow::Result<sshwarden_config::cache::LocalKeyCacheFile> {
    let keep_platform_slots_in_shared_cache = !multi_device_mode();
    let cache = build_envelope_local_key_cache(
        keys,
        &existing.header.email,
        &existing.header.server_url,
        local_cache_key,
        existing.local_cache_key.pin_encrypted.clone(),
        existing.local_cache_key.pin_salt.clone(),
        keep_platform_slots_in_shared_cache
            .then(|| existing.local_cache_key.hello_challenge.clone())
            .flatten(),
        keep_platform_slots_in_shared_cache
            .then(|| existing.local_cache_key.hello_encrypted.clone())
            .flatten(),
        keep_platform_slots_in_shared_cache
            .then(|| existing.local_cache_key.native_encrypted.clone())
            .flatten(),
    )?;
    cache.save()?;
    Ok(cache)
}

pub(crate) fn multi_device_mode() -> bool {
    match sshwarden_config::multi_device_enabled() {
        Ok(value) => value,
        Err(e) => {
            // The decision is cached after the first successful Config::load, so
            // this only fires if config is unreadable very early. Warn instead of
            // silently assuming single-device, which would otherwise mis-route
            // device-local unlock material into the shared cache.
            tracing::warn!(
                "Could not determine multi-device mode (assuming disabled): {}",
                e
            );
            false
        }
    }
}

pub(crate) fn load_device_unlock_slots() -> Option<sshwarden_config::unlock_slots::UnlockSlotsFile>
{
    match sshwarden_config::unlock_slots::UnlockSlotsFile::load() {
        Ok(slots) => slots,
        Err(e) => {
            // Distinguish a corrupt/torn slots file from a missing one: log loudly
            // so a truncated unlock-slots.json is not silently treated as "no
            // platform unlock" without any signal.
            tracing::warn!(
                "Failed to load device unlock slots (treating as none): {}",
                e
            );
            None
        }
    }
}

pub(crate) fn current_native_unlock_slot(
    cache: &sshwarden_config::cache::LocalKeyCacheFile,
) -> Option<String> {
    let device_slot = load_device_unlock_slots().and_then(|slots| slots.native_encrypted);
    if multi_device_mode() {
        device_slot
    } else {
        device_slot.or_else(|| cache.local_cache_key.native_encrypted.clone())
    }
}

pub(crate) fn persist_device_unlock_slots_from_cache(
    cache: &sshwarden_config::cache::LocalKeyCacheFile,
) -> anyhow::Result<()> {
    if !multi_device_mode() {
        return Ok(());
    }

    let mut slots = load_device_unlock_slots().unwrap_or_default();
    let mut changed = false;
    if slots.native_encrypted.is_none() && cache.local_cache_key.native_encrypted.is_some() {
        slots.native_encrypted = cache.local_cache_key.native_encrypted.clone();
        changed = true;
    }
    if slots.hello_challenge.is_none() && cache.local_cache_key.hello_challenge.is_some() {
        slots.hello_challenge = cache.local_cache_key.hello_challenge.clone();
        changed = true;
    }
    if slots.hello_encrypted.is_none() && cache.local_cache_key.hello_encrypted.is_some() {
        slots.hello_encrypted = cache.local_cache_key.hello_encrypted.clone();
        changed = true;
    }
    if changed {
        slots.save()?;
    }
    Ok(())
}

pub(crate) async fn reload_shared_local_cache_from_disk_if_multi_device(
    local_key_cache_data: &Arc<RwLock<Option<sshwarden_config::cache::LocalKeyCacheFile>>>,
) {
    if !multi_device_mode() {
        return;
    }
    match sshwarden_config::cache::LocalKeyCacheFile::load() {
        Ok(Some(cache)) => {
            if let Err(e) = persist_device_unlock_slots_from_cache(&cache) {
                tracing::warn!("Failed to persist device unlock slots: {}", e);
            }
            *local_key_cache_data.write().await = Some(cache);
        }
        Ok(None) => {
            // The shared cache is momentarily absent (e.g. an in-flight OneDrive
            // rename or conflict-copy swap). Keep the valid in-memory copy rather
            // than dropping it, which would make the next unlock fail spuriously.
            tracing::debug!("Shared local key cache not found on reload; keeping in-memory copy");
        }
        Err(e) => tracing::warn!("Failed to reload shared local key cache: {}", e),
    }
}

#[cfg(windows)]
pub(crate) fn current_hello_unlock_info(
    cache: &sshwarden_config::cache::LocalKeyCacheFile,
) -> Option<(String, String)> {
    let device_slot = load_device_unlock_slots()
        .and_then(|slots| Some((slots.hello_challenge?, slots.hello_encrypted?)));
    if multi_device_mode() {
        device_slot
    } else {
        device_slot.or_else(|| {
            Some((
                cache.local_cache_key.hello_challenge.clone()?,
                cache.local_cache_key.hello_encrypted.clone()?,
            ))
        })
    }
}

#[cfg(windows)]
pub(crate) fn current_hello_challenge_b64() -> Option<String> {
    let device_challenge = load_device_unlock_slots().and_then(|slots| slots.hello_challenge);
    if multi_device_mode() {
        device_challenge
    } else {
        device_challenge
            .or_else(|| {
                // After set-pin / envelope migration the Hello challenge lives in
                // the envelope cache (local-key-cache.json), not vault.enc.
                sshwarden_config::cache::LocalKeyCacheFile::load()
                    .ok()
                    .flatten()
                    .and_then(|cache| cache.local_cache_key.hello_challenge)
            })
            .or_else(|| {
                sshwarden_config::vault::VaultFile::load()
                    .ok()
                    .flatten()
                    .and_then(|vault| vault.hello_challenge)
            })
    }
}

pub(crate) fn enroll_native_for_local_key_cache(
    cache: &mut sshwarden_config::cache::LocalKeyCacheFile,
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
) -> anyhow::Result<()> {
    if !sshwarden_ui::unlock::native::native_available() {
        anyhow::bail!("native unlock is not available");
    }
    if multi_device_mode() {
        // Device-local slot only; keep platform material out of the shared cache.
        native_encrypt_device_slot(local_cache_key)?;
        cache.local_cache_key.native_encrypted = None;
    } else {
        let encoded_local_cache_key = sshwarden_api::crypto::encode_symmetric_key(local_cache_key);
        let native_slot =
            sshwarden_ui::unlock::native::native_encrypt_local_cache_key(&encoded_local_cache_key)?;
        cache.local_cache_key.native_encrypted = Some(native_slot);
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn enroll_hello_for_local_key_cache(
    cache: &mut sshwarden_config::cache::LocalKeyCacheFile,
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
) -> anyhow::Result<()> {
    if multi_device_mode() {
        // Device-local slot only; keep platform material out of the shared cache.
        hello_encrypt_device_slot(local_cache_key)?;
        cache.local_cache_key.hello_challenge = None;
        cache.local_cache_key.hello_encrypted = None;
    } else {
        let challenge: [u8; 16] = rand::random();
        let hello_encrypted = encrypt_local_cache_key_with_hello(local_cache_key, &challenge)?;
        let hello_challenge = base64::engine::general_purpose::STANDARD.encode(challenge);
        cache.local_cache_key.hello_challenge = Some(hello_challenge);
        cache.local_cache_key.hello_encrypted = Some(hello_encrypted);
    }
    Ok(())
}

/// Native-encrypt the Local Cache Key into THIS device's `unlock-slots.json`.
pub(crate) fn native_encrypt_device_slot(
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
) -> anyhow::Result<()> {
    let encoded_local_cache_key = sshwarden_api::crypto::encode_symmetric_key(local_cache_key);
    let native_slot =
        sshwarden_ui::unlock::native::native_encrypt_local_cache_key(&encoded_local_cache_key)?;
    let mut slots = load_device_unlock_slots().unwrap_or_default();
    slots.native_encrypted = Some(native_slot);
    slots.save()
}

/// Windows Hello-encrypt the Local Cache Key into THIS device's `unlock-slots.json`.
#[cfg(windows)]
pub(crate) fn hello_encrypt_device_slot(
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
) -> anyhow::Result<()> {
    let challenge: [u8; 16] = rand::random();
    let hello_encrypted = encrypt_local_cache_key_with_hello(local_cache_key, &challenge)?;
    let hello_challenge = base64::engine::general_purpose::STANDARD.encode(challenge);
    let mut slots = load_device_unlock_slots().unwrap_or_default();
    slots.hello_challenge = Some(hello_challenge);
    slots.hello_encrypted = Some(hello_encrypted);
    slots.save()
}

/// Multi-device: after a successful PIN unlock, make sure THIS device has its own
/// platform unlock slot. The shared cache no longer carries Hello/native slots
/// (refresh strips them in multi-device mode), so a device that joins later would
/// otherwise be stuck PIN-only forever. Best-effort: failures are logged but never
/// surfaced, and a slot that already exists is left untouched.
pub(crate) fn enroll_device_platform_slots_if_missing(
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
) {
    if !multi_device_mode() {
        return;
    }
    let slots = load_device_unlock_slots().unwrap_or_default();
    if slots.native_encrypted.is_none() && sshwarden_ui::unlock::native::native_available() {
        match native_encrypt_device_slot(local_cache_key) {
            Ok(()) => info!("Enrolled this device's native unlock slot"),
            Err(e) => tracing::warn!("Failed to enroll device native unlock slot: {}", e),
        }
    }
    #[cfg(windows)]
    {
        if slots.hello_encrypted.is_none() && sshwarden_ui::unlock::hello_crypto::hello_available()
        {
            match hello_encrypt_device_slot(local_cache_key) {
                Ok(()) => info!("Enrolled this device's Windows Hello unlock slot"),
                Err(e) => tracing::warn!("Failed to enroll device Hello unlock slot: {}", e),
            }
        }
    }
}

/// Encrypt the local cache key with a PIN, generating a fresh random salt.
/// Returns `(pin_encrypted, pin_salt_b64)` for the v3 cache format (SEC-04).
pub(crate) fn encrypt_local_cache_key_with_pin(
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
    pin: &str,
) -> anyhow::Result<(String, String)> {
    let encoded_local_cache_key = sshwarden_api::crypto::encode_symmetric_key(local_cache_key);
    let salt = sshwarden_api::crypto::random_pin_salt();
    let pin_encrypted =
        sshwarden_api::crypto::pin_encrypt_with_salt(&encoded_local_cache_key, pin, &salt)?;
    let pin_salt = base64::engine::general_purpose::STANDARD.encode(salt);
    Ok((pin_encrypted, pin_salt))
}

#[cfg(windows)]
pub(crate) fn encrypt_local_cache_key_with_hello(
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
    challenge: &[u8; 16],
) -> anyhow::Result<String> {
    let encoded_local_cache_key = sshwarden_api::crypto::encode_symmetric_key(local_cache_key);
    try_hello_encrypt(&encoded_local_cache_key, challenge)
}

pub(crate) fn decrypt_envelope_payload(
    cache: &sshwarden_config::cache::LocalKeyCacheFile,
    local_cache_key: sshwarden_api::crypto::SymmetricKey,
) -> anyhow::Result<(String, sshwarden_api::crypto::SymmetricKey)> {
    let payload =
        sshwarden_api::crypto::decrypt_enc_string(&cache.encrypted_payload, &local_cache_key)
            .context("Failed to decrypt local key cache payload")?;
    let keys_json =
        String::from_utf8(payload).context("Local key cache payload is not valid UTF-8")?;
    Ok((keys_json, local_cache_key))
}

#[allow(dead_code)]
pub(crate) fn decrypt_envelope_local_key_cache_with_native(
    cache: &sshwarden_config::cache::LocalKeyCacheFile,
) -> anyhow::Result<(String, sshwarden_api::crypto::SymmetricKey)> {
    let native_slot =
        current_native_unlock_slot(cache).context("Local key cache has no native unlock slot")?;
    let encoded_lck = sshwarden_ui::unlock::native::native_decrypt_local_cache_key(&native_slot)
        .context("Failed to unlock Local Cache Key with native unlock")?;
    let local_cache_key = sshwarden_api::crypto::decode_symmetric_key(&encoded_lck)
        .context("Failed to decode Local Cache Key")?;
    decrypt_envelope_payload(cache, local_cache_key)
}

pub(crate) async fn finish_native_unlock_response(
    cache: sshwarden_config::cache::LocalKeyCacheFile,
    agent: &mut sshwarden_agent::SshWardenAgent,
    vault_locked: &Arc<std::sync::atomic::AtomicBool>,
    cached_key_tuples: &CachedKeyTuples,
    key_names: &Arc<RwLock<std::collections::HashMap<String, String>>>,
    local_cache_key_state: &LocalCacheKeyHandle,
    success_msg: &str,
) -> sshwarden_agent::ControlResponse {
    match decrypt_envelope_local_key_cache_with_native(&cache) {
        Ok((keys_json, local_cache_key)) => {
            local_cache_key_state.write().await.set(local_cache_key);
            finish_unlock_with_json(
                &keys_json,
                agent,
                vault_locked,
                cached_key_tuples,
                key_names,
                success_msg,
            )
            .await
        }
        Err(e) => sshwarden_agent::ControlResponse::err(&format!("Native unlock failed: {}", e)),
    }
}

pub(crate) fn decrypt_envelope_local_key_cache_with_pin(
    cache: &sshwarden_config::cache::LocalKeyCacheFile,
    pin: &str,
) -> anyhow::Result<(String, sshwarden_api::crypto::SymmetricKey)> {
    let encrypted_lck = cache
        .local_cache_key
        .pin_encrypted
        .as_deref()
        .context("Local key cache has no PIN unlock slot")?;
    let encoded_lck = match cache.local_cache_key.pin_salt.as_deref() {
        Some(salt_b64) => {
            let salt = base64::engine::general_purpose::STANDARD
                .decode(salt_b64)
                .context("Invalid PIN salt in local key cache")?;
            sshwarden_api::crypto::pin_decrypt_with_salt(encrypted_lck, pin, &salt)
        }
        // Pre-v3 cache: the PIN slot was derived with the fixed legacy salt.
        None => sshwarden_api::crypto::pin_decrypt_with_salt(
            encrypted_lck,
            pin,
            &sshwarden_api::crypto::legacy_pin_salt(),
        ),
    }
    .context("Failed to unlock Local Cache Key with PIN")?;
    let local_cache_key = sshwarden_api::crypto::decode_symmetric_key(&encoded_lck)
        .context("Failed to decode Local Cache Key")?;
    decrypt_envelope_payload(cache, local_cache_key)
}

/// Transparently migrate a pre-v3 (fixed-salt) cache to v3 with a fresh random
/// PIN salt after a successful PIN unlock (SEC-04). Only the PIN slot is
/// re-wrapped; the local cache key and other slots (Hello/native) are preserved
/// so there is no biometric re-prompt. Best-effort: a failure is logged, not
/// fatal (the unlock itself already succeeded).
pub(crate) fn needs_pin_salt_migration(cache: &sshwarden_config::cache::LocalKeyCacheFile) -> bool {
    cache.local_cache_key.pin_encrypted.is_some()
        && (cache.version < 3 || cache.local_cache_key.pin_salt.is_none())
}

pub(crate) fn migrate_pin_salt_to_v3(
    cache: &sshwarden_config::cache::LocalKeyCacheFile,
    local_cache_key: &sshwarden_api::crypto::SymmetricKey,
    pin: &str,
) -> anyhow::Result<sshwarden_config::cache::LocalKeyCacheFile> {
    let (pin_encrypted, pin_salt) = encrypt_local_cache_key_with_pin(local_cache_key, pin)?;
    let mut migrated = cache.clone();
    migrated.version = 3;
    migrated.local_cache_key.pin_encrypted = Some(pin_encrypted);
    migrated.local_cache_key.pin_salt = Some(pin_salt);
    migrated.save()?;
    Ok(migrated)
}

#[cfg(windows)]
pub(crate) fn decrypt_envelope_local_key_cache_with_hello(
    cache: &sshwarden_config::cache::LocalKeyCacheFile,
) -> anyhow::Result<(String, sshwarden_api::crypto::SymmetricKey)> {
    let (challenge_b64, hello_encrypted) = current_hello_unlock_info(cache)
        .context("Local key cache has no Windows Hello unlock slot for this device")?;
    let challenge_bytes = base64::engine::general_purpose::STANDARD
        .decode(&challenge_b64)
        .context("Failed to decode Windows Hello challenge")?;
    if challenge_bytes.len() != 16 {
        anyhow::bail!("Invalid Windows Hello challenge length");
    }
    let mut challenge = [0u8; 16];
    challenge.copy_from_slice(&challenge_bytes);
    let encoded_lck = try_hello_unlock(&challenge, &hello_encrypted)
        .context("Failed to unlock Local Cache Key with Windows Hello")?;
    let local_cache_key = sshwarden_api::crypto::decode_symmetric_key(&encoded_lck)
        .context("Failed to decode Local Cache Key")?;
    decrypt_envelope_payload(cache, local_cache_key)
}

pub(crate) fn key_material_fingerprints_from_tuples(
    keys: &[(String, String, String)],
) -> std::collections::HashMap<String, String> {
    use sha2::{Digest, Sha256};

    keys.iter()
        .map(|(pem, _name, vault_item_id)| {
            let mut hasher = Sha256::new();
            hasher.update(pem.as_bytes());
            (vault_item_id.clone(), format!("{:x}", hasher.finalize()))
        })
        .collect()
}

pub(crate) async fn clear_authorization_memory_for_changed_keys_async(
    old_fingerprints: &std::collections::HashMap<String, String>,
    new_keys: &[(String, String, String)],
    authorization_memory: &AuthorizationMemorySet,
) -> (usize, std::collections::HashMap<String, String>) {
    let new_fingerprints = key_material_fingerprints_from_tuples(new_keys);
    let changed_or_removed: std::collections::HashSet<String> = old_fingerprints
        .iter()
        .filter_map(
            |(vault_item_id, old_fingerprint)| match new_fingerprints.get(vault_item_id) {
                Some(new_fingerprint) if new_fingerprint == old_fingerprint => None,
                _ => Some(vault_item_id.clone()),
            },
        )
        .chain(
            new_fingerprints
                .keys()
                .filter(|id| !old_fingerprints.contains_key(*id))
                .cloned(),
        )
        .collect();

    if changed_or_removed.is_empty() {
        return (0, new_fingerprints);
    }

    let mut memory = authorization_memory.write().await;
    let before = memory.len();
    memory.retain(|(vault_item_id, _operation)| !changed_or_removed.contains(vault_item_id));
    (before.saturating_sub(memory.len()), new_fingerprints)
}

pub(crate) fn key_tuples_from_cache_header(
    cache: &sshwarden_config::cache::LocalKeyCacheFile,
) -> Vec<(String, String, String)> {
    cache
        .header
        .keys
        .iter()
        .map(|key| {
            (
                key.public_key_openssh.clone(),
                key.name.clone(),
                key.vault_item_id.clone(),
            )
        })
        .collect()
}

/// Load `ManagedKey`s from the local key cache header (offline, no decryption).
///
/// Returns an error when no cache exists — callers should surface this as a
/// hint that the user needs to log in or sync first.
pub(crate) fn load_managed_keys_from_cache() -> anyhow::Result<Vec<ManagedKey>> {
    let cache = sshwarden_config::cache::LocalKeyCacheFile::load()
        .context("Failed to load local key cache")?
        .context("No local key cache found — run `sshwarden login` or `sshwarden sync` first")?;
    Ok(ManagedKey::from_cache_header(&cache.header.keys))
}
