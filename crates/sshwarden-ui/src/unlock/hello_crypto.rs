//! Windows Hello sign-path utilities for SSHWarden.
//!
//! Uses KeyCredentialManager to derive a 32-byte symmetric key from a
//! Windows Hello–protected signature, then encrypts/decrypts vault data
//! with that key via AES-256-CBC + HMAC-SHA256 (reusing sshwarden_api crypto).
//!
//! The Hello-encrypted ciphertext is stored in vault.enc (not Credential
//! Manager) to avoid the 2560-byte CredentialBlob size limit and to
//! keep everything portable.

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{debug, info};
use windows::core::{h, Interface, HSTRING};
use windows::Security::Credentials::{
    KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Storage::Streams::IBuffer;
use windows::Win32::System::WinRT::IBufferByteAccess;

const CREDENTIAL_NAME: &HSTRING = h!("SSHWardenBiometrics");

// ── Hello sign-path key derivation ───────────────────────────────────────

/// Derive a 32-byte symmetric key via Windows Hello sign path.
///
/// 1. Ensure a KeyCredential named "SSHWardenBiometrics" exists (FailIfExists → OpenAsync).
/// 2. Sign the given `challenge` with the credential (triggers Hello prompt).
/// 3. SHA-256(signature) → 32-byte key.
///
/// Must be called from `spawn_blocking` (synchronous WinRT `.get()` calls).
pub fn hello_derive_key(challenge: &[u8; 16]) -> Result<[u8; 32]> {
    // Focus helper thread (same pattern as existing Windows Hello code)
    let stop_focusing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_clone = stop_focusing.clone();
    std::thread::spawn(move || {
        let mut interval_ms = 50u64;
        while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
            super::windows::focus_and_center_security_prompt_pub();
            std::thread::sleep(std::time::Duration::from_millis(interval_ms));
            // Gradual backoff: 50 → 100 → 200ms (cap)
            if interval_ms < 200 {
                interval_ms = (interval_ms * 2).min(200);
            }
        }
    });
    let _guard = scopeguard::guard((), |_| {
        stop_focusing.store(true, std::sync::atomic::Ordering::Relaxed);
    });

    // Create or open the signing credential
    let credential = {
        let creation_result = KeyCredentialManager::RequestCreateAsync(
            CREDENTIAL_NAME,
            KeyCredentialCreationOption::FailIfExists,
        )?
        .get()?;

        match creation_result.Status()? {
            KeyCredentialStatus::CredentialAlreadyExists => {
                debug!("Hello credential already exists, opening");
                KeyCredentialManager::OpenAsync(CREDENTIAL_NAME)?.get()?
            }
            KeyCredentialStatus::Success => {
                info!("Created new Hello signing credential");
                creation_result
            }
            status => return Err(anyhow!("Failed to create Hello credential: {:?}", status)),
        }
    }
    .Credential()?;

    // Sign the challenge
    let challenge_buffer = CryptographicBuffer::CreateFromByteArray(challenge.as_slice())?;

    let sign_result = credential.RequestSignAsync(&challenge_buffer)?.get()?;
    drop(credential);

    if sign_result.Status()? != KeyCredentialStatus::Success {
        return Err(anyhow!("Hello sign request failed or was cancelled"));
    }

    let mut sig_buffer = sign_result.Result()?;
    let sig_bytes = unsafe { as_mut_bytes(&mut sig_buffer)? };

    let key: [u8; 32] = Sha256::digest(sig_bytes).into();
    Ok(key)
}

/// Check whether Windows Hello signing (KeyCredentialManager) is available.
pub fn hello_available() -> bool {
    use windows::Security::Credentials::UI::{
        UserConsentVerifier, UserConsentVerifierAvailability,
    };
    let Ok(op) = UserConsentVerifier::CheckAvailabilityAsync() else {
        return false;
    };
    let Ok(avail) = op.get() else {
        return false;
    };
    avail == UserConsentVerifierAvailability::Available
}

// ── Hello encrypt / decrypt using EncString ────────────────────────────────

/// Build a SymmetricKey from a 32-byte Hello-derived raw key.
fn hello_sym_key(raw_key: &[u8; 32]) -> sshwarden_api::crypto::SymmetricKey {
    let mut hasher = Sha256::new();
    hasher.update(b"sshwarden-hello-mac");
    hasher.update(raw_key);
    sshwarden_api::crypto::SymmetricKey {
        enc_key: raw_key[..].to_vec(),
        mac_key: hasher.finalize().to_vec(),
    }
}

/// Encrypt `key_tuples_json` with a Hello-derived key.
///
/// Returns the encrypted EncString (type 2 format).
pub fn hello_encrypt_keys(key_tuples_json: &str, challenge: &[u8; 16]) -> Result<String> {
    let raw_key = hello_derive_key(challenge)?;
    sshwarden_api::crypto::encrypt_enc_string(key_tuples_json.as_bytes(), &hello_sym_key(&raw_key))
}

/// Decrypt an EncString with a Hello-derived key.
///
/// Returns the decrypted JSON string.
pub fn hello_decrypt_keys(enc_string: &str, challenge: &[u8; 16]) -> Result<String> {
    let raw_key = hello_derive_key(challenge)?;
    let bytes = sshwarden_api::crypto::decrypt_enc_string(enc_string, &hello_sym_key(&raw_key))?;
    String::from_utf8(bytes).map_err(|e| anyhow!("Hello decrypted data is not valid UTF-8: {}", e))
}

// ── IBuffer helper ─────────────────────────────────────────────────────────

unsafe fn as_mut_bytes(buffer: &mut IBuffer) -> Result<&mut [u8]> {
    let interop = buffer.cast::<IBufferByteAccess>()?;
    unsafe {
        let data = interop.Buffer()?;
        Ok(std::slice::from_raw_parts_mut(
            data,
            buffer.Length()? as usize,
        ))
    }
}
