use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::{anyhow, Context};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::trace;

use crate::models::{KdfType, PreloginResponse};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// Symmetric key: 32-byte encryption key + 32-byte MAC key
#[derive(Clone)]
pub struct SymmetricKey {
    pub enc_key: Vec<u8>, // 32 bytes
    pub mac_key: Vec<u8>, // 32 bytes
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymmetricKey")
            .field("enc_key", &"[REDACTED]")
            .field("mac_key", &"[REDACTED]")
            .finish()
    }
}

/// Derive the master key from master password using the KDF parameters.
///
/// Returns a 32-byte master key.
pub fn derive_master_key(
    password: &str,
    email: &str,
    prelogin: &PreloginResponse,
) -> anyhow::Result<Vec<u8>> {
    let salt = email.trim().to_lowercase();

    match prelogin.kdf {
        KdfType::Pbkdf2 => {
            let mut master_key = vec![0u8; 32];
            pbkdf2::pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                salt.as_bytes(),
                prelogin.kdf_iterations,
                &mut master_key,
            );
            Ok(master_key)
        }
        KdfType::Argon2id => {
            let memory = prelogin
                .kdf_memory
                .ok_or_else(|| anyhow!("Argon2id requires kdf_memory"))? * 1024; // KiB
            let parallelism = prelogin
                .kdf_parallelism
                .ok_or_else(|| anyhow!("Argon2id requires kdf_parallelism"))?;
            let iterations = prelogin.kdf_iterations;

            // Argon2id uses SHA-256 hash of email as salt
            use sha2::Digest;
            let salt_hash = Sha256::digest(salt.as_bytes());

            let params = argon2::Params::new(memory, iterations, parallelism, Some(32))
                .map_err(|e| anyhow!("Invalid Argon2 params: {e}"))?;
            let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

            let mut master_key = vec![0u8; 32];
            argon2
                .hash_password_into(password.as_bytes(), &salt_hash, &mut master_key)
                .map_err(|e| anyhow!("Argon2 hashing failed: {e}"))?;
            Ok(master_key)
        }
    }
}

/// Derive the password hash that gets sent to the server for authentication.
///
/// This is PBKDF2-SHA256 with 1 iteration: PBKDF2(masterKey, password, 1)
pub fn derive_password_hash(master_key: &[u8], password: &str) -> anyhow::Result<String> {
    let mut password_hash = vec![0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(master_key, password.as_bytes(), 1, &mut password_hash);
    Ok(STANDARD.encode(&password_hash))
}

/// Stretch the 32-byte master key into a SymmetricKey (enc_key + mac_key) using HKDF-Expand-SHA256.
///
/// Bitwarden uses HKDF-Expand only (no extract step), treating the master key directly as the PRK.
pub fn stretch_master_key(master_key: &[u8]) -> anyhow::Result<SymmetricKey> {
    let hk = hkdf::Hkdf::<Sha256>::from_prk(master_key)
        .map_err(|e| anyhow!("HKDF from_prk failed: {e}"))?;
    let mut enc_key = vec![0u8; 32];
    let mut mac_key = vec![0u8; 32];
    hk.expand(b"enc", &mut enc_key)
        .map_err(|e| anyhow!("HKDF expand enc failed: {e}"))?;
    hk.expand(b"mac", &mut mac_key)
        .map_err(|e| anyhow!("HKDF expand mac failed: {e}"))?;
    Ok(SymmetricKey { enc_key, mac_key })
}

/// Decrypt the user's encrypted symmetric key (Profile.Key from token/sync response).
///
/// The encrypted key is an EncString that, when decrypted with the stretched master key,
/// yields 64 bytes: first 32 = enc_key, last 32 = mac_key.
pub fn decrypt_user_key(
    encrypted_key_str: &str,
    master_key: &[u8],
) -> anyhow::Result<SymmetricKey> {
    let stretched = stretch_master_key(master_key)?;
    let decrypted = decrypt_enc_string(encrypted_key_str, &stretched)
        .context("Failed to decrypt user symmetric key")?;

    if decrypted.len() != 64 {
        return Err(anyhow!(
            "Decrypted user key has unexpected length: {} (expected 64)",
            decrypted.len()
        ));
    }

    Ok(SymmetricKey {
        enc_key: decrypted[..32].to_vec(),
        mac_key: decrypted[32..].to_vec(),
    })
}

/// Parse and decrypt a Bitwarden EncString.
///
/// EncString formats:
///   - type 0: `0.{iv}|{data}` — AesCbc256_B64 (no HMAC)
///   - type 2: `2.{iv}|{data}|{mac}` — AesCbc256_HmacSha256_B64
pub fn decrypt_enc_string(enc_string: &str, key: &SymmetricKey) -> anyhow::Result<Vec<u8>> {
    let (enc_type, payload) = enc_string
        .split_once('.')
        .ok_or_else(|| anyhow!("Invalid EncString: no type separator"))?;

    let enc_type: u8 = enc_type
        .parse()
        .map_err(|_| anyhow!("Invalid EncString type: {enc_type}"))?;

    match enc_type {
        0 => decrypt_type0(payload, key),
        2 => decrypt_type2(payload, key),
        _ => Err(anyhow!("Unsupported EncString type: {enc_type}")),
    }
}

/// Type 0: AesCbc256_B64 — IV|Data (no HMAC)
fn decrypt_type0(payload: &str, key: &SymmetricKey) -> anyhow::Result<Vec<u8>> {
    let parts: Vec<&str> = payload.split('|').collect();
    if parts.len() != 2 {
        return Err(anyhow!(
            "Invalid EncString type 0: expected 2 parts (iv|data), got {}",
            parts.len()
        ));
    }

    let iv = STANDARD.decode(parts[0]).context("Failed to decode IV")?;
    let data = STANDARD.decode(parts[1]).context("Failed to decode ciphertext")?;

    let decryptor = Aes256CbcDec::new_from_slices(&key.enc_key, &iv)
        .map_err(|e| anyhow!("AES-CBC init failed: {e}"))?;

    let plaintext = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(&data)
        .map_err(|e| anyhow!("AES-CBC decryption failed: {e}"))?;

    Ok(plaintext)
}

/// Type 2: AesCbc256_HmacSha256_B64 — IV|Data|MAC
fn decrypt_type2(payload: &str, key: &SymmetricKey) -> anyhow::Result<Vec<u8>> {
    let parts: Vec<&str> = payload.split('|').collect();
    if parts.len() != 3 {
        return Err(anyhow!(
            "Invalid EncString type 2: expected 3 parts (iv|data|mac), got {}",
            parts.len()
        ));
    }

    let iv = STANDARD.decode(parts[0]).context("Failed to decode IV")?;
    let data = STANDARD.decode(parts[1]).context("Failed to decode ciphertext")?;
    let mac = STANDARD.decode(parts[2]).context("Failed to decode MAC")?;

    // Verify HMAC-SHA256
    let mut hmac = HmacSha256::new_from_slice(&key.mac_key)
        .map_err(|e| anyhow!("HMAC init failed: {e}"))?;
    hmac.update(&iv);
    hmac.update(&data);
    hmac.verify_slice(&mac)
        .map_err(|_| anyhow!("HMAC verification failed - wrong key or corrupted data"))?;

    trace!("HMAC verified, decrypting {} bytes", data.len());

    // Decrypt AES-256-CBC
    let decryptor = Aes256CbcDec::new_from_slices(&key.enc_key, &iv)
        .map_err(|e| anyhow!("AES-CBC init failed: {e}"))?;

    let plaintext = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(&data)
        .map_err(|e| anyhow!("AES-CBC decryption failed: {e}"))?;

    Ok(plaintext)
}

/// Decrypt an EncString to a UTF-8 string.
pub fn decrypt_enc_string_to_string(
    enc_string: &str,
    key: &SymmetricKey,
) -> anyhow::Result<String> {
    let bytes = decrypt_enc_string(enc_string, key)?;
    String::from_utf8(bytes).context("Decrypted data is not valid UTF-8")
}

/// Encrypt data with AES-256-CBC + HMAC-SHA256, returning a type 2 EncString.
pub fn encrypt_enc_string(data: &[u8], key: &SymmetricKey) -> anyhow::Result<String> {
    use rand::Rng;
    let iv: [u8; 16] = rand::thread_rng().gen();

    let encryptor = Aes256CbcEnc::new_from_slices(&key.enc_key, &iv)
        .map_err(|e| anyhow!("AES-CBC encrypt init failed: {e}"))?;

    let ciphertext = encryptor.encrypt_padded_vec_mut::<Pkcs7>(data);

    // HMAC over IV + ciphertext
    let mut hmac = HmacSha256::new_from_slice(&key.mac_key)
        .map_err(|e| anyhow!("HMAC init failed: {e}"))?;
    hmac.update(&iv);
    hmac.update(&ciphertext);
    let mac = hmac.finalize().into_bytes();

    Ok(format!(
        "2.{}|{}|{}",
        STANDARD.encode(iv),
        STANDARD.encode(&ciphertext),
        STANDARD.encode(mac),
    ))
}

/// Derive a SymmetricKey from a PIN using Argon2id.
///
/// Uses a fixed salt derived from the purpose string. For PIN-based encryption
/// this is sufficient as the PIN is just a convenience unlock mechanism.
pub fn derive_pin_key(pin: &str) -> anyhow::Result<SymmetricKey> {
    use sha2::Digest;
    let salt = Sha256::digest(b"sshwarden-pin-key-derivation");

    let params = argon2::Params::new(64 * 1024, 3, 1, Some(64))
        .map_err(|e| anyhow!("Invalid Argon2 params: {e}"))?;
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    let mut key_material = vec![0u8; 64];
    argon2
        .hash_password_into(pin.as_bytes(), &salt, &mut key_material)
        .map_err(|e| anyhow!("Argon2 PIN derivation failed: {e}"))?;

    Ok(SymmetricKey {
        enc_key: key_material[..32].to_vec(),
        mac_key: key_material[32..].to_vec(),
    })
}

/// Encrypt a string with a PIN-derived key.
pub fn pin_encrypt(data: &str, pin: &str) -> anyhow::Result<String> {
    let key = derive_pin_key(pin)?;
    encrypt_enc_string(data.as_bytes(), &key)
}

/// Decrypt a string with a PIN-derived key.
pub fn pin_decrypt(enc_string: &str, pin: &str) -> anyhow::Result<String> {
    let key = derive_pin_key(pin)?;
    let bytes = decrypt_enc_string(enc_string, &key)?;
    String::from_utf8(bytes).context("PIN-decrypted data is not valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_master_key_pbkdf2() {
        let prelogin = PreloginResponse {
            kdf: KdfType::Pbkdf2,
            kdf_iterations: 600000,
            kdf_memory: None,
            kdf_parallelism: None,
        };

        let key = derive_master_key("password123", "test@example.com", &prelogin).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_password_hash() {
        let master_key = vec![0u8; 32];
        let hash = derive_password_hash(&master_key, "password123").unwrap();
        // Base64 of 32 bytes = 44 chars
        assert_eq!(hash.len(), 44);
    }

    #[test]
    fn test_stretch_master_key() {
        let master_key = vec![1u8; 32];
        let stretched = stretch_master_key(&master_key);
        assert!(stretched.is_ok());
        let key = stretched.unwrap();
        assert_eq!(key.enc_key.len(), 32);
        assert_eq!(key.mac_key.len(), 32);
        // enc and mac should be different
        assert_ne!(key.enc_key, key.mac_key);
    }

    #[test]
    fn test_pin_encrypt_decrypt_roundtrip() {
        let data = r#"[["key1","name1","id1"],["key2","name2","id2"]]"#;
        let pin = "1234";

        let encrypted = pin_encrypt(data, pin).unwrap();
        assert!(encrypted.starts_with("2."));

        let decrypted = pin_decrypt(&encrypted, pin).unwrap();
        assert_eq!(decrypted, data);

        // Wrong PIN should fail
        let wrong = pin_decrypt(&encrypted, "9999");
        assert!(wrong.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = SymmetricKey {
            enc_key: vec![42u8; 32],
            mac_key: vec![84u8; 32],
        };
        let original = b"hello sshwarden encryption test";
        let encrypted = encrypt_enc_string(original, &key).unwrap();
        assert!(encrypted.starts_with("2."));
        let decrypted = decrypt_enc_string(&encrypted, &key).unwrap();
        assert_eq!(decrypted, original);
    }
}
