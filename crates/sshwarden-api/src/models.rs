use serde::Deserialize;

// ── KDF ──

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "u8")]
pub enum KdfType {
    Pbkdf2 = 0,
    Argon2id = 1,
}

impl TryFrom<u8> for KdfType {
    type Error = String;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(KdfType::Pbkdf2),
            1 => Ok(KdfType::Argon2id),
            _ => Err(format!("Unknown KDF type: {v}")),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PreloginResponse {
    #[serde(alias = "Kdf", alias = "kdf")]
    pub kdf: KdfType,
    #[serde(alias = "KdfIterations", alias = "kdfIterations")]
    pub kdf_iterations: u32,
    #[serde(default, alias = "KdfMemory", alias = "kdfMemory")]
    pub kdf_memory: Option<u32>,
    #[serde(default, alias = "KdfParallelism", alias = "kdfParallelism")]
    pub kdf_parallelism: Option<u32>,
}

// ── Login ──

#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub token_type: String,
    pub refresh_token: Option<String>,
    #[serde(alias = "Key", alias = "key")]
    pub key: Option<String>,
    #[serde(alias = "PrivateKey", alias = "privateKey")]
    pub private_key: Option<String>,
    #[serde(alias = "Kdf", alias = "kdf")]
    pub kdf_type: Option<u8>,
    #[serde(alias = "KdfIterations", alias = "kdfIterations")]
    pub kdf_iterations: Option<u32>,
}

// ── Sync ──

#[derive(Debug, Clone, Deserialize)]
pub struct SyncResponse {
    #[serde(alias = "Profile", alias = "profile")]
    pub profile: SyncProfile,
    #[serde(alias = "Ciphers", alias = "ciphers")]
    pub ciphers: Vec<Cipher>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyncProfile {
    #[serde(alias = "Id", alias = "id")]
    pub id: String,
    #[serde(alias = "Email", alias = "email")]
    pub email: String,
    #[serde(alias = "Key", alias = "key")]
    pub key: String,
    #[serde(alias = "PrivateKey", alias = "privateKey")]
    pub private_key: Option<String>,
}

// ── Cipher ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherType {
    Login,
    SecureNote,
    Card,
    Identity,
    SshKey,
    Unknown(u8),
}

impl<'de> Deserialize<'de> for CipherType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = u8::deserialize(deserializer)?;
        Ok(match v {
            1 => CipherType::Login,
            2 => CipherType::SecureNote,
            3 => CipherType::Card,
            4 => CipherType::Identity,
            5 => CipherType::SshKey,
            other => CipherType::Unknown(other),
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Cipher {
    #[serde(alias = "Id", alias = "id")]
    pub id: String,
    #[serde(alias = "Type", alias = "type")]
    pub cipher_type: CipherType,
    #[serde(alias = "Name", alias = "name")]
    pub name: Option<String>,
    #[serde(alias = "DeletedDate", alias = "deletedDate")]
    pub deleted_date: Option<String>,
    #[serde(alias = "SshKey", alias = "sshKey")]
    pub ssh_key: Option<SshKeyData>,
    #[serde(alias = "OrganizationId", alias = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(alias = "Key", alias = "key")]
    pub key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SshKeyData {
    #[serde(alias = "PrivateKey", alias = "privateKey")]
    pub private_key: String,
    #[serde(alias = "PublicKey", alias = "publicKey")]
    pub public_key: String,
    #[serde(alias = "KeyFingerprint", alias = "keyFingerprint")]
    pub key_fingerprint: String,
}
