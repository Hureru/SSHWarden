use std::path::PathBuf;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Persistent vault file stored alongside the executable (`vault.enc`).
///
/// Contains PIN-encrypted SSH key data so the daemon can be unlocked
/// after restart without re-entering the master password.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFile {
    /// File format version (currently 1).
    pub version: u32,
    /// PIN-encrypted `cached_key_tuples` JSON (type 2 EncString).
    pub pin_encrypted: String,
    /// Base64-encoded 16-byte challenge for Windows Hello sign path (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hello_challenge: Option<String>,
    /// Hello-encrypted `cached_key_tuples` JSON (type 2 EncString, optional).
    /// Stored here instead of Credential Manager to avoid the 2560-byte blob limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hello_encrypted: Option<String>,
    /// User email (for display / re-login).
    pub email: String,
    /// Bitwarden server URL.
    pub server_url: String,
}

impl VaultFile {
    /// Path to the vault file (alongside the executable).
    pub fn path() -> anyhow::Result<PathBuf> {
        Ok(crate::config_dir()?.join("vault.enc"))
    }

    /// Load the vault file from disk. Returns `None` if the file does not exist.
    pub fn load() -> anyhow::Result<Option<Self>> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read vault file: {}", path.display()))?;
        let vault: VaultFile = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse vault file: {}", path.display()))?;
        Ok(Some(vault))
    }

    /// Save the vault file to disk, creating the parent directory if needed.
    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create vault directory: {}", parent.display())
            })?;
        }
        let content =
            serde_json::to_string_pretty(self).context("Failed to serialize vault file")?;
        std::fs::write(&path, content)
            .with_context(|| format!("Failed to write vault file: {}", path.display()))?;
        Ok(())
    }

    /// Delete the vault file from disk (if it exists).
    pub fn delete() -> anyhow::Result<()> {
        let path = Self::path()?;
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("Failed to delete vault file: {}", path.display()))?;
        }
        Ok(())
    }
}
