use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalKeyCacheFile {
    pub version: u32,
    pub header: LocalKeyCacheHeader,
    pub encrypted_payload: String,
    pub local_cache_key: LocalCacheKeySlots,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalKeyCacheHeader {
    pub email: String,
    pub server_url: String,
    pub keys: Vec<KeyIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyIdentity {
    pub name: String,
    pub vault_item_id: String,
    pub public_key_openssh: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalCacheKeySlots {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_encrypted: Option<String>,
    /// Base64-encoded random salt for PIN key derivation (format v3+). When
    /// absent (pre-v3 caches), the fixed legacy salt is used; a successful
    /// unlock transparently re-saves with a fresh random salt (SEC-04).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_salt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hello_challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hello_encrypted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_encrypted: Option<String>,
}

impl LocalKeyCacheFile {
    /// Supported on-disk format versions. v2 is the original envelope format;
    /// v3 adds a per-cache random PIN salt (`LocalCacheKeySlots::pin_salt`).
    const SUPPORTED_VERSIONS: &'static [u32] = &[2, 3];

    pub fn path() -> anyhow::Result<PathBuf> {
        Ok(crate::config_dir()?.join("local-key-cache.json"))
    }

    pub fn load() -> anyhow::Result<Option<Self>> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read local key cache: {}", path.display()))?;
        let cache: LocalKeyCacheFile = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse local key cache: {}", path.display()))?;
        if !Self::SUPPORTED_VERSIONS.contains(&cache.version) {
            anyhow::bail!(
                "Unsupported local key cache version {} (supported: {:?}): {}",
                cache.version,
                Self::SUPPORTED_VERSIONS,
                path.display()
            );
        }
        Ok(Some(cache))
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed to create local key cache directory: {}",
                    parent.display()
                )
            })?;
        }
        let content =
            serde_json::to_string_pretty(self).context("Failed to serialize local key cache")?;
        write_owner_only_file(&path, content)
            .with_context(|| format!("Failed to write local key cache: {}", path.display()))?;
        Ok(())
    }

    pub fn delete() -> anyhow::Result<()> {
        let path = Self::path()?;
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("Failed to delete local key cache: {}", path.display()))?;
        }
        Ok(())
    }
}

fn write_owner_only_file(path: &Path, content: impl AsRef<[u8]>) -> anyhow::Result<()> {
    std::fs::write(path, content)?;
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}
