use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Per-device platform unlock slots for a shared Local Key Cache.
///
/// The shared `local-key-cache.json` keeps the encrypted key payload and the
/// shared PIN slot. Platform-native unlock material (Windows Hello / macOS
/// Keychain / Linux Secret Service) is device-specific and belongs here under
/// `{device_data_dir}/unlock-slots.json` so multiple OneDrive-synced machines do
/// not overwrite one another's native unlock slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockSlotsFile {
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hello_challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hello_encrypted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_encrypted: Option<String>,
}

impl Default for UnlockSlotsFile {
    fn default() -> Self {
        Self {
            version: 1,
            hello_challenge: None,
            hello_encrypted: None,
            native_encrypted: None,
        }
    }
}

impl UnlockSlotsFile {
    const SUPPORTED_VERSIONS: &'static [u32] = &[1];

    pub fn path() -> anyhow::Result<PathBuf> {
        Ok(crate::device_data_dir()?.join("unlock-slots.json"))
    }

    pub fn load() -> anyhow::Result<Option<Self>> {
        let path = Self::path()?;
        // Read directly and match the error kind instead of an exists() pre-check,
        // which would race if the file is removed/renamed between the two calls.
        let content = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(anyhow::Error::from(e).context(format!(
                    "Failed to read unlock slots file: {}",
                    path.display()
                )))
            }
        };
        let slots: UnlockSlotsFile = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse unlock slots file: {}", path.display()))?;
        Self::ensure_supported_version(slots.version, &path)?;
        Ok(Some(slots))
    }

    /// Reject versions this build cannot round-trip. Used by both `load` and
    /// `save` so we never persist a file we would later refuse to read back.
    fn ensure_supported_version(version: u32, path: &Path) -> anyhow::Result<()> {
        if !Self::SUPPORTED_VERSIONS.contains(&version) {
            anyhow::bail!(
                "Unsupported unlock slots version {} (supported: {:?}): {}",
                version,
                Self::SUPPORTED_VERSIONS,
                path.display()
            );
        }
        Ok(())
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::path()?;
        // Refuse to persist a version we could not read back (mirrors `load`).
        Self::ensure_supported_version(self.version, &path)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed to create unlock slots directory: {}",
                    parent.display()
                )
            })?;
        }
        let content =
            serde_json::to_string_pretty(self).context("Failed to serialize unlock slots")?;
        crate::write_owner_only_file(&path, content)
            .with_context(|| format!("Failed to write unlock slots file: {}", path.display()))?;
        Ok(())
    }

    pub fn delete() -> anyhow::Result<()> {
        let path = Self::path()?;
        // Remove directly and tolerate NotFound rather than exists()-then-remove,
        // which can race with concurrent removal/sync.
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(anyhow::Error::from(e).context(format!(
                "Failed to delete unlock slots file: {}",
                path.display()
            ))),
        }
    }
}
