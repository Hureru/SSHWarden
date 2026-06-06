use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Device-specific session file.
///
/// In multi-device storage mode this lives under
/// `{shared_data_dir}/devices/<device-id>/session-{hostname}.enc` so two
/// OneDrive-synced machines do not overwrite each other's Bitwarden refresh
/// token/session state. Without multi-device mode it remains in the historical
/// shared data directory.
///
/// The session file stores an encrypted refresh token that allows the daemon to
/// restore a Bitwarden API session after a PIN/Hello unlock without requiring
/// the master password.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionFile {
    /// File format version (currently 1).
    pub version: u32,
    /// Persistent device UUID — unique per machine, stable across restarts.
    pub device_id: String,
    /// PIN-encrypted Bitwarden refresh_token (type 2 EncString).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_encrypted_token: Option<String>,
    /// Hello-encrypted Bitwarden refresh_token (type 2 EncString).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hello_encrypted_token: Option<String>,
    /// Identity URL used for token refresh (`{base}/identity`).
    pub identity_url: String,
}

impl SessionFile {
    /// Supported on-disk format versions for the device session file.
    const SUPPORTED_VERSIONS: &'static [u32] = &[1];

    /// Path to the current device's session file.
    pub fn path() -> anyhow::Result<PathBuf> {
        Ok(crate::device_data_dir()?.join(Self::file_name()))
    }

    /// Historical path used before multi-device runtime/session state was
    /// separated. Used as a best-effort read/delete fallback for migration.
    fn legacy_path() -> anyhow::Result<PathBuf> {
        Ok(crate::shared_data_dir()?.join(Self::file_name()))
    }

    fn file_name() -> String {
        let hostname = hostname();
        format!("session-{hostname}.enc")
    }

    /// Load the session file from disk. Returns `None` if the file does not exist.
    pub fn load() -> anyhow::Result<Option<Self>> {
        let path = Self::path()?;
        let path = if path.exists() {
            path
        } else {
            let legacy = Self::legacy_path()?;
            if legacy.exists() {
                legacy
            } else {
                return Ok(None);
            }
        };
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read session file: {}", path.display()))?;
        let session: SessionFile = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse session file: {}", path.display()))?;
        if !Self::SUPPORTED_VERSIONS.contains(&session.version) {
            anyhow::bail!(
                "Unsupported session file version {} (supported: {:?}): {}",
                session.version,
                Self::SUPPORTED_VERSIONS,
                path.display()
            );
        }
        Ok(Some(session))
    }

    /// Save the session file to disk.
    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create session directory: {}", parent.display())
            })?;
        }
        let content =
            serde_json::to_string_pretty(self).context("Failed to serialize session file")?;
        write_owner_only_file(&path, content)
            .with_context(|| format!("Failed to write session file: {}", path.display()))?;
        Ok(())
    }

    /// Delete the session file from disk (if it exists).
    pub fn delete() -> anyhow::Result<()> {
        let path = Self::path()?;
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("Failed to delete session file: {}", path.display()))?;
        }
        let legacy = Self::legacy_path()?;
        if legacy.exists() && legacy != path {
            std::fs::remove_file(&legacy).with_context(|| {
                format!("Failed to delete legacy session file: {}", legacy.display())
            })?;
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

/// Get the machine hostname, sanitised for use in file names.
fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| gethostname())
        .unwrap_or_else(|_| "unknown".to_string())
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

/// Fallback hostname retrieval via `hostname` command.
fn gethostname() -> Result<String, std::env::VarError> {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or(std::env::VarError::NotPresent)
}
