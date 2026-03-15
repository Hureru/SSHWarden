use std::path::PathBuf;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Device-specific session file stored alongside the executable.
///
/// Each device gets its own session file (`session-{hostname}.enc`) so that
/// multiple machines sharing the same exe directory via OneDrive do not
/// interfere with each other.
///
/// The session file stores an encrypted refresh token that allows the daemon
/// to restore a Bitwarden API session after a PIN/Hello unlock without
/// requiring the master password.
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
    /// Path to the session file: `{config_dir}/session-{hostname}.enc`
    pub fn path() -> anyhow::Result<PathBuf> {
        let hostname = hostname();
        Ok(crate::config_dir()?.join(format!("session-{hostname}.enc")))
    }

    /// Load the session file from disk. Returns `None` if the file does not exist.
    pub fn load() -> anyhow::Result<Option<Self>> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read session file: {}", path.display()))?;
        let session: SessionFile = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse session file: {}", path.display()))?;
        Ok(Some(session))
    }

    /// Save the session file to disk.
    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed to create session directory: {}",
                    parent.display()
                )
            })?;
        }
        let content =
            serde_json::to_string_pretty(self).context("Failed to serialize session file")?;
        std::fs::write(&path, content)
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
        Ok(())
    }
}

/// Get the machine hostname, sanitised for use in file names.
fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| {
            gethostname()
        })
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
