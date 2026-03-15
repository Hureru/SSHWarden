pub mod session;
pub mod vault;

use std::path::PathBuf;

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub agent: AgentConfig,
    #[serde(default)]
    pub unlock: UnlockConfig,
    #[serde(default)]
    pub socket: SocketConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    pub api_url: Option<String>,
    pub identity_url: Option<String>,
    pub notifications_url: Option<String>,
}

fn default_base_url() -> String {
    "https://vault.bitwarden.com".to_string()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            base_url: default_base_url(),
            api_url: None,
            identity_url: None,
            notifications_url: None,
        }
    }
}

impl ServerConfig {
    pub fn api_url(&self) -> String {
        self.api_url
            .clone()
            .unwrap_or_else(|| format!("{}/api", self.base_url))
    }

    pub fn identity_url(&self) -> String {
        self.identity_url
            .clone()
            .unwrap_or_else(|| format!("{}/identity", self.base_url))
    }

    pub fn notifications_url(&self) -> String {
        self.notifications_url.clone().unwrap_or_else(|| {
            if self.base_url.contains("vault.bitwarden.com") {
                "https://notifications.bitwarden.com".to_string()
            } else {
                format!("{}/notifications", self.base_url)
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_auth_method")]
    pub method: String,
    #[serde(default)]
    pub email: String,
}

fn default_auth_method() -> String {
    "password".to_string()
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            method: default_auth_method(),
            email: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PromptBehavior {
    #[default]
    Always,
    Never,
    RememberUntilLock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default)]
    pub prompt_behavior: PromptBehavior,
    #[serde(default = "default_sync_interval")]
    pub sync_interval: u64,
    #[serde(default = "default_lock_timeout")]
    pub lock_timeout: u64,
}

fn default_sync_interval() -> u64 {
    300
}

fn default_lock_timeout() -> u64 {
    3600
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            prompt_behavior: PromptBehavior::default(),
            sync_interval: default_sync_interval(),
            lock_timeout: default_lock_timeout(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnlockMethod {
    WindowsHello,
    Pin,
    Password,
}

// Cannot use #[derive(Default)] due to conditional compilation
#[allow(clippy::derivable_impls)]
impl Default for UnlockMethod {
    fn default() -> Self {
        #[cfg(windows)]
        {
            Self::WindowsHello
        }
        #[cfg(not(windows))]
        {
            Self::Password
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FallbackMethod {
    #[default]
    Pin,
    Password,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockConfig {
    #[serde(default)]
    pub method: UnlockMethod,
    #[serde(default)]
    pub fallback: FallbackMethod,
    #[serde(default = "default_true")]
    pub auto_unlock_on_request: bool,
}

fn default_true() -> bool {
    true
}

impl Default for UnlockConfig {
    fn default() -> Self {
        Self {
            method: UnlockMethod::default(),
            fallback: FallbackMethod::default(),
            auto_unlock_on_request: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SocketConfig {
    pub path: Option<String>,
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let path = config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
        Ok(config)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = config_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create config directory: {}", parent.display())
            })?;
        }
        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;
        std::fs::write(&path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;
        Ok(())
    }
}

/// Get the base directory for all SSHWarden data files.
///
/// Uses the directory where the executable is located, making the
/// application fully portable (all files travel with the exe).
pub fn config_dir() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe().context("Could not determine executable path")?;
    let dir = exe
        .parent()
        .context("Executable has no parent directory")?
        .to_path_buf();
    Ok(dir)
}

pub fn config_path() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}
