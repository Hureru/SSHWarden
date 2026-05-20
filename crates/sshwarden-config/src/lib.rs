pub mod bindings;
pub mod cache;
pub mod session;
pub mod ssh_config;
pub mod vault;

use std::path::PathBuf;
use std::sync::OnceLock;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Cached resolution of the data directory, populated on first call to [`config_dir`].
///
/// All callers share a single resolution outcome for the lifetime of the process —
/// this prevents flapping when, for example, a portable probe file is written
/// after some path has already been computed.
static RESOLVED_DIR: OnceLock<PathBuf> = OnceLock::new();

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
    #[serde(default)]
    pub storage: StorageConfig,
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
        self.notifications_url
            .clone()
            .unwrap_or_else(|| default_notifications_url(&self.base_url))
    }
}

fn default_notifications_url(base_url: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let host = base
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(base);

    match host {
        "vault.bitwarden.com" => "https://notifications.bitwarden.com".to_string(),
        "vault.bitwarden.eu" => "https://notifications.bitwarden.eu".to_string(),
        _ => format!("{base}/notifications"),
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
    #[serde(default = "default_notification_keepalive_interval")]
    pub notification_keepalive_interval: u64,
    #[serde(default = "default_notification_idle_timeout")]
    pub notification_idle_timeout: u64,
    #[serde(default = "default_notification_reconnect_attempts_before_fallback")]
    pub notification_reconnect_attempts_before_fallback: usize,
    #[serde(default = "default_notification_reconnect_max_backoff")]
    pub notification_reconnect_max_backoff: u64,
}

fn default_sync_interval() -> u64 {
    300
}

fn default_lock_timeout() -> u64 {
    3600
}

fn default_notification_keepalive_interval() -> u64 {
    30
}

fn default_notification_idle_timeout() -> u64 {
    90
}

fn default_notification_reconnect_attempts_before_fallback() -> usize {
    3
}

fn default_notification_reconnect_max_backoff() -> u64 {
    60
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            prompt_behavior: PromptBehavior::default(),
            sync_interval: default_sync_interval(),
            lock_timeout: default_lock_timeout(),
            notification_keepalive_interval: default_notification_keepalive_interval(),
            notification_idle_timeout: default_notification_idle_timeout(),
            notification_reconnect_attempts_before_fallback:
                default_notification_reconnect_attempts_before_fallback(),
            notification_reconnect_max_backoff: default_notification_reconnect_max_backoff(),
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
    /// Optional custom SSH agent endpoint path.
    pub path: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Keep user data beside the executable instead of platform-standard storage.
    #[serde(default)]
    pub portable: bool,
    /// Optional explicit portable directory. Used only when portable is true.
    pub portable_dir: Option<String>,
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

/// Get the base directory for persistent SSHWarden configuration/data files.
///
/// Resolution priority (highest first):
/// 1. `SSHWARDEN_HOME=<dir>` environment variable (explicit override).
/// 2. `SSHWARDEN_PORTABLE=1` environment variable (executable's directory).
/// 3. `<exe>/config.toml` with `[storage] portable = true` (probe-based portable mode).
///    If `portable_dir` is set and non-empty, uses that path; otherwise uses the
///    executable's directory.
/// 4. Platform-standard config directory (e.g. `%APPDATA%\SSHWarden` on Windows).
///
/// The resolution is cached in [`RESOLVED_DIR`] on first call, so subsequent calls
/// from any module return the same path even if the probe file is added or removed
/// mid-run.
pub fn config_dir() -> anyhow::Result<PathBuf> {
    if let Some(dir) = RESOLVED_DIR.get() {
        return Ok(dir.clone());
    }
    let resolved = resolve_data_dir()?;
    // Ignore the race-loser case where another caller populated the cache first;
    // both callers would have computed the same value.
    let _ = RESOLVED_DIR.set(resolved.clone());
    Ok(resolved)
}

fn resolve_data_dir() -> anyhow::Result<PathBuf> {
    if let Some(dir) = env_path("SSHWARDEN_HOME") {
        return Ok(dir);
    }
    if env_bool("SSHWARDEN_PORTABLE") {
        return executable_dir();
    }
    if let Some(dir) = probe_portable_from_exe() {
        return Ok(dir);
    }
    platform_config_dir()
}

/// Probe `<exe>/config.toml` for an opt-in portable configuration.
///
/// Returns `Some(dir)` only when the file exists, parses successfully, and has
/// `[storage] portable = true`. Returns `None` otherwise; parse/read errors are
/// reported via `eprintln!` because tracing is not yet initialised this early in
/// startup.
fn probe_portable_from_exe() -> Option<PathBuf> {
    let exe = executable_dir().ok()?;
    let probe = exe.join("config.toml");
    if !probe.exists() {
        return None;
    }
    let content = match std::fs::read_to_string(&probe) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                path = %probe.display(),
                error = %e,
                "Failed to read config.toml for portable probe"
            );
            return None;
        }
    };
    let cfg: Config = match toml::from_str(&content) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!(
                path = %probe.display(),
                error = %e,
                "Failed to parse config.toml for portable probe"
            );
            return None;
        }
    };
    if !cfg.storage.portable {
        return None;
    }
    if let Some(dir) = cfg
        .storage
        .portable_dir
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some(PathBuf::from(dir));
    }
    Some(exe)
}

pub fn config_path() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

pub fn runtime_dir() -> anyhow::Result<PathBuf> {
    if let Some(dir) = env_path("SSHWARDEN_RUNTIME_DIR") {
        return Ok(dir);
    }

    #[cfg(windows)]
    {
        Ok(config_dir()?.join("run"))
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(dir) = env_path("XDG_RUNTIME_DIR") {
            return Ok(dir.join("sshwarden"));
        }
        Ok(config_dir()?.join("run"))
    }

    #[cfg(target_os = "macos")]
    {
        Ok(config_dir()?.join("run"))
    }

    #[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
    {
        Ok(config_dir()?.join("run"))
    }
}

pub fn default_agent_socket_path() -> anyhow::Result<PathBuf> {
    #[cfg(windows)]
    {
        Ok(PathBuf::from(r"\\.\pipe\openssh-ssh-agent"))
    }

    #[cfg(not(windows))]
    {
        Ok(runtime_dir()?.join("agent.sock"))
    }
}

pub fn default_control_socket_path() -> anyhow::Result<PathBuf> {
    #[cfg(windows)]
    {
        Ok(PathBuf::from(r"\\.\pipe\sshwarden-control"))
    }

    #[cfg(not(windows))]
    {
        Ok(runtime_dir()?.join("control.sock"))
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn env_bool(name: &str) -> bool {
    std::env::var(name)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn executable_dir() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe().context("Could not determine executable path")?;
    exe.parent()
        .context("Executable has no parent directory")
        .map(PathBuf::from)
}

#[cfg(windows)]
fn platform_config_dir() -> anyhow::Result<PathBuf> {
    env_path("APPDATA")
        .context("APPDATA environment variable not set")
        .map(|dir| dir.join("SSHWarden"))
}

#[cfg(target_os = "linux")]
fn platform_config_dir() -> anyhow::Result<PathBuf> {
    if let Some(dir) = env_path("XDG_CONFIG_HOME") {
        return Ok(dir.join("sshwarden"));
    }
    home_dir().map(|home| home.join(".config").join("sshwarden"))
}

#[cfg(target_os = "macos")]
fn platform_config_dir() -> anyhow::Result<PathBuf> {
    home_dir().map(|home| {
        home.join("Library")
            .join("Application Support")
            .join("SSHWarden")
    })
}

#[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
fn platform_config_dir() -> anyhow::Result<PathBuf> {
    home_dir().map(|home| home.join(".sshwarden"))
}

#[cfg(not(windows))]
fn home_dir() -> anyhow::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME environment variable not set")
}

#[cfg(not(windows))]
fn user_runtime_suffix() -> String {
    std::env::var("UID")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "unknown".to_string())
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
        .collect()
}
