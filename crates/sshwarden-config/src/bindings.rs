use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Local mapping of vault SSH keys to the SSH host patterns they should be offered for.
///
/// Stored in `{config_dir}/bindings.json`. Used to generate a managed SSH config
/// snippet (`sshwarden.conf`) that pins `IdentityFile` + `IdentitiesOnly yes`
/// per host, so the SSH client only offers the correct key and never trips
/// `MaxAuthTries`.
///
/// Keys are indexed by `cipher_uuid` (stable across renames) — never by display name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostBindingsFile {
    pub version: u32,
    #[serde(default)]
    pub bindings: BTreeMap<String, KeyBinding>,
}

impl Default for HostBindingsFile {
    fn default() -> Self {
        Self {
            version: 1,
            bindings: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyBinding {
    /// SSH host patterns this key is bound to.
    ///
    /// Each entry is whatever can legally appear after `Host` in `ssh_config`:
    /// hostnames (`github.com`), IPv4 literals (`192.168.1.10`), IPv6 literals
    /// (`2001:db8::1`), or globs (`*.prod.example.com`, `10.0.*.*`).
    /// CIDR notation is not supported by OpenSSH — use glob form instead.
    pub hosts: Vec<String>,
    /// Unix timestamp (seconds) of last modification.
    #[serde(default)]
    pub updated_at: i64,
}

impl HostBindingsFile {
    pub fn path() -> anyhow::Result<PathBuf> {
        Ok(crate::config_dir()?.join("bindings.json"))
    }

    pub fn load() -> anyhow::Result<Self> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read bindings file: {}", path.display()))?;
        let file: HostBindingsFile = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse bindings file: {}", path.display()))?;
        Ok(file)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create bindings directory: {}", parent.display())
            })?;
        }
        let content =
            serde_json::to_string_pretty(self).context("Failed to serialize bindings file")?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, content)
            .with_context(|| format!("Failed to write bindings tmp file: {}", tmp.display()))?;
        // Best-effort atomic replace: on Windows `rename` over an existing file
        // can fail, so fall back to remove+rename.
        if let Err(e) = std::fs::rename(&tmp, &path) {
            if path.exists() {
                let _ = std::fs::remove_file(&path);
                std::fs::rename(&tmp, &path).with_context(|| {
                    format!("Failed to replace bindings file: {}", path.display())
                })?;
            } else {
                return Err(anyhow::Error::from(e).context(format!(
                    "Failed to rename bindings tmp file: {}",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    pub fn delete() -> anyhow::Result<()> {
        let path = Self::path()?;
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("Failed to delete bindings file: {}", path.display()))?;
        }
        Ok(())
    }

    /// Replace the host patterns bound to `cipher_uuid`. Empty list removes the entry.
    pub fn set_hosts(&mut self, cipher_uuid: &str, hosts: Vec<String>) -> anyhow::Result<()> {
        for h in &hosts {
            validate_host_pattern(h)?;
        }
        let mut deduped: Vec<String> = Vec::with_capacity(hosts.len());
        for h in hosts {
            let trimmed = h.trim().to_string();
            if !deduped.iter().any(|existing| existing.eq_ignore_ascii_case(&trimmed)) {
                deduped.push(trimmed);
            }
        }
        if deduped.is_empty() {
            self.bindings.remove(cipher_uuid);
        } else {
            self.bindings.insert(
                cipher_uuid.to_string(),
                KeyBinding {
                    hosts: deduped,
                    updated_at: now_secs(),
                },
            );
        }
        Ok(())
    }

    /// Add a single host pattern, no-op if already present (case-insensitive).
    pub fn add_host(&mut self, cipher_uuid: &str, host: &str) -> anyhow::Result<()> {
        validate_host_pattern(host)?;
        let host = host.trim().to_string();
        let entry = self.bindings.entry(cipher_uuid.to_string()).or_default();
        if !entry.hosts.iter().any(|h| h.eq_ignore_ascii_case(&host)) {
            entry.hosts.push(host);
        }
        entry.updated_at = now_secs();
        Ok(())
    }

    /// Remove a single host pattern. Returns true if removed.
    pub fn remove_host(&mut self, cipher_uuid: &str, host: &str) -> bool {
        let Some(entry) = self.bindings.get_mut(cipher_uuid) else {
            return false;
        };
        let before = entry.hosts.len();
        entry.hosts.retain(|h| !h.eq_ignore_ascii_case(host));
        let removed = entry.hosts.len() != before;
        if entry.hosts.is_empty() {
            self.bindings.remove(cipher_uuid);
        } else if removed {
            entry.updated_at = now_secs();
        }
        removed
    }

    /// Remove all bindings for a key.
    pub fn clear_key(&mut self, cipher_uuid: &str) -> bool {
        self.bindings.remove(cipher_uuid).is_some()
    }

    /// Drop entries whose `cipher_uuid` is not in `known_ids`.
    /// Returns the number of orphan entries pruned.
    pub fn prune_orphans<I, S>(&mut self, known_ids: I) -> usize
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let known: std::collections::HashSet<String> = known_ids
            .into_iter()
            .map(|s| s.as_ref().to_string())
            .collect();
        let before = self.bindings.len();
        self.bindings.retain(|id, _| known.contains(id));
        before - self.bindings.len()
    }
}

/// Validate a host pattern accepted by OpenSSH's `Host` directive.
///
/// Accepts: hostnames, IPv4/IPv6 literals, and glob patterns (`*`, `?`).
/// Rejects: empty/whitespace-only strings, embedded whitespace (would split the
/// directive), control chars, and quote/backslash chars hostile to the config
/// format. Leading `!` (negation) is allowed since OpenSSH supports it.
pub fn validate_host_pattern(pattern: &str) -> anyhow::Result<()> {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        anyhow::bail!("Host pattern is empty");
    }
    if trimmed.chars().any(|c| c.is_whitespace()) {
        anyhow::bail!("Host pattern must not contain whitespace: {pattern:?}");
    }
    if trimmed.chars().any(|c| c.is_control()) {
        anyhow::bail!("Host pattern must not contain control characters: {pattern:?}");
    }
    if trimmed.chars().any(|c| matches!(c, '"' | '\'' | '\\' | '#')) {
        anyhow::bail!("Host pattern contains a character that is unsafe in ssh_config: {pattern:?}");
    }
    Ok(())
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_hostname_ipv4_ipv6_and_glob() {
        validate_host_pattern("github.com").unwrap();
        validate_host_pattern("192.168.1.10").unwrap();
        validate_host_pattern("2001:db8::1").unwrap();
        validate_host_pattern("*.prod.example.com").unwrap();
        validate_host_pattern("10.0.*.*").unwrap();
        validate_host_pattern("bastion?.corp").unwrap();
        validate_host_pattern("!badhost.example").unwrap();
    }

    #[test]
    fn rejects_empty_or_whitespace() {
        assert!(validate_host_pattern("").is_err());
        assert!(validate_host_pattern("   ").is_err());
        assert!(validate_host_pattern("foo bar").is_err());
        assert!(validate_host_pattern("foo\tbar").is_err());
    }

    #[test]
    fn rejects_unsafe_characters() {
        assert!(validate_host_pattern("foo\"bar").is_err());
        assert!(validate_host_pattern("foo#bar").is_err());
        assert!(validate_host_pattern("foo\\bar").is_err());
        assert!(validate_host_pattern("foo\x01bar").is_err());
    }

    #[test]
    fn set_hosts_dedupes_case_insensitively() {
        let mut file = HostBindingsFile::default();
        file.set_hosts(
            "id-1",
            vec!["GitHub.com".into(), "github.com".into(), "  github.com  ".into()],
        )
        .unwrap();
        let entry = file.bindings.get("id-1").unwrap();
        assert_eq!(entry.hosts.len(), 1);
        assert_eq!(entry.hosts[0], "GitHub.com");
    }

    #[test]
    fn set_hosts_empty_removes_entry() {
        let mut file = HostBindingsFile::default();
        file.set_hosts("id-1", vec!["github.com".into()]).unwrap();
        assert!(file.bindings.contains_key("id-1"));
        file.set_hosts("id-1", vec![]).unwrap();
        assert!(!file.bindings.contains_key("id-1"));
    }

    #[test]
    fn add_and_remove_host() {
        let mut file = HostBindingsFile::default();
        file.add_host("id-1", "github.com").unwrap();
        file.add_host("id-1", "github.com").unwrap(); // dedup
        file.add_host("id-1", "*.example.com").unwrap();
        assert_eq!(file.bindings.get("id-1").unwrap().hosts.len(), 2);

        assert!(file.remove_host("id-1", "GITHUB.COM"));
        assert_eq!(file.bindings.get("id-1").unwrap().hosts.len(), 1);

        assert!(file.remove_host("id-1", "*.example.com"));
        assert!(!file.bindings.contains_key("id-1"));

        assert!(!file.remove_host("id-1", "nope"));
    }

    #[test]
    fn prune_orphans_drops_unknown_keys() {
        let mut file = HostBindingsFile::default();
        file.add_host("id-1", "a.com").unwrap();
        file.add_host("id-2", "b.com").unwrap();
        file.add_host("id-3", "c.com").unwrap();

        let pruned = file.prune_orphans(["id-1", "id-3"]);
        assert_eq!(pruned, 1);
        assert!(file.bindings.contains_key("id-1"));
        assert!(!file.bindings.contains_key("id-2"));
        assert!(file.bindings.contains_key("id-3"));
    }

    #[test]
    fn clear_key_removes_entry() {
        let mut file = HostBindingsFile::default();
        file.add_host("id-1", "a.com").unwrap();
        assert!(file.clear_key("id-1"));
        assert!(!file.clear_key("id-1"));
    }

    #[test]
    fn rejects_invalid_pattern_in_set_hosts() {
        let mut file = HostBindingsFile::default();
        let err = file.set_hosts("id-1", vec!["bad host".into()]);
        assert!(err.is_err());
        // Entry must not be partially created on validation failure.
        assert!(!file.bindings.contains_key("id-1"));
    }
}
