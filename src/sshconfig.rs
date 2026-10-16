//! Key selector files and the managed OpenSSH config snippet / Include line.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 3b).

use anyhow::Context;
use tracing::info;

use crate::naming::{selector_file_name, vault_item_id_prefix};
use crate::path_util::{
    create_private_dir, ensure_managed_ssh_config_path_is_safe, write_private_file,
};

pub(crate) fn key_selector_dir() -> anyhow::Result<std::path::PathBuf> {
    Ok(sshwarden_config::config_dir()?.join("keys"))
}

pub(crate) fn selector_path_for_key(
    key_name: &str,
    cipher_id: &str,
) -> anyhow::Result<std::path::PathBuf> {
    Ok(key_selector_dir()?.join(selector_file_name(key_name, cipher_id)))
}

pub(crate) fn write_key_selector_files(
    keys: &[sshwarden_api::DecryptedSshKey],
) -> anyhow::Result<()> {
    let dir = key_selector_dir()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create key selector directory: {}", dir.display()))?;

    let mut active_paths = std::collections::HashSet::new();
    for key in keys {
        let path = selector_path_for_key(&key.name, &key.cipher_id)?;
        active_paths.insert(path.clone());
        let content = format!("{}\n", key.public_key_openssh.trim());
        std::fs::write(&path, content)
            .with_context(|| format!("Failed to write key selector file: {}", path.display()))?;
    }

    // Remove selector files for deleted/archived/unavailable items. Rename aliases
    // are retained because they have a different path for the same Vault Item Id.
    if dir.exists() {
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("Failed to read key selector directory: {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("pub")
                && !active_paths.contains(&path)
            {
                let file_name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("");
                let active_key_for_alias = keys.iter().find(|key| {
                    let prefix = vault_item_id_prefix(&key.cipher_id);
                    !prefix.is_empty() && file_name.ends_with(&format!("--{prefix}.pub"))
                });
                if let Some(key) = active_key_for_alias {
                    let content = format!("{}\n", key.public_key_openssh.trim());
                    std::fs::write(&path, content).with_context(|| {
                        format!("Failed to update key selector alias: {}", path.display())
                    })?;
                } else {
                    std::fs::remove_file(&path).with_context(|| {
                        format!(
                            "Failed to remove stale key selector file: {}",
                            path.display()
                        )
                    })?;
                }
            }
        }
    }

    Ok(())
}

/// Generate a managed `sshwarden_config` snippet driven by [`HostBindingsFile`].
///
/// Each key with one or more bound host patterns produces a real `Host` block
/// pointing at its `.pub` selector file, with `IdentitiesOnly yes`. Keys without
/// any binding are emitted as commented-out templates below, so the user can
/// see what is available to bind.
/// Slim key reference used by snippet generation — avoids touching `DecryptedSshKey`
/// (which holds the sensitive private PEM) when only metadata is needed.
#[derive(Debug, Clone)]
pub(crate) struct ManagedKey {
    pub(crate) name: String,
    pub(crate) cipher_id: String,
}

impl ManagedKey {
    pub(crate) fn from_decrypted(keys: &[sshwarden_api::DecryptedSshKey]) -> Vec<Self> {
        keys.iter()
            .map(|k| Self {
                name: k.name.clone(),
                cipher_id: k.cipher_id.clone(),
            })
            .collect()
    }

    pub(crate) fn from_cache_header(keys: &[sshwarden_config::cache::KeyIdentity]) -> Vec<Self> {
        keys.iter()
            .map(|k| Self {
                name: k.name.clone(),
                cipher_id: k.vault_item_id.clone(),
            })
            .collect()
    }
}

pub(crate) const SSHWARDEN_KEY_MARKER_PREFIX: &str = "# sshwarden:key ";

pub(crate) fn load_host_bindings_importing_managed(
    keys: &[ManagedKey],
) -> anyhow::Result<sshwarden_config::bindings::HostBindingsFile> {
    let mut bindings = sshwarden_config::bindings::HostBindingsFile::load()?;
    if keys.is_empty() {
        return Ok(bindings);
    }

    let include_path = managed_sshwarden_include_path()?;
    if import_host_bindings_from_managed_file(&include_path, keys, &mut bindings)? {
        bindings
            .save()
            .context("Failed to save host bindings imported from managed SSH config")?;
    }
    Ok(bindings)
}

pub(crate) fn import_host_bindings_from_managed_file(
    path: &std::path::Path,
    keys: &[ManagedKey],
    bindings: &mut sshwarden_config::bindings::HostBindingsFile,
) -> anyhow::Result<bool> {
    if !path.exists() {
        return Ok(false);
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read managed SSH config: {}", path.display()))?;
    let known_ids: std::collections::HashSet<&str> =
        keys.iter().map(|key| key.cipher_id.as_str()).collect();
    let mut pending_cipher_id: Option<String> = None;
    let mut changed = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(cipher_id) = sshwarden_key_marker_cipher_id(trimmed)
            .or_else(|| legacy_key_comment_cipher_id(trimmed))
            .filter(|id| known_ids.contains(id.as_str()))
        {
            pending_cipher_id = Some(cipher_id);
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let Some(directive) = parts.next() else {
            continue;
        };
        if !directive.eq_ignore_ascii_case("Host") {
            continue;
        }
        let Some(cipher_id) = pending_cipher_id.take() else {
            continue;
        };

        let hosts: Vec<String> = parts
            .filter(|host| *host != "<host>")
            .map(str::to_string)
            .collect();
        if hosts.is_empty() {
            continue;
        }
        let mut valid_hosts = true;
        for host in &hosts {
            if let Err(e) = sshwarden_config::bindings::validate_host_pattern(host) {
                tracing::warn!(
                    path = %path.display(),
                    host = %host,
                    error = %e,
                    "Ignoring invalid manually edited SSHWarden Host pattern"
                );
                valid_hosts = false;
                break;
            }
        }
        if !valid_hosts {
            continue;
        }

        let current = bindings
            .bindings
            .get(&cipher_id)
            .map(|binding| binding.hosts.as_slice());
        if current != Some(hosts.as_slice()) {
            bindings.set_hosts(&cipher_id, hosts)?;
            changed = true;
        }
    }

    Ok(changed)
}

pub(crate) fn sshwarden_key_marker_cipher_id(line: &str) -> Option<String> {
    line.strip_prefix(SSHWARDEN_KEY_MARKER_PREFIX)
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(String::from)
}

pub(crate) fn legacy_key_comment_cipher_id(line: &str) -> Option<String> {
    let comment = line.strip_prefix("# ")?;
    let (_, suffix) = comment.rsplit_once(" (")?;
    suffix.strip_suffix(')').map(String::from)
}

pub(crate) fn ssh_config_snippet_with_bindings(
    keys: &[ManagedKey],
    bindings: &sshwarden_config::bindings::HostBindingsFile,
) -> anyhow::Result<String> {
    let path_style = sshwarden_config::Config::load()?.ssh_config.path_style;
    let mut lines = vec![
        "# SSHWarden managed SSH config".to_string(),
        "# You may edit Host lines in SSHWarden key blocks; they are imported before regeneration."
            .to_string(),
        "# Other lines are regenerated. Manage bindings via `sshwarden keys bind/unbind ...`."
            .to_string(),
        String::new(),
    ];

    let mut bound_keys: Vec<&ManagedKey> = Vec::new();
    let mut unbound_keys: Vec<&ManagedKey> = Vec::new();
    for key in keys {
        match bindings.bindings.get(&key.cipher_id) {
            Some(b) if !b.hosts.is_empty() => bound_keys.push(key),
            _ => unbound_keys.push(key),
        }
    }

    for key in &bound_keys {
        let path = selector_path_for_key(&key.name, &key.cipher_id)?;
        let binding = bindings
            .bindings
            .get(&key.cipher_id)
            .expect("bound_keys filtered for presence");
        lines.push(format!("{}{}", SSHWARDEN_KEY_MARKER_PREFIX, key.cipher_id));
        lines.push(format!("# {} ({})", key.name, key.cipher_id));
        lines.push(format!("Host {}", binding.hosts.join(" ")));
        lines.push(format!(
            "    IdentityFile {}",
            sshwarden_config::ssh_config::path_arg_with_style(&path, path_style)
        ));
        lines.push("    IdentitiesOnly yes".to_string());
        lines.push(String::new());
    }

    if !unbound_keys.is_empty() {
        lines.push("# --- Unbound keys (uncomment + edit to use) ---".to_string());
        lines.push(String::new());
        for key in &unbound_keys {
            let path = selector_path_for_key(&key.name, &key.cipher_id)?;
            lines.push(format!("{}{}", SSHWARDEN_KEY_MARKER_PREFIX, key.cipher_id));
            lines.push(format!("# {} ({})", key.name, key.cipher_id));
            lines.push("# Host <host>".to_string());
            lines.push(format!(
                "#     IdentityFile {}",
                sshwarden_config::ssh_config::path_arg_with_style(&path, path_style)
            ));
            lines.push("#     IdentitiesOnly yes".to_string());
            lines.push(String::new());
        }
    }

    Ok(lines.join("\n"))
}

/// Refresh the managed `sshwarden_config` file from current vault keys + bindings.
///
/// Behaviour:
/// - Loads [`HostBindingsFile`] (defaults to empty if missing).
/// - Prunes bindings whose `cipher_uuid` is no longer in `keys`, persists if changed.
/// - Writes the snippet only if there are bindings OR the managed file already
///   exists — never creates the file unsolicited for users who have not opted in.
/// - Does NOT modify `~/.ssh/config`; the `Include` line is installed separately.
pub(crate) fn sync_managed_ssh_config_with_bindings(
    keys: &[sshwarden_api::DecryptedSshKey],
) -> anyhow::Result<()> {
    let managed = ManagedKey::from_decrypted(keys);
    sync_managed_ssh_config_inner(&managed, false)
}

/// Inner sync: optionally force write even when no bindings + no existing file
/// (used by `ssh-config write`).
pub(crate) fn sync_managed_ssh_config_inner(
    keys: &[ManagedKey],
    force_write: bool,
) -> anyhow::Result<()> {
    let mut bindings =
        load_host_bindings_importing_managed(keys).context("Failed to load host bindings")?;
    // UX-7/data-safety: an empty key set means we have no cache metadata to
    // classify orphans against — e.g. binding ahead of first sync (see
    // resolve_cipher_id), or the local key cache isn't loaded. Pruning against an
    // empty known-set would delete EVERY binding, so only prune when we actually
    // know the current key set.
    if !keys.is_empty() {
        let known_ids: Vec<&str> = keys.iter().map(|k| k.cipher_id.as_str()).collect();
        let pruned = bindings.prune_orphans(known_ids.iter().copied());
        if pruned > 0 {
            bindings
                .save()
                .context("Failed to save host bindings after pruning orphans")?;
            info!("Pruned {} orphan host binding(s)", pruned);
        }
    }

    let include_path = managed_sshwarden_include_path()?;
    let has_bindings = !bindings.bindings.is_empty();
    if !force_write && !has_bindings && !include_path.exists() {
        return Ok(());
    }

    let snippet = ssh_config_snippet_with_bindings(keys, &bindings)?;
    write_private_file(&include_path, snippet).with_context(|| {
        format!(
            "Failed to write managed SSHWarden SSH config: {}",
            include_path.display()
        )
    })?;
    Ok(())
}

pub(crate) fn managed_sshwarden_include_path() -> anyhow::Result<std::path::PathBuf> {
    let config = sshwarden_config::Config::load()?;
    let path = sshwarden_config::managed_ssh_config_path(&config)?;
    let user_config = user_ssh_config_path()?;
    ensure_managed_ssh_config_path_is_safe(&path, &user_config)?;
    Ok(path)
}

pub(crate) fn user_ssh_config_path() -> anyhow::Result<std::path::PathBuf> {
    sshwarden_config::user_ssh_config_path()
}

pub(crate) fn write_sshwarden_include_line(
    config_path: &std::path::Path,
    include_path: &std::path::Path,
) -> anyhow::Result<()> {
    if let Some(parent) = config_path.parent() {
        create_private_dir(parent).with_context(|| {
            format!(
                "Failed to create SSH config directory: {}",
                parent.display()
            )
        })?;
    }

    let include_line = sshwarden_config::ssh_config::include_line_with_style(
        include_path,
        sshwarden_config::Config::load()?.ssh_config.path_style,
    );
    let existing = std::fs::read_to_string(config_path).unwrap_or_default();
    // Return only when the desired line is already present. A legacy absolute
    // line may still "match" SSHWarden's include semantically, but in
    // home-relative multi-device mode we want the marked block below to rewrite
    // it so a synced ~/.ssh/config works across different Windows usernames.
    if existing.lines().any(|line| line.trim() == include_line) {
        return Ok(());
    }

    const MARKER: &str = sshwarden_config::ssh_config::SSHWARDEN_INCLUDE_MARKER;
    let mut rewritten: Vec<String> = Vec::with_capacity(existing.lines().count() + 2);
    let mut marker_waiting_for_include = false;
    let mut replaced_marked_include = false;
    let mut dropped_unmarked_include = false;

    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed == MARKER {
            marker_waiting_for_include = true;
            rewritten.push(line.to_string());
            continue;
        }
        if marker_waiting_for_include {
            if trimmed.is_empty() {
                rewritten.push(line.to_string());
                continue;
            }
            if is_ssh_include_directive(trimmed)
                || line_matches_current_or_legacy_sshwarden_include(trimmed, include_path)
            {
                rewritten.push(include_line.clone());
                marker_waiting_for_include = false;
                replaced_marked_include = true;
                continue;
            }
            marker_waiting_for_include = false;
        }
        if line_matches_current_or_legacy_sshwarden_include(trimmed, include_path) {
            // Drop unmarked older SSHWarden Include lines. A fresh marked line
            // with the desired path style is appended below if no marked block
            // was rewritten.
            dropped_unmarked_include = true;
            continue;
        }
        rewritten.push(line.to_string());
    }

    if replaced_marked_include {
        let mut new_config = rewritten.join("\n");
        if !new_config.is_empty() && !new_config.ends_with('\n') {
            new_config.push('\n');
        }
        write_private_file(config_path, &new_config)
            .with_context(|| format!("Failed to update SSH config: {}", config_path.display()))?;
        return Ok(());
    }

    let mut new_config = if dropped_unmarked_include {
        rewritten.join("\n")
    } else {
        existing
    };
    if !new_config.is_empty() && !new_config.ends_with('\n') {
        new_config.push('\n');
    }
    new_config.push_str("\n# SSHWarden managed key selector snippets\n");
    new_config.push_str(&include_line);
    new_config.push('\n');
    write_private_file(config_path, &new_config)
        .with_context(|| format!("Failed to update SSH config: {}", config_path.display()))?;

    Ok(())
}

pub(crate) fn is_ssh_include_directive(line: &str) -> bool {
    line.split_whitespace()
        .next()
        .map(|directive| directive.eq_ignore_ascii_case("Include"))
        .unwrap_or(false)
}

pub(crate) fn line_matches_current_or_legacy_sshwarden_include(
    line: &str,
    include_path: &std::path::Path,
) -> bool {
    if sshwarden_config::ssh_config::line_matches_sshwarden_include(line, include_path) {
        return true;
    }
    sshwarden_config::legacy_home_managed_ssh_config_path()
        .map(|legacy| sshwarden_config::ssh_config::line_matches_sshwarden_include(line, &legacy))
        .unwrap_or(false)
}

/// Remove the sshwarden `Include` line and its preceding marker comment from
/// `~/.ssh/config`. Returns `true` if anything was changed.
pub(crate) fn remove_sshwarden_include_line(
    config_path: &std::path::Path,
    include_path: &std::path::Path,
) -> anyhow::Result<bool> {
    if !config_path.exists() {
        return Ok(false);
    }
    let existing = std::fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read SSH config: {}", config_path.display()))?;
    const MARKER: &str = sshwarden_config::ssh_config::SSHWARDEN_INCLUDE_MARKER;

    let mut kept: Vec<&str> = Vec::with_capacity(existing.lines().count());
    let mut removed_any = false;
    let mut skip_marker_for_next_include = false;
    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed == MARKER {
            // Defer the decision: drop only if the next non-empty line is our Include.
            skip_marker_for_next_include = true;
            kept.push(line);
            continue;
        }
        if line_matches_current_or_legacy_sshwarden_include(trimmed, include_path)
            || (skip_marker_for_next_include && is_ssh_include_directive(trimmed))
        {
            // Drop the include line and retroactively drop the marker if it was the previous kept entry.
            if skip_marker_for_next_include {
                while let Some(last) = kept.last() {
                    if last.trim().is_empty() {
                        kept.pop();
                    } else if last.trim() == MARKER {
                        kept.pop();
                        break;
                    } else {
                        break;
                    }
                }
            }
            skip_marker_for_next_include = false;
            removed_any = true;
            continue;
        }
        if !trimmed.is_empty() {
            skip_marker_for_next_include = false;
        }
        kept.push(line);
    }

    if !removed_any {
        return Ok(false);
    }

    let mut new_config = kept.join("\n");
    if !new_config.is_empty() && !new_config.ends_with('\n') {
        new_config.push('\n');
    }
    if let Some(parent) = config_path.parent() {
        create_private_dir(parent).with_context(|| {
            format!(
                "Failed to prepare SSH config directory: {}",
                parent.display()
            )
        })?;
    }
    write_private_file(config_path, &new_config)
        .with_context(|| format!("Failed to update SSH config: {}", config_path.display()))?;
    Ok(true)
}
