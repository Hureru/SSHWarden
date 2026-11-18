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

/// Run a read-modify-write cycle on `bindings.json` under an exclusive file
/// lock, first seeding any bindings recovered from the managed SSH config.
///
/// This is the concurrency-safe counterpart to
/// [`load_host_bindings_importing_managed`] + `save`: concurrent
/// `sshwarden keys bind` / sign-flow binding writes are serialised so the last
/// writer cannot discard the earlier one's update.
pub(crate) fn with_host_bindings_locked<T, F>(keys: &[ManagedKey], mutate: F) -> anyhow::Result<T>
where
    F: FnOnce(&mut sshwarden_config::bindings::HostBindingsFile) -> anyhow::Result<T>,
{
    let path = sshwarden_config::bindings::HostBindingsFile::path()?;
    sshwarden_config::bindings::HostBindingsFile::update_locked(&path, |bindings| {
        if !keys.is_empty() {
            let include_path = managed_sshwarden_include_path()?;
            import_host_bindings_from_managed_file(&include_path, keys, bindings)?;
        }
        mutate(bindings)
    })
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
    Ok(ssh_config_snippet_with_bindings_in(
        keys,
        bindings,
        &key_selector_dir()?,
        path_style,
    ))
}

/// Pure snippet builder behind [`ssh_config_snippet_with_bindings`]: the
/// selector directory and path style are injected so the generated content can
/// be asserted in tests without touching the real config directory.
fn ssh_config_snippet_with_bindings_in(
    keys: &[ManagedKey],
    bindings: &sshwarden_config::bindings::HostBindingsFile,
    selector_dir: &std::path::Path,
    path_style: sshwarden_config::SshConfigPathStyle,
) -> String {
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
        let path = selector_dir.join(selector_file_name(&key.name, &key.cipher_id));
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
            let path = selector_dir.join(selector_file_name(&key.name, &key.cipher_id));
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

    lines.join("\n")
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
/// (used by `ssh-config write`). Hand edits to `Host` lines in the old snippet
/// are imported first.
pub(crate) fn sync_managed_ssh_config_inner(
    keys: &[ManagedKey],
    force_write: bool,
) -> anyhow::Result<()> {
    let bindings =
        load_host_bindings_importing_managed(keys).context("Failed to load host bindings")?;
    write_managed_ssh_config(keys, bindings, force_write)
}

/// Rebuild the managed snippet right after a change made through
/// [`with_host_bindings_locked`]. `bindings.json` is the truth here: the old
/// snippet still shows the hosts from before the change, so importing it again
/// would undo the change (hand edits were already imported before it).
pub(crate) fn regenerate_managed_ssh_config_after_change(
    keys: &[ManagedKey],
) -> anyhow::Result<()> {
    let bindings = sshwarden_config::bindings::HostBindingsFile::load()
        .context("Failed to load host bindings")?;
    write_managed_ssh_config(keys, bindings, true)
}

fn write_managed_ssh_config(
    keys: &[ManagedKey],
    mut bindings: sshwarden_config::bindings::HostBindingsFile,
    force_write: bool,
) -> anyhow::Result<()> {
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

/// Read the user's SSH config for a rewrite. Only a missing file counts as
/// empty: any other error (bad encoding, permissions) must stop the caller,
/// or the rewrite would replace the whole file with just our lines.
fn read_user_ssh_config(config_path: &std::path::Path) -> anyhow::Result<String> {
    match std::fs::read_to_string(config_path) {
        Ok(content) => Ok(content),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(anyhow::Error::from(e).context(format!(
            "Failed to read SSH config: {} (left unchanged)",
            config_path.display()
        ))),
    }
}

/// Replace the user's SSH config through a temp file and a rename, so a crash
/// cannot leave it half written. A symlinked config (dotfiles) is resolved
/// first, so the rename replaces the target and keeps the link.
fn write_user_ssh_config(config_path: &std::path::Path, content: &str) -> anyhow::Result<()> {
    let target = std::fs::canonicalize(config_path).unwrap_or_else(|_| config_path.to_path_buf());
    sshwarden_config::write_owner_only_file(&target, content)
}

/// True for a line that opens a `Host` or `Match` block.
fn opens_host_or_match_block(trimmed: &str) -> bool {
    let keyword = trimmed
        .split(|c: char| c.is_whitespace() || c == '=')
        .next()
        .unwrap_or_default();
    keyword.eq_ignore_ascii_case("Host") || keyword.eq_ignore_ascii_case("Match")
}

/// True when a line accepted by `is_include` comes before the first `Host` /
/// `Match` line. OpenSSH reads an `Include` placed after such a line only when
/// that block matches, so only an Include above all of them works for every host.
fn include_precedes_first_block(content: &str, is_include: impl Fn(&str) -> bool) -> bool {
    content
        .lines()
        .map(str::trim)
        .take_while(|line| !opens_host_or_match_block(line))
        .any(is_include)
}

/// Whether `ssh` reads the managed snippet for every host: the user's SSH
/// config has SSHWarden's Include line before the first `Host` / `Match` block.
pub(crate) fn sshwarden_include_is_active(
    config_path: &std::path::Path,
    include_path: &std::path::Path,
) -> bool {
    std::fs::read_to_string(config_path)
        .map(|content| {
            include_precedes_first_block(&content, |line| {
                sshwarden_config::ssh_config::line_matches_sshwarden_include(line, include_path)
            })
        })
        .unwrap_or(false)
}

/// Put the marker and SSHWarden's `Include` line at the top of the user's SSH
/// config, moving an older one (marked, or unmarked with our path) from
/// wherever it was. No write when the wanted line is already above every block.
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
    let existing = read_user_ssh_config(config_path)?;
    // Only the exact wanted line counts: a legacy absolute line still "matches"
    // semantically, but in home-relative multi-device mode it must be rewritten
    // so a synced ~/.ssh/config works across different Windows usernames.
    if include_precedes_first_block(&existing, |line| line == include_line) {
        return Ok(());
    }

    // Lines we did not write stay byte for byte when there is nothing to move.
    let rest = strip_sshwarden_include(&existing, include_path).unwrap_or(existing);
    let rest = rest.trim_start_matches(['\r', '\n']);
    const MARKER: &str = sshwarden_config::ssh_config::SSHWARDEN_INCLUDE_MARKER;
    let mut new_config = format!("{MARKER}\n{include_line}\n");
    if !rest.is_empty() {
        new_config.push('\n');
        new_config.push_str(rest);
        if !new_config.ends_with('\n') {
            new_config.push('\n');
        }
    }
    write_user_ssh_config(config_path, &new_config)
        .with_context(|| format!("Failed to update SSH config: {}", config_path.display()))
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

/// `existing` without SSHWarden's Include lines: the marker comment with the
/// Include that follows it, and unmarked Includes of the managed snippet.
/// `None` when there is none.
fn strip_sshwarden_include(existing: &str, include_path: &std::path::Path) -> Option<String> {
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
        return None;
    }
    let mut new_config = kept.join("\n");
    if !new_config.is_empty() && !new_config.ends_with('\n') {
        new_config.push('\n');
    }
    Some(new_config)
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
    let existing = read_user_ssh_config(config_path)?;
    let Some(new_config) = strip_sshwarden_include(&existing, include_path) else {
        return Ok(false);
    };
    write_user_ssh_config(config_path, &new_config)
        .with_context(|| format!("Failed to update SSH config: {}", config_path.display()))?;
    Ok(true)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::path_util::write_private_file;
    use sshwarden_config::bindings::HostBindingsFile;
    use sshwarden_config::SshConfigPathStyle;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "sshwarden-snippet-test-{}-{unique}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// End-to-end: bind a host via `HostBindingsFile::add_host`, generate the
    /// managed snippet, write it to disk the way the sync path does, then read it
    /// back and assert the generated content.
    #[test]
    fn managed_snippet_reflects_bindings_round_tripped_through_disk() {
        let dir = temp_dir("snippet");
        let selector_dir = dir.join("keys");

        let keys = vec![
            ManagedKey {
                name: "Github".to_string(),
                cipher_id: "id-1".to_string(),
            },
            ManagedKey {
                name: "Server".to_string(),
                cipher_id: "id-2".to_string(),
            },
        ];
        let mut bindings = HostBindingsFile::default();
        bindings.add_host("id-1", "github.com").unwrap();
        bindings.add_host("id-1", "gitlab.com").unwrap();

        let snippet = ssh_config_snippet_with_bindings_in(
            &keys,
            &bindings,
            &selector_dir,
            SshConfigPathStyle::Absolute,
        );

        let managed_path = dir.join("sshwarden_config");
        write_private_file(&managed_path, &snippet).unwrap();
        let written = std::fs::read_to_string(&managed_path).unwrap();

        assert!(written.contains("# sshwarden:key id-1"));
        assert!(written.contains("Host github.com gitlab.com"));
        assert!(written.contains("    IdentitiesOnly yes"));

        let bound_selector = selector_dir.join(selector_file_name("Github", "id-1"));
        let expected_identity = format!(
            "    IdentityFile {}",
            sshwarden_config::ssh_config::path_arg_with_style(
                &bound_selector,
                SshConfigPathStyle::Absolute
            )
        );
        assert!(
            written.contains(&expected_identity),
            "bound key should point at its selector file; snippet was:\n{written}"
        );

        // The unbound key appears only as a commented template.
        assert!(written.contains("# --- Unbound keys (uncomment + edit to use) ---"));
        assert!(written.contains("# sshwarden:key id-2"));
        assert!(written.contains("# Host <host>"));
        assert!(!written.lines().any(|line| line == "Host id-2"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn managed_snippet_empty_bindings_only_lists_unbound_templates() {
        let dir = temp_dir("snippet-empty");
        let keys = vec![ManagedKey {
            name: "Github".to_string(),
            cipher_id: "id-1".to_string(),
        }];
        let bindings = HostBindingsFile::default();

        let snippet = ssh_config_snippet_with_bindings_in(
            &keys,
            &bindings,
            &dir,
            SshConfigPathStyle::Absolute,
        );

        assert!(snippet.contains("# sshwarden:key id-1"));
        assert!(snippet.contains("# Host <host>"));
        assert!(!snippet.lines().any(|line| line.starts_with("Host ")));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Audit #4: an unreadable config (here: not UTF-8) must fail the command
    /// and stay byte-for-byte as it was, not be replaced by the Include line.
    #[test]
    fn include_write_leaves_unreadable_config_untouched() {
        let dir = temp_dir("include-non-utf8");
        let config_path = dir.join("config");
        let original = b"# caf\xff comment\nHost work\n    User me\n".to_vec();
        std::fs::write(&config_path, &original).unwrap();

        let result = write_sshwarden_include_line(&config_path, &dir.join("sshwarden_config"));

        assert!(result.is_err());
        assert_eq!(std::fs::read(&config_path).unwrap(), original);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn include_write_keeps_symlinked_config_a_symlink() {
        let dir = temp_dir("include-symlink");
        let real = dir.join("dotfiles-config");
        let link = dir.join("config");
        std::fs::write(&real, "Host work\n    User me\n").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        write_sshwarden_include_line(&link, &dir.join("sshwarden_config")).unwrap();

        assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
        assert!(std::fs::read_to_string(&real).unwrap().contains("Include "));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Audit #6: an Include after a `Host` block is read only for that host,
    /// so it must be written above every block, and moved there when older
    /// versions appended it at the end.
    #[test]
    fn include_is_written_above_the_first_host_block() {
        let dir = temp_dir("include-top");
        let config_path = dir.join("config");
        let include_path = dir.join("sshwarden_config");
        let include_line = sshwarden_config::ssh_config::include_line(&include_path);
        const MARKER: &str = sshwarden_config::ssh_config::SSHWARDEN_INCLUDE_MARKER;
        let user_part = "Host work\n    User me\n\nMatch host *.corp\n    Port 2222\n";

        // Fresh config that starts with a Host block.
        std::fs::write(&config_path, user_part).unwrap();
        assert!(!sshwarden_include_is_active(&config_path, &include_path));
        write_sshwarden_include_line(&config_path, &include_path).unwrap();
        let expected = format!("{MARKER}\n{include_line}\n\n{user_part}");
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), expected);
        assert!(sshwarden_include_is_active(&config_path, &include_path));

        // Second run changes nothing.
        write_sshwarden_include_line(&config_path, &include_path).unwrap();
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), expected);

        // An Include appended at the end by an older version is moved up.
        std::fs::write(
            &config_path,
            format!("{user_part}\n{MARKER}\n{include_line}\n"),
        )
        .unwrap();
        assert!(!sshwarden_include_is_active(&config_path, &include_path));
        write_sshwarden_include_line(&config_path, &include_path).unwrap();
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), expected);

        let _ = std::fs::remove_dir_all(dir);
    }
}
