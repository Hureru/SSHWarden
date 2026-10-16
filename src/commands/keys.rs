//! `keys` / host-binding commands (`bind`, `unbind`) and the offline keys list.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 5c).

use anyhow::Context;

use crate::cache::load_managed_keys_from_cache;
use crate::cli::KeysAction;
use crate::control::cmd_control;
use crate::sshconfig::{
    load_host_bindings_importing_managed, managed_sshwarden_include_path, selector_path_for_key,
    sync_managed_ssh_config_inner, user_ssh_config_path, write_sshwarden_include_line, ManagedKey,
};
use crate::{err_line, out_line};
/// Resolve a user-supplied `key` argument to a cipher_uuid.
///
/// Accepts an exact cipher_uuid match or a case-insensitive exact name match.
/// If no local cache exists, the input is treated as a cipher_uuid verbatim
/// (no validation) so users can bind ahead of first sync.
pub(crate) fn resolve_cipher_id(query: &str) -> anyhow::Result<String> {
    let keys = match sshwarden_config::cache::LocalKeyCacheFile::load()? {
        Some(cache) => cache.header.keys,
        None => return Ok(query.to_string()),
    };
    if keys.iter().any(|k| k.vault_item_id == query) {
        return Ok(query.to_string());
    }
    let name_matches: Vec<&sshwarden_config::cache::KeyIdentity> = keys
        .iter()
        .filter(|k| k.name.eq_ignore_ascii_case(query))
        .collect();
    match name_matches.len() {
        0 => anyhow::bail!(
            "No key matches '{}'. Run `sshwarden keys` to see available keys.",
            query
        ),
        1 => Ok(name_matches[0].vault_item_id.clone()),
        n => anyhow::bail!(
            "'{}' matches {} keys by name — pass the cipher uuid instead.",
            query,
            n
        ),
    }
}

/// Dispatch the `keys` command group: an offline list plus host-binding
/// management (the former `bindings` subcommands).
pub(crate) async fn cmd_keys(action: KeysAction) -> anyhow::Result<()> {
    match action {
        KeysAction::List => cmd_keys_list().await,
        KeysAction::Bind { key, hosts } => cmd_bindings_add(&key, &hosts).await,
        KeysAction::Unbind { key, host, all } => cmd_keys_unbind(&key, host.as_deref(), all).await,
        KeysAction::Ui => cmd_control("bind-hosts-dialog").await,
    }
}

/// Merge of the former `bindings remove` + `bindings clear`: `--all` clears
/// every host for the key; otherwise a host pattern is required.
pub(crate) async fn cmd_keys_unbind(
    key: &str,
    host: Option<&str>,
    all: bool,
) -> anyhow::Result<()> {
    if all {
        cmd_bindings_clear(key).await
    } else {
        cmd_bindings_remove(key, host, false).await
    }
}

/// Offline unified key view: each cached key with its bound hosts and whether a
/// public-key selector file exists, plus a one-line ssh-config Include summary
/// and a best-effort live lock state. Reads only local files (no network); the
/// daemon is contacted opportunistically and its absence is not an error.
pub(crate) async fn cmd_keys_list() -> anyhow::Result<()> {
    let cache = sshwarden_config::cache::LocalKeyCacheFile::load()?;

    let Some(cache) = cache else {
        out_line("No keys cached yet. Run `sshwarden login` (or `sshwarden sync`) first.");
        return Ok(());
    };
    if cache.header.keys.is_empty() {
        out_line(
            "No SSH keys in the local cache. Add SSH keys in Bitwarden, then `sshwarden sync`.",
        );
        return Ok(());
    }

    let managed_keys = ManagedKey::from_cache_header(&cache.header.keys);
    let bindings = load_host_bindings_importing_managed(&managed_keys).unwrap_or_else(|e| {
        tracing::warn!("Failed to load host bindings: {}", e);
        sshwarden_config::bindings::HostBindingsFile::default()
    });

    // Best-effort live lock state; omit silently when the daemon is down.
    let locked: Option<bool> =
        match sshwarden_agent::control::send_control_command("status-json").await {
            Ok(resp) => resp
                .details
                .as_ref()
                .and_then(|d| d.get("locked"))
                .and_then(|v| v.as_bool()),
            Err(_) => None,
        };
    let state = match locked {
        Some(true) => " — vault locked",
        Some(false) => " — vault unlocked",
        None => "",
    };

    out_line(format!(
        "Cached SSH keys ({}){}:",
        cache.header.keys.len(),
        state
    ));
    for key in &cache.header.keys {
        let selector_ok = selector_path_for_key(&key.name, &key.vault_item_id)
            .map(|p| p.exists())
            .unwrap_or(false);
        out_line(format!(
            "  • {} ({})  [{}]",
            key.name,
            key.vault_item_id,
            if selector_ok {
                "selector ready"
            } else {
                "selector missing — run `sshwarden ssh-config write`"
            }
        ));
        match bindings.bindings.get(&key.vault_item_id) {
            Some(b) if !b.hosts.is_empty() => {
                for host in &b.hosts {
                    out_line(format!("      host: {host}"));
                }
            }
            _ => out_line("      hosts: none — `sshwarden keys bind <key> <host>`".to_string()),
        }
    }

    // One-line Include summary so the user knows whether `ssh` will route via
    // these selectors.
    let include_path = managed_sshwarden_include_path()?;
    let config_path = user_ssh_config_path()?;
    let has_include = std::fs::read_to_string(&config_path)
        .map(|s| {
            s.lines().any(|l| {
                sshwarden_config::ssh_config::line_matches_sshwarden_include(l, &include_path)
            })
        })
        .unwrap_or(false);
    if has_include {
        out_line("\nssh-config: Include active (ssh will use the bound keys).");
    } else {
        out_line(format!(
            "\nssh-config: not included — run `sshwarden ssh-config write` to wire {}.",
            config_path.display()
        ));
    }
    Ok(())
}

pub(crate) async fn cmd_bindings_add(key: &str, hosts: &[String]) -> anyhow::Result<()> {
    let cipher_id = resolve_cipher_id(key)?;
    let keys = load_managed_keys_from_cache().unwrap_or_default();
    let mut bindings = load_host_bindings_importing_managed(&keys)?;
    for host in hosts {
        if is_catch_all_host_pattern(host) {
            tracing::warn!(
                "Binding a key to '{}' may cause SSH to offer this key for many hosts and can reintroduce MaxAuthTries failures.",
                host
            );
        }
        bindings.add_host(&cipher_id, host)?;
    }
    bindings.save()?;

    // UX-7: a failed snippet regeneration means `ssh host` would route to the
    // wrong key (or none), so fail loudly rather than warn-and-continue.
    sync_managed_ssh_config_inner(&keys, true)
        .context("Bindings saved but managed snippet regeneration failed")?;

    // CFG-2: a binding does nothing unless ~/.ssh/config Includes the managed
    // snippet. Auto-install the Include line so `bindings add` is never a silent
    // no-op (idempotent — only writes when the line is missing).
    let include_path = managed_sshwarden_include_path()?;
    let config_path = user_ssh_config_path()?;
    if let Err(e) = write_sshwarden_include_line(&config_path, &include_path) {
        err_line(format!(
            "Binding saved, but failed to ensure the Include line in {}: {e}. Run `sshwarden ssh-config write`.",
            config_path.display()
        ));
    }

    out_line(format!(
        "Added {} host pattern(s) to key {}.",
        hosts.len(),
        cipher_id
    ));
    Ok(())
}

pub(crate) fn is_catch_all_host_pattern(host: &str) -> bool {
    matches!(host.trim(), "*" | "!*")
}

pub(crate) async fn cmd_bindings_remove(
    key: &str,
    host: Option<&str>,
    all: bool,
) -> anyhow::Result<()> {
    let cipher_id = resolve_cipher_id(key)?;
    let keys = load_managed_keys_from_cache().unwrap_or_default();
    let mut bindings = load_host_bindings_importing_managed(&keys)?;

    let changed = match (host, all) {
        (Some(_), true) => anyhow::bail!("Pass either a host argument or `--all`, not both."),
        (None, false) => anyhow::bail!(
            "Specify a host pattern to remove, or pass `--all` to clear every host for this key."
        ),
        (None, true) => bindings.clear_key(&cipher_id),
        (Some(h), false) => bindings.remove_host(&cipher_id, h),
    };

    if !changed {
        anyhow::bail!("No matching host binding found for key {}", cipher_id);
    }
    bindings.save()?;

    sync_managed_ssh_config_inner(&keys, true)
        .context("Bindings saved but managed snippet regeneration failed")?;

    out_line(format!("Updated bindings for key {cipher_id}."));
    Ok(())
}

pub(crate) async fn cmd_bindings_clear(key: &str) -> anyhow::Result<()> {
    cmd_bindings_remove(key, None, true).await
}
