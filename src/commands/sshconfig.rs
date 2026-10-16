//! `ssh-config` commands: show / write / status / uninstall.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 5c).

use anyhow::Context;

use crate::cache::load_managed_keys_from_cache;
use crate::out_line;
use crate::sshconfig::{
    load_host_bindings_importing_managed, managed_sshwarden_include_path,
    remove_sshwarden_include_line, sync_managed_ssh_config_inner, user_ssh_config_path,
    write_sshwarden_include_line, ManagedKey,
};
/// `ssh-config write`: regenerate the managed snippet from the local cache +
/// bindings and ensure the Include line in ~/.ssh/config (offline). Selector
/// `.pub` files are written during `login`/`sync`. Merges the former
/// `ssh-config --write` / `install` / `regenerate`.
pub(crate) async fn cmd_sshcfg_write() -> anyhow::Result<()> {
    let keys = load_managed_keys_from_cache()?;
    sync_managed_ssh_config_inner(&keys, true)?;

    let include_path = managed_sshwarden_include_path()?;
    let config_path = user_ssh_config_path()?;
    write_sshwarden_include_line(&config_path, &include_path)?;

    out_line(format!("Wrote managed snippet: {}", include_path.display()));
    out_line(format!(
        "Include line ensured in: {}",
        config_path.display()
    ));
    Ok(())
}

pub(crate) async fn cmd_sshcfg_uninstall() -> anyhow::Result<()> {
    let include_path = managed_sshwarden_include_path()?;
    let config_path = user_ssh_config_path()?;
    let removed = remove_sshwarden_include_line(&config_path, &include_path)?;

    #[allow(clippy::print_stdout)]
    {
        if removed {
            println!("Removed Include line from {}", config_path.display());
        } else {
            println!(
                "No sshwarden Include line found in {}",
                config_path.display()
            );
        }
        println!(
            "Note: snippet file {} is preserved. Delete it manually if you want a clean uninstall.",
            include_path.display()
        );
    }
    Ok(())
}

pub(crate) async fn cmd_sshcfg_status() -> anyhow::Result<()> {
    let include_path = managed_sshwarden_include_path()?;
    let config_path = user_ssh_config_path()?;
    let cache = sshwarden_config::cache::LocalKeyCacheFile::load()?;
    let bindings = cache
        .as_ref()
        .map(|cache| ManagedKey::from_cache_header(&cache.header.keys))
        .map(|keys| load_host_bindings_importing_managed(&keys))
        .transpose()?
        .unwrap_or_default();

    let user_config_has_include = std::fs::read_to_string(&config_path)
        .map(|s| {
            s.lines().any(|l| {
                sshwarden_config::ssh_config::line_matches_sshwarden_include(l, &include_path)
            })
        })
        .unwrap_or(false);

    let snippet_size = std::fs::metadata(&include_path).map(|m| m.len()).ok();

    #[allow(clippy::print_stdout)]
    {
        println!(
            "Bindings file:   {}",
            sshwarden_config::bindings::HostBindingsFile::path()?.display()
        );
        println!("Managed snippet: {}", include_path.display());
        if let Some(size) = snippet_size {
            println!("  → exists ({size} bytes)");
        } else {
            println!("  → not present");
        }
        println!("User ssh config: {}", config_path.display());
        println!(
            "  → Include line {}",
            if user_config_has_include {
                "present"
            } else {
                "missing"
            }
        );
        println!(
            "Key cache:       {} keys",
            cache.as_ref().map(|c| c.header.keys.len()).unwrap_or(0)
        );
        let total_hosts: usize = bindings.bindings.values().map(|b| b.hosts.len()).sum();
        println!(
            "Bindings:        {} key(s) bound to {} host pattern(s)",
            bindings.bindings.len(),
            total_hosts
        );
    }
    Ok(())
}

pub(crate) async fn cmd_sshcfg_show() -> anyhow::Result<()> {
    let include_path = managed_sshwarden_include_path()?;
    let content = std::fs::read_to_string(&include_path)
        .with_context(|| format!("Failed to read {}", include_path.display()))?;
    #[allow(clippy::print_stdout)]
    {
        print!("{}", content);
        if !content.ends_with('\n') {
            println!();
        }
    }
    Ok(())
}
