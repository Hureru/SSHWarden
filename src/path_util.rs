//! Filesystem path-safety helpers and private-file writing.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 1).

use std::path::{Component, Path, PathBuf};

pub(crate) fn ensure_managed_ssh_config_path_is_safe(
    managed_path: &Path,
    user_config_path: &Path,
) -> anyhow::Result<()> {
    if paths_equivalent_for_safety(managed_path, user_config_path) {
        anyhow::bail!(
            "managed SSH config path must not be the user's main SSH config: {}",
            managed_path.display()
        );
    }
    Ok(())
}

pub(crate) fn paths_equivalent_for_safety(a: &Path, b: &Path) -> bool {
    if let (Ok(a), Ok(b)) = (a.canonicalize(), b.canonicalize()) {
        return path_values_equal_for_safety(&a, &b);
    }

    let a = normalized_absolute_path_for_safety(a);
    let b = normalized_absolute_path_for_safety(b);
    path_values_equal_for_safety(&a, &b)
}

pub(crate) fn normalized_absolute_path_for_safety(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else if let Ok(cwd) = std::env::current_dir() {
        cwd.join(path)
    } else {
        path.to_path_buf()
    };

    normalize_path_components_for_safety(&absolute)
}

pub(crate) fn normalize_path_components_for_safety(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(
                    normalized.components().next_back(),
                    Some(Component::Normal(_))
                ) {
                    normalized.pop();
                } else if !path.is_absolute() {
                    normalized.push(component.as_os_str());
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

pub(crate) fn path_values_equal_for_safety(a: &Path, b: &Path) -> bool {
    #[cfg(windows)]
    {
        a.to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

pub(crate) fn create_parent_dir(path: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path)?;
    Ok(())
}

pub(crate) fn create_private_dir(path: &Path) -> anyhow::Result<()> {
    create_parent_dir(path)?;
    sshwarden_config::ssh_config::ensure_ssh_dir_permissions(path)?;
    Ok(())
}

pub(crate) fn write_private_file(path: &Path, content: impl AsRef<[u8]>) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        create_parent_dir(parent)?;
    }
    std::fs::write(path, content)?;
    sshwarden_config::ssh_config::ensure_private_file_permissions(path)?;
    Ok(())
}
