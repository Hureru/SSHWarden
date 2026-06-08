use std::path::{Path, PathBuf};

use crate::SshConfigPathStyle;

pub const SSHWARDEN_INCLUDE_MARKER: &str = "# SSHWarden managed key selector snippets";

/// Format a value for use as one ssh_config argument.
///
/// Paths are always double-quoted so spaces and non-ASCII characters are kept
/// as one argument. Backslashes and double quotes are escaped for OpenSSH's
/// parser. On Windows, backslashes are first converted to forward slashes,
/// which OpenSSH for Windows accepts and which avoids accidental escape
/// sequences such as `\U` in quoted config values.
pub fn quote_ssh_config_arg(value: &str) -> String {
    let normalized = normalize_ssh_config_path(value);
    let mut out = String::with_capacity(normalized.len() + 2);
    out.push('"');
    for ch in normalized.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

pub fn path_arg(path: &Path) -> String {
    quote_ssh_config_arg(&path.to_string_lossy())
}

pub fn path_arg_with_style(path: &Path, style: SshConfigPathStyle) -> String {
    if matches!(style, SshConfigPathStyle::HomeRelative) && home_relative_path(path).is_none() {
        // Fell back to the absolute path: on Windows this embeds the concrete
        // `C:\Users\<name>` and will not be shareable across accounts via a
        // synced snippet. Warn only here, on the write path — never from the
        // match helpers below, which would otherwise log on every comparison
        // while parsing ~/.ssh/config.
        tracing::warn!(
            "ssh_config path_style=home_relative but {} is not under the user home; \
             writing an absolute path that may embed a username",
            path.display()
        );
    }
    path_arg_with_style_quiet(path, style)
}

/// Like [`path_arg_with_style`] but never logs. Used by include-line matching so
/// that parsing `~/.ssh/config` does not emit a warning on every comparison.
fn path_arg_with_style_quiet(path: &Path, style: SshConfigPathStyle) -> String {
    let display_path = match style {
        SshConfigPathStyle::Absolute => path.to_path_buf(),
        SshConfigPathStyle::HomeRelative => {
            home_relative_path(path).unwrap_or_else(|| path.to_path_buf())
        }
    };
    quote_ssh_config_arg(&display_path.to_string_lossy())
}

pub fn include_line(include_path: &Path) -> String {
    format!("Include {}", path_arg(include_path))
}

pub fn include_line_with_style(include_path: &Path, style: SshConfigPathStyle) -> String {
    format!("Include {}", path_arg_with_style_quiet(include_path, style))
}

pub fn legacy_unquoted_include_line(include_path: &Path) -> String {
    format!("Include {}", include_path.display())
}

/// Match both the current quoted Include line and the legacy unquoted line
/// written by earlier SSHWarden builds.
pub fn line_matches_sshwarden_include(line: &str, include_path: &Path) -> bool {
    let trimmed = line.trim();
    trimmed == include_line(include_path)
        || trimmed == include_line_with_style(include_path, SshConfigPathStyle::HomeRelative)
        || trimmed == legacy_unquoted_include_line(include_path)
}

pub fn ensure_ssh_dir_permissions(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub fn ensure_private_file_permissions(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn normalize_ssh_config_path(value: &str) -> String {
    #[cfg(windows)]
    {
        value.replace('\\', "/")
    }
    #[cfg(not(windows))]
    {
        value.to_string()
    }
}

fn home_relative_path(path: &Path) -> Option<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)?;
    home_relative_path_with_home(path, &home)
}

/// Rewrite `path` as `~/...` when it lives under `home`.
///
/// On Windows the comparison is case-insensitive: the OneDrive key paths and the
/// `USERPROFILE` casing Windows reports can differ (drive-letter or profile-folder
/// case), and a byte-exact `strip_prefix` would otherwise silently fall back to an
/// absolute, username-bearing path and defeat cross-account sharing.
fn home_relative_path_with_home(path: &Path, home: &Path) -> Option<PathBuf> {
    if let Ok(relative) = path.strip_prefix(home) {
        return Some(tilde_join(relative));
    }
    #[cfg(windows)]
    {
        if let Some(relative) = strip_prefix_case_insensitive(path, home) {
            return Some(tilde_join(&relative));
        }
    }
    None
}

fn tilde_join(relative: &Path) -> PathBuf {
    if relative.as_os_str().is_empty() {
        PathBuf::from("~")
    } else {
        PathBuf::from("~").join(relative)
    }
}

/// Strip `prefix` from `path`, comparing each component case-insensitively.
/// Used on Windows, whose filesystem is case-insensitive.
#[cfg(windows)]
fn strip_prefix_case_insensitive(path: &Path, prefix: &Path) -> Option<PathBuf> {
    let mut path_components = path.components();
    for prefix_component in prefix.components() {
        let next = path_components.next()?;
        let actual = next.as_os_str().to_string_lossy().to_lowercase();
        let expected = prefix_component
            .as_os_str()
            .to_string_lossy()
            .to_lowercase();
        if actual != expected {
            return None;
        }
    }
    Some(path_components.as_path().to_path_buf())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn quotes_paths_with_spaces() {
        assert_eq!(
            quote_ssh_config_arg("/tmp/Application Support/sshwarden_config"),
            "\"/tmp/Application Support/sshwarden_config\""
        );
    }

    #[test]
    fn escapes_quotes_inside_paths() {
        assert_eq!(
            quote_ssh_config_arg("/tmp/a\"b/sshwarden_config"),
            "\"/tmp/a\\\"b/sshwarden_config\""
        );
    }

    #[test]
    fn include_match_accepts_quoted_and_legacy_unquoted() {
        let path = Path::new("/tmp/Application Support/sshwarden_config");
        assert!(line_matches_sshwarden_include(&include_line(path), path));
        assert!(line_matches_sshwarden_include(
            &legacy_unquoted_include_line(path),
            path
        ));
        assert!(!line_matches_sshwarden_include(
            "Include /tmp/other_config",
            path
        ));
    }

    #[test]
    fn home_relative_rewrites_paths_under_home() {
        let home = Path::new("/home/alice");
        assert_eq!(
            home_relative_path_with_home(Path::new("/home/alice/OneDrive/keys/id.pub"), home),
            Some(PathBuf::from("~/OneDrive/keys/id.pub"))
        );
    }

    #[test]
    fn home_relative_path_equal_to_home_is_tilde() {
        let home = Path::new("/home/alice");
        assert_eq!(
            home_relative_path_with_home(Path::new("/home/alice"), home),
            Some(PathBuf::from("~"))
        );
    }

    #[test]
    fn home_relative_path_outside_home_is_none() {
        let home = Path::new("/home/alice");
        assert_eq!(
            home_relative_path_with_home(Path::new("/etc/ssh/keys/id.pub"), home),
            None
        );
    }

    #[cfg(windows)]
    #[test]
    fn home_relative_path_is_case_insensitive_on_windows() {
        // USERPROFILE casing as Windows reports it differs from the on-disk path
        // casing; the rewrite must still succeed instead of leaking an absolute,
        // username-bearing path into a shared snippet.
        let home = Path::new(r"C:\users\administrator");
        assert_eq!(
            home_relative_path_with_home(
                Path::new(r"C:\Users\Administrator\OneDrive\keys\id.pub"),
                home
            ),
            Some(PathBuf::from(r"~\OneDrive\keys\id.pub"))
        );
    }
}
