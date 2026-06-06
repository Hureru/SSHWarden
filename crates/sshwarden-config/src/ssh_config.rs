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
    format!("Include {}", path_arg_with_style(include_path, style))
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
    let relative = path.strip_prefix(&home).ok()?;
    if relative.as_os_str().is_empty() {
        return Some(PathBuf::from("~"));
    }
    Some(PathBuf::from("~").join(relative))
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
}
