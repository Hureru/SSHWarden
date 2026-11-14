//! SSH client argv parsing helpers (used for best-effort host inference).
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 1).

/// Short single-character SSH flags that consume the next argv element as a value.
///
/// Reference: `ssh(1)` OPTIONS section. We intentionally over-approximate to be
/// safe — any unknown flag is treated as value-taking only if the character
/// matches this set.
const SSH_VALUE_TAKING_FLAGS: &str = "BbcDEeFIiJLlmOopQRSWw";

/// What an SSH client process was asked to do, read from its argv.
///
/// Best-effort and spoofable by the local process: use it to choose which key
/// to offer first, never to decide whether a request is authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SshInvocation {
    /// Destination as typed (may be an `ssh_config` alias).
    pub(crate) host: String,
    pub(crate) user: Option<String>,
    /// Remote Git repository path (`owner/name`) when Git drives the client.
    pub(crate) repo: Option<String>,
}

/// Parse the argv of an `ssh`/`scp`/`sftp` process.
pub(crate) fn parse_ssh_argv(argv: &[String]) -> Option<SshInvocation> {
    let basename = std::path::Path::new(argv.first()?)
        .file_name()
        .and_then(|s| s.to_str())?
        .to_ascii_lowercase();
    let basename = basename.strip_suffix(".exe").unwrap_or(&basename);
    if !matches!(
        basename,
        "ssh" | "scp" | "sftp" | "ssh-keyscan" | "ssh-copy-id"
    ) {
        return None;
    }

    let mut login_flag: Option<String> = None;
    let mut iter = argv.iter().skip(1);
    let target = loop {
        let arg = iter.next()?;
        if arg == "--" {
            break iter.next()?;
        }
        let Some(rest) = arg.strip_prefix('-') else {
            break arg;
        };
        // Walk combined short opts; a value-taking flag either carries its value
        // inline (the remaining chars) or consumes the next argv element.
        if let Some((i, flag)) = rest
            .char_indices()
            .find(|(_, c)| SSH_VALUE_TAKING_FLAGS.contains(*c))
        {
            let inline = &rest[i + flag.len_utf8()..];
            let value = if inline.is_empty() {
                iter.next().map(String::as_str)
            } else {
                Some(inline)
            };
            if flag == 'l' {
                login_flag = value.map(String::from);
            }
        }
    };

    let (user, host) = match target.rsplit_once('@') {
        Some((user, host)) => (Some(user.to_string()), host.to_string()),
        None => (None, target.clone()),
    };
    let command = iter.map(String::as_str).collect::<Vec<_>>().join(" ");
    Some(SshInvocation {
        host,
        // Like ssh itself: `-l` wins over `user@`.
        user: login_flag.or(user),
        repo: git_repo_from_command(&command),
    })
}

/// Read the argv of `pid` and parse it; `None` when it is not an SSH client or
/// the process cannot be inspected.
pub(crate) fn invocation_for_pid(pid: u32) -> Option<SshInvocation> {
    if pid == 0 {
        return None;
    }
    let invocation = parse_ssh_argv(&sshwarden_agent::peerinfo::gather::get_peer_cmd(pid)?);
    if invocation.is_none() {
        tracing::debug!(pid, "Peer is not an SSH client with a recognizable target");
    }
    invocation
}

/// `git-upload-pack '/acme/widgets.git'` -> `acme/widgets`.
fn git_repo_from_command(command: &str) -> Option<String> {
    let path = [
        "git-upload-pack ",
        "git-receive-pack ",
        "git-upload-archive ",
    ]
    .iter()
    .find_map(|prefix| command.strip_prefix(prefix))?;
    let path = path
        .trim()
        .trim_matches(['\'', '"'])
        .trim_start_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    (!path.is_empty()).then(|| path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(parts: &[&str]) -> Option<SshInvocation> {
        parse_ssh_argv(&parts.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn reads_user_from_target_or_login_flag() {
        let inv = parse(&["ssh", "git@github.com"]).expect("ssh target");
        assert_eq!(
            (inv.host.as_str(), inv.user.as_deref()),
            ("github.com", Some("git"))
        );

        let inv = parse(&["ssh", "-p", "2222", "-l", "deploy", "bastion"]).expect("ssh target");
        assert_eq!(
            (inv.host.as_str(), inv.user.as_deref()),
            ("bastion", Some("deploy"))
        );

        let inv = parse(&["ssh", "-vlroot", "other@host"]).expect("ssh target");
        assert_eq!(inv.user.as_deref(), Some("root"), "-l wins over user@");

        assert_eq!(parse(&["ssh", "host"]).expect("ssh target").user, None);
    }

    #[test]
    fn reads_git_repository_from_remote_command() {
        // scp-like remote (git@github.com:acme/widgets.git)
        let inv = parse(&[
            "ssh",
            "-o",
            "SendEnv=GIT_PROTOCOL",
            "git@github.com",
            "git-upload-pack 'acme/widgets.git'",
        ])
        .expect("ssh target");
        assert_eq!(inv.host, "github.com");
        assert_eq!(inv.repo.as_deref(), Some("acme/widgets"));

        // ssh:// remote: absolute path, as observed from a real `git fetch`
        let inv = parse(&["ssh", "host", "git-receive-pack '/srv/git/tools.git'"]).expect("target");
        assert_eq!(inv.repo.as_deref(), Some("srv/git/tools"));

        assert_eq!(
            parse(&["ssh", "host", "uptime"]).expect("target").repo,
            None
        );
        assert_eq!(parse(&["ssh", "host"]).expect("target").repo, None);
    }
}
