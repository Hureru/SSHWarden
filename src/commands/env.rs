//! `env` command: shell environment exports for agent discovery.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 5c).

use crate::shell::{powershell_single_quote, shell_single_quote};
pub(crate) fn cmd_env(config: &sshwarden_config::Config, shell: &str) -> anyhow::Result<()> {
    // UX-5: Windows OpenSSH uses the fixed pipe and ignores SSH_AUTH_SOCK, so
    // these exports are usually only relevant for a custom [socket] endpoint or
    // third-party clients that honour SSH_AUTH_SOCK. Note goes to stderr so it
    // doesn't break `eval`.
    #[cfg(windows)]
    err_line(
        r"# Note: Windows OpenSSH talks to the fixed pipe \\.\pipe\openssh-ssh-agent and ignores SSH_AUTH_SOCK; these exports only matter for a custom [socket] endpoint or clients that honour SSH_AUTH_SOCK.",
    );

    let endpoint = config
        .socket
        .path
        .as_deref()
        .map(std::path::PathBuf::from)
        .unwrap_or(sshwarden_config::default_agent_socket_path()?);
    let endpoint = endpoint.display().to_string();

    #[allow(clippy::print_stdout)]
    match shell {
        "sh" | "bash" | "zsh" | "posix" => {
            println!("export SSH_AUTH_SOCK='{}'", shell_single_quote(&endpoint));
            println!(
                "export SSHWARDEN_SSH_AUTH_SOCK='{}'",
                shell_single_quote(&endpoint)
            );
        }
        "fish" => {
            println!("set -gx SSH_AUTH_SOCK '{}';", shell_single_quote(&endpoint));
            println!(
                "set -gx SSHWARDEN_SSH_AUTH_SOCK '{}';",
                shell_single_quote(&endpoint)
            );
        }
        "powershell" | "pwsh" | "ps" => {
            println!(
                "$env:SSH_AUTH_SOCK = '{}'",
                powershell_single_quote(&endpoint)
            );
            println!(
                "$env:SSHWARDEN_SSH_AUTH_SOCK = '{}'",
                powershell_single_quote(&endpoint)
            );
        }
        "cmd" => {
            println!("set SSH_AUTH_SOCK={endpoint}");
            println!("set SSHWARDEN_SSH_AUTH_SOCK={endpoint}");
        }
        other => {
            anyhow::bail!("Unsupported shell syntax '{other}'. Use sh, fish, powershell, or cmd.")
        }
    }

    Ok(())
}
