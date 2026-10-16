//! Command-line surface (clap definitions).
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 2).

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "sshwarden",
    version = env!("SSHWARDEN_VERSION"),
    about = "SSH Agent backed by Bitwarden vault"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<Commands>,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Start the SSHWarden agent (foreground; Ctrl-C to stop). [starts the agent]
    Run {
        /// Detach and run in the background — used by `startup enable`. [starts the agent]
        #[arg(long)]
        background: bool,
    },
    /// Stop the running agent. [needs running agent]
    Stop,
    /// Restart the agent in the background. [needs running agent]
    Restart,
    /// Show agent + vault status and a suggested next step. [reads the agent if up, else local files]
    Status {
        /// Print the full machine-readable status JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run diagnostics; with --fix, apply safe repairs. [local + running agent]
    Doctor {
        /// Print machine-readable diagnostic JSON.
        #[arg(long)]
        json: bool,
        /// Apply safe repairs (e.g. add the SSHWarden Include line to ~/.ssh/config).
        #[arg(long)]
        fix: bool,
    },
    /// Authenticate, sync keys, set up this device (PIN), and hand keys to the agent. [contacts Bitwarden]
    Login {
        /// Bitwarden server base URL — standalone login only (rejected if a daemon is running).
        #[arg(long)]
        base_url: Option<String>,
        /// Email address — standalone login only.
        #[arg(long)]
        email: Option<String>,
    },
    /// Sync keys from Bitwarden into the running agent. [needs running agent + Bitwarden]
    Sync,
    /// Forget remembered device material. In multi-device mode this is device-only by default. [needs running agent]
    Forget {
        /// Also remove the shared Local Key Cache / legacy vault cache.
        #[arg(long)]
        shared_cache: bool,
    },
    /// Lock the vault (clear private keys from memory). [needs running agent]
    Lock,
    /// Unlock the vault. [needs running agent]
    Unlock {
        /// Unlock method: auto (platform unlock then PIN), pin, hello, or native.
        #[arg(long, default_value = "auto")]
        method: UnlockMethod,
    },
    /// Set or update the quick-unlock PIN. [needs running agent]
    SetPin,
    /// Show cached SSH keys + host bindings (offline), or manage bindings. [local only]
    Keys {
        #[command(subcommand)]
        action: Option<KeysAction>,
    },
    /// Print shell environment exports for SSHWarden agent discovery. [local only]
    Env {
        /// Shell syntax to emit: sh, powershell, fish, or cmd.
        #[arg(long, default_value = "sh")]
        shell: String,
    },
    /// Show or update the managed SSH config snippet + Include line (offline). [local only]
    SshConfig {
        #[command(subcommand)]
        action: Option<SshConfigAction>,
    },
    /// Manage auto-start of the agent at login. [local only]
    Startup {
        #[command(subcommand)]
        action: StartupAction,
    },
    /// Show the config file path (creating a default if missing). [local only]
    Config,
}

/// Unlock method selected via `unlock --method`.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnlockMethod {
    /// Try platform unlock (Windows Hello / native), falling back to a PIN prompt.
    Auto,
    /// Prompt for the quick-unlock PIN.
    Pin,
    /// Use the Windows Hello sign path.
    Hello,
    /// Use platform-native unlock (macOS Keychain / Linux Secret Service).
    Native,
}

#[derive(Subcommand, Clone)]
pub(crate) enum KeysAction {
    /// List cached keys with bound hosts and ssh-config status (offline; the default).
    List,
    /// Bind one or more host patterns to a key (by name or cipher id). [local only]
    Bind {
        /// Key name (as shown in `sshwarden keys`) or cipher uuid.
        key: String,
        /// Host patterns: hostnames, IPs, or globs (e.g. `*.prod.example.com`).
        #[arg(required = true)]
        hosts: Vec<String>,
    },
    /// Remove a host from a key's bindings, or all of them with `--all`. [local only]
    Unbind {
        /// Key name or cipher uuid.
        key: String,
        /// Host pattern to remove (omit with `--all` to clear every host).
        host: Option<String>,
        /// Remove every host bound to this key.
        #[arg(long)]
        all: bool,
    },
    /// Open the graphical bindings manager. [needs running agent]
    Ui,
}

#[derive(Subcommand, Clone)]
pub(crate) enum SshConfigAction {
    /// Print the managed snippet to stdout.
    Show,
    /// Regenerate the snippet from the local cache + bindings and ensure the Include line (offline).
    Write,
    /// Remove the Include line from ~/.ssh/config (the snippet file is preserved).
    Remove,
}

#[derive(Subcommand, Clone)]
pub(crate) enum StartupAction {
    /// Enable auto-start at login (requires a Remembered Device — run `login` first).
    Enable,
    /// Disable auto-start at login.
    Disable,
}
