//! `login` / `set-pin` commands and the shared prompt / API-client helpers.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 5c).

use anyhow::Context;
use tracing::info;

use crate::control::cmd_control;
use crate::process::is_daemon_running;
use crate::{err_line, has_remembered_device_on_disk, out_line};
/// Set PIN command: prompt for PIN and send to daemon.
pub(crate) async fn cmd_set_pin() -> anyhow::Result<()> {
    let pin = prompt_password("Enter new PIN: ")?;
    if pin.len() < 4 {
        err_line("PIN must be at least 4 characters");
        return Ok(());
    }
    let pin_confirm = prompt_password("Confirm PIN: ")?;
    if pin != pin_confirm {
        info!("PINs do not match");
        return Ok(());
    }

    let cmd = format!("set-pin:{}", &*pin);
    cmd_control(&cmd).await
}

/// Prompt for a password from the terminal (hides input).
/// Returns `Zeroizing<String>` to ensure the password is wiped from memory when dropped.
pub(crate) fn prompt_password(prompt: &str) -> anyhow::Result<zeroize::Zeroizing<String>> {
    Ok(zeroize::Zeroizing::new(
        rpassword::prompt_password(prompt).context("Failed to read password")?,
    ))
}

/// Prompt for an email from the terminal.
pub(crate) fn prompt_email(prompt: &str) -> anyhow::Result<String> {
    #[allow(clippy::print_stderr)]
    {
        eprint!("{}", prompt);
    }
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("Failed to read email")?;
    Ok(input.trim().to_string())
}

/// Create a BitwardenClient from config, with optional overrides.
pub(crate) fn create_client(
    config: &sshwarden_config::Config,
    base_url_override: Option<&str>,
) -> sshwarden_api::BitwardenClient {
    let base = base_url_override.unwrap_or(&config.server.base_url);
    let api_url = config
        .server
        .api_url
        .as_deref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}/api", base));
    let identity_url = config
        .server
        .identity_url
        .as_deref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}/identity", base));
    sshwarden_api::BitwardenClient::new(base, &api_url, &identity_url)
}

/// Login command: authenticate and load keys into the running agent.
///
/// UX-2: routes through the running daemon (via the control channel) so a
/// successful login actually loads keys into the agent serving SSH clients.
/// Falls back to a standalone login that only lists keys if no daemon is up.
pub(crate) async fn cmd_login(
    config: &sshwarden_config::Config,
    base_url: Option<&str>,
    email: Option<&str>,
) -> anyhow::Result<()> {
    // UX-2: a running daemon logs in with its OWN configured server/account; the
    // control protocol carries only the password. If the caller supplied
    // --email/--base-url, reject up front — BEFORE prompting — rather than
    // silently logging into the wrong account/server (and without wasting a
    // password/email prompt the caller can't use).
    if (email.is_some() || base_url.is_some()) && is_daemon_running() {
        anyhow::bail!(
            "A daemon is already running and logs in with its own configured account/server; \
             --email/--base-url cannot be applied to it. Stop the daemon to log in standalone, \
             or omit these flags."
        );
    }

    let password = prompt_password("Master password: ")?;

    // Prefer the running daemon: it performs the login + sync and loads keys
    // into the live agent. The control protocol carries only the password, so
    // the daemon uses its own configured server/email.
    match sshwarden_agent::control::send_control_command(&format!("unlock-password:{}", &*password))
        .await
    {
        Ok(response) => {
            if response.ok {
                if base_url.is_some() {
                    info!("Note: the running agent uses its own configured server; --base-url is ignored.");
                }
                out_line(
                    response
                        .message
                        .as_deref()
                        .unwrap_or("Logged in; keys loaded into the running agent."),
                );
                // Onboarding: if this device has no Remembered Device yet, offer to
                // set a PIN so future unlocks skip the master password. The PIN is
                // entered here (client side) and persisted by the agent's SetPin
                // handler, so it works even when the agent runs detached.
                if !has_remembered_device_on_disk() {
                    offer_pin_setup().await?;
                }
            } else {
                err_line(format!(
                    "Login failed: {}",
                    response.error.as_deref().unwrap_or("unknown error")
                ));
                std::process::exit(1);
            }
            return Ok(());
        }
        Err(_) => {
            info!(
                "No agent running; logging in for listing only (start `sshwarden run --background` to serve keys)."
            );
        }
    }

    // Standalone fallback: authenticate and list keys without touching an agent.
    // Resolve the email here (prompting only now) — the daemon path never needs it.
    let email = match email {
        Some(e) => e.to_string(),
        None if !config.auth.email.is_empty() => config.auth.email.clone(),
        None => prompt_email("Email: ")?,
    };
    let mut client = create_client(config, base_url);
    info!("Logging in as {}...", email);
    client.login_password(&email, &password).await?;

    let keys = client.sync_ssh_keys().await?;
    if keys.is_empty() {
        out_line("No SSH keys found in vault. Add SSH keys in Bitwarden to use them.");
    } else {
        out_line("Login successful. Vault SSH keys:");
        for key in &keys {
            out_line(format!(
                "  SSH Key: {} (cipher: {})",
                key.name, key.cipher_id
            ));
        }
        out_line(
            "\nNote: no agent was running, so keys were not loaded. Start `sshwarden run --background`, then run `sshwarden login` again.",
        );
    }

    Ok(())
}

/// Offer to set a quick-unlock PIN after a successful daemon login. The PIN is
/// read on this (client) terminal and sent to the agent's SetPin handler, which
/// writes the envelope Local Key Cache — completing the Remembered Device. Works
/// even when the agent runs detached, since the prompt is client-side.
pub(crate) async fn offer_pin_setup() -> anyhow::Result<()> {
    use std::io::Write;
    #[allow(clippy::print_stderr)]
    {
        eprint!("Set up a PIN to unlock without your master password next time? [Y/n] ");
    }
    let _ = std::io::stderr().flush();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return Ok(());
    }
    let input = input.trim().to_lowercase();
    if !input.is_empty() && input != "y" && input != "yes" {
        out_line("Skipped PIN setup. You can set it later with `sshwarden set-pin`.");
        return Ok(());
    }
    let pin = prompt_password("Enter new PIN (>= 4 chars): ")?;
    if pin.len() < 4 {
        err_line("PIN must be at least 4 characters. Skipped — run `sshwarden set-pin` later.");
        return Ok(());
    }
    let confirm = prompt_password("Confirm PIN: ")?;
    if *pin != *confirm {
        err_line("PINs do not match. Skipped — run `sshwarden set-pin` later.");
        return Ok(());
    }
    match sshwarden_agent::control::send_control_command(&format!("set-pin:{}", &*pin)).await {
        Ok(resp) if resp.ok => out_line("PIN set — this device is now remembered."),
        Ok(resp) => err_line(format!(
            "Could not set PIN: {}",
            resp.error.as_deref().unwrap_or("unknown error")
        )),
        Err(e) => err_line(format!("Could not set PIN: {e}")),
    }
    Ok(())
}
