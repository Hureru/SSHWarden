//! Control-channel CLI commands and the daemon-side control command handler,
//! plus vault locking and PIN-failure throttling state.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 5a).

use std::sync::Arc;

use anyhow::Context;
use tracing::info;

use crate::bindings_cli::dispatch_standalone_bind_hosts_dialog;
#[cfg(windows)]
use crate::cache::decrypt_envelope_local_key_cache_with_hello;
use crate::cache::{
    current_native_unlock_slot, finish_native_unlock_response, key_tuples_from_cache_header,
    multi_device_mode, reload_shared_local_cache_from_disk_if_multi_device,
    write_envelope_local_key_cache, write_envelope_local_key_cache_with_key,
};
use crate::commands::login::create_client;
use crate::notifications::connect_notification_client;
use crate::process::{is_daemon_running, spawn_background_agent};
use crate::runtime::{DaemonState, UIRequestTx};
use crate::sshconfig::{sync_managed_ssh_config_with_bindings, write_key_selector_files};
use crate::sync::{do_sync, reconcile_synced_key_state, resolve_pending_sync};
#[cfg(windows)]
use crate::unlock::finish_unlock_with_json;
use crate::unlock::{
    ensure_local_cache_key_for_manual_sync, pin_dialog_validator, restore_api_session,
    save_device_session, unlock_with_pin,
};
use crate::{err_line, out_line};
pub(crate) async fn cmd_control(cmd: &str) -> anyhow::Result<()> {
    match sshwarden_agent::control::send_control_command(cmd).await {
        Ok(response) => {
            if response.ok {
                if cmd == "status-json" {
                    let value = response
                        .details
                        .as_ref()
                        .cloned()
                        .unwrap_or_else(|| serde_json::to_value(&response).unwrap_or_default());
                    out_line(serde_json::to_string_pretty(&value)?);
                    return Ok(());
                }
                if let Some(msg) = &response.message {
                    out_line(msg);
                }
                if let Some(locked) = response.locked {
                    out_line(format!("  Locked: {locked}"));
                }
                if let Some(count) = response.key_count {
                    out_line(format!("  Keys: {count}"));
                }
                if let Some(details) = &response.details {
                    if let Some(notification) = details.get("notification") {
                        out_line(format!("  Notification: {notification}"));
                    }
                    if let Some(pending) = details.get("pending_sync") {
                        out_line(format!("  Pending sync: {pending}"));
                    }
                    if let Some(authenticated) = details.get("authenticated") {
                        out_line(format!("  Authenticated: {authenticated}"));
                    }
                }
            } else {
                let err = response.error.as_deref().unwrap_or("Unknown error");
                err_line(format!("Error: {err}"));
                std::process::exit(1);
            }
            Ok(())
        }
        Err(e) => {
            err_line(format!("Could not connect to SSHWarden agent: {e}"));
            err_line("Is the agent running? Start it with: sshwarden run");
            std::process::exit(2);
        }
    }
}

/// Three-way outcome of trying to reach the running daemon over the control
/// channel. Drives `stop`/`restart`, which treat the control channel — not the
/// PID file — as the source of truth for "is a daemon live", and only fall back
/// to PID-file logic when nothing answers.
pub(crate) enum DaemonContact {
    /// The daemon replied.
    Replied(sshwarden_agent::ControlResponse),
    /// A daemon was reached, but no usable reply came back before the channel
    /// closed or the wait timed out — the expected outcome when the agent tears
    /// the channel down during a clean `stop`. Callers confirm the real state
    /// via the PID file rather than assume the daemon is gone.
    Unconfirmed(String),
    /// Nothing is listening on the control channel — no daemon is running.
    NotRunning,
}

/// Contact the running daemon over the control channel with a bounded timeout so
/// a wedged or busy agent cannot hang `stop`/`restart` indefinitely. A connect
/// failure is reported as [`DaemonContact::NotRunning`]; any post-connect error
/// or timeout is [`DaemonContact::Unconfirmed`] (a daemon was there, but we
/// can't be sure of the result).
pub(crate) async fn contact_daemon(cmd: &str) -> DaemonContact {
    let send = sshwarden_agent::control::send_control_command(cmd);
    match tokio::time::timeout(std::time::Duration::from_secs(5), send).await {
        Ok(Ok(resp)) => DaemonContact::Replied(resp),
        Ok(Err(e)) => {
            if e.downcast_ref::<sshwarden_agent::control::ControlUnreachable>()
                .is_some()
            {
                DaemonContact::NotRunning
            } else {
                DaemonContact::Unconfirmed(e.to_string())
            }
        }
        Err(_) => DaemonContact::Unconfirmed("no reply within 5s".to_string()),
    }
}

/// `stop`: ask the running agent to shut down cleanly over the control channel,
/// then wait briefly for it to release the PID file. The control channel is
/// contacted unconditionally — a missing or stale PID file must not turn `stop`
/// into a silent no-op while a daemon is still reachable. Idempotent — stopping
/// an agent that is not running is reported and treated as success.
pub(crate) async fn cmd_stop() -> anyhow::Result<()> {
    match contact_daemon("stop").await {
        DaemonContact::Replied(resp) if resp.ok => {
            out_line(resp.message.as_deref().unwrap_or("Stopping agent"));
        }
        DaemonContact::Replied(resp) => {
            err_line(format!(
                "Stop failed: {}",
                resp.error.as_deref().unwrap_or("unknown error")
            ));
            std::process::exit(1);
        }
        DaemonContact::NotRunning => {
            out_line("No running SSHWarden agent.");
            return Ok(());
        }
        DaemonContact::Unconfirmed(reason) => {
            // The agent may have torn down the control channel before its reply
            // reached us — the expected outcome of a clean stop, not a failure.
            // Fall through to the wait loop and let the PID file decide whether
            // it actually exited.
            err_line(format!(
                "No stop confirmation from the agent ({reason}); confirming it exited…"
            ));
        }
    }
    // Wait up to ~5s for the agent to exit and remove its PID file.
    for _ in 0..50 {
        if !is_daemon_running() {
            out_line("Agent stopped.");
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    err_line("Agent acknowledged stop but is still running after 5s.");
    std::process::exit(1);
}

/// `restart`: stop any reachable agent, wait for it to exit, then spawn a fresh
/// detached background agent (`run --background`). The running agent is detected
/// over the control channel rather than the PID file — skipping the stop because
/// of a missing or stale PID file would spawn a second agent that fights the
/// live one for the SSH endpoint and control pipe.
pub(crate) async fn cmd_restart() -> anyhow::Result<()> {
    if !matches!(contact_daemon("stop").await, DaemonContact::NotRunning) {
        // Replied, errored, or timed out — a daemon was (or may still be) alive.
        // Confirm it actually exits before starting a replacement.
        let mut stopped = false;
        for _ in 0..50 {
            if !is_daemon_running() {
                stopped = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if !stopped {
            err_line("Existing agent did not stop within 5s; not restarting.");
            std::process::exit(1);
        }
        out_line("Stopped existing agent.");
    }

    let exe = std::env::current_exe().context("Failed to find the SSHWarden executable")?;
    spawn_background_agent(&exe)?;
    out_line("Started agent in the background.");
    Ok(())
}

/// Lock the vault: clear private key tuples while retaining public key identities
/// in the SSH agent so locked remembered devices remain listable.
pub(crate) async fn lock_vault(
    agent: &mut sshwarden_agent::SshWardenAgent,
    state: &DaemonState,
) -> Result<(), anyhow::Error> {
    // First, so that it holds even when the lock itself fails.
    state
        .keyring_auto_unlock
        .store(false, std::sync::atomic::Ordering::Relaxed);
    agent.lock()?;
    state
        .vault_locked
        .store(true, std::sync::atomic::Ordering::Relaxed);
    state.cached_key_tuples.write().await.clear();
    state.local_cache_key_state.write().await.clear();
    state.authorization_memory.write().await.clear();
    // The user key opens the whole vault. The tokens stay: they are refreshed
    // while locked, and the next unlock loads the key again (ADR 0028).
    if let Some(client) = state.api_client.write().await.as_mut() {
        client.clear_user_key();
    }
    Ok(())
}

/// SEC-03: in-memory PIN brute-force protection. Kept per daemon run (not
/// persisted) so it cannot be reset by tampering with on-disk state.
#[derive(Default)]
pub(crate) struct PinFailureState {
    consecutive_failures: u32,
    locked_until: Option<std::time::Instant>,
}

pub(crate) type PinFailureHandle = Arc<std::sync::Mutex<PinFailureState>>;

/// Lock PIN unlock after this many consecutive wrong attempts.
pub(crate) const PIN_MAX_ATTEMPTS: u32 = 5;
/// Per-failure delay scales with the failure count, capped, to slow guessing.
pub(crate) const PIN_FAILURE_BASE_DELAY: std::time::Duration =
    std::time::Duration::from_millis(500);
pub(crate) const PIN_FAILURE_MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(5);
/// Lockout window once PIN_MAX_ATTEMPTS consecutive failures is reached.
pub(crate) const PIN_LOCKOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Reject a PIN attempt outright while a lockout is active. Returns the
/// remaining lockout duration if locked, clearing an expired lockout.
pub(crate) fn pin_lockout_remaining(
    pin_failures: &PinFailureHandle,
) -> Option<std::time::Duration> {
    let now = std::time::Instant::now();
    let mut st = pin_failures.lock().unwrap_or_else(|e| e.into_inner());
    match st.locked_until {
        Some(until) if until > now => Some(until - now),
        Some(_) => {
            st.locked_until = None;
            None
        }
        None => None,
    }
}

/// Record a PIN unlock outcome: reset on success, otherwise bump the failure
/// counter (arming a lockout at the threshold) and return the delay to apply.
pub(crate) fn record_pin_attempt(
    pin_failures: &PinFailureHandle,
    success: bool,
) -> std::time::Duration {
    let mut st = pin_failures.lock().unwrap_or_else(|e| e.into_inner());
    if success {
        st.consecutive_failures = 0;
        st.locked_until = None;
        return std::time::Duration::ZERO;
    }
    st.consecutive_failures = st.consecutive_failures.saturating_add(1);
    if st.consecutive_failures >= PIN_MAX_ATTEMPTS {
        st.locked_until = Some(std::time::Instant::now() + PIN_LOCKOUT);
    }
    std::cmp::min(
        PIN_FAILURE_BASE_DELAY * st.consecutive_failures,
        PIN_FAILURE_MAX_DELAY,
    )
}

pub(crate) async fn build_status_response(
    json: bool,
    agent: &sshwarden_agent::SshWardenAgent,
    state: &DaemonState,
) -> sshwarden_agent::ControlResponse {
    let locked = state
        .vault_locked
        .load(std::sync::atomic::Ordering::Relaxed);
    let count = agent.key_count();
    let signable = agent.signable_key_count();
    let agent_running = agent.is_running();
    // SEC: PIN availability lives in the v3 local key cache
    // (`local_cache_key.pin_encrypted`).
    let has_pin = state
        .local_key_cache_data
        .read()
        .await
        .as_ref()
        .map(|c| c.local_cache_key.pin_encrypted.is_some())
        .unwrap_or(false);
    let has_local_key_cache = state.local_key_cache_data.read().await.is_some();
    let authenticated = state.api_client.read().await.is_some();
    let pending = state
        .pending_sync
        .load(std::sync::atomic::Ordering::Relaxed);
    let notification = state.notification_state.read().await.clone();
    // P1-3 / multi-device: surface both the shared Bitwarden-projection
    // directory and this device's runtime/session directory so users can tell
    // exactly which OneDrive files are shared and which are device-local.
    let shared_data_dir = sshwarden_config::shared_data_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unresolved>".to_string());
    let device_data_dir = sshwarden_config::device_data_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unresolved>".to_string());
    // P1-3 / multi-device: PID/log/socket state is machine-local and deliberately
    // lives outside the (possibly cloud-synced) shared data root, so surface it
    // too — users look for sshwarden.log next to the executable.
    let local_state_dir = sshwarden_config::local_state_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unresolved>".to_string());
    let log_path = crate::process::log_file_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unresolved>".to_string());
    let device_id =
        sshwarden_config::current_device_id().unwrap_or_else(|_| "<unresolved>".to_string());
    let multi_device = sshwarden_config::multi_device_enabled().unwrap_or(false);
    let ssh_config_path_style = sshwarden_config::Config::load()
        .map(|config| match config.ssh_config.path_style {
            sshwarden_config::SshConfigPathStyle::Absolute => "absolute",
            sshwarden_config::SshConfigPathStyle::HomeRelative => "home_relative",
        })
        .unwrap_or("absolute");

    let details = serde_json::json!({
        // Stable contract version for `status --json` consumers (see status_report.rs).
        "schema_version": crate::status_report::STATUS_SCHEMA_VERSION,
        // The daemon's own pid: `status` prints this instead of re-verifying the
        // pid file, which only works when the client binary is the same file.
        "agent_pid": std::process::id(),
        "locked": locked,
        "key_count": count,
        "signable_key_count": signable,
        "agent_running": agent_running,
        "has_pin": has_pin,
        "has_local_key_cache": has_local_key_cache,
        "authenticated": authenticated,
        "pending_sync": pending,
        "data_dir": device_data_dir,
        "shared_data_dir": shared_data_dir,
        "device_data_dir": device_data_dir,
        "local_state_dir": local_state_dir,
        "log_path": log_path,
        "device_id": device_id,
        "multi_device": multi_device,
        "ssh_config_path_style": ssh_config_path_style,
        "notification": notification.to_json(),
    });

    let mut resp = sshwarden_agent::ControlResponse::status(locked, count).with_details(details);
    let mut extras = Vec::new();
    if !agent_running {
        // RT-01: surface the zombie state — the agent task is not serving SSH
        // clients even though the control channel still answers.
        extras.push("AGENT NOT SERVING (SSH endpoint unavailable)".to_string());
    }
    if count > 0 && signable < count {
        // lock-keystore: identities are listed (ssh-add -l) but have no private
        // material, so signing fails until unlock. Make that explicit.
        extras.push("keys listed but not signable until unlock".to_string());
    }
    if has_pin {
        extras.push("PIN configured".to_string());
    }
    if has_local_key_cache {
        extras.push("local key cache present".to_string());
    }
    if authenticated {
        extras.push("API session restored".to_string());
    }
    if multi_device {
        extras.push("multi-device storage".to_string());
    }
    if pending {
        extras.push("pending sync".to_string());
    }
    if notification.stale_cache {
        // Not a connectivity problem: the last sync succeeded but refreshing the
        // local key cache did not, so say so instead of implying a sync problem.
        extras.push("local key cache refresh failed".to_string());
    }
    // Delivery health, not just a state word: a socket that dropped and is now
    // retrying used to be indistinguishable from a healthy one here.
    extras.push(format!(
        "notifications {}",
        notification.health_label(authenticated)
    ));

    if json {
        resp.message = None;
    } else if !extras.is_empty() {
        resp.message = Some(format!(
            "{} ({})",
            resp.message.unwrap_or_default(),
            extras.join(", ")
        ));
    }

    resp
}

/// What every successful unlock does next: get the Bitwarden session back and
/// start the sync that waited. A problem with the session goes into the reply.
async fn after_unlock(
    mut resp: sshwarden_agent::ControlResponse,
    state: &DaemonState,
    agent: &sshwarden_agent::SshWardenAgent,
    notification_rx: &mut Option<tokio::sync::mpsc::Receiver<sshwarden_api::SyncEvent>>,
    notification_client: &mut Option<sshwarden_api::NotificationClient>,
) -> sshwarden_agent::ControlResponse {
    if resp.ok {
        if let Some(hint) = restore_api_session(state, notification_rx, notification_client).await {
            resp.message = Some(format!("{}\n{hint}", resp.message.unwrap_or_default()));
        }
        resolve_pending_sync(state, agent);
    }
    resp
}

/// The `sync` command. The main loop runs it in its own task: the fetch can
/// wait 30 s on a silent server, and signing must go on meanwhile.
pub(crate) async fn sync_response(
    state: &DaemonState,
    agent: &mut sshwarden_agent::SshWardenAgent,
) -> sshwarden_agent::ControlResponse {
    reload_shared_local_cache_from_disk_if_multi_device(&state.local_key_cache_data).await;
    // Locked means nothing is pulled or decrypted (ADR 0009): the sync
    // waits as a Pending Sync, and the next unlock runs it.
    if state
        .vault_locked
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        state
            .pending_sync
            .store(true, std::sync::atomic::Ordering::Relaxed);
        return sshwarden_agent::ControlResponse::ok(
            "Vault is locked; sync will run on next unlock",
        );
    }
    // Only multi-device mode needs the shared cache reconciled before a
    // manual sync. Gating this avoids a NEW PIN prompt (and a hard failure
    // on cancel) for legacy single-device users whose unlock path did not
    // keep the Local Cache Key in memory.
    if multi_device_mode() {
        // If this unlocked session was restored without keeping the Local
        // Cache Key in memory, a plain sync would update the live agent but
        // leave `sshwarden keys` showing the old cache header. Prompt for
        // PIN first so the synced key set can be persisted atomically.
        if let Err(e) = ensure_local_cache_key_for_manual_sync(state).await {
            return sshwarden_agent::ControlResponse::err(&e);
        }
    }
    match do_sync(state, agent).await {
        Ok((count, skipped)) => sshwarden_agent::ControlResponse::ok(&sync_reply(count, skipped)),
        Err(e) => sshwarden_agent::ControlResponse::err(&e),
    }
}

fn sync_reply(count: usize, skipped: usize) -> String {
    if skipped == 0 {
        return format!("Synced {count} SSH keys");
    }
    format!(
        "Synced {count} SSH keys; {skipped} skipped (could not be decrypted: organisation-owned keys are not supported; details in the log)"
    )
}

/// Handle a control command from the IPC channel.
pub(crate) async fn handle_control_command(
    action: sshwarden_agent::ControlAction,
    agent: &mut sshwarden_agent::SshWardenAgent,
    state: &DaemonState,
    notification_rx: &mut Option<tokio::sync::mpsc::Receiver<sshwarden_api::SyncEvent>>,
    notification_client: &mut Option<sshwarden_api::NotificationClient>,
) -> sshwarden_agent::ControlResponse {
    use sshwarden_agent::ControlAction;

    if matches!(
        &action,
        ControlAction::Unlock
            | ControlAction::UnlockNative
            | ControlAction::UnlockHello
            | ControlAction::UnlockPin { .. }
    ) {
        reload_shared_local_cache_from_disk_if_multi_device(&state.local_key_cache_data).await;
    }

    match action {
        // `Stop` is intercepted by the run_foreground select! loop (it breaks out
        // to run the cancel-token cleanup); this arm is only defensive.
        ControlAction::Stop => sshwarden_agent::ControlResponse::ok("Stopping agent"),
        ControlAction::Lock => {
            if state
                .vault_locked
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                sshwarden_agent::ControlResponse::ok("Vault is already locked")
            } else {
                match lock_vault(agent, state).await {
                    Ok(()) => {
                        info!("Vault locked via control command");
                        sshwarden_agent::ControlResponse::ok("Vault locked")
                    }
                    Err(e) => {
                        sshwarden_agent::ControlResponse::err(&format!("Failed to lock: {}", e))
                    }
                }
            }
        }
        ControlAction::Unlock => {
            if !state
                .vault_locked
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return sshwarden_agent::ControlResponse::ok("Vault is already unlocked");
            }

            // Try platform-native Local Key Cache first, then Windows Hello.
            // Not after a lock: then only `unlock --method native` uses the keyring.
            #[cfg(not(windows))]
            if let Some(cache) = state
                .local_key_cache_data
                .read()
                .await
                .as_ref()
                .filter(|_| {
                    state
                        .keyring_auto_unlock
                        .load(std::sync::atomic::Ordering::Relaxed)
                })
                .cloned()
            {
                let resp = finish_native_unlock_response(
                    cache,
                    agent,
                    state,
                    "Vault unlocked via platform-native local key cache",
                )
                .await;
                if resp.ok {
                    return after_unlock(resp, state, agent, notification_rx, notification_client)
                        .await;
                }
                tracing::warn!("Platform-native local key cache unlock failed");
            }

            // Try envelope Local Key Cache Windows Hello.
            #[cfg(windows)]
            if let Some(cache) = state.local_key_cache_data.read().await.as_ref().cloned() {
                match decrypt_envelope_local_key_cache_with_hello(&cache) {
                    Ok((keys_json, local_cache_key)) => {
                        state
                            .local_cache_key_state
                            .write()
                            .await
                            .set(local_cache_key);
                        let resp = finish_unlock_with_json(
                            &keys_json,
                            agent,
                            state,
                            "Vault unlocked via Windows Hello local key cache",
                        )
                        .await;
                        return after_unlock(
                            resp,
                            state,
                            agent,
                            notification_rx,
                            notification_client,
                        )
                        .await;
                    }
                    Err(e) => tracing::warn!("Windows Hello local key cache unlock failed: {}", e),
                }
            }

            // Fall back to the PIN dialog (v3 local key cache only).
            if state.config.unlock.auto_unlock_on_request {
                info!("Trying PIN dialog fallback");
                let envelope_cache = {
                    let guard = state.local_key_cache_data.read().await;
                    guard
                        .as_ref()
                        .filter(|c| c.local_cache_key.pin_encrypted.is_some())
                        .cloned()
                };
                if let Some(cache) = envelope_cache {
                    let (validator, holder) = pin_dialog_validator(cache, &state.pin_failures);
                    let pin_result =
                        sshwarden_ui::unlock::request_pin_dialog(&state.ui_request_tx, validator)
                            .await;

                    if let Some(ref entered_pin) = pin_result {
                        let decrypted = holder.lock().unwrap_or_else(|e| e.into_inner()).take();
                        if let Err(e) = unlock_with_pin(state, agent, entered_pin, decrypted).await
                        {
                            return sshwarden_agent::ControlResponse::err(&e);
                        }
                        return after_unlock(
                            sshwarden_agent::ControlResponse::ok("Vault unlocked via PIN dialog"),
                            state,
                            agent,
                            notification_rx,
                            notification_client,
                        )
                        .await;
                    }
                }
                return sshwarden_agent::ControlResponse::err(
                    "Unlock cancelled. Try: sshwarden unlock --method pin (or sshwarden login).",
                );
            }

            sshwarden_agent::ControlResponse::err(
                "Auto-unlock is disabled. Use: sshwarden unlock --method pin (or sshwarden login).",
            )
        }
        ControlAction::UnlockNative => {
            if !state
                .vault_locked
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return sshwarden_agent::ControlResponse::ok("Vault is already unlocked");
            }

            let cache = match state.local_key_cache_data.read().await.as_ref().cloned() {
                Some(cache) => cache,
                None => return sshwarden_agent::ControlResponse::err("No Local Key Cache found"),
            };

            let resp = finish_native_unlock_response(
                cache,
                agent,
                state,
                "Vault unlocked via platform-native local key cache",
            )
            .await;

            after_unlock(resp, state, agent, notification_rx, notification_client).await
        }
        ControlAction::UnlockHello => {
            if !state
                .vault_locked
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return sshwarden_agent::ControlResponse::ok("Vault is already unlocked");
            }

            #[cfg(windows)]
            {
                if let Some(cache) = state.local_key_cache_data.read().await.as_ref().cloned() {
                    match decrypt_envelope_local_key_cache_with_hello(&cache) {
                        Ok((keys_json, local_cache_key)) => {
                            state
                                .local_cache_key_state
                                .write()
                                .await
                                .set(local_cache_key);
                            let resp = finish_unlock_with_json(
                                &keys_json,
                                agent,
                                state,
                                "Vault unlocked via Windows Hello local key cache",
                            )
                            .await;
                            return after_unlock(
                                resp,
                                state,
                                agent,
                                notification_rx,
                                notification_client,
                            )
                            .await;
                        }
                        Err(e) => {
                            tracing::warn!("Windows Hello local key cache unlock failed: {}", e)
                        }
                    }
                }

                sshwarden_agent::ControlResponse::err(
                    "Windows Hello is not enrolled. Set PIN with Hello available to enroll.",
                )
            }

            #[cfg(not(windows))]
            sshwarden_agent::ControlResponse::err("Windows Hello is only supported on Windows")
        }
        ControlAction::Status { json } => build_status_response(json, agent, state).await,
        ControlAction::UnlockPin { pin } => {
            if !state
                .vault_locked
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return sshwarden_agent::ControlResponse::ok("Vault is already unlocked");
            }

            // SEC-03: reject outright while a brute-force lockout is active (no
            // Argon2 work performed) so the control channel can't be hammered.
            if let Some(wait) = pin_lockout_remaining(&state.pin_failures) {
                return sshwarden_agent::ControlResponse::err(&format!(
                    "Too many failed PIN attempts; locked for {}s",
                    wait.as_secs() + 1
                ));
            }

            let resp = match unlock_with_pin(state, agent, &pin, None).await {
                Ok(()) => {
                    sshwarden_agent::ControlResponse::ok("Vault unlocked via PIN local key cache")
                }
                Err(e) => sshwarden_agent::ControlResponse::err(&e),
            };

            // SEC-03: record the outcome — reset on success, otherwise apply an
            // escalating delay and arm a lockout once the threshold is reached.
            let delay = record_pin_attempt(&state.pin_failures, resp.ok);
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            after_unlock(resp, state, agent, notification_rx, notification_client).await
        }
        ControlAction::UnlockPassword { password } => {
            let was_locked = state
                .vault_locked
                .load(std::sync::atomic::Ordering::Relaxed);

            // Email from &state.config (used for re-login).
            let email = state.config.auth.email.clone();

            if email.is_empty() {
                return sshwarden_agent::ControlResponse::err(
                    "No email configured. Cannot re-login.",
                );
            }

            let mut client = create_client(state.config.as_ref(), None);
            match client.login_password(&email, &password).await {
                Ok(()) => {}
                Err(e) => {
                    return sshwarden_agent::ControlResponse::err(&format!("Login failed: {}", e))
                }
            }

            match client.sync_ssh_keys().await {
                Ok(keys) => {
                    let key_tuples: crate::runtime::KeyTuples = zeroize::Zeroizing::new(
                        keys.iter()
                            .map(|k| {
                                (
                                    (*k.private_key_pem).clone(),
                                    k.name.clone(),
                                    k.cipher_id.clone(),
                                )
                            })
                            .collect(),
                    );
                    let count = key_tuples.len();
                    if let Err(e) = write_key_selector_files(&keys) {
                        tracing::warn!("Failed to write key selector files: {}", e);
                    }
                    if let Err(e) = sync_managed_ssh_config_with_bindings(&keys) {
                        tracing::warn!("Failed to sync managed SSH config: {}", e);
                    }
                    reconcile_synced_key_state(&key_tuples, state).await;

                    // Update &state.key_names
                    {
                        let mut names = state.key_names.write().await;
                        names.clear();
                        for k in &keys {
                            names.insert(k.cipher_id.clone(), k.name.clone());
                        }
                    }

                    if let Err(e) = agent.set_keys(&key_tuples) {
                        return sshwarden_agent::ControlResponse::err(&format!(
                            "Login succeeded but failed to load keys: {}",
                            e
                        ));
                    }
                    state
                        .vault_locked
                        .store(false, std::sync::atomic::Ordering::Relaxed);

                    // Save device session + connect notifications
                    let local_cache_key = state.local_cache_key_state.read().await.clone_key();
                    save_device_session(&client, local_cache_key.as_ref()).await;

                    if let Some(token) = client.access_token() {
                        connect_notification_client(
                            &state.config,
                            Some(&client),
                            token,
                            notification_rx,
                            notification_client,
                            &state.notification_state,
                        )
                        .await;
                    }

                    *state.api_client.write().await = Some(client);
                    resolve_pending_sync(state, agent);

                    let message = if was_locked {
                        format!("Vault unlocked, {} SSH keys loaded", count)
                    } else {
                        format!("Bitwarden session refreshed, {} SSH keys loaded", count)
                    };
                    info!("{}", message);
                    let message = if state.notification_state.read().await.stale_cache {
                        format!(
                            "{message}\nWarning: the saved keys on disk were not updated (the vault was not unlocked with the PIN first). Run `sshwarden lock`, `sshwarden unlock`, then `sshwarden sync`."
                        )
                    } else {
                        message
                    };
                    sshwarden_agent::ControlResponse::ok(&message)
                }
                Err(e) => sshwarden_agent::ControlResponse::err(&format!(
                    "Sync failed after login: {}",
                    e
                )),
            }
        }
        // Intercepted by the main loop, which runs `sync_response` in its own
        // task; this arm is only defensive (calling it here would wait on the
        // change lock that the loop holds for this command).
        ControlAction::Sync => {
            sshwarden_agent::ControlResponse::err("sync is run by the main loop")
        }
        ControlAction::Forget { shared } => {
            // EH-06: accumulate failures to delete on-disk material so a
            // revocation that left secrets on disk is not reported as success.
            let mut failures: Vec<String> = Vec::new();
            let multi_device = multi_device_mode();
            let remove_shared_cache = shared || !multi_device;

            if remove_shared_cache {
                if let Err(e) = sshwarden_config::cache::LocalKeyCacheFile::delete() {
                    tracing::warn!("Failed to delete local key cache: {}", e);
                    failures.push(format!("local key cache ({e})"));
                }
            }

            let native_slot = &state
                .local_key_cache_data
                .read()
                .await
                .as_ref()
                .and_then(current_native_unlock_slot);
            if let Err(e) =
                sshwarden_ui::unlock::native::native_delete_local_cache_key(native_slot.as_deref())
            {
                tracing::warn!("Failed to delete native unlock material: {}", e);
                failures.push(format!("native unlock material ({e})"));
            }
            if let Err(e) = sshwarden_config::unlock_slots::UnlockSlotsFile::delete() {
                tracing::warn!("Failed to delete device unlock slots file: {}", e);
                failures.push(format!("device unlock slots file ({e})"));
            }
            if let Err(e) = sshwarden_config::session::SessionFile::delete() {
                tracing::warn!("Failed to delete device session file: {}", e);
                failures.push(format!("device session file ({e})"));
            }

            state.local_cache_key_state.write().await.clear();
            state.authorization_memory.write().await.clear();
            state.cached_key_tuples.write().await.clear();
            *state.api_client.write().await = None;
            state
                .pending_sync
                .store(false, std::sync::atomic::Ordering::Relaxed);
            if let Some(client) = notification_client.take() {
                client.stop();
            }
            // Full reset rather than clearing one field: the client is gone, so
            // every field (state, url, counters, last error) would otherwise
            // describe a connection that no longer exists.
            state.notification_state.write().await.reset();
            *notification_rx = None;
            state
                .vault_locked
                .store(true, std::sync::atomic::Ordering::Relaxed);

            if remove_shared_cache {
                *state.local_key_cache_data.write().await = None;
                state.key_names.write().await.clear();
                let _ = agent.clear_keys();
            } else {
                // Multi-device plain `forget` is device-only: remove this
                // device's API session/native unlock material, but keep the
                // shared key cache listable and PIN-unlockable for all devices.
                let cache = sshwarden_config::cache::LocalKeyCacheFile::load()
                    .ok()
                    .flatten();
                *state.local_key_cache_data.write().await = cache.clone();
                // Clear unconditionally (mirroring the shared-cache branch): if the
                // shared cache fails to reload below, stale labels from the
                // just-forgotten session must not linger in memory.
                state.key_names.write().await.clear();
                let _ = agent.clear_keys();
                if let Some(cache) = cache {
                    let identities = key_tuples_from_cache_header(&cache);
                    if let Err(e) = agent.set_public_identities(identities.clone()) {
                        tracing::warn!(
                            "Failed to reload public identities after device forget: {}",
                            e
                        );
                    }
                    let mut names = state.key_names.write().await;
                    for (_, name, vault_item_id) in identities {
                        names.insert(vault_item_id, name);
                    }
                }
            }

            if failures.is_empty() {
                let message = if remove_shared_cache {
                    "Forgot shared local key cache and device session material"
                } else {
                    "Forgot this device's session and native unlock material; shared key cache was kept"
                };
                sshwarden_agent::ControlResponse::ok(message)
            } else {
                sshwarden_agent::ControlResponse::err(&format!(
                    "Cleared in-memory state, but FAILED to delete on-disk material: {}. \
                     This material may still exist on disk — remove it manually.",
                    failures.join("; ")
                ))
            }
        }
        ControlAction::SetPin { pin } => {
            if let Err(e) = crate::unlock::check_new_pin(&pin) {
                return sshwarden_agent::ControlResponse::err(&e);
            }

            let keys = state.cached_key_tuples.read().await.clone_inner();
            if keys.is_empty() {
                return sshwarden_agent::ControlResponse::err("No keys loaded. Login first.");
            }

            let email = state.config.auth.email.clone();
            let server_url = state.config.server.base_url.clone();

            let local_cache_key = state.local_cache_key_state.read().await.clone_key();
            let cache_write_result = match local_cache_key {
                Some(local_cache_key) => write_envelope_local_key_cache_with_key(
                    &keys,
                    &email,
                    &server_url,
                    &pin,
                    &local_cache_key,
                ),
                None => write_envelope_local_key_cache(&keys, &email, &server_url, &pin),
            };

            match cache_write_result {
                Ok((cache, local_cache_key)) => {
                    *state.local_key_cache_data.write().await = Some(cache);
                    state
                        .local_cache_key_state
                        .write()
                        .await
                        .set(local_cache_key);
                    info!("Envelope local key cache saved");

                    if let Some(client) = state.api_client.read().await.as_ref() {
                        let local_cache_key = state.local_cache_key_state.read().await.clone_key();
                        save_device_session(client, local_cache_key.as_ref()).await;
                    }

                    sshwarden_agent::ControlResponse::ok(
                        "PIN set successfully (persisted to local key cache)",
                    )
                }
                Err(e) => sshwarden_agent::ControlResponse::err(&format!(
                    "Failed to save envelope local key cache: {}",
                    e
                )),
            }
        }
        // The daemon loop runs this one in its own task; kept for the match.
        ControlAction::BindHostsDialog => bind_hosts_dialog_response(&state.ui_request_tx).await,
    }
}

/// `keys ui`: open the host-binding dialog and report what the user did.
pub(crate) async fn bind_hosts_dialog_response(
    ui_request_tx: &UIRequestTx,
) -> sshwarden_agent::ControlResponse {
    match dispatch_standalone_bind_hosts_dialog(ui_request_tx).await {
        Ok(true) => sshwarden_agent::ControlResponse::ok("Bindings updated"),
        Ok(false) => sshwarden_agent::ControlResponse::ok("Dialog cancelled"),
        Err(e) => sshwarden_agent::ControlResponse::err(&format!(
            "Failed to open bind-hosts dialog: {}",
            e
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::sync_reply;

    #[test]
    fn the_sync_reply_names_skipped_keys() {
        assert_eq!(sync_reply(3, 0), "Synced 3 SSH keys");
        assert!(sync_reply(3, 2).contains("2 skipped"));
    }
}
