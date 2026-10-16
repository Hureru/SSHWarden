//! Control-channel CLI commands and the daemon-side control command handler,
//! plus vault locking and PIN-failure throttling state.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 5a).

use std::sync::Arc;

use anyhow::Context;
use tokio::sync::RwLock;
use tracing::info;

#[cfg(windows)]
use crate::cache::decrypt_envelope_local_key_cache_with_hello;
use crate::cache::{
    current_native_unlock_slot, decrypt_envelope_local_key_cache_with_pin,
    enroll_device_platform_slots_if_missing, finish_native_unlock_response,
    key_tuples_from_cache_header, migrate_pin_salt_to_v3, multi_device_mode,
    needs_pin_salt_migration, reload_shared_local_cache_from_disk_if_multi_device,
    write_envelope_local_key_cache, write_envelope_local_key_cache_with_key,
};
use crate::notifications::connect_notification_client;
use crate::process::{is_daemon_running, spawn_background_agent};
use crate::runtime::{
    AuthorizationMemorySet, CachedKeyTuples, KeyMaterialFingerprints, LocalCacheKeyHandle,
    NotificationRuntimeState, UIRequestTx,
};
use crate::sshconfig::{sync_managed_ssh_config_with_bindings, write_key_selector_files};
use crate::sync::{do_sync, reconcile_synced_key_state, resolve_pending_sync};
use crate::unlock::{
    ensure_local_cache_key_for_manual_sync, finish_unlock_with_json, gate_pin_validator,
    get_pin_encrypted_data, make_pin_validator, save_device_session, try_restore_api_session,
    DecryptedCache, PinValidator,
};
#[cfg(windows)]
use crate::unlock::{try_hello_unlock, try_restore_api_session_hello};
use crate::{create_client, dispatch_standalone_bind_hosts_dialog, err_line, out_line};
#[cfg(windows)]
use base64::Engine;
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
    vault_locked: &Arc<std::sync::atomic::AtomicBool>,
    cached_key_tuples: &CachedKeyTuples,
    local_cache_key_state: Option<&LocalCacheKeyHandle>,
    authorization_memory: Option<&AuthorizationMemorySet>,
) -> Result<(), anyhow::Error> {
    agent.lock()?;
    vault_locked.store(true, std::sync::atomic::Ordering::Relaxed);
    cached_key_tuples.write().await.clear();
    if let Some(state) = local_cache_key_state {
        state.write().await.clear();
    }
    if let Some(memory) = authorization_memory {
        memory.write().await.clear();
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn build_status_response(
    json: bool,
    agent: &sshwarden_agent::SshWardenAgent,
    vault_locked: &Arc<std::sync::atomic::AtomicBool>,
    pin_encrypted_keys: &Arc<RwLock<Option<String>>>,
    vault_file_data: &Arc<RwLock<Option<sshwarden_config::vault::VaultFile>>>,
    api_client: &Arc<RwLock<Option<sshwarden_api::BitwardenClient>>>,
    pending_sync: &Arc<std::sync::atomic::AtomicBool>,
    notification_state: &Arc<RwLock<NotificationRuntimeState>>,
    local_key_cache_data: &Arc<RwLock<Option<sshwarden_config::cache::LocalKeyCacheFile>>>,
) -> sshwarden_agent::ControlResponse {
    let locked = vault_locked.load(std::sync::atomic::Ordering::Relaxed);
    let count = agent.key_count();
    let signable = agent.signable_key_count();
    let agent_running = agent.is_running();
    // SEC: reflect PIN availability across both layouts — the legacy
    // pin_encrypted_keys slot AND the v3 local key cache, where set-pin/migration
    // moves the PIN into local_cache_key.pin_encrypted (and clears the legacy slot).
    let has_pin = pin_encrypted_keys.read().await.is_some()
        || local_key_cache_data
            .read()
            .await
            .as_ref()
            .map(|c| c.local_cache_key.pin_encrypted.is_some())
            .unwrap_or(false);
    let has_vault = vault_file_data.read().await.is_some();
    let has_local_key_cache = local_key_cache_data.read().await.is_some();
    let authenticated = api_client.read().await.is_some();
    let pending = pending_sync.load(std::sync::atomic::Ordering::Relaxed);
    let notification = notification_state.read().await.clone();
    // P1-3 / multi-device: surface both the shared Bitwarden-projection
    // directory and this device's runtime/session directory so users can tell
    // exactly which OneDrive files are shared and which are device-local.
    let shared_data_dir = sshwarden_config::shared_data_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unresolved>".to_string());
    let device_data_dir = sshwarden_config::device_data_dir()
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
        "locked": locked,
        "key_count": count,
        "signable_key_count": signable,
        "agent_running": agent_running,
        "has_pin": has_pin,
        "has_vault_file": has_vault,
        "has_local_key_cache": has_local_key_cache,
        "legacy_migration_available": has_vault && !has_local_key_cache,
        "authenticated": authenticated,
        "pending_sync": pending,
        "data_dir": device_data_dir,
        "shared_data_dir": shared_data_dir,
        "device_data_dir": device_data_dir,
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
        extras.push("AGENT NOT SERVING (SSH endpoint unavailable)");
    }
    if count > 0 && signable < count {
        // lock-keystore: identities are listed (ssh-add -l) but have no private
        // material, so signing fails until unlock. Make that explicit.
        extras.push("keys listed but not signable until unlock");
    }
    if has_pin {
        extras.push("PIN configured");
    }
    if has_vault {
        extras.push("vault.enc present");
    }
    if has_local_key_cache {
        extras.push("local key cache present");
    }
    if has_vault && !has_local_key_cache {
        extras.push("legacy migration available");
    }
    if authenticated {
        extras.push("API session restored");
    }
    if multi_device {
        extras.push("multi-device storage");
    }
    if pending {
        extras.push("pending sync");
    }
    if notification.stale_cache {
        extras.push("stale cache");
    }
    extras.push(notification.state_name());

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

/// Handle a control command from the IPC channel.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_control_command(
    action: sshwarden_agent::ControlAction,
    agent: &mut sshwarden_agent::SshWardenAgent,
    vault_locked: &Arc<std::sync::atomic::AtomicBool>,
    cached_key_tuples: &CachedKeyTuples,
    public_key_identity_tuples: &CachedKeyTuples,
    api_client: &Arc<RwLock<Option<sshwarden_api::BitwardenClient>>>,
    pin_encrypted_keys: &Arc<RwLock<Option<String>>>,
    vault_file_data: &Arc<RwLock<Option<sshwarden_config::vault::VaultFile>>>,
    local_key_cache_data: &Arc<RwLock<Option<sshwarden_config::cache::LocalKeyCacheFile>>>,
    local_cache_key_state: &LocalCacheKeyHandle,
    key_material_fingerprints: &KeyMaterialFingerprints,
    key_names: &Arc<RwLock<std::collections::HashMap<String, String>>>,
    config: &Arc<sshwarden_config::Config>,
    auto_unlock: bool,
    ui_request_tx: &UIRequestTx,
    notification_rx: &mut Option<tokio::sync::mpsc::Receiver<sshwarden_api::SyncEvent>>,
    notification_client: &mut Option<sshwarden_api::NotificationClient>,
    pending_sync: &Arc<std::sync::atomic::AtomicBool>,
    notification_state: &Arc<RwLock<NotificationRuntimeState>>,
    authorization_memory: &AuthorizationMemorySet,
    pin_failures: &PinFailureHandle,
) -> sshwarden_agent::ControlResponse {
    use sshwarden_agent::ControlAction;

    if matches!(
        &action,
        ControlAction::Unlock
            | ControlAction::UnlockNative
            | ControlAction::UnlockHello
            | ControlAction::UnlockPin { .. }
            | ControlAction::Sync
    ) {
        reload_shared_local_cache_from_disk_if_multi_device(local_key_cache_data).await;
    }

    match action {
        // `Stop` is intercepted by the run_foreground select! loop (it breaks out
        // to run the cancel-token cleanup); this arm is only defensive.
        ControlAction::Stop => sshwarden_agent::ControlResponse::ok("Stopping agent"),
        ControlAction::Lock => {
            if vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
                sshwarden_agent::ControlResponse::ok("Vault is already locked")
            } else {
                match lock_vault(
                    agent,
                    vault_locked,
                    cached_key_tuples,
                    Some(local_cache_key_state),
                    Some(authorization_memory),
                )
                .await
                {
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
            if !vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
                return sshwarden_agent::ControlResponse::ok("Vault is already unlocked");
            }

            // Try platform-native Local Key Cache first, then Windows Hello/legacy Hello.
            #[cfg(not(windows))]
            if let Some(cache) = local_key_cache_data.read().await.as_ref().cloned() {
                let resp = finish_native_unlock_response(
                    cache,
                    agent,
                    vault_locked,
                    cached_key_tuples,
                    key_names,
                    local_cache_key_state,
                    "Vault unlocked via platform-native local key cache",
                )
                .await;
                if resp.ok {
                    resolve_pending_sync(
                        pending_sync,
                        api_client,
                        cached_key_tuples,
                        public_key_identity_tuples,
                        local_key_cache_data,
                        local_cache_key_state,
                        authorization_memory,
                        key_material_fingerprints,
                        vault_locked,
                        agent,
                        key_names,
                        notification_state,
                    )
                    .await;
                    return resp;
                }
                tracing::warn!("Platform-native local key cache unlock failed");
            }

            // Try envelope Local Key Cache Windows Hello first, then legacy Hello.
            #[cfg(windows)]
            if let Some(cache) = local_key_cache_data.read().await.as_ref().cloned() {
                match decrypt_envelope_local_key_cache_with_hello(&cache) {
                    Ok((keys_json, local_cache_key)) => {
                        local_cache_key_state.write().await.set(local_cache_key);
                        let resp = finish_unlock_with_json(
                            &keys_json,
                            agent,
                            vault_locked,
                            cached_key_tuples,
                            key_names,
                            "Vault unlocked via Windows Hello local key cache",
                        )
                        .await;
                        if resp.ok {
                            try_restore_api_session_hello(
                                api_client,
                                config,
                                notification_rx,
                                notification_client,
                                notification_state,
                            )
                            .await;
                            resolve_pending_sync(
                                pending_sync,
                                api_client,
                                cached_key_tuples,
                                public_key_identity_tuples,
                                local_key_cache_data,
                                local_cache_key_state,
                                authorization_memory,
                                key_material_fingerprints,
                                vault_locked,
                                agent,
                                key_names,
                                notification_state,
                            )
                            .await;
                        }
                        return resp;
                    }
                    Err(e) => tracing::warn!("Windows Hello local key cache unlock failed: {}", e),
                }
            }

            // Try legacy Hello sign-path (if hello_challenge available).
            #[cfg(windows)]
            {
                let hello_info = {
                    let vf = vault_file_data.read().await;
                    vf.as_ref().and_then(|v| {
                        let challenge = v.hello_challenge.as_ref()?;
                        let encrypted = v.hello_encrypted.as_ref()?;
                        Some((challenge.clone(), encrypted.clone()))
                    })
                };

                if let Some((challenge_b64, hello_encrypted)) = hello_info {
                    if let Ok(challenge_bytes) =
                        base64::engine::general_purpose::STANDARD.decode(&challenge_b64)
                    {
                        if challenge_bytes.len() == 16 {
                            let mut challenge = [0u8; 16];
                            challenge.copy_from_slice(&challenge_bytes);

                            // Try Hello sign-path unlock
                            let hello_result = tokio::task::spawn_blocking(move || {
                                try_hello_unlock(&challenge, &hello_encrypted)
                            })
                            .await;

                            if let Ok(Ok(keys_json)) = hello_result {
                                let resp = finish_unlock_with_json(
                                    &keys_json,
                                    agent,
                                    vault_locked,
                                    cached_key_tuples,
                                    key_names,
                                    "Vault unlocked via Windows Hello",
                                )
                                .await;

                                if resp.ok {
                                    try_restore_api_session_hello(
                                        api_client,
                                        config,
                                        notification_rx,
                                        notification_client,
                                        notification_state,
                                    )
                                    .await;
                                    resolve_pending_sync(
                                        pending_sync,
                                        api_client,
                                        cached_key_tuples,
                                        public_key_identity_tuples,
                                        local_key_cache_data,
                                        local_cache_key_state,
                                        authorization_memory,
                                        key_material_fingerprints,
                                        vault_locked,
                                        agent,
                                        key_names,
                                        notification_state,
                                    )
                                    .await;
                                }

                                return resp;
                            }
                            info!("Hello unlock failed or cancelled, trying fallback");
                        }
                    }
                }
            }

            // Fall back to PIN dialog when Hello sign-path fails
            if auto_unlock {
                info!("Hello sign-path failed, trying PIN dialog fallback");
                // Envelope-first (v3 local key cache) with legacy vault.enc
                // fallback, mirroring the SSH-request path so v3 PINs validate in
                // this dialog too (get_pin_encrypted_data only reads legacy slots).
                let envelope_cache = {
                    let guard = local_key_cache_data.read().await;
                    guard
                        .as_ref()
                        .filter(|c| c.local_cache_key.pin_encrypted.is_some())
                        .cloned()
                };
                let validator_parts: Option<(PinValidator, DecryptedCache, _)> =
                    if let Some(cache) = envelope_cache {
                        let dc: DecryptedCache = Arc::new(std::sync::Mutex::new(None));
                        let kh: Arc<std::sync::Mutex<Option<sshwarden_api::crypto::SymmetricKey>>> =
                            Arc::new(std::sync::Mutex::new(None));
                        let dc_inner = dc.clone();
                        let kh_inner = kh.clone();
                        let v: PinValidator = Arc::new(move |pin: &str| -> bool {
                            match decrypt_envelope_local_key_cache_with_pin(&cache, pin) {
                                Ok((keys_json, lck)) => {
                                    *dc_inner.lock().unwrap_or_else(|e| e.into_inner()) =
                                        Some(keys_json);
                                    *kh_inner.lock().unwrap_or_else(|e| e.into_inner()) = Some(lck);
                                    true
                                }
                                Err(_) => false,
                            }
                        });
                        Some((v, dc, Some(kh)))
                    } else if let Some(enc_data) =
                        get_pin_encrypted_data(pin_encrypted_keys, vault_file_data).await
                    {
                        let (v, dc) = make_pin_validator(enc_data);
                        Some((v, dc, None))
                    } else {
                        None
                    };

                if let Some((validator, decrypted_cache, lck_holder)) = validator_parts {
                    // SEC-03: share the daemon-wide PIN brute-force lockout with
                    // `unlock --pin` so dialog attempts can't bypass the cap.
                    let validator = gate_pin_validator(validator, pin_failures);
                    let pin_result =
                        sshwarden_ui::unlock::request_pin_dialog(ui_request_tx, validator).await;

                    if let Some(ref entered_pin) = pin_result {
                        let keys_json = match decrypted_cache
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .take()
                        {
                            Some(j) => j,
                            None => {
                                tracing::warn!(
                                    "PIN validator reported success but cache was empty"
                                );
                                return sshwarden_agent::ControlResponse::err(
                                    "PIN unlock failed: internal cache error",
                                );
                            }
                        };
                        // If unlocked via the v3 envelope, hold the decrypted local
                        // cache key so later operations (sync/re-encrypt) have it.
                        if let Some(kh) = lck_holder {
                            let maybe_lck = kh.lock().unwrap_or_else(|e| e.into_inner()).take();
                            if let Some(lck) = maybe_lck {
                                local_cache_key_state.write().await.set(lck);
                            }
                        }
                        let resp = finish_unlock_with_json(
                            &keys_json,
                            agent,
                            vault_locked,
                            cached_key_tuples,
                            key_names,
                            "Vault unlocked via PIN dialog",
                        )
                        .await;

                        if resp.ok {
                            try_restore_api_session(
                                api_client,
                                config,
                                entered_pin,
                                notification_rx,
                                notification_client,
                                notification_state,
                            )
                            .await;
                            resolve_pending_sync(
                                pending_sync,
                                api_client,
                                cached_key_tuples,
                                public_key_identity_tuples,
                                local_key_cache_data,
                                local_cache_key_state,
                                authorization_memory,
                                key_material_fingerprints,
                                vault_locked,
                                agent,
                                key_names,
                                notification_state,
                            )
                            .await;
                        }

                        return resp;
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
            if !vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
                return sshwarden_agent::ControlResponse::ok("Vault is already unlocked");
            }

            let cache = match local_key_cache_data.read().await.as_ref().cloned() {
                Some(cache) => cache,
                None => return sshwarden_agent::ControlResponse::err("No Local Key Cache found"),
            };

            let resp = finish_native_unlock_response(
                cache,
                agent,
                vault_locked,
                cached_key_tuples,
                key_names,
                local_cache_key_state,
                "Vault unlocked via platform-native local key cache",
            )
            .await;

            if resp.ok {
                resolve_pending_sync(
                    pending_sync,
                    api_client,
                    cached_key_tuples,
                    public_key_identity_tuples,
                    local_key_cache_data,
                    local_cache_key_state,
                    authorization_memory,
                    key_material_fingerprints,
                    vault_locked,
                    agent,
                    key_names,
                    notification_state,
                )
                .await;
            }

            resp
        }
        ControlAction::UnlockHello => {
            if !vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
                return sshwarden_agent::ControlResponse::ok("Vault is already unlocked");
            }

            #[cfg(windows)]
            {
                if let Some(cache) = local_key_cache_data.read().await.as_ref().cloned() {
                    match decrypt_envelope_local_key_cache_with_hello(&cache) {
                        Ok((keys_json, local_cache_key)) => {
                            local_cache_key_state.write().await.set(local_cache_key);
                            let resp = finish_unlock_with_json(
                                &keys_json,
                                agent,
                                vault_locked,
                                cached_key_tuples,
                                key_names,
                                "Vault unlocked via Windows Hello local key cache",
                            )
                            .await;
                            if resp.ok {
                                try_restore_api_session_hello(
                                    api_client,
                                    config,
                                    notification_rx,
                                    notification_client,
                                    notification_state,
                                )
                                .await;
                                resolve_pending_sync(
                                    pending_sync,
                                    api_client,
                                    cached_key_tuples,
                                    public_key_identity_tuples,
                                    local_key_cache_data,
                                    local_cache_key_state,
                                    authorization_memory,
                                    key_material_fingerprints,
                                    vault_locked,
                                    agent,
                                    key_names,
                                    notification_state,
                                )
                                .await;
                            }
                            return resp;
                        }
                        Err(e) => {
                            tracing::warn!("Windows Hello local key cache unlock failed: {}", e)
                        }
                    }
                }

                let vf = vault_file_data.read().await;
                let (challenge_b64, hello_encrypted) = match *vf {
                    Some(ref v) => (v.hello_challenge.clone(), v.hello_encrypted.clone()),
                    None => {
                        return sshwarden_agent::ControlResponse::err(
                            "No vault file found. Set PIN first.",
                        )
                    }
                };
                drop(vf);

                let challenge_b64 =
                    match challenge_b64 {
                        Some(c) => c,
                        None => return sshwarden_agent::ControlResponse::err(
                            "Windows Hello not enrolled. Set PIN with Hello available to enroll.",
                        ),
                    };

                let hello_encrypted =
                    match hello_encrypted {
                        Some(e) => e,
                        None => return sshwarden_agent::ControlResponse::err(
                            "Windows Hello not enrolled. Set PIN with Hello available to enroll.",
                        ),
                    };

                let challenge_bytes =
                    match base64::engine::general_purpose::STANDARD.decode(&challenge_b64) {
                        Ok(b) if b.len() == 16 => {
                            let mut arr = [0u8; 16];
                            arr.copy_from_slice(&b);
                            arr
                        }
                        _ => {
                            return sshwarden_agent::ControlResponse::err(
                                "Invalid hello_challenge in vault file",
                            )
                        }
                    };

                let hello_result = tokio::task::spawn_blocking(move || {
                    try_hello_unlock(&challenge_bytes, &hello_encrypted)
                })
                .await;

                match hello_result {
                    Ok(Ok(keys_json)) => {
                        let resp = finish_unlock_with_json(
                            &keys_json,
                            agent,
                            vault_locked,
                            cached_key_tuples,
                            key_names,
                            "Vault unlocked via Windows Hello",
                        )
                        .await;
                        if resp.ok {
                            try_restore_api_session_hello(
                                api_client,
                                config,
                                notification_rx,
                                notification_client,
                                notification_state,
                            )
                            .await;
                            resolve_pending_sync(
                                pending_sync,
                                api_client,
                                cached_key_tuples,
                                public_key_identity_tuples,
                                local_key_cache_data,
                                local_cache_key_state,
                                authorization_memory,
                                key_material_fingerprints,
                                vault_locked,
                                agent,
                                key_names,
                                notification_state,
                            )
                            .await;
                        }
                        resp
                    }
                    Ok(Err(e)) => sshwarden_agent::ControlResponse::err(&format!(
                        "Hello unlock failed: {}",
                        e
                    )),
                    Err(e) => sshwarden_agent::ControlResponse::err(&format!(
                        "Hello unlock task failed: {}",
                        e
                    )),
                }
            }

            #[cfg(not(windows))]
            sshwarden_agent::ControlResponse::err("Windows Hello is only supported on Windows")
        }
        ControlAction::Status { json } => {
            build_status_response(
                json,
                agent,
                vault_locked,
                pin_encrypted_keys,
                vault_file_data,
                api_client,
                pending_sync,
                notification_state,
                local_key_cache_data,
            )
            .await
        }
        ControlAction::UnlockPin { pin } => {
            let pin = zeroize::Zeroizing::new(pin);
            if !vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
                return sshwarden_agent::ControlResponse::ok("Vault is already unlocked");
            }

            // SEC-03: reject outright while a brute-force lockout is active (no
            // Argon2 work performed) so the control channel can't be hammered.
            if let Some(wait) = pin_lockout_remaining(pin_failures) {
                return sshwarden_agent::ControlResponse::err(&format!(
                    "Too many failed PIN attempts; locked for {}s",
                    wait.as_secs() + 1
                ));
            }

            let resp = 'unlock: {
                if let Some(cache) = local_key_cache_data.read().await.as_ref().cloned() {
                    match decrypt_envelope_local_key_cache_with_pin(&cache, &pin) {
                        Ok((keys_json, local_cache_key)) => {
                            // SEC-04: now that we hold the local cache key and a
                            // verified PIN, transparently upgrade a pre-v3 (fixed
                            // salt) cache to a random per-cache salt.
                            if needs_pin_salt_migration(&cache) {
                                match migrate_pin_salt_to_v3(&cache, &local_cache_key, &pin) {
                                    Ok(migrated) => {
                                        *local_key_cache_data.write().await = Some(migrated);
                                        info!(
                                            "Migrated local key cache PIN slot to v3 (random salt)"
                                        );
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "PIN salt v3 migration failed (non-fatal): {e}"
                                        )
                                    }
                                }
                            }
                            // Multi-device: seed THIS device's own platform unlock
                            // slot from the freshly recovered key, so a later-joining
                            // device isn't stuck PIN-only after the shared cache is
                            // stripped of platform slots. No-op in single-device mode
                            // or when a slot already exists.
                            enroll_device_platform_slots_if_missing(&local_cache_key);
                            local_cache_key_state.write().await.set(local_cache_key);
                            let resp = finish_unlock_with_json(
                                &keys_json,
                                agent,
                                vault_locked,
                                cached_key_tuples,
                                key_names,
                                "Vault unlocked via PIN local key cache",
                            )
                            .await;

                            if resp.ok {
                                try_restore_api_session(
                                    api_client,
                                    config,
                                    &pin,
                                    notification_rx,
                                    notification_client,
                                    notification_state,
                                )
                                .await;
                                resolve_pending_sync(
                                    pending_sync,
                                    api_client,
                                    cached_key_tuples,
                                    public_key_identity_tuples,
                                    local_key_cache_data,
                                    local_cache_key_state,
                                    authorization_memory,
                                    key_material_fingerprints,
                                    vault_locked,
                                    agent,
                                    key_names,
                                    notification_state,
                                )
                                .await;
                            }

                            break 'unlock resp;
                        }
                        Err(e) => {
                            tracing::warn!("PIN unlock from local key cache failed: {}", e);
                        }
                    }
                }

                // Fall back to legacy in-memory/vault.enc cache.
                let encrypted = {
                    let mem = pin_encrypted_keys.read().await.clone();
                    if mem.is_some() {
                        mem
                    } else {
                        vault_file_data
                            .read()
                            .await
                            .as_ref()
                            .map(|v| v.pin_encrypted.clone())
                    }
                };

                match encrypted {
                    Some(enc_data) => match sshwarden_api::crypto::pin_decrypt(&enc_data, &pin) {
                        Ok(keys_json) => {
                            if local_key_cache_data.read().await.is_none() {
                                let keys_for_migration: Result<Vec<(String, String, String)>, _> =
                                    serde_json::from_str(&keys_json);
                                if let Ok(keys_for_migration) = keys_for_migration {
                                    match write_envelope_local_key_cache(
                                    &keys_for_migration,
                                    &config.auth.email,
                                    &config.server.base_url,
                                    &pin,
                                ) {
                                    Ok((cache, local_cache_key)) => {
                                        *local_key_cache_data.write().await = Some(cache);
                                        local_cache_key_state.write().await.set(local_cache_key);
                                        *pin_encrypted_keys.write().await = None;
                                        *vault_file_data.write().await = None;
                                        if let Err(e) = sshwarden_config::vault::VaultFile::delete() {
                                            tracing::warn!("Failed to delete legacy vault file after migration: {}", e);
                                        }
                                        info!("Migrated legacy vault.enc to envelope local key cache");
                                    }
                                    Err(e) => tracing::warn!(
                                        "Failed to migrate legacy vault.enc to envelope local key cache: {}",
                                        e
                                    ),
                                }
                                }
                            }
                            let resp = finish_unlock_with_json(
                                &keys_json,
                                agent,
                                vault_locked,
                                cached_key_tuples,
                                key_names,
                                "Vault unlocked via PIN",
                            )
                            .await;

                            if resp.ok {
                                // Try to restore API session from device session file
                                try_restore_api_session(
                                    api_client,
                                    config,
                                    &pin,
                                    notification_rx,
                                    notification_client,
                                    notification_state,
                                )
                                .await;
                                resolve_pending_sync(
                                    pending_sync,
                                    api_client,
                                    cached_key_tuples,
                                    public_key_identity_tuples,
                                    local_key_cache_data,
                                    local_cache_key_state,
                                    authorization_memory,
                                    key_material_fingerprints,
                                    vault_locked,
                                    agent,
                                    key_names,
                                    notification_state,
                                )
                                .await;
                            }

                            resp
                        }
                        Err(_) => sshwarden_agent::ControlResponse::err("Invalid PIN"),
                    },
                    None => sshwarden_agent::ControlResponse::err(
                        "No PIN configured. Use 'sshwarden set-pin' first.",
                    ),
                }
            };

            // SEC-03: record the outcome — reset on success, otherwise apply an
            // escalating delay and arm a lockout once the threshold is reached.
            let delay = record_pin_attempt(pin_failures, resp.ok);
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            resp
        }
        ControlAction::UnlockPassword { password } => {
            let password = zeroize::Zeroizing::new(password);
            let was_locked = vault_locked.load(std::sync::atomic::Ordering::Relaxed);

            // Get email from vault file or config
            let email = {
                let vf = vault_file_data.read().await;
                vf.as_ref()
                    .map(|v| v.email.clone())
                    .unwrap_or_else(|| config.auth.email.clone())
            };

            if email.is_empty() {
                return sshwarden_agent::ControlResponse::err(
                    "No email configured. Cannot re-login.",
                );
            }

            let mut client = create_client(config.as_ref(), None);
            match client.login_password(&email, &password).await {
                Ok(()) => {}
                Err(e) => {
                    return sshwarden_agent::ControlResponse::err(&format!("Login failed: {}", e))
                }
            }

            match client.sync_ssh_keys().await {
                Ok(keys) => {
                    let key_tuples: Vec<(String, String, String)> = keys
                        .iter()
                        .map(|k| {
                            (
                                (*k.private_key_pem).clone(),
                                k.name.clone(),
                                k.cipher_id.clone(),
                            )
                        })
                        .collect();
                    let count = key_tuples.len();
                    if let Err(e) = write_key_selector_files(&keys) {
                        tracing::warn!("Failed to write key selector files: {}", e);
                    }
                    if let Err(e) = sync_managed_ssh_config_with_bindings(&keys) {
                        tracing::warn!("Failed to sync managed SSH config: {}", e);
                    }
                    reconcile_synced_key_state(
                        &key_tuples,
                        cached_key_tuples,
                        public_key_identity_tuples,
                        local_key_cache_data,
                        local_cache_key_state,
                        authorization_memory,
                        key_material_fingerprints,
                        notification_state,
                    )
                    .await;

                    // Update key_names
                    {
                        let mut names = key_names.write().await;
                        names.clear();
                        for k in &keys {
                            names.insert(k.cipher_id.clone(), k.name.clone());
                        }
                    }

                    if let Err(e) = agent.set_keys(key_tuples) {
                        return sshwarden_agent::ControlResponse::err(&format!(
                            "Login succeeded but failed to load keys: {}",
                            e
                        ));
                    }
                    vault_locked.store(false, std::sync::atomic::Ordering::Relaxed);

                    // Save device session + connect notifications
                    save_device_session(&client, config, None).await;

                    if let Some(token) = client.access_token() {
                        connect_notification_client(
                            config,
                            Some(&client),
                            token,
                            notification_rx,
                            notification_client,
                            notification_state,
                        )
                        .await;
                    }

                    *api_client.write().await = Some(client);
                    resolve_pending_sync(
                        pending_sync,
                        api_client,
                        cached_key_tuples,
                        public_key_identity_tuples,
                        local_key_cache_data,
                        local_cache_key_state,
                        authorization_memory,
                        key_material_fingerprints,
                        vault_locked,
                        agent,
                        key_names,
                        notification_state,
                    )
                    .await;

                    let message = if was_locked {
                        format!("Vault unlocked, {} SSH keys loaded", count)
                    } else {
                        format!("Bitwarden session refreshed, {} SSH keys loaded", count)
                    };
                    info!("{}", message);
                    sshwarden_agent::ControlResponse::ok(&message)
                }
                Err(e) => sshwarden_agent::ControlResponse::err(&format!(
                    "Sync failed after login: {}",
                    e
                )),
            }
        }
        ControlAction::Sync => {
            // do_sync cannot load keys into the agent while the vault is locked
            // (no private material is held); it only refreshes the on-disk cache.
            // Report that honestly and mark a pending sync so the next unlock
            // applies the keys, instead of claiming the running agent was updated.
            let was_locked = vault_locked.load(std::sync::atomic::Ordering::Relaxed);
            // Only multi-device mode needs the shared cache reconciled before a
            // manual sync. Gating this avoids a NEW PIN prompt (and a hard failure
            // on cancel) for legacy single-device users whose unlock path did not
            // keep the Local Cache Key in memory.
            if !was_locked && multi_device_mode() {
                // If this unlocked session was restored without keeping the Local
                // Cache Key in memory, a plain sync would update the live agent but
                // leave `sshwarden keys` showing the old cache header. Prompt for
                // PIN first so the synced key set can be persisted atomically.
                if let Err(e) = ensure_local_cache_key_for_manual_sync(
                    local_key_cache_data,
                    local_cache_key_state,
                    ui_request_tx,
                    pin_failures,
                )
                .await
                {
                    return sshwarden_agent::ControlResponse::err(&e);
                }
            }
            match do_sync(
                api_client,
                cached_key_tuples,
                public_key_identity_tuples,
                local_key_cache_data,
                local_cache_key_state,
                authorization_memory,
                key_material_fingerprints,
                vault_locked,
                agent,
                key_names,
                notification_state,
            )
            .await
            {
                Ok(count) => {
                    if was_locked {
                        pending_sync.store(true, std::sync::atomic::Ordering::Relaxed);
                        sshwarden_agent::ControlResponse::ok(&format!(
                            "Synced {count} SSH keys to cache; they will load into the agent on next unlock"
                        ))
                    } else {
                        sshwarden_agent::ControlResponse::ok(&format!("Synced {count} SSH keys"))
                    }
                }
                Err(e) => sshwarden_agent::ControlResponse::err(&e),
            }
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
                if let Err(e) = sshwarden_config::vault::VaultFile::delete() {
                    tracing::warn!("Failed to delete legacy vault file: {}", e);
                    failures.push(format!("legacy vault file ({e})"));
                }
            }

            let native_slot = local_key_cache_data
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

            local_cache_key_state.write().await.clear();
            authorization_memory.write().await.clear();
            cached_key_tuples.write().await.clear();
            *api_client.write().await = None;
            pending_sync.store(false, std::sync::atomic::Ordering::Relaxed);
            {
                let mut state = notification_state.write().await;
                state.stale_cache = false;
                state.stale_cache_error = None;
            }
            if let Some(client) = notification_client.take() {
                client.stop();
            }
            *notification_rx = None;
            vault_locked.store(true, std::sync::atomic::Ordering::Relaxed);

            if remove_shared_cache {
                *local_key_cache_data.write().await = None;
                *vault_file_data.write().await = None;
                *pin_encrypted_keys.write().await = None;
                public_key_identity_tuples.write().await.clear();
                key_names.write().await.clear();
                let _ = agent.clear_keys();
            } else {
                // Multi-device plain `forget` is device-only: remove this
                // device's API session/native unlock material, but keep the
                // shared key cache listable and PIN-unlockable for all devices.
                let cache = sshwarden_config::cache::LocalKeyCacheFile::load()
                    .ok()
                    .flatten();
                *local_key_cache_data.write().await = cache.clone();
                *vault_file_data.write().await =
                    sshwarden_config::vault::VaultFile::load().ok().flatten();
                *pin_encrypted_keys.write().await = vault_file_data
                    .read()
                    .await
                    .as_ref()
                    .map(|v| v.pin_encrypted.clone());
                public_key_identity_tuples.write().await.clear();
                // Clear unconditionally (mirroring the shared-cache branch): if the
                // shared cache fails to reload below, stale labels from the
                // just-forgotten session must not linger in memory.
                key_names.write().await.clear();
                let _ = agent.clear_keys();
                if let Some(cache) = cache {
                    let identities = key_tuples_from_cache_header(&cache);
                    if let Err(e) = agent.set_public_identities(identities.clone()) {
                        tracing::warn!(
                            "Failed to reload public identities after device forget: {}",
                            e
                        );
                    }
                    public_key_identity_tuples
                        .write()
                        .await
                        .set(identities.clone());
                    let mut names = key_names.write().await;
                    for (_, name, vault_item_id) in identities {
                        names.insert(vault_item_id, name);
                    }
                }
            }

            if failures.is_empty() {
                let message = if remove_shared_cache {
                    "Forgot shared local key cache, legacy vault file, and device session material"
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
            let pin = zeroize::Zeroizing::new(pin);
            if pin.len() < 4 {
                return sshwarden_agent::ControlResponse::err("PIN must be at least 4 characters");
            }

            let keys = cached_key_tuples.read().await.clone_inner();
            if keys.is_empty() {
                return sshwarden_agent::ControlResponse::err("No keys loaded. Login first.");
            }

            let email = config.auth.email.clone();
            let server_url = config.server.base_url.clone();

            let cache_write_result = match local_cache_key_state.read().await.clone_key() {
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
                    *local_key_cache_data.write().await = Some(cache);
                    local_cache_key_state.write().await.set(local_cache_key);
                    *pin_encrypted_keys.write().await = None;
                    *vault_file_data.write().await = None;
                    if let Err(e) = sshwarden_config::vault::VaultFile::delete() {
                        tracing::warn!(
                            "Failed to delete legacy vault file after envelope cache write: {}",
                            e
                        );
                    }
                    info!("Envelope local key cache saved");

                    // Save device session with PIN-encrypted refresh token
                    {
                        let client_guard = api_client.read().await;
                        if let Some(ref client) = *client_guard {
                            save_device_session(client, config, Some(&pin)).await;
                        }
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
        ControlAction::BindHostsDialog => {
            match dispatch_standalone_bind_hosts_dialog(ui_request_tx).await {
                Ok(saved) => {
                    if saved {
                        sshwarden_agent::ControlResponse::ok("Bindings updated")
                    } else {
                        sshwarden_agent::ControlResponse::ok("Dialog cancelled")
                    }
                }
                Err(e) => sshwarden_agent::ControlResponse::err(&format!(
                    "Failed to open bind-hosts dialog: {}",
                    e
                )),
            }
        }
    }
}
