//! Foreground agent loop (`run_foreground`): the daemon's main event loop
//! wiring the SSH agent, control channel, notification hub, and UI requests.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 6a).

use std::sync::Arc;

use anyhow::Context;
use tokio::sync::RwLock;
use tracing::info;

use crate::cache::{
    key_material_fingerprints_from_tuples, key_tuples_from_cache_header,
    persist_device_unlock_slots_from_cache,
};
use crate::commands::login::prompt_email;
use crate::control::{handle_control_command, lock_vault, PinFailureHandle, PinFailureState};
use crate::notifications::connect_notification_client;
use crate::runtime::{
    AuthorizationMemorySet, CachedKeyTuples, KeyMaterialFingerprints, LocalCacheKeyHandle,
    LocalCacheKeyState, NotificationConnectionState, NotificationRuntimeState, RuntimeEvent,
    SecureKeyCache, UIRequestTx,
};
use crate::sshconfig::{sync_managed_ssh_config_with_bindings, write_key_selector_files};
use crate::sync::{do_sync, resolve_pending_sync};
use crate::ui::{fetch_vault_keys_with_client, handle_ui_request, prompt_setup_pin};
#[cfg(windows)]
use crate::unlock::try_restore_api_session_hello;
use crate::unlock::{save_device_session, try_restore_api_session};

pub(crate) async fn run_foreground(
    mut config: sshwarden_config::Config,
    ui_request_tx: UIRequestTx,
) -> anyhow::Result<()> {
    info!("Starting SSHWarden SSH Agent...");
    info!("Server: {}", config.server.base_url);

    // Check for persisted cache/vault files BEFORE prompting for master password.
    let local_key_cache = sshwarden_config::cache::LocalKeyCacheFile::load()
        .unwrap_or_else(|e| {
            tracing::warn!("Failed to load local key cache: {}", e);
            None
        })
        .inspect(|cache| {
            // Multi-device migration aid: if an older shared cache still carries
            // platform unlock slots, copy them into this device's private
            // unlock-slots file. Future cache writes strip platform slots from
            // the shared file so devices stop overwriting each other.
            if let Err(e) = persist_device_unlock_slots_from_cache(cache) {
                tracing::warn!("Failed to persist device unlock slots: {}", e);
            }
        });
    let has_local_key_cache = local_key_cache.is_some();
    let has_remembered_device = has_local_key_cache;

    // Login and fetch keys BEFORE starting the agent server (so password prompt works cleanly)
    // Skip if we have a remembered device — user will unlock with PIN/Hello/password later.
    let mut api_client: Option<sshwarden_api::BitwardenClient> = None;
    let mut first_login = false;
    let vault_keys = if has_remembered_device {
        if has_local_key_cache {
            info!("Local key cache found. Starting locked with listable key identities.");
        } else {
            info!("Legacy vault file found. Use Hello/PIN/password to unlock.");
        }
        None
    } else {
        // No vault file — need to login with master password
        // If email is not configured, ask interactively and save to config
        if config.auth.email.is_empty() {
            let email = prompt_email("Email: ")?;
            if email.is_empty() {
                info!("No email provided. Agent will start with no keys.");
                None
            } else {
                config.auth.email = email;
                if let Err(e) = config.save() {
                    tracing::warn!("Failed to save config: {}", e);
                } else {
                    info!("Email saved to config.toml");
                }
                first_login = true;
                match fetch_vault_keys_with_client(&config).await {
                    Ok((keys, client)) => {
                        info!("Fetched {} SSH key(s) from vault", keys.len());
                        api_client = Some(client);
                        Some(keys)
                    }
                    Err(e) => {
                        tracing::warn!("Failed to fetch vault keys: {}.", e);
                        None
                    }
                }
            }
        } else {
            first_login = true;
            match fetch_vault_keys_with_client(&config).await {
                Ok((keys, client)) => {
                    info!("Fetched {} SSH key(s) from vault", keys.len());
                    api_client = Some(client);
                    Some(keys)
                }
                Err(e) => {
                    tracing::warn!("Failed to fetch vault keys: {}.", e);
                    None
                }
            }
        }
    };

    // Create channels for UI communication
    let (request_tx, mut request_rx) =
        tokio::sync::mpsc::channel::<sshwarden_agent::SshAgentUIRequest>(32);
    // CONC-4 mitigation: a generous capacity makes a broadcast `Lagged` (which
    // would otherwise be treated as a denial in confirm()/can_list()) effectively
    // impossible under realistic concurrency. The fully race-free fix (per-request
    // oneshot registry) needs runtime verification of the signing path and is
    // tracked as a follow-up.
    let (response_tx, _response_rx) = tokio::sync::broadcast::channel::<(u32, bool)>(256);
    let response_tx = Arc::new(response_tx);
    let (runtime_event_tx, mut runtime_event_rx) = tokio::sync::mpsc::channel::<RuntimeEvent>(32);

    // Start the SSH agent server
    let agent_endpoint = config.socket.path.as_deref().map(std::path::PathBuf::from);
    let mut agent = sshwarden_agent::SshWardenAgent::start_server_with_endpoint(
        request_tx,
        response_tx.clone(),
        agent_endpoint,
    )
    .context("Failed to start SSH agent server")?;

    // RT-01: watch for a fatal agent-transport failure (e.g. the OpenSSH pipe
    // could not be claimed) so the daemon shuts down instead of running as a
    // zombie that still answers status/unlock while serving no SSH client.
    let mut agent_fatal_rx = agent.fatal_rx();

    // Build a map of cipher_id -> key_name for UI display
    let key_names: Arc<std::collections::HashMap<String, String>> = Arc::new(
        vault_keys
            .as_ref()
            .map(|keys| {
                keys.iter()
                    .map(|k| (k.cipher_id.clone(), k.name.clone()))
                    .collect()
            })
            .unwrap_or_default(),
    );

    // Cache key tuples for re-loading after unlock, track public key identities,
    // and track vault lock state.
    let cached_key_tuples: CachedKeyTuples = Arc::new(RwLock::new(SecureKeyCache::new()));
    let public_key_identity_tuples: CachedKeyTuples = Arc::new(RwLock::new(SecureKeyCache::new()));
    let vault_locked = Arc::new(std::sync::atomic::AtomicBool::new(has_remembered_device));
    let api_client: Arc<RwLock<Option<sshwarden_api::BitwardenClient>>> =
        Arc::new(RwLock::new(api_client));
    let local_key_cache_data: Arc<RwLock<Option<sshwarden_config::cache::LocalKeyCacheFile>>> =
        Arc::new(RwLock::new(local_key_cache));
    let local_cache_key_state: LocalCacheKeyHandle =
        Arc::new(RwLock::new(LocalCacheKeyState::default()));
    let authorization_memory: AuthorizationMemorySet =
        Arc::new(RwLock::new(std::collections::HashSet::new()));
    let key_material_fingerprints: KeyMaterialFingerprints =
        Arc::new(RwLock::new(std::collections::HashMap::new()));
    let pending_sync = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let pin_failures: PinFailureHandle =
        Arc::new(std::sync::Mutex::new(PinFailureState::default()));
    // CONC-6: count in-flight UI requests (sign/unlock prompts) so the inactivity
    // auto-lock does not fire while a prompt is open (last_activity is only
    // refreshed at request arrival, not while the user is deciding).
    let in_flight_prompts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let key_names = Arc::new(RwLock::new((*key_names).clone()));

    // Load vault keys into agent
    if let Some(keys) = vault_keys {
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
        if count > 0 {
            if let Err(e) = write_key_selector_files(&keys) {
                tracing::warn!("Failed to write key selector files: {}", e);
            }
            if let Err(e) = sync_managed_ssh_config_with_bindings(&keys) {
                tracing::warn!("Failed to sync managed SSH config: {}", e);
            }
            public_key_identity_tuples
                .write()
                .await
                .set(key_tuples.clone());
            cached_key_tuples.write().await.set(key_tuples.clone());
            *key_material_fingerprints.write().await =
                key_material_fingerprints_from_tuples(&key_tuples);
            agent.set_keys(key_tuples)?;
            info!("Loaded {} SSH key(s) into agent", count);

            // After first login with keys loaded, offer to set up PIN for persistence
            if first_login {
                prompt_setup_pin(
                    &cached_key_tuples,
                    &local_key_cache_data,
                    &local_cache_key_state,
                    &config,
                    &api_client,
                )
                .await;
            }
        }
    } else if let Some(cache) = local_key_cache_data.read().await.as_ref() {
        let identities = key_tuples_from_cache_header(cache);
        let count = identities.len();
        if count > 0 {
            public_key_identity_tuples
                .write()
                .await
                .set(identities.clone());
            {
                let mut names = key_names.write().await;
                names.clear();
                for (_, name, vault_item_id) in &identities {
                    names.insert(vault_item_id.clone(), name.clone());
                }
            }
            if let Err(e) = agent.set_public_identities(identities) {
                tracing::warn!(
                    "Failed to load public key identities from local cache: {}",
                    e
                );
            } else {
                info!(
                    "Loaded {} public key identity/identities from local key cache",
                    count
                );
            }
        } else {
            info!("Local key cache has no key identities.");
        }
    } else {
        info!("Agent running with no keys.");
    }

    // Start the IPC control server
    #[allow(unused_variables)]
    let (control_tx, mut control_rx) =
        tokio::sync::mpsc::channel::<sshwarden_agent::ControlRequest>(16);
    let cancel_token = tokio_util::sync::CancellationToken::new();

    {
        let cancel_clone = cancel_token.clone();
        tokio::spawn(async move {
            sshwarden_agent::control::start_control_server(control_tx, cancel_clone).await;
        });
    }

    info!("SSH Agent is running. Press Ctrl+C to stop.");

    // Main loop configuration
    let prompt_behavior = config.agent.prompt_behavior;
    let auto_unlock = config.unlock.auto_unlock_on_request;
    let lock_timeout = config.agent.lock_timeout;
    let config = Arc::new(config);
    let mut last_activity = tokio::time::Instant::now();
    let mut lock_check_interval = tokio::time::interval(std::time::Duration::from_secs(60));
    // Poll often enough that an access token is renewed shortly after it starts
    // expiring. The notification hub rejects a stale token with HTTP 401, so a
    // lazy tick costs a reconnect storm plus a fallback-sync window.
    let mut token_refresh_interval = tokio::time::interval(std::time::Duration::from_secs(5 * 60));
    // Skip the first immediate tick for token refresh
    token_refresh_interval.tick().await;

    // Notification hub state
    let mut notification_rx: Option<tokio::sync::mpsc::Receiver<sshwarden_api::SyncEvent>> = None;
    let mut _notification_client: Option<sshwarden_api::NotificationClient> = None;
    let notification_state = Arc::new(RwLock::new(NotificationRuntimeState::default()));

    // Connect to notification hub if we already have an API session (first login)
    {
        let client_guard = api_client.read().await;
        if let Some(ref client) = *client_guard {
            if let Some(token) = client.access_token() {
                connect_notification_client(
                    &config,
                    Some(client),
                    token,
                    &mut notification_rx,
                    &mut _notification_client,
                    &notification_state,
                )
                .await;

                // Save device session for this host
                save_device_session(client, &config, None).await;
            }
        }
    }

    loop {
        tokio::select! {
            // Control commands from IPC
            Some(ctrl_req) = control_rx.recv() => {
                last_activity = tokio::time::Instant::now();
                // `stop` shuts the daemon down cleanly: ack, then break the loop
                // so the cancel-token cleanup below runs (same path as Ctrl-C).
                if matches!(ctrl_req.action, sshwarden_agent::ControlAction::Stop) {
                    let _ = ctrl_req
                        .reply
                        .send(sshwarden_agent::ControlResponse::ok("Stopping agent"));
                    info!("Received stop command, shutting down...");
                    break;
                }
                // Watchdog: control actions run serially here, so an action that
                // never returns (a lock wait, a network call without a timeout)
                // would otherwise wedge every later command — including `stop` —
                // until the process is killed. Bound it and report the timeout
                // instead; dropping the future releases whatever it held.
                let budget = control_action_timeout(&ctrl_req.action);
                let label = control_action_label(&ctrl_req.action);
                let response = run_control_action(
                    label,
                    budget,
                    handle_control_command(
                        ctrl_req.action,
                        &mut agent,
                        &vault_locked,
                        &cached_key_tuples,
                        &public_key_identity_tuples,
                        &api_client,
                        &local_key_cache_data,
                        &local_cache_key_state,
                        &key_material_fingerprints,
                        &key_names,
                        &config,
                        auto_unlock,
                        &ui_request_tx,
                        &mut notification_rx,
                        &mut _notification_client,
                        &pending_sync,
                        &notification_state,
                        &authorization_memory,
                        &pin_failures,
                    ),
                )
                .await;
                let _ = ctrl_req.reply.send(response);
            }
            // UI requests from SSH agent
            Some(request) = request_rx.recv() => {
                last_activity = tokio::time::Instant::now();

                // CONC-6: mark a request in flight for the duration of the
                // handler (which may open a long sign/unlock prompt).
                in_flight_prompts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let in_flight_done = in_flight_prompts.clone();

                // Spawn a task to handle each request so we don't block the main loop
                let response_tx_clone = (*response_tx).clone();
                let vault_locked_clone = vault_locked.clone();
                let cached_keys_clone = cached_key_tuples.clone();
                let agent_clone = agent.clone();
                let key_names_clone = key_names.clone();
                let local_key_cache_clone = local_key_cache_data.clone();
                let local_cache_key_state_clone = local_cache_key_state.clone();
                let runtime_event_tx_clone = runtime_event_tx.clone();
                let authorization_memory_clone = authorization_memory.clone();
                let pin_failures_clone = pin_failures.clone();

                let ui_tx_clone = ui_request_tx.clone();

                tokio::spawn(async move {
                    handle_ui_request(
                        request,
                        response_tx_clone,
                        vault_locked_clone,
                        cached_keys_clone,
                        agent_clone,
                        key_names_clone,
                        local_key_cache_clone,
                        local_cache_key_state_clone,
                        prompt_behavior,
                        auto_unlock,
                        ui_tx_clone,
                        runtime_event_tx_clone,
                        authorization_memory_clone,
                        pin_failures_clone,
                    ).await;
                    in_flight_done.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                });
            }
            // Runtime events from spawned SSH request handlers
            Some(event) = runtime_event_rx.recv() => {
                match event {
                    #[cfg(windows)]
                    RuntimeEvent::AutoUnlockedWindowsHello => {
                        try_restore_api_session_hello(
                            &api_client,
                            &config,
                            &mut notification_rx,
                            &mut _notification_client,
                            &notification_state,
                        )
                        .await;
                        resolve_pending_sync(
                            &pending_sync,
                            &api_client,
                            &cached_key_tuples,
                            &public_key_identity_tuples,
                            &local_key_cache_data,
                            &local_cache_key_state,
                            &authorization_memory,
                            &key_material_fingerprints,
                            &vault_locked,
                            &mut agent,
                            &key_names,
                            &notification_state,
                        )
                        .await;
                    }
                    RuntimeEvent::AutoUnlockedPin { pin } => {
                        try_restore_api_session(
                            &api_client,
                            &config,
                            &pin,
                            &mut notification_rx,
                            &mut _notification_client,
                            &notification_state,
                        )
                        .await;
                        resolve_pending_sync(
                            &pending_sync,
                            &api_client,
                            &cached_key_tuples,
                            &public_key_identity_tuples,
                            &local_key_cache_data,
                            &local_cache_key_state,
                            &authorization_memory,
                            &key_material_fingerprints,
                            &vault_locked,
                            &mut agent,
                            &key_names,
                            &notification_state,
                        )
                        .await;
                    }
                    RuntimeEvent::AutoUnlockedNative => {
                        // Native (Keychain / Secret Service / DPAPI) unlock cannot
                        // currently restore an API session — SessionFile has no
                        // native_encrypted_token slot — so we only resolve any
                        // sync that was deferred while the vault was locked.
                        resolve_pending_sync(
                            &pending_sync,
                            &api_client,
                            &cached_key_tuples,
                            &public_key_identity_tuples,
                            &local_key_cache_data,
                            &local_cache_key_state,
                            &authorization_memory,
                            &key_material_fingerprints,
                            &vault_locked,
                            &mut agent,
                            &key_names,
                            &notification_state,
                        )
                        .await;
                    }
                }
            }
            // Notification hub events
            Some(event) = async {
                match notification_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match event {
                    sshwarden_api::SyncEvent::ConnectionStatus(status) => {
                        notification_state.write().await.apply_status(&status);
                    }
                    sshwarden_api::SyncEvent::CipherChanged => {
                        if vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
                            pending_sync.store(true, std::sync::atomic::Ordering::Relaxed);
                            // Count it as delivered: "no events for a while" must
                            // mean "no events", not "no processed events".
                            notification_state.write().await.record_event();
                            info!("Notification: cipher changed while locked; sync pending until unlock");
                        } else {
                            info!("Notification: cipher changed, syncing...");
                            match do_sync(&api_client, &cached_key_tuples, &public_key_identity_tuples, &local_key_cache_data, &local_cache_key_state, &authorization_memory, &key_material_fingerprints, &vault_locked, &mut agent, &key_names, &notification_state).await {
                                Ok(count) => {
                                    notification_state.write().await.last_event_at = Some(std::time::Instant::now());
                                    info!("Auto-synced: {} SSH keys", count)
                                },
                                Err(e) => {
                                    pending_sync.store(true, std::sync::atomic::Ordering::Relaxed);
                                    tracing::warn!("Auto-sync failed: {}; sync remains pending", e);
                                }
                            }
                        }
                    }
                    sshwarden_api::SyncEvent::LogOut => {
                        notification_state.write().await.record_event();
                        info!("Notification: remote logout");
                        let _ = lock_vault(&mut agent, &vault_locked, &cached_key_tuples, Some(&local_cache_key_state), Some(&authorization_memory)).await;
                    }
                    sshwarden_api::SyncEvent::FallbackSyncDue => {
                        if vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
                            pending_sync.store(true, std::sync::atomic::Ordering::Relaxed);
                            info!("Notification degraded while locked; sync pending until unlock");
                        } else {
                            info!("Notification degraded or reconnected, running fallback sync...");
                            match do_sync(&api_client, &cached_key_tuples, &public_key_identity_tuples, &local_key_cache_data, &local_cache_key_state, &authorization_memory, &key_material_fingerprints, &vault_locked, &mut agent, &key_names, &notification_state).await {
                                Ok(count) => {
                                    notification_state.write().await.record_fallback_sync();
                                    info!("Fallback-synced: {} SSH keys", count)
                                },
                                Err(e) => {
                                    pending_sync.store(true, std::sync::atomic::Ordering::Relaxed);
                                    tracing::warn!("Fallback sync failed: {}; sync remains pending", e);
                                }
                            }
                        }
                    }
                }
            }
            // Token auto-refresh
            _ = token_refresh_interval.tick() => {
                let mut client_guard = api_client.write().await;
                if let Some(ref mut client) = *client_guard {
                    if client.is_token_expiring_soon() {
                        match client.refresh_access_token().await {
                            Ok(()) => {
                                info!("Access token refreshed");
                                // Update session file with new refresh token
                                save_device_session(client, &config, None).await;
                                if let Some(token) = client.access_token().map(str::to_string) {
                                    connect_notification_client(
                                        &config,
                                        Some(&*client),
                                        &token,
                                        &mut notification_rx,
                                        &mut _notification_client,
                                        &notification_state,
                                    ).await;
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Token refresh failed: {}", e);
                            }
                        }
                    }
                }
            }
            // Auto-lock check
            _ = lock_check_interval.tick() => {
                if lock_timeout > 0
                    && !vault_locked.load(std::sync::atomic::Ordering::Relaxed)
                    && in_flight_prompts.load(std::sync::atomic::Ordering::Relaxed) == 0
                    && last_activity.elapsed().as_secs() >= lock_timeout
                {
                    info!("Auto-locking vault due to inactivity ({} seconds)", lock_timeout);
                    let _ = lock_vault(&mut agent, &vault_locked, &cached_key_tuples, Some(&local_cache_key_state), Some(&authorization_memory)).await;
                }
            }
            // SSH agent transport failed (e.g. could not claim the OpenSSH pipe).
            // Shut down rather than run as a zombie that answers status/unlock
            // while serving no SSH client (RT-01).
            changed = agent_fatal_rx.changed() => {
                if changed.is_err() {
                    tracing::error!("SSH agent signal channel closed; shutting down");
                    break;
                }
                let reason = agent_fatal_rx.borrow().clone();
                if let Some(reason) = reason {
                    tracing::error!(%reason, "SSH agent transport failed; shutting down daemon");
                    break;
                }
            }
            // Shutdown signal
            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl+C, shutting down...");
                break;
            }
        }
    }

    cancel_token.cancel();
    notification_state.write().await.state = NotificationConnectionState::Stopped;
    agent.stop();
    info!("SSHWarden stopped.");
    Ok(())
}

/// Time budget for a control action that does not wait on the user.
///
/// Generous compared to a healthy run (the slowest normal action is `login`,
/// whose KDF plus sync takes seconds) so it only fires on a genuine stall.
const CONTROL_ACTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Time budget for a control action that legitimately waits for the user.
///
/// Windows Hello, macOS Keychain, and Linux Secret Service user-presence
/// prompts, and the host-binding dialog, stay open until the user answers —
/// bounded anyway so a walked-away prompt cannot wedge the control channel
/// forever.
const CONTROL_ACTION_USER_PROMPT_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(15 * 60);

/// Run one control action under its watchdog budget, turning a stall into an
/// error reply instead of a wedged control channel.
///
/// Dropping the timed-out future releases any lock guard it held, which is what
/// lets the loop serve the next command (`stop`, `status`, ...) again.
async fn run_control_action<F>(
    label: &'static str,
    budget: std::time::Duration,
    action: F,
) -> sshwarden_agent::ControlResponse
where
    F: std::future::Future<Output = sshwarden_agent::ControlResponse>,
{
    match tokio::time::timeout(budget, action).await {
        Ok(response) => response,
        Err(_) => {
            tracing::warn!(
                action = label,
                budget_secs = budget.as_secs(),
                "Control action exceeded its time budget and was aborted so the control channel stays responsive"
            );
            sshwarden_agent::ControlResponse::err(&format!(
                "Control action '{label}' timed out after {}s and was aborted; the agent is still running. Check the daemon log for what it was doing.",
                budget.as_secs()
            ))
        }
    }
}

/// Per-action watchdog budget, see [`CONTROL_ACTION_TIMEOUT`].
fn control_action_timeout(action: &sshwarden_agent::ControlAction) -> std::time::Duration {
    use sshwarden_agent::ControlAction;
    match action {
        // These prompt for user presence or wait on a dialog.
        ControlAction::Unlock
        | ControlAction::UnlockHello
        | ControlAction::UnlockNative
        | ControlAction::BindHostsDialog => CONTROL_ACTION_USER_PROMPT_TIMEOUT,
        _ => CONTROL_ACTION_TIMEOUT,
    }
}

/// Stable, secret-free label for logging and error messages.
///
/// Never derive this from `Debug`: the PIN/password variants hold credentials.
fn control_action_label(action: &sshwarden_agent::ControlAction) -> &'static str {
    use sshwarden_agent::ControlAction;
    match action {
        ControlAction::Lock => "lock",
        ControlAction::Unlock => "unlock",
        ControlAction::UnlockPin { .. } => "unlock-pin",
        ControlAction::UnlockHello => "unlock-hello",
        ControlAction::UnlockNative => "unlock-native",
        ControlAction::UnlockPassword { .. } => "unlock-password",
        ControlAction::Status { .. } => "status",
        ControlAction::Sync => "sync",
        ControlAction::SetPin { .. } => "set-pin",
        ControlAction::Forget { .. } => "forget",
        ControlAction::Stop => "stop",
        ControlAction::BindHostsDialog => "bind-hosts-dialog",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use sshwarden_agent::ControlAction;

    #[test]
    fn user_prompt_actions_get_the_long_budget() {
        for action in [
            ControlAction::Unlock,
            ControlAction::UnlockHello,
            ControlAction::UnlockNative,
            ControlAction::BindHostsDialog,
        ] {
            assert_eq!(
                control_action_timeout(&action),
                CONTROL_ACTION_USER_PROMPT_TIMEOUT,
                "{} should use the user-prompt budget",
                control_action_label(&action)
            );
        }

        for action in [
            ControlAction::Status { json: true },
            ControlAction::Sync,
            ControlAction::Lock,
            ControlAction::Forget { shared: false },
            ControlAction::Stop,
        ] {
            assert_eq!(
                control_action_timeout(&action),
                CONTROL_ACTION_TIMEOUT,
                "{} should use the short budget",
                control_action_label(&action)
            );
        }
    }

    #[test]
    fn labels_are_stable_and_secret_free() {
        // `ControlAction` deliberately does not implement `Debug` (the PIN and
        // password variants hold credentials), so logs and error messages must go
        // through this helper; pin the strings so a rename cannot silently change
        // user-visible diagnostics.
        let pin = "1234".to_string();
        let password = "hunter2".to_string();

        assert_eq!(
            control_action_label(&ControlAction::UnlockPin { pin: pin.clone() }),
            "unlock-pin"
        );
        assert_eq!(
            control_action_label(&ControlAction::SetPin { pin }),
            "set-pin"
        );
        assert_eq!(
            control_action_label(&ControlAction::UnlockPassword { password }),
            "unlock-password"
        );
        assert_eq!(
            control_action_label(&ControlAction::Status { json: false }),
            "status"
        );
        assert_eq!(
            control_action_label(&ControlAction::Forget { shared: true }),
            "forget"
        );
    }

    #[tokio::test]
    async fn stuck_control_action_is_aborted_and_reported() {
        let stuck = run_control_action(
            "sync",
            std::time::Duration::from_millis(50),
            std::future::pending(),
        )
        .await;

        assert!(!stuck.ok, "a stalled action must not report success");
        let error = stuck.error.unwrap_or_default();
        assert!(
            error.contains("timed out"),
            "timeout should be reported to the caller, got: {error}"
        );
    }

    #[tokio::test]
    async fn fast_control_action_passes_through_unchanged() {
        let response = run_control_action("status", std::time::Duration::from_secs(30), async {
            sshwarden_agent::ControlResponse::ok("all good")
        })
        .await;

        assert!(response.ok);
        assert_eq!(response.message.as_deref(), Some("all good"));
    }
}
