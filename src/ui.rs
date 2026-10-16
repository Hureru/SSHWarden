//! UI request handling: key-name resolution, decrypted-key state application,
//! authorization / unlock prompts, and the agent UI request dispatcher.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 6b).

use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::info;

use crate::bindings_cli::prompt_authorization_with_bind_flow;
#[cfg(windows)]
use crate::cache::{current_hello_unlock_info, decrypt_envelope_local_key_cache_with_hello};
use crate::cache::{
    current_native_unlock_slot, decrypt_envelope_local_key_cache_with_native,
    decrypt_envelope_local_key_cache_with_pin, enroll_device_platform_slots_if_missing,
    write_envelope_local_key_cache,
};
use crate::commands::login::{create_client, prompt_password};
use crate::control::PinFailureHandle;
use crate::runtime::{
    AuthorizationMemorySet, CachedKeyTuples, LocalCacheKeyHandle, RuntimeEvent, UIRequestTx,
};
use crate::unlock::{gate_pin_validator, save_device_session, DecryptedCache, PinValidator};
/// Resolve the human-friendly key name for an SSH UI request, given the
/// freshly-decrypted key list. Falls back to "Unknown key" when no `cipher_id`
/// match is found.
pub(crate) fn key_name_for_request(
    request: &sshwarden_agent::SshAgentUIRequest,
    keys: &[(String, String, String)],
) -> String {
    request
        .cipher_id
        .as_ref()
        .and_then(|cid| keys.iter().find(|(_, _, id)| id == cid))
        .map(|(_, name, _)| name.clone())
        .unwrap_or_else(|| "Unknown key".to_string())
}

/// Apply freshly-decrypted keys to the shared state (key_names map + cached tuples).
/// Does **not** touch the in-memory agent — that is the caller's responsibility.
pub(crate) async fn apply_decrypted_keys_state(
    key_names: &Arc<RwLock<std::collections::HashMap<String, String>>>,
    cached_key_tuples: &CachedKeyTuples,
    keys: &[(String, String, String)],
) {
    {
        let mut names = key_names.write().await;
        names.clear();
        for (_, name, cipher_id) in keys {
            names.insert(cipher_id.clone(), name.clone());
        }
    }
    cached_key_tuples.write().await.set(keys.to_vec());
}

/// Run the authorization prompt if required by the request and configured
/// prompt behaviour. Agent forwarding always forces a prompt regardless of
/// the global setting.
pub(crate) async fn run_authorization_prompt(
    request: &sshwarden_agent::SshAgentUIRequest,
    key_name: String,
    prompt_behavior: sshwarden_config::PromptBehavior,
    ui_request_tx: &UIRequestTx,
) -> bool {
    let needs_prompt = request.is_forwarding
        || match prompt_behavior {
            sshwarden_config::PromptBehavior::Always => true,
            sshwarden_config::PromptBehavior::Never => false,
            sshwarden_config::PromptBehavior::RememberUntilLock => true,
        };
    if !needs_prompt {
        return true;
    }
    let sign_info = sshwarden_ui::SignRequestInfo {
        key_name,
        process_name: request.process_name.clone(),
        namespace: request.namespace.clone(),
        operation_kind: operation_kind_for_request(request).to_string(),
        is_forwarding: request.is_forwarding,
    };
    prompt_authorization_with_bind_flow(
        ui_request_tx,
        sign_info,
        request.pid,
        request.cipher_id.as_deref(),
    )
    .await
}

/// Handle a single UI request from the SSH agent (runs in a spawned task).
#[allow(clippy::too_many_arguments)]
#[allow(unused_variables)]
pub(crate) async fn handle_ui_request(
    request: sshwarden_agent::SshAgentUIRequest,
    response_tx: tokio::sync::broadcast::Sender<(u32, bool)>,
    vault_locked: Arc<std::sync::atomic::AtomicBool>,
    cached_key_tuples: CachedKeyTuples,
    agent: sshwarden_agent::SshWardenAgent,
    key_names: Arc<RwLock<std::collections::HashMap<String, String>>>,
    local_key_cache_data: Arc<RwLock<Option<sshwarden_config::cache::LocalKeyCacheFile>>>,
    local_cache_key_state: LocalCacheKeyHandle,
    prompt_behavior: sshwarden_config::PromptBehavior,
    auto_unlock: bool,
    ui_request_tx: UIRequestTx,
    runtime_event_tx: tokio::sync::mpsc::Sender<RuntimeEvent>,
    authorization_memory: AuthorizationMemorySet,
    pin_failures: PinFailureHandle,
) {
    if request.is_list {
        if vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
            info!(
                request_id = request.request_id,
                process = %request.process_name,
                "Key list request while vault locked - listing public identities without unlock"
            );
        }

        agent.clear_needs_unlock();
        info!(
            request_id = request.request_id,
            process = %request.process_name,
            "Key list request - auto-approving"
        );
        let _ = response_tx.send((request.request_id, true));
        return;
    }

    // Check if vault is locked; if so, try to unlock
    if vault_locked.load(std::sync::atomic::Ordering::Relaxed) && auto_unlock {
        info!(
            request_id = request.request_id,
            "Vault is locked, attempting auto-unlock"
        );

        // 1. Native envelope unlock (platform Keychain / Secret Service / DPAPI).
        //    No UI prompt; if the slot is present and unlock succeeds, use it.
        {
            let cache_opt = local_key_cache_data.read().await.clone();
            if let Some(cache) = cache_opt.filter(|c| current_native_unlock_slot(c).is_some()) {
                let cache_for_unlock = cache.clone();
                let native_result = tokio::task::spawn_blocking(move || {
                    decrypt_envelope_local_key_cache_with_native(&cache_for_unlock)
                })
                .await;
                match native_result {
                    Ok(Ok((keys_json, lck))) => {
                        if let Ok(keys) =
                            serde_json::from_str::<Vec<(String, String, String)>>(&keys_json)
                        {
                            let key_name = key_name_for_request(&request, &keys);
                            apply_decrypted_keys_state(&key_names, &cached_key_tuples, &keys).await;
                            let mut agent_for_unlock = agent.clone();
                            if agent_for_unlock.set_keys(keys).is_ok() {
                                local_cache_key_state.write().await.set(lck);
                                vault_locked.store(false, std::sync::atomic::Ordering::Relaxed);
                                info!("Auto-unlocked via native local key cache");
                                let _ = runtime_event_tx
                                    .send(RuntimeEvent::AutoUnlockedNative)
                                    .await;
                                let approved = run_authorization_prompt(
                                    &request,
                                    key_name,
                                    prompt_behavior,
                                    &ui_request_tx,
                                )
                                .await;
                                let _ = response_tx.send((request.request_id, approved));
                                return;
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        info!(
                            "Native local key cache auto-unlock failed: {}; trying next method",
                            e
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Native unlock task join failed: {}", e);
                    }
                }
            }
        }

        // 2. Windows Hello envelope unlock (local-key-cache.json).
        #[cfg(windows)]
        {
            // Envelope-based Hello unlock from local-key-cache.json.
            let cache_opt = local_key_cache_data.read().await.clone();
            if let Some(cache) = cache_opt.filter(|c| current_hello_unlock_info(c).is_some()) {
                let cache_for_unlock = cache.clone();
                let hello_result = tokio::task::spawn_blocking(move || {
                    decrypt_envelope_local_key_cache_with_hello(&cache_for_unlock)
                })
                .await;
                match hello_result {
                    Ok(Ok((keys_json, lck))) => {
                        if let Ok(keys) =
                            serde_json::from_str::<Vec<(String, String, String)>>(&keys_json)
                        {
                            let key_name = key_name_for_request(&request, &keys);
                            apply_decrypted_keys_state(&key_names, &cached_key_tuples, &keys).await;
                            let mut agent_for_unlock = agent.clone();
                            if agent_for_unlock.set_keys(keys).is_ok() {
                                local_cache_key_state.write().await.set(lck);
                                vault_locked.store(false, std::sync::atomic::Ordering::Relaxed);
                                info!("Auto-unlocked via Windows Hello envelope");
                                let _ = runtime_event_tx
                                    .send(RuntimeEvent::AutoUnlockedWindowsHello)
                                    .await;
                                let approved = run_authorization_prompt(
                                    &request,
                                    key_name,
                                    prompt_behavior,
                                    &ui_request_tx,
                                )
                                .await;
                                let _ = response_tx.send((request.request_id, approved));
                                return;
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        info!(
                            "Hello envelope auto-unlock failed: {}; trying legacy sign-path",
                            e
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Hello envelope task join failed: {}", e);
                    }
                }
            }
        }

        // 3. PIN dialog: envelope-first validator with legacy fallback.
        //    The validator runs synchronously inside the dialog and captures the
        //    decrypted payload (and SymmetricKey, for envelope) into shared cells.
        let envelope_cache = {
            let guard = local_key_cache_data.read().await;
            guard
                .as_ref()
                .filter(|c| c.local_cache_key.pin_encrypted.is_some())
                .cloned()
        };

        let (validator, decrypted_cache, lck_holder): (PinValidator, DecryptedCache, _) =
            if let Some(cache) = envelope_cache {
                let dc: DecryptedCache = Arc::new(std::sync::Mutex::new(None));
                let kh: Arc<std::sync::Mutex<Option<sshwarden_api::crypto::SymmetricKey>>> =
                    Arc::new(std::sync::Mutex::new(None));
                let dc_inner = dc.clone();
                let kh_inner = kh.clone();
                let v: PinValidator = Arc::new(move |pin: &str| -> bool {
                    match decrypt_envelope_local_key_cache_with_pin(&cache, pin) {
                        Ok((keys_json, lck)) => {
                            *dc_inner.lock().unwrap_or_else(|e| e.into_inner()) = Some(keys_json);
                            *kh_inner.lock().unwrap_or_else(|e| e.into_inner()) = Some(lck);
                            true
                        }
                        Err(_) => false,
                    }
                });
                (v, dc, Some(kh))
            } else {
                // No PIN credentials — bail out.
                info!(
                    request_id = request.request_id,
                    "Auto-unlock failed: no PIN credentials available"
                );
                let _ = response_tx.send((request.request_id, false));
                return;
            };

        // SEC-03: share the daemon-wide PIN brute-force lockout with the control
        // channel so repeated wrong PINs in the SSH-request dialog also count.
        let validator = gate_pin_validator(validator, &pin_failures);

        let context_key_name = {
            let names = key_names.read().await;
            request
                .cipher_id
                .as_ref()
                .and_then(|cid| names.get(cid))
                .cloned()
                .unwrap_or_else(|| "Unknown key".to_string())
        };
        let pin_result = sshwarden_ui::unlock::request_pin_dialog_with_context(
            &ui_request_tx,
            validator,
            Some(unlock_context_for_request(&request, context_key_name)),
        )
        .await;

        if let Some(pin) = pin_result {
            let keys_json = match decrypted_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                Some(j) => j,
                None => {
                    tracing::warn!("PIN validator reported success but cache was empty");
                    let _ = response_tx.send((request.request_id, false));
                    return;
                }
            };
            if let Ok(keys) = serde_json::from_str::<Vec<(String, String, String)>>(&keys_json) {
                let key_name = key_name_for_request(&request, &keys);
                apply_decrypted_keys_state(&key_names, &cached_key_tuples, &keys).await;
                let mut agent_for_unlock = agent.clone();
                if agent_for_unlock.set_keys(keys).is_ok() {
                    if let Some(kh) = lck_holder {
                        let maybe_lck = kh.lock().unwrap_or_else(|e| e.into_inner()).take();
                        if let Some(lck) = maybe_lck {
                            // Multi-device: seed this device's own platform unlock
                            // slot from the freshly recovered key, mirroring the
                            // explicit unlock-pin control path (no-op in
                            // single-device mode or if a slot already exists).
                            enroll_device_platform_slots_if_missing(&lck);
                            local_cache_key_state.write().await.set(lck);
                        }
                    }
                    vault_locked.store(false, std::sync::atomic::Ordering::Relaxed);
                    info!("Auto-unlocked via PIN dialog");
                    let _ = runtime_event_tx
                        .send(RuntimeEvent::AutoUnlockedPin { pin })
                        .await;
                    let approved = run_authorization_prompt(
                        &request,
                        key_name,
                        prompt_behavior,
                        &ui_request_tx,
                    )
                    .await;
                    let _ = response_tx.send((request.request_id, approved));
                    return;
                }
            }
        }

        // PIN cancelled or every path failed → deny the request.
        let _ = response_tx.send((request.request_id, false));
        return;
    }

    // LOGIC-2: reaching here with the vault still locked means the auto-unlock
    // block above was skipped (auto_unlock disabled). The loaded entries have no
    // private material, so deny cleanly rather than auto-approving under
    // prompt_behavior=Never — otherwise ssh sees an "approval" followed by a
    // broken signature with no way to recover.
    if vault_locked.load(std::sync::atomic::Ordering::Relaxed) {
        info!(
            request_id = request.request_id,
            process = %request.process_name,
            "Sign request denied: vault is locked and auto-unlock is disabled. \
             Run `sshwarden unlock`, or enable [unlock] auto_unlock_on_request."
        );
        let _ = response_tx.send((request.request_id, false));
        return;
    }

    let operation_kind = operation_kind_for_request(&request).to_string();
    let memory_key = request
        .cipher_id
        .as_ref()
        .map(|vault_item_id| (vault_item_id.clone(), operation_kind.clone()));

    if !request.is_forwarding
        && matches!(
            prompt_behavior,
            sshwarden_config::PromptBehavior::RememberUntilLock
        )
        && memory_key.as_ref().is_some_and(|key| {
            authorization_memory
                .try_read()
                .is_ok_and(|memory| memory.contains(key))
        })
    {
        info!(
            request_id = request.request_id,
            process = %request.process_name,
            operation = %operation_kind,
            "Sign request - auto-approved from authorization memory"
        );
        let _ = response_tx.send((request.request_id, true));
        return;
    }

    // Sign request - check prompt behavior.
    // Agent forwarding always requires explicit approval, regardless of prompt_behavior.
    let should_prompt = request.is_forwarding
        || match prompt_behavior {
            sshwarden_config::PromptBehavior::Always => true,
            sshwarden_config::PromptBehavior::Never => false,
            sshwarden_config::PromptBehavior::RememberUntilLock => true,
        };

    if !should_prompt {
        info!(
            request_id = request.request_id,
            process = %request.process_name,
            "Sign request - auto-approved (prompt_behavior=never)"
        );
        let _ = response_tx.send((request.request_id, true));
        return;
    }

    // Build request info for UI — use try_read to avoid blocking on write lock
    let key_name = match key_names.try_read() {
        Ok(names) => request
            .cipher_id
            .as_ref()
            .and_then(|id| names.get(id))
            .cloned()
            .unwrap_or_else(|| "Unknown key".to_string()),
        Err(_) => "Unknown key".to_string(),
    };

    let sign_info = sshwarden_ui::SignRequestInfo {
        key_name,
        process_name: request.process_name.clone(),
        namespace: request.namespace.clone(),
        operation_kind: operation_kind.clone(),
        is_forwarding: request.is_forwarding,
    };

    info!(
        request_id = request.request_id,
        process = %request.process_name,
        key = %sign_info.key_name,
        "Sign request - prompting user"
    );

    let result_pid = request.pid;
    let result_cipher_id = request.cipher_id.clone();
    let approved = prompt_authorization_with_bind_flow(
        &ui_request_tx,
        sign_info,
        result_pid,
        result_cipher_id.as_deref(),
    )
    .await;
    if approved
        && !request.is_forwarding
        && matches!(
            prompt_behavior,
            sshwarden_config::PromptBehavior::RememberUntilLock
        )
    {
        if let Some(key) = memory_key {
            authorization_memory.write().await.insert(key);
        }
    }
    let _ = response_tx.send((request.request_id, approved));
}

pub(crate) fn unlock_context_for_request(
    request: &sshwarden_agent::SshAgentUIRequest,
    key_name: String,
) -> sshwarden_ui::UnlockRequestContext {
    sshwarden_ui::UnlockRequestContext {
        key_name,
        process_name: request.process_name.clone(),
        operation_kind: operation_kind_for_request(request).to_string(),
        is_forwarding: request.is_forwarding,
    }
}

pub(crate) fn operation_kind_for_request(
    request: &sshwarden_agent::SshAgentUIRequest,
) -> &'static str {
    request.operation_kind.as_str()
}

/// Login to the vault and fetch SSH keys, returning both keys and the authenticated client.
pub(crate) async fn fetch_vault_keys_with_client(
    config: &sshwarden_config::Config,
) -> anyhow::Result<(
    Vec<sshwarden_api::DecryptedSshKey>,
    sshwarden_api::BitwardenClient,
)> {
    let password = prompt_password("Master password: ")?;

    let mut client = create_client(config, None);
    client.login_password(&config.auth.email, &password).await?;

    let keys = client.sync_ssh_keys().await?;
    Ok((keys, client))
}

/// After first login, ask the user if they want to set a PIN for persistent unlock.
///
/// This avoids requiring the master password on every restart.
pub(crate) async fn prompt_setup_pin(
    cached_key_tuples: &CachedKeyTuples,
    local_key_cache_data: &Arc<RwLock<Option<sshwarden_config::cache::LocalKeyCacheFile>>>,
    local_cache_key_state: &LocalCacheKeyHandle,
    config: &sshwarden_config::Config,
    api_client: &Arc<RwLock<Option<sshwarden_api::BitwardenClient>>>,
) {
    #[allow(clippy::print_stderr)]
    {
        eprint!("Set up a PIN to unlock without master password next time? [Y/n] ");
    }
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return;
    }
    let input = input.trim().to_lowercase();
    if !input.is_empty() && input != "y" && input != "yes" {
        info!("Skipped PIN setup. You can set it later with 'sshwarden set-pin'.");
        return;
    }

    let pin = match prompt_password("Enter new PIN (>= 4 chars): ") {
        Ok(p) => p,
        Err(_) => return,
    };
    if pin.len() < 4 {
        info!("PIN must be at least 4 characters. Skipped.");
        return;
    }
    let pin_confirm = match prompt_password("Confirm PIN: ") {
        Ok(p) => p,
        Err(_) => return,
    };
    if pin != pin_confirm {
        info!("PINs do not match. Skipped.");
        return;
    }

    let keys = cached_key_tuples.read().await.clone_inner();
    match write_envelope_local_key_cache(&keys, &config.auth.email, &config.server.base_url, &pin) {
        Ok((cache, local_cache_key)) => {
            *local_key_cache_data.write().await = Some(cache);
            local_cache_key_state.write().await.set(local_cache_key);
            info!("PIN set. Envelope local key cache saved.");
        }
        Err(e) => {
            tracing::warn!("Failed to save envelope local key cache: {}", e);
            return;
        }
    }

    // Save device session with PIN-encrypted refresh token
    {
        let client_guard = api_client.read().await;
        if let Some(ref client) = *client_guard {
            save_device_session(client, config, Some(&pin)).await;
        }
    }
}
