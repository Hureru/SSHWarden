//! Bind-and-approve UI flow: host-binding dialogs and their persistence.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 6c).

use crate::cache::load_managed_keys_from_cache;
use crate::infer_ssh_target_from_pid;
use crate::runtime::UIRequestTx;
use crate::sshconfig::{
    load_host_bindings_importing_managed, managed_sshwarden_include_path,
    sync_managed_ssh_config_inner, user_ssh_config_path, write_sshwarden_include_line,
};
/// Prompt the user to authorize a sign request, supporting the
/// "Bind & Approve…" secondary action. Returns true if the request was
/// approved (either directly or after a successful binding save).
pub(crate) async fn prompt_authorization_with_bind_flow(
    ui_request_tx: &UIRequestTx,
    sign_info: sshwarden_ui::SignRequestInfo,
    pid: u32,
    cipher_id: Option<&str>,
) -> bool {
    match sshwarden_ui::notify::request_authorization(ui_request_tx, &sign_info).await {
        sshwarden_ui::AuthorizationResult::Approved => true,
        sshwarden_ui::AuthorizationResult::Denied | sshwarden_ui::AuthorizationResult::Timeout => {
            false
        }
        sshwarden_ui::AuthorizationResult::BindRequested => {
            run_bind_hosts_flow(ui_request_tx, pid, cipher_id).await
        }
    }
}

/// Show the host-binding dialog, persist on save, and return whether the
/// original sign request should be approved.
pub(crate) async fn run_bind_hosts_flow(
    ui_request_tx: &UIRequestTx,
    pid: u32,
    initial_cipher_id: Option<&str>,
) -> bool {
    let keys = match load_managed_keys_from_cache() {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(
                "Bind dialog requested but local key cache is unavailable: {}",
                e
            );
            return false;
        }
    };
    let bindings = load_host_bindings_importing_managed(&keys).unwrap_or_else(|e| {
        tracing::warn!("Failed to load host bindings: {}", e);
        sshwarden_config::bindings::HostBindingsFile::default()
    });
    let entries: Vec<sshwarden_ui::BindHostsKeyEntry> = keys
        .iter()
        .map(|k| sshwarden_ui::BindHostsKeyEntry {
            cipher_id: k.cipher_id.clone(),
            name: k.name.clone(),
            hosts: bindings
                .bindings
                .get(&k.cipher_id)
                .map(|b| b.hosts.clone())
                .unwrap_or_default(),
        })
        .collect();

    if entries.is_empty() {
        tracing::warn!("Bind dialog requested but no keys are available to bind");
        return false;
    }

    let prefill_host = infer_ssh_target_from_pid(pid);
    let bind_request = sshwarden_ui::BindHostsRequest {
        keys: entries,
        initial_selection: initial_cipher_id.map(String::from),
        prefill_host,
        approve_on_save: true,
    };

    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    if ui_request_tx
        .send(sshwarden_ui::UIRequest::BindHostsDialog {
            request: bind_request,
            response_tx,
        })
        .await
        .is_err()
    {
        tracing::error!("Failed to dispatch bind-hosts dialog request");
        return false;
    }

    let bind_result =
        match tokio::time::timeout(std::time::Duration::from_secs(600), response_rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => {
                tracing::error!("Bind dialog response channel closed unexpectedly");
                return false;
            }
            Err(_) => {
                tracing::warn!("Bind dialog timed out after 600s");
                return false;
            }
        };

    match bind_result {
        sshwarden_ui::BindHostsResult::Cancelled => false,
        sshwarden_ui::BindHostsResult::Saved { bindings: payload } => {
            if let Err(e) = persist_bind_payload(&payload).await {
                tracing::error!("Failed to persist host bindings: {}", e);
                return false;
            }
            true
        }
    }
}

/// Persist the user's final binding decisions and regenerate the managed snippet.
///
/// Runs the blocking file I/O inside `spawn_blocking` to keep the tokio
/// runtime responsive.
pub(crate) async fn persist_bind_payload(
    payload: &std::collections::BTreeMap<String, Vec<String>>,
) -> anyhow::Result<()> {
    let payload = payload.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let keys = load_managed_keys_from_cache().unwrap_or_default();
        let mut bindings = load_host_bindings_importing_managed(&keys)?;
        for (cipher_id, hosts) in &payload {
            bindings.set_hosts(cipher_id, hosts.clone())?;
        }
        bindings.save()?;

        sync_managed_ssh_config_inner(&keys, true)?;

        // CFG-2: a binding is inert unless ~/.ssh/config Includes the managed
        // snippet. Mirror cmd_bindings_add so UI/sign-flow bindings install the
        // Include line too (idempotent). Non-fatal — the snippet is already saved.
        let include_path = managed_sshwarden_include_path()?;
        let config_path = user_ssh_config_path()?;
        if let Err(e) = write_sshwarden_include_line(&config_path, &include_path) {
            tracing::warn!(
                "Bindings saved, but failed to ensure the Include line in {}: {e}",
                config_path.display()
            );
        }
        Ok(())
    })
    .await
    .map_err(|e| anyhow::anyhow!("Bindings persist task panicked: {}", e))?
}

/// Open the BindHostsDialog standalone (no in-flight sign request).
/// Returns true if the user saved, false if they cancelled.
pub(crate) async fn dispatch_standalone_bind_hosts_dialog(
    ui_request_tx: &UIRequestTx,
) -> anyhow::Result<bool> {
    let keys = load_managed_keys_from_cache()?;
    let bindings = load_host_bindings_importing_managed(&keys).unwrap_or_else(|e| {
        tracing::warn!("Failed to load host bindings: {}", e);
        sshwarden_config::bindings::HostBindingsFile::default()
    });
    let entries: Vec<sshwarden_ui::BindHostsKeyEntry> = keys
        .iter()
        .map(|k| sshwarden_ui::BindHostsKeyEntry {
            cipher_id: k.cipher_id.clone(),
            name: k.name.clone(),
            hosts: bindings
                .bindings
                .get(&k.cipher_id)
                .map(|b| b.hosts.clone())
                .unwrap_or_default(),
        })
        .collect();
    if entries.is_empty() {
        anyhow::bail!("No SSH keys available — run `sshwarden sync` or login first");
    }

    let bind_request = sshwarden_ui::BindHostsRequest {
        keys: entries,
        initial_selection: None,
        prefill_host: None,
        approve_on_save: false,
    };

    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    ui_request_tx
        .send(sshwarden_ui::UIRequest::BindHostsDialog {
            request: bind_request,
            response_tx,
        })
        .await
        .map_err(|_| anyhow::anyhow!("UI request channel closed"))?;

    // CONC-1: this dialog response is awaited inline in the main select! loop
    // (via the BindHostsDialog control command), so an unbounded wait would
    // freeze auto-lock, token refresh and notification handling. Bound it.
    match tokio::time::timeout(std::time::Duration::from_secs(600), response_rx).await {
        Ok(Ok(sshwarden_ui::BindHostsResult::Saved { bindings: payload })) => {
            persist_bind_payload(&payload).await?;
            Ok(true)
        }
        Ok(Ok(sshwarden_ui::BindHostsResult::Cancelled)) => Ok(false),
        Ok(Err(_)) => anyhow::bail!("Dialog response channel closed unexpectedly"),
        Err(_) => anyhow::bail!("Host-binding dialog timed out after 600s"),
    }
}
