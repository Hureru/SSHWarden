use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU32},
        Arc, RwLock,
    },
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use bitwarden_russh::{
    session_bind::SessionBindResult,
    ssh_agent::{self, SshKey},
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::peerinfo::models::PeerInfo;
use crate::request_parser;

/// A UI request from the SSH agent to the host application.
pub struct SshAgentUIRequest {
    pub request_id: u32,
    pub cipher_id: Option<String>,
    pub process_name: String,
    /// PID of the calling process (best-effort; 0 if unknown). Used by the
    /// host application for UX features like host inference.
    pub pid: u32,
    pub namespace: Option<String>,
    pub operation_kind: crate::request_parser::OperationKind,
    pub is_forwarding: bool,
    /// Host key from the connection's last session-bind (empty if the client
    /// sent none, i.e. OpenSSH < 8.9 or a non-OpenSSH client).
    pub host_key: Vec<u8>,
    /// The user picked exactly this key for this connection in the key picker.
    pub preselected: bool,
}

/// Asks the host application which identities to list for one connection.
pub struct SshAgentListRequest {
    pub pid: u32,
    pub process_name: String,
    pub is_forwarding: bool,
    /// See [`SshAgentUIRequest::host_key`].
    pub host_key: Vec<u8>,
    /// Listable keys as `(vault item id, name)`.
    pub keys: Vec<(String, String)>,
    /// Dropping this without replying fails the list request closed.
    pub reply: tokio::sync::oneshot::Sender<ListSelection>,
}

/// The identities to list, in the order they should be offered.
pub struct ListSelection {
    pub cipher_ids: Vec<String>,
    /// The user explicitly picked `cipher_ids[0]` for this connection.
    pub user_picked: bool,
}

/// An SSH key stored in the agent's keystore.
#[derive(Clone)]
pub struct SshWardenKey {
    pub private_key: Option<ssh_key::private::PrivateKey>,
    pub public_key_bytes: Vec<u8>,
    pub name: String,
    pub cipher_uuid: String,
}

impl SshKey for SshWardenKey {
    fn name(&self) -> &str {
        &self.name
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key_bytes.clone()
    }

    fn sign(&self, data: &[u8], flags: u32) -> anyhow::Result<ssh_key::Signature> {
        let result = match &self.private_key {
            Some(private_key) => sign_with(private_key, data, flags),
            None => Err(anyhow::anyhow!("the key is locked")),
        };
        // The client only ever sees "agent refused operation"; the reason goes here.
        if let Err(e) = &result {
            error!(key = %self.name, error = %e, "Signing failed");
        }
        result
    }
}

// SIGN_REQUEST flags (draft-miller-ssh-agent): which hash an RSA key signs with.
const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;

fn sign_with(
    private_key: &ssh_key::private::PrivateKey,
    data: &[u8],
    flags: u32,
) -> anyhow::Result<ssh_key::Signature> {
    use rsa::signature::{SignatureEncoding, Signer};

    let ssh_key::private::KeypairData::Rsa(keypair) = private_key.key_data() else {
        return Ok(private_key.try_sign(data)?);
    };
    // Not `private_key.try_sign`: ssh-key 0.6.7 builds the RSA key from the
    // prime p twice instead of p and q, and the `rsa` crate rejects that.
    let key = rsa::RsaPrivateKey::from_components(
        rsa::BigUint::try_from(&keypair.public.n)?,
        rsa::BigUint::try_from(&keypair.public.e)?,
        rsa::BigUint::try_from(&keypair.private.d)?,
        vec![
            rsa::BigUint::try_from(&keypair.private.p)?,
            rsa::BigUint::try_from(&keypair.private.q)?,
        ],
    )?;
    let (hash, signature) = if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
        let key = rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha512>::new(key);
        (ssh_key::HashAlg::Sha512, key.try_sign(data)?.to_vec())
    } else if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
        let key = rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(key);
        (ssh_key::HashAlg::Sha256, key.try_sign(data)?.to_vec())
    } else {
        // OpenSSH has refused these signatures since 8.8.
        anyhow::bail!("the client asked for an ssh-rsa (SHA-1) signature, which is not supported");
    };
    Ok(ssh_key::Signature::new(
        ssh_key::Algorithm::Rsa { hash: Some(hash) },
        signature,
    )?)
}

/// The SSHWarden SSH Agent implementation.
#[derive(Clone)]
pub struct SshWardenAgent {
    keystore: ssh_agent::KeyStore<SshWardenKey>,
    cancellation_token: CancellationToken,
    show_ui_request_tx: tokio::sync::mpsc::Sender<SshAgentUIRequest>,
    list_request_tx: tokio::sync::mpsc::Sender<SshAgentListRequest>,
    ui_response_tx: Arc<tokio::sync::broadcast::Sender<(u32, bool)>>,
    request_id: Arc<AtomicU32>,
    is_running: Arc<AtomicBool>,
    /// Reports a fatal agent-transport failure (e.g. the SSH agent endpoint
    /// could not be claimed). The main loop watches this so the daemon shuts
    /// down instead of running as a zombie that still answers status/unlock
    /// while serving no SSH client (RT-01).
    fatal_tx: Arc<tokio::sync::watch::Sender<Option<String>>>,
}

impl ssh_agent::Agent<PeerInfo, SshWardenKey> for SshWardenAgent {
    async fn confirm(&self, ssh_key: SshWardenKey, data: &[u8], info: &PeerInfo) -> bool {
        if !self.is_running() {
            error!("Agent is not running, but tried to call confirm");
            return false;
        }

        let request_id = self.get_request_id();
        let request_data = match request_parser::parse_request(data) {
            Ok(data) => data,
            Err(e) => {
                error!(error = %e, "Error while parsing request");
                return false;
            }
        };
        let operation_kind = request_data.operation_kind();
        let namespace = match request_data {
            request_parser::SshAgentSignRequest::SshSigRequest(ref req) => {
                Some(req.namespace.clone())
            }
            _ => None,
        };

        info!(
            is_forwarding = %info.is_forwarding(),
            namespace = ?namespace.as_ref(),
            host_key = %STANDARD.encode(info.host_key()),
            "Confirming request from application: {}",
            info.process_name(),
        );

        let mut rx_channel = self.ui_response_tx.subscribe();
        if self
            .show_ui_request_tx
            .send(SshAgentUIRequest {
                request_id,
                cipher_id: Some(ssh_key.cipher_uuid.clone()),
                process_name: info.process_name().to_string(),
                pid: info.pid(),
                namespace,
                operation_kind,
                is_forwarding: info.is_forwarding(),
                host_key: info.host_key(),
                preselected: info.picked().as_deref() == Some(ssh_key.cipher_uuid.as_str()),
            })
            .await
            .is_err()
        {
            // The host application's UI channel is gone (daemon shutting down or
            // main loop exited). Fail closed instead of panicking the serve task.
            error!("UI request channel closed; denying sign request");
            return false;
        }
        while let Ok((id, response)) = rx_channel.recv().await {
            if id == request_id {
                return response;
            }
        }
        false
    }

    async fn identities(&self, info: &PeerInfo) -> Option<Vec<SshWardenKey>> {
        let keys = self
            .keystore
            .0
            .read()
            .expect("RwLock is not poisoned")
            .values()
            .map(|key| (key.cipher_uuid.clone(), key.name.clone()))
            .collect();
        let (reply, selection) = tokio::sync::oneshot::channel();
        let request = SshAgentListRequest {
            pid: info.pid(),
            process_name: info.process_name().to_string(),
            is_forwarding: info.is_forwarding(),
            host_key: info.host_key(),
            keys,
            reply,
        };
        if self.list_request_tx.send(request).await.is_err() {
            // Host application is gone (daemon shutting down); fail closed.
            error!("List request channel closed; denying list request");
            return None;
        }
        let selection = selection.await.ok()?;
        if selection.user_picked {
            info.set_picked(selection.cipher_ids.first().cloned());
        }

        let keystore = self.keystore.0.read().expect("RwLock is not poisoned");
        Some(
            selection
                .cipher_ids
                .iter()
                .filter_map(|id| keystore.values().find(|key| &key.cipher_uuid == id))
                // Listing needs no private material; do not copy it around.
                .map(|key| SshWardenKey {
                    private_key: None,
                    public_key_bytes: key.public_key_bytes.clone(),
                    name: key.name.clone(),
                    cipher_uuid: key.cipher_uuid.clone(),
                })
                .collect(),
        )
    }

    async fn set_sessionbind_info(
        &self,
        session_bind_info_result: &SessionBindResult,
        connection_info: &PeerInfo,
    ) {
        match session_bind_info_result {
            SessionBindResult::Success(session_bind_info) => {
                // A forwarded connection is bound twice: by the local ssh with
                // is_forwarding=1, then by the remote ssh with is_forwarding=0.
                // Never clear the flag, or forwarded requests look local.
                if session_bind_info.is_forwarding {
                    connection_info.set_forwarding(true);
                }
                // The last bind names the host actually being authenticated to.
                connection_info.set_host_key(session_bind_info.host_key.clone());
            }
            SessionBindResult::SignatureFailure => {
                error!("Session bind failure: Signature failure");
            }
        }
    }
}

impl SshWardenAgent {
    pub fn new(
        auth_request_tx: tokio::sync::mpsc::Sender<SshAgentUIRequest>,
        list_request_tx: tokio::sync::mpsc::Sender<SshAgentListRequest>,
        auth_response_tx: Arc<tokio::sync::broadcast::Sender<(u32, bool)>>,
    ) -> Self {
        let (fatal_tx, _fatal_rx) = tokio::sync::watch::channel(None);
        Self {
            keystore: ssh_agent::KeyStore(Arc::new(RwLock::new(HashMap::new()))),
            cancellation_token: CancellationToken::new(),
            show_ui_request_tx: auth_request_tx,
            list_request_tx,
            ui_response_tx: auth_response_tx,
            request_id: Arc::new(AtomicU32::new(0)),
            is_running: Arc::new(AtomicBool::new(false)),
            fatal_tx: Arc::new(fatal_tx),
        }
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation_token.clone()
    }

    pub fn stop(&self) {
        if !self.is_running() {
            error!("Tried to stop agent while it is not running");
            return;
        }

        self.is_running
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.cancellation_token.cancel();
        self.keystore
            .0
            .write()
            .expect("RwLock is not poisoned")
            .clear();
    }

    pub fn set_keys(&mut self, new_keys: &[(String, String, String)]) -> Result<(), anyhow::Error> {
        if !self.is_running() {
            return Err(anyhow::anyhow!(
                "[SshWardenAgent] Tried to set keys while agent is not running"
            ));
        }

        let keystore = &mut self.keystore;
        keystore.0.write().expect("RwLock is not poisoned").clear();

        for (key, name, cipher_id) in new_keys.iter() {
            match parse_key_safe(key) {
                Ok(private_key) => {
                    let public_key_bytes = private_key
                        .public_key()
                        .to_bytes()
                        .expect("Cipher private key is always correctly parsed");
                    let displaced = keystore.0.write().expect("RwLock is not poisoned").insert(
                        public_key_bytes.clone(),
                        SshWardenKey {
                            private_key: Some(private_key),
                            public_key_bytes,
                            name: name.clone(),
                            cipher_uuid: cipher_id.clone(),
                        },
                    );
                    if displaced.is_some() {
                        // LOGIC-7: the keystore is keyed by public key bytes, so
                        // two vault items sharing a public key collapse into one.
                        // Warn so the operator understands why status/key_count
                        // can be lower than the number of vault keys.
                        tracing::warn!(
                            key = %name,
                            "Duplicate public key: overwrote an earlier agent keystore entry; \
                             status key_count will be lower than the vault key count"
                        );
                    }
                }
                Err(e) => {
                    error!(error=%e, "Error while parsing key");
                }
            }
        }

        Ok(())
    }

    pub fn set_public_identities(
        &mut self,
        identities: Vec<(String, String, String)>,
    ) -> Result<(), anyhow::Error> {
        if !self.is_running() {
            return Err(anyhow::anyhow!(
                "[SshWardenAgent] Tried to set identities while agent is not running"
            ));
        }

        let keystore = &mut self.keystore;
        keystore.0.write().expect("RwLock is not poisoned").clear();

        for (public_key_openssh, name, cipher_id) in identities {
            match ssh_key::PublicKey::from_openssh(&public_key_openssh)
                .and_then(|public_key| public_key.to_bytes())
            {
                Ok(public_key_bytes) => {
                    keystore.0.write().expect("RwLock is not poisoned").insert(
                        public_key_bytes.clone(),
                        SshWardenKey {
                            private_key: None,
                            public_key_bytes,
                            name,
                            cipher_uuid: cipher_id,
                        },
                    );
                }
                Err(e) => {
                    error!(error=%e, "Error while parsing public key identity");
                }
            }
        }

        Ok(())
    }

    pub fn lock(&mut self) -> Result<(), anyhow::Error> {
        if !self.is_running() {
            return Err(anyhow::anyhow!(
                "[SshWardenAgent] Tried to lock agent, but it is not running"
            ));
        }

        let keystore = &mut self.keystore;
        keystore
            .0
            .write()
            .expect("RwLock is not poisoned")
            .iter_mut()
            .for_each(|(_public_key, key)| {
                key.private_key = None;
            });
        Ok(())
    }

    pub fn clear_keys(&mut self) -> Result<(), anyhow::Error> {
        let keystore = &mut self.keystore;
        keystore.0.write().expect("RwLock is not poisoned").clear();
        Ok(())
    }

    pub fn key_count(&self) -> usize {
        self.keystore
            .0
            .read()
            .expect("RwLock is not poisoned")
            .len()
    }

    /// Number of loaded keys that actually hold private material and can sign.
    /// While the vault is locked this is 0 even though `key_count()` (listed
    /// identities) may be non-zero. status reports this so what it shows matches
    /// what the agent can actually sign.
    pub fn signable_key_count(&self) -> usize {
        self.keystore
            .0
            .read()
            .expect("RwLock is not poisoned")
            .values()
            .filter(|k| k.private_key.is_some())
            .count()
    }

    pub fn is_running(&self) -> bool {
        self.is_running.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn set_running(&self, value: bool) {
        self.is_running
            .store(value, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_running_flag(&self) -> Arc<AtomicBool> {
        self.is_running.clone()
    }

    /// A receiver the main loop watches for a fatal agent-transport failure.
    /// When a value is sent, the daemon should shut down rather than keep
    /// running as a zombie that still answers status/unlock (RT-01).
    pub fn fatal_rx(&self) -> tokio::sync::watch::Receiver<Option<String>> {
        self.fatal_tx.subscribe()
    }

    /// A clonable sender the transport listener uses to report a fatal failure.
    pub fn fatal_tx(&self) -> Arc<tokio::sync::watch::Sender<Option<String>>> {
        self.fatal_tx.clone()
    }

    pub fn keystore_clone(&self) -> ssh_agent::KeyStore<SshWardenKey> {
        self.keystore.clone()
    }

    fn get_request_id(&self) -> u32 {
        if !self.is_running() {
            error!("Agent is not running, but tried to get request id");
            return 0;
        }

        self.request_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }
}

fn parse_key_safe(pem: &str) -> Result<ssh_key::private::PrivateKey, anyhow::Error> {
    match ssh_key::private::PrivateKey::from_openssh(pem) {
        Ok(key) => match key.public_key().to_bytes() {
            Ok(_) => Ok(key),
            Err(e) => Err(anyhow::Error::msg(format!(
                "Failed to parse public key: {e}"
            ))),
        },
        Err(e) => Err(anyhow::Error::msg(format!("Failed to parse key: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::Signature;
    use std::sync::atomic::Ordering;

    const TEST_ED25519_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAOYor3+kyAsXYs2sGikmUuhpxmVf2hAGd2TK7KwN4N9gAAAJj79ujB+/bo
wQAAAAtzc2gtZWQyNTUxOQAAACAOYor3+kyAsXYs2sGikmUuhpxmVf2hAGd2TK7KwN4N9g
AAAEAgAQkLDKjON00XO+Y09BoIBuQsAXAx6HUhQoTEodVzig5iivf6TICxdizawaKSZS6G
nGZV/aEAZ3ZMrsrA3g32AAAAEHRlc3RAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----";

    const TEST_RSA_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEArygx7enKdJxedA34y7LoOwLu/bbXECX1TRV3CY66VSPsptyal5vs
Me+3/QLXvkOBKpA/Gn8+ygUWEe4gA4a9Jey8ljo8nzO/NQarUWdr7u3qX6/MtFD9oO0nQ/
LukiHgbYUzkR/UzhusK5Z7Go8xMWsOZaENnpbElb3AWzCn/1094pAVtnGDKhE0RNuBKNMY
l0P2GeS0LekW0qdLyZxp1VY+GEGGP39Ewh3Eq70sF5etkPIHbOrEf5mZXqONSSd1sgBmI1
T4YEgZQedFT98uofFMjsTDfztAGJpgGBL5bhwVhLD8cKg9/JPfmAps1lpnJU0XIRkYRw3Z
Ic/cUYQtjQAAA8jMw6IEzMOiBAAAAAdzc2gtcnNhAAABAQCvKDHt6cp0nF50DfjLsug7Au
79ttcQJfVNFXcJjrpVI+ym3JqXm+wx77f9Ate+Q4EqkD8afz7KBRYR7iADhr0l7LyWOjyf
M781BqtRZ2vu7epfr8y0UP2g7SdD8u6SIeBthTORH9TOG6wrlnsajzExaw5loQ2elsSVvc
BbMKf/XT3ikBW2cYMqETRE24Eo0xiXQ/YZ5LQt6RbSp0vJnGnVVj4YQYY/f0TCHcSrvSwX
l62Q8gds6sR/mZleo41JJ3WyAGYjVPhgSBlB50VP3y6h8UyOxMN/O0AYmmAYEvluHBWEsP
xwqD38k9+YCmzWWmclTRchGRhHDdkhz9xRhC2NAAAAAwEAAQAAAP8WaE364a3EvTxYHHF3
nauX4Qgx7PIWXsTC17wivN+ZhL8BmbctLgVJXiFrfLGc5YXgrBNmkGC3926bXJs72EDaWS
7HCSw4MaaEYhYIk/J63nTdSOAnMTVBIRWk268pgqvzVtcB+dB/jYq5CMc23pqsd8WfurrD
TwZXIa85+z+Cq3SCdhbalFl6UEgLLe4CwGWzMxiohHaARvOIGJBGqCnplHjLvw4M+lctFm
k3NKGAcYBkFB3pDJYJrMwDaglKK6wxIi2PUMOv1KvMOQqxdAa5P2vcXazF9BFc5p3srRdV
cG4RuanGvTvEDBe3zAUX62HBkJF1NHOiaRUwjmND3XkAAACBAIZYHZANpvfgVa+okm8mav
vdNy4fAna+lHCRwA9Q++JxAyL9dAecAoQAHv6ZXCEdzFEKDmYwxObrpp86qw/NE2w5rpaO
S86lIEBTndxYJ1W//a/kVKzE5OBVpj1jM/yYixlZorMvz6KFKnPSJ/sDGyX8xAlC4y2frr
RVrt0U95gJAAAAgQDrkoW60sX7m+o4axz0lYEsk9D4Yk2QZ/GGdMf00ysZaSIu0H66G4oH
m3xSz21Xqh8cIufcj2OY/VNnyvlDDGYikfYiO+kVirVRf11zU/WM3j78A04LxyylCh8kVV
cRaCU5UDXOYygiwvxwiWXcBaFP0vrSBrnfgQKwDQvyltRYRQAAAIEAvliCvgtjlr27bk9N
ad4d4KrAzATef3nUwrdlb2n4oADFky6a7P6SbM1Mu7RRB5IFPrHPexLyrcKtGpvJK1SK5s
PBBdAFsAHGszaqV4azJzjCxPK+vnKoRoIGI7igbNTfTXuSxIOD8DGI6BlG2+6CkRBL05VO
V1e7S3lMGgbgyKkAAAAQdGVzdEBleGFtcGxlLmNvbQECAw==
-----END OPENSSH PRIVATE KEY-----";

    fn create_test_agent() -> (
        SshWardenAgent,
        tokio::sync::mpsc::Receiver<SshAgentUIRequest>,
        tokio::sync::broadcast::Sender<(u32, bool)>,
    ) {
        let (request_tx, request_rx) = tokio::sync::mpsc::channel::<SshAgentUIRequest>(16);
        let (list_tx, _list_rx) = tokio::sync::mpsc::channel::<SshAgentListRequest>(16);
        let (response_tx, _response_rx) = tokio::sync::broadcast::channel::<(u32, bool)>(16);
        let response_tx = Arc::new(response_tx);

        let agent = SshWardenAgent::new(request_tx, list_tx, response_tx.clone());
        (agent, request_rx, (*response_tx).clone())
    }

    const TEST_ED25519_PUB: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA5iivf6TICxdizawaKSZS6GnGZV/aEAZ3ZMrsrA3g32";
    const SECOND_ED25519_PUB: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICThYtp4xYWmZnmkqU5+TxPcMxxqy3tEVxPX9Qi/5IqD";

    /// Send REQUEST_IDENTITIES over a real `serve` connection and return the
    /// raw reply body. `answer` plays the host application.
    async fn list_over_the_wire(
        answer: impl FnOnce(SshAgentListRequest) + Send + 'static,
    ) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (request_tx, _request_rx) = tokio::sync::mpsc::channel::<SshAgentUIRequest>(16);
        let (list_tx, mut list_rx) = tokio::sync::mpsc::channel::<SshAgentListRequest>(16);
        let (response_tx, _response_rx) = tokio::sync::broadcast::channel::<(u32, bool)>(16);
        let mut agent = SshWardenAgent::new(request_tx, list_tx, Arc::new(response_tx));
        agent.is_running.store(true, Ordering::Relaxed);
        agent
            .set_public_identities(vec![
                (
                    TEST_ED25519_PUB.to_string(),
                    "first".to_string(),
                    "id-1".to_string(),
                ),
                (
                    SECOND_ED25519_PUB.to_string(),
                    "second".to_string(),
                    "id-2".to_string(),
                ),
            ])
            .expect("set_public_identities should succeed");

        let (mut client, server) = tokio::io::duplex(4096);
        let listener = futures::stream::iter(vec![Ok((server, PeerInfo::unknown()))]);
        tokio::spawn(ssh_agent::serve(
            listener,
            agent.clone(),
            agent.keystore_clone(),
            agent.cancellation_token(),
        ));
        tokio::spawn(async move {
            if let Some(request) = list_rx.recv().await {
                answer(request);
            }
        });

        client.write_all(&[0, 0, 0, 1, 11]).await.expect("write");
        let len = client.read_u32().await.expect("reply length") as usize;
        let mut body = vec![0; len];
        client.read_exact(&mut body).await.expect("reply body");
        agent.cancellation_token().cancel();
        body
    }

    /// Comments of an IDENTITIES_ANSWER body, in wire order.
    fn listed_names(body: &[u8]) -> Vec<String> {
        fn take<'a>(rest: &mut &'a [u8]) -> &'a [u8] {
            let len = u32::from_be_bytes(rest[..4].try_into().expect("u32")) as usize;
            let (value, tail) = rest[4..].split_at(len);
            *rest = tail;
            value
        }
        assert_eq!(body[0], 12, "expected SSH_AGENT_IDENTITIES_ANSWER");
        let mut rest = &body[5..];
        (0..u32::from_be_bytes(body[1..5].try_into().expect("u32")))
            .map(|_| {
                take(&mut rest); // key blob
                String::from_utf8_lossy(take(&mut rest)).into_owned()
            })
            .collect()
    }

    #[tokio::test]
    async fn identities_are_listed_in_the_selected_order() {
        let body = list_over_the_wire(|request| {
            assert_eq!(request.keys.len(), 2, "both keys are offered for selection");
            let _ = request.reply.send(ListSelection {
                cipher_ids: vec![
                    "id-2".to_string(),
                    "unknown".to_string(),
                    "id-1".to_string(),
                ],
                user_picked: false,
            });
        })
        .await;
        assert_eq!(listed_names(&body), ["second", "first"]);

        let body = list_over_the_wire(|request| {
            let _ = request.reply.send(ListSelection {
                cipher_ids: vec!["id-1".to_string()],
                user_picked: true,
            });
        })
        .await;
        assert_eq!(listed_names(&body), ["first"]);
    }

    #[tokio::test]
    async fn dropped_selection_fails_the_list_request_closed() {
        let body = list_over_the_wire(drop).await;
        assert_eq!(body, [5], "expected SSH_AGENT_FAILURE");
    }

    /// Audit #9: a message length over the limit closes the connection.
    #[tokio::test]
    async fn oversized_message_length_closes_the_connection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (agent, _request_rx, _response_tx) = create_test_agent();
        let (mut client, server) = tokio::io::duplex(4096);
        let listener = futures::stream::iter(vec![Ok((server, PeerInfo::unknown()))]);
        tokio::spawn(ssh_agent::serve(
            listener,
            agent.clone(),
            agent.keystore_clone(),
            agent.cancellation_token(),
        ));

        client.write_all(&[0xff; 4]).await.expect("write");
        let mut reply = [0u8; 1];
        let read = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut reply))
            .await
            .expect("the agent should hang up at once");
        assert_eq!(read.expect("read"), 0, "expected end of stream");
        agent.cancellation_token().cancel();
    }

    /// Audit #21: every ECDSA curve signs.
    #[test]
    fn ecdsa_keys_sign_on_every_curve() {
        use rsa::signature::Verifier;
        use ssh_key::{Algorithm, EcdsaCurve};

        let message = b"test message for ecdsa";
        for curve in [
            EcdsaCurve::NistP256,
            EcdsaCurve::NistP384,
            EcdsaCurve::NistP521,
        ] {
            let key = ssh_key::PrivateKey::random(
                &mut ssh_key::rand_core::OsRng,
                Algorithm::Ecdsa { curve },
            )
            .expect("key generation should work");
            let signature = sign_with(&key, message, 0).expect("signing should work");
            assert_eq!(
                signature.algorithm().as_str(),
                format!("ecdsa-sha2-{}", curve.as_str())
            );
            key.public_key()
                .key_data()
                .verify(message, &signature)
                .expect("signature should verify");
        }
    }

    #[tokio::test]
    async fn test_agent_sign_with_ed25519_key() {
        let (mut agent, _request_rx, _response_tx) = create_test_agent();
        agent.is_running.store(true, Ordering::Relaxed);

        let keys = vec![(
            TEST_ED25519_KEY.to_string(),
            "ed25519-key".to_string(),
            "ed25519-uuid".to_string(),
        )];
        agent.set_keys(&keys).expect("set_keys should succeed");

        let keystore = agent.keystore.0.read().expect("RwLock is not poisoned");
        assert_eq!(keystore.len(), 1);
        let (_pub_bytes, ssh_key) = keystore.iter().next().expect("should have one key");

        assert_eq!(ssh_key.name, "ed25519-key");
        assert_eq!(ssh_key.cipher_uuid, "ed25519-uuid");
        assert!(!ssh_key.public_key_bytes().is_empty());

        let message = b"test message for ed25519";
        let signature: Signature = ssh_key.sign(message, 0).expect("signing should work");

        assert!(!signature.as_bytes().is_empty());
        assert_eq!(signature.algorithm(), ssh_key::Algorithm::Ed25519);
    }

    /// Audit #1: RSA keys sign, with the hash the client asked for.
    #[test]
    fn rsa_key_signs_with_the_requested_hash() {
        use rsa::signature::Verifier;
        use ssh_key::{Algorithm, HashAlg};

        let (mut agent, _request_rx, _response_tx) = create_test_agent();
        agent.is_running.store(true, Ordering::Relaxed);
        agent
            .set_keys(&[(
                TEST_RSA_KEY.to_string(),
                "rsa-key".to_string(),
                "rsa-uuid".to_string(),
            )])
            .expect("set_keys should succeed");
        let keystore = agent.keystore.0.read().expect("RwLock is not poisoned");
        let ssh_key = keystore.values().next().expect("should have one key");
        let public_key = ssh_key
            .private_key
            .as_ref()
            .expect("unlocked")
            .public_key()
            .clone();

        let message = b"test message for rsa";
        for (flags, hash) in [
            (SSH_AGENT_RSA_SHA2_256, HashAlg::Sha256),
            (SSH_AGENT_RSA_SHA2_512, HashAlg::Sha512),
        ] {
            let signature = ssh_key.sign(message, flags).expect("signing should work");
            assert_eq!(signature.algorithm(), Algorithm::Rsa { hash: Some(hash) });
            public_key
                .key_data()
                .verify(message, &signature)
                .expect("signature should verify");
        }
        assert!(
            ssh_key.sign(message, 0).is_err(),
            "SHA-1 ssh-rsa is refused"
        );
    }

    #[tokio::test]
    async fn forwarding_flag_survives_the_remote_hop_session_bind() {
        use bitwarden_russh::session_bind::SessionBindInfo;
        use bitwarden_russh::ssh_agent::Agent as _;

        let (agent, _request_rx, _response_tx) = create_test_agent();
        let info = PeerInfo::new(0, 1, "ssh".to_string());
        for (is_forwarding, host_key) in [(true, b"hop1".to_vec()), (false, b"hop2".to_vec())] {
            agent
                .set_sessionbind_info(
                    &SessionBindResult::Success(SessionBindInfo {
                        is_forwarding,
                        host_key,
                        session_identifier: Vec::new(),
                    }),
                    &info,
                )
                .await;
        }

        assert!(
            info.is_forwarding(),
            "second bind must not clear forwarding"
        );
        assert_eq!(info.host_key(), b"hop2", "last bind is the destination");
    }

    // lock-keystore: after lock(), identities remain listable (ssh-add -l keeps
    // working so auto-unlock-on-request can fire) but hold no private material,
    // so signable_key_count drops to 0 and status can report the truth.
    #[test]
    fn lock_keeps_keys_listable_but_not_signable() {
        let (mut agent, _request_rx, _response_tx) = create_test_agent();
        agent.is_running.store(true, Ordering::Relaxed);
        agent
            .set_keys(&[(
                TEST_ED25519_KEY.to_string(),
                "ed25519-key".to_string(),
                "ed25519-uuid".to_string(),
            )])
            .expect("set_keys should succeed");

        assert_eq!(agent.key_count(), 1);
        assert_eq!(agent.signable_key_count(), 1);

        agent.lock().expect("lock should succeed");

        assert_eq!(agent.key_count(), 1, "identity stays listable while locked");
        assert_eq!(
            agent.signable_key_count(),
            0,
            "no private material is signable while locked"
        );
    }
}
