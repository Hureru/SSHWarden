use std::time::Duration;

use anyhow::{anyhow, Context};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

/// Events emitted by the notification hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncEvent {
    /// A cipher was created, updated, deleted, or the vault was synced.
    CipherChanged,
    /// The server requests a logout (e.g., remote session revocation).
    LogOut,
}

/// Bitwarden/Vaultwarden SignalR notification client.
///
/// Connects via WebSocket to the `/notifications/hub` endpoint and emits
/// [`SyncEvent`]s when the vault changes on the server side.
pub struct NotificationClient {
    cancel: tokio_util::sync::CancellationToken,
    _task: tokio::task::JoinHandle<()>,
}

/// SignalR record separator (ASCII 0x1E).
const RECORD_SEP: u8 = 0x1E;

impl NotificationClient {
    /// Connect to the notification hub and start the background listener.
    ///
    /// Returns the client handle and a receiver for sync events.
    pub async fn connect(
        notifications_url: &str,
        access_token: &str,
    ) -> anyhow::Result<(Self, mpsc::Receiver<SyncEvent>)> {
        // Perform initial connect + handshake
        let ws_url = build_ws_url(notifications_url, access_token)?;
        do_connect_and_handshake(&ws_url).await?;

        info!("Connected to notification hub");

        let (event_tx, event_rx) = mpsc::channel::<SyncEvent>(32);
        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel_clone = cancel.clone();
        let url = notifications_url.to_string();
        let token = access_token.to_string();

        let task = tokio::spawn(async move {
            run_message_loop(url, token, event_tx, cancel_clone).await;
        });

        Ok((
            Self {
                cancel,
                _task: task,
            },
            event_rx,
        ))
    }

    /// Stop the notification client.
    pub fn stop(&self) {
        self.cancel.cancel();
    }
}

impl Drop for NotificationClient {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Connect to the WebSocket and perform the SignalR handshake.
///
/// Returns `Ok(())` on success. The actual message processing is done in `run_message_loop`
/// which reconnects independently.
async fn do_connect_and_handshake(ws_url: &str) -> anyhow::Result<()> {
    debug!("Connecting to notification hub: {}", ws_url);
    let (ws_stream, _) = tokio_tungstenite::connect_async(ws_url)
        .await
        .context("Failed to connect to notification hub")?;

    let (mut ws_write, mut ws_read) = ws_stream.split();

    // SignalR handshake
    let handshake = format!(
        "{{\"protocol\":\"messagepack\",\"version\":1}}{}",
        RECORD_SEP as char
    );
    ws_write
        .send(Message::Text(handshake.into()))
        .await
        .context("Failed to send SignalR handshake")?;

    // Read handshake response — expect `{}\x1e`
    let handshake_resp = tokio::time::timeout(Duration::from_secs(10), ws_read.next())
        .await
        .context("Handshake timeout")?
        .ok_or_else(|| anyhow!("WebSocket closed during handshake"))?
        .context("WebSocket error during handshake")?;

    match &handshake_resp {
        Message::Text(t) => {
            let trimmed = t.trim_end_matches(RECORD_SEP as char);
            if trimmed != "{}" {
                warn!("Unexpected handshake response: {}", t);
            }
        }
        _ => warn!("Unexpected handshake message type: {:?}", handshake_resp),
    }

    // Drop the stream — run_message_loop creates its own connection.
    // This initial connect is just to validate that the URL and token work.
    drop(ws_write);
    drop(ws_read);
    Ok(())
}

/// Background loop: connect, read messages, parse SignalR/MessagePack frames, forward events.
/// Automatically reconnects with exponential backoff on disconnect.
async fn run_message_loop(
    notifications_url: String,
    access_token: String,
    event_tx: mpsc::Sender<SyncEvent>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(60);

    loop {
        if cancel.is_cancelled() {
            return;
        }

        // Connect
        let ws_url = match build_ws_url(&notifications_url, &access_token) {
            Ok(url) => url,
            Err(e) => {
                warn!("Failed to build notification URL: {}", e);
                return;
            }
        };

        let ws_result = tokio_tungstenite::connect_async(&ws_url).await;
        let (ws_stream, _) = match ws_result {
            Ok(s) => {
                backoff = Duration::from_secs(1);
                s
            }
            Err(e) => {
                warn!("Notification hub connect failed: {}", e);
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(max_backoff);
                continue;
            }
        };

        let (mut ws_write, mut ws_read) = ws_stream.split();

        // Handshake
        let handshake = format!(
            "{{\"protocol\":\"messagepack\",\"version\":1}}{}",
            RECORD_SEP as char
        );
        if ws_write.send(Message::Text(handshake.into())).await.is_err() {
            warn!("Failed to send handshake, reconnecting...");
            continue;
        }

        // Read handshake response
        match tokio::time::timeout(Duration::from_secs(10), ws_read.next()).await {
            Ok(Some(Ok(_))) => {}
            _ => {
                warn!("Handshake response failed, reconnecting...");
                continue;
            }
        }

        debug!("Notification hub handshake complete");

        // Message loop
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    debug!("Notification client cancelled");
                    return;
                }
                msg = ws_read.next() => {
                    match msg {
                        Some(Ok(Message::Binary(data))) => {
                            if let Some(event) = parse_signalr_message(&data) {
                                if event_tx.send(event).await.is_err() {
                                    debug!("Event receiver dropped");
                                    return;
                                }
                            }
                            backoff = Duration::from_secs(1);
                        }
                        Some(Ok(Message::Text(text))) => {
                            let trimmed = text.trim_end_matches(RECORD_SEP as char);
                            if trimmed.contains("\"type\":6") || trimmed.contains("\"type\": 6") {
                                let pong = format!("{{\"type\":6}}{}", RECORD_SEP as char);
                                let _ = ws_write.send(Message::Text(pong.into())).await;
                            }
                        }
                        Some(Ok(Message::Ping(data))) => {
                            let _ = ws_write.send(Message::Pong(data)).await;
                        }
                        Some(Ok(Message::Close(_))) => {
                            info!("Notification hub closed by server");
                            break;
                        }
                        Some(Err(e)) => {
                            warn!("Notification hub error: {}", e);
                            break;
                        }
                        None => {
                            info!("Notification hub stream ended");
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        // Disconnected — wait before reconnecting
        info!(
            "Reconnecting to notification hub in {}s...",
            backoff.as_secs()
        );
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(max_backoff);
    }
}

/// Build the WebSocket URL for the notification hub.
fn build_ws_url(notifications_url: &str, access_token: &str) -> anyhow::Result<String> {
    let base = notifications_url.trim_end_matches('/');
    let ws_base = if base.starts_with("https://") {
        base.replacen("https://", "wss://", 1)
    } else if base.starts_with("http://") {
        base.replacen("http://", "ws://", 1)
    } else {
        format!("wss://{base}")
    };
    // Vaultwarden/Bitwarden uses /notifications/hub for WebSocket endpoint
    // If the base already ends with /notifications, append /hub
    // Otherwise append /notifications/hub
    let path = if ws_base.ends_with("/notifications") {
        format!("{}/hub", ws_base)
    } else {
        format!("{}/notifications/hub", ws_base)
    };
    Ok(format!("{}?access_token={}", path, access_token))
}

/// Parse a SignalR MessagePack binary frame and extract SyncEvent if applicable.
///
/// SignalR binary format: variable-length prefix (VarInt) + MessagePack payload.
/// Invocation messages (type=1): `[1, headers, invocationId, target, arguments]`
/// where arguments[0] is a map containing `{"Type": <UpdateType>, ...}`.
fn parse_signalr_message(data: &[u8]) -> Option<SyncEvent> {
    let (payload_len, header_size) = read_varint(data)?;
    let payload_start = header_size;
    let payload_end = payload_start + payload_len;

    if payload_end > data.len() {
        debug!(
            "SignalR frame truncated: expected {} bytes, got {}",
            payload_end,
            data.len()
        );
        return None;
    }

    let payload = &data[payload_start..payload_end];

    let mut cursor = std::io::Cursor::new(payload);
    let value = match rmpv::decode::read_value(&mut cursor) {
        Ok(v) => v,
        Err(e) => {
            debug!("Failed to decode MessagePack: {}", e);
            return None;
        }
    };

    let arr = value.as_array()?;
    let msg_type = arr.first()?.as_u64()?;

    match msg_type {
        1 => {
            // Invocation: [1, headers, invocationId, target, arguments]
            let arguments = arr.get(4)?.as_array()?;
            let first_arg = arguments.first()?;
            let update_type = extract_update_type(first_arg)?;

            match update_type {
                0 | 1 | 2 | 4 | 5 | 6 => {
                    debug!("Notification: cipher changed (UpdateType={})", update_type);
                    Some(SyncEvent::CipherChanged)
                }
                11 => {
                    debug!("Notification: logout requested");
                    Some(SyncEvent::LogOut)
                }
                _ => {
                    debug!("Notification: unhandled UpdateType={}", update_type);
                    None
                }
            }
        }
        6 => None, // Ping
        _ => {
            debug!("SignalR message type={}, ignoring", msg_type);
            None
        }
    }
}

/// Extract "Type" field from a MessagePack map value.
fn extract_update_type(value: &rmpv::Value) -> Option<u64> {
    if let Some(map) = value.as_map() {
        for (k, v) in map {
            let key_str = k.as_str().unwrap_or("");
            if key_str == "Type" || key_str == "type" {
                return v.as_u64();
            }
        }
    }
    None
}

/// Read a SignalR VarInt from the start of a byte slice.
/// Returns `(value, bytes_consumed)`.
fn read_varint(data: &[u8]) -> Option<(usize, usize)> {
    let mut result: usize = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        result |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}
