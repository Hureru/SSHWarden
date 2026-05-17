use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use futures_util::{Sink, SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type WsWrite = futures_util::stream::SplitSink<WsStream, Message>;
type WsRead = futures_util::stream::SplitStream<WsStream>;

/// Events emitted by the notification hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncEvent {
    /// A cipher was created, updated, deleted, or the vault was synced.
    CipherChanged,
    /// The server requests a logout (e.g. remote session revocation).
    LogOut,
    /// Notification delivery is degraded; caller should fallback-sync if safe.
    FallbackSyncDue,
}

/// Runtime options for the notification connection.
#[derive(Debug, Clone, Copy)]
pub struct NotificationOptions {
    /// SignalR binary ping cadence while the WebSocket is connected.
    pub keepalive_interval: Duration,
    /// Maximum time without any message/echo/ping/pong before reconnecting.
    pub idle_timeout: Duration,
    /// Failed reconnect attempts before emitting [`SyncEvent::FallbackSyncDue`].
    pub reconnect_attempts_before_fallback: usize,
    /// Maximum exponential reconnect backoff.
    pub reconnect_max_backoff: Duration,
    /// Cadence for fallback sync events while notifications remain degraded.
    pub fallback_sync_interval: Duration,
}

impl Default for NotificationOptions {
    fn default() -> Self {
        Self {
            keepalive_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(90),
            reconnect_attempts_before_fallback: 3,
            reconnect_max_backoff: Duration::from_secs(60),
            fallback_sync_interval: Duration::from_secs(300),
        }
    }
}

/// Bitwarden/Vaultwarden SignalR notification client.
///
/// Connects via WebSocket to the configured notification hub endpoint and emits
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
        Self::connect_with_options(
            notifications_url,
            access_token,
            NotificationOptions::default(),
        )
        .await
    }

    /// Connect to the notification hub using explicit runtime options.
    pub async fn connect_with_options(
        notifications_url: &str,
        access_token: &str,
        options: NotificationOptions,
    ) -> anyhow::Result<(Self, mpsc::Receiver<SyncEvent>)> {
        // Try one eager connect + handshake so a healthy hub is usable
        // immediately. If it fails, still start the background reconnect loop;
        // fallback-sync events are emitted only after repeated reconnect failures.
        let ws_url = build_ws_url(notifications_url, access_token)?;
        let initial_connection = match connect_and_initialize(&ws_url).await {
            Ok(connection) => {
                info!("Connected to notification hub");
                Some(connection)
            }
            Err(e) => {
                warn!(
                    "Initial notification hub connect failed; will retry in background: {}",
                    e
                );
                None
            }
        };

        let (event_tx, event_rx) = mpsc::channel::<SyncEvent>(32);
        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel_clone = cancel.clone();
        let url = notifications_url.to_string();
        let token = access_token.to_string();

        let task = tokio::spawn(async move {
            run_message_loop(
                url,
                token,
                options,
                event_tx,
                cancel_clone,
                initial_connection,
            )
            .await;
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

/// Background loop: connect, read messages, parse SignalR/MessagePack frames,
/// forward events, keep the connection alive, and emit fallback-sync events when
/// notifications remain degraded.
async fn run_message_loop(
    notifications_url: String,
    access_token: String,
    options: NotificationOptions,
    event_tx: mpsc::Sender<SyncEvent>,
    cancel: tokio_util::sync::CancellationToken,
    mut initial_connection: Option<(WsWrite, WsRead)>,
) {
    let mut backoff = Duration::from_secs(1);
    let mut failed_reconnect_attempts = 0usize;
    let mut last_fallback_sent: Option<Instant> = None;

    loop {
        if cancel.is_cancelled() {
            return;
        }

        let (mut ws_write, mut ws_read) = if let Some(parts) = initial_connection.take() {
            parts
        } else {
            let ws_url = match build_ws_url(&notifications_url, &access_token) {
                Ok(url) => url,
                Err(e) => {
                    warn!("Failed to build notification URL: {}", e);
                    return;
                }
            };

            match connect_and_initialize(&ws_url).await {
                Ok(parts) => {
                    failed_reconnect_attempts = 0;
                    backoff = Duration::from_secs(1);
                    parts
                }
                Err(e) => {
                    failed_reconnect_attempts = failed_reconnect_attempts.saturating_add(1);
                    warn!(
                        attempts = failed_reconnect_attempts,
                        "Notification hub connect/handshake failed: {}", e
                    );
                    maybe_emit_fallback_sync(
                        failed_reconnect_attempts,
                        &mut last_fallback_sent,
                        &options,
                        &event_tx,
                    )
                    .await;
                    wait_before_reconnect(backoff, &cancel).await;
                    backoff = (backoff * 2).min(options.reconnect_max_backoff);
                    continue;
                }
            }
        };

        debug!("Notification hub handshake complete");
        let mut last_seen = Instant::now();
        let mut keepalive_interval = tokio::time::interval(options.keepalive_interval);
        keepalive_interval.tick().await; // skip immediate tick
        let mut idle_check_interval = tokio::time::interval(Duration::from_secs(5));
        idle_check_interval.tick().await;

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    debug!("Notification client cancelled");
                    return;
                }
                _ = keepalive_interval.tick() => {
                    if let Err(e) = ws_write.send(Message::Binary(create_signalr_ping().into())).await {
                        warn!("Failed to send notification keepalive ping: {}", e);
                        break;
                    }
                }
                _ = idle_check_interval.tick() => {
                    if last_seen.elapsed() > options.idle_timeout {
                        warn!(
                            idle_secs = last_seen.elapsed().as_secs(),
                            "Notification hub idle timeout exceeded, reconnecting"
                        );
                        let _ = ws_write.close().await;
                        break;
                    }
                }
                msg = ws_read.next() => {
                    match msg {
                        Some(Ok(Message::Binary(data))) => {
                            last_seen = Instant::now();
                            if let Some(event) = parse_signalr_message(&data) {
                                if event_tx.send(event).await.is_err() {
                                    debug!("Event receiver dropped");
                                    return;
                                }
                            }
                        }
                        Some(Ok(Message::Text(text))) => {
                            last_seen = Instant::now();
                            let trimmed = text.trim_end_matches(RECORD_SEP as char);
                            if trimmed.contains("\"type\":6") || trimmed.contains("\"type\": 6") {
                                let pong = format!("{{\"type\":6}}{}", RECORD_SEP as char);
                                let _ = ws_write.send(Message::Text(pong.into())).await;
                            }
                        }
                        Some(Ok(Message::Ping(data))) => {
                            last_seen = Instant::now();
                            let _ = ws_write.send(Message::Pong(data)).await;
                        }
                        Some(Ok(Message::Pong(_))) => {
                            last_seen = Instant::now();
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

        failed_reconnect_attempts = failed_reconnect_attempts.saturating_add(1);
        maybe_emit_fallback_sync(
            failed_reconnect_attempts,
            &mut last_fallback_sent,
            &options,
            &event_tx,
        )
        .await;

        info!(
            "Reconnecting to notification hub in {}s...",
            backoff.as_secs()
        );
        wait_before_reconnect(backoff, &cancel).await;
        backoff = (backoff * 2).min(options.reconnect_max_backoff);
    }
}

async fn connect_and_initialize(ws_url: &str) -> anyhow::Result<(WsWrite, WsRead)> {
    let (ws_stream, _) = tokio_tungstenite::connect_async(ws_url)
        .await
        .context("Failed to connect to notification hub")?;
    let (mut ws_write, mut ws_read) = ws_stream.split();
    send_initial_message(&mut ws_write).await?;

    let handshake_resp = tokio::time::timeout(Duration::from_secs(10), ws_read.next())
        .await
        .context("Handshake timeout")?
        .ok_or_else(|| anyhow!("WebSocket closed during handshake"))?
        .context("WebSocket error during handshake")?;

    if !is_handshake_response(&handshake_resp) {
        return Err(anyhow!(
            "Unexpected notification handshake response: {:?}",
            handshake_resp
        ));
    }

    Ok((ws_write, ws_read))
}

async fn send_initial_message<S>(ws_write: &mut S) -> anyhow::Result<()>
where
    S: Sink<Message> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let handshake = format!(
        "{{\"protocol\":\"messagepack\",\"version\":1}}{}",
        RECORD_SEP as char
    );
    ws_write
        .send(Message::Text(handshake.into()))
        .await
        .context("Failed to send SignalR handshake")
}

async fn wait_before_reconnect(backoff: Duration, cancel: &tokio_util::sync::CancellationToken) {
    tokio::select! {
        _ = cancel.cancelled() => {}
        _ = tokio::time::sleep(backoff) => {}
    }
}

async fn maybe_emit_fallback_sync(
    failed_reconnect_attempts: usize,
    last_fallback_sent: &mut Option<Instant>,
    options: &NotificationOptions,
    event_tx: &mpsc::Sender<SyncEvent>,
) {
    if options.fallback_sync_interval.is_zero()
        || failed_reconnect_attempts < options.reconnect_attempts_before_fallback
    {
        return;
    }

    let should_emit = last_fallback_sent
        .map(|instant| instant.elapsed() >= options.fallback_sync_interval)
        .unwrap_or(true);

    if should_emit {
        *last_fallback_sent = Some(Instant::now());
        if event_tx.send(SyncEvent::FallbackSyncDue).await.is_err() {
            debug!("Event receiver dropped before fallback sync event");
        }
    }
}

/// Build the WebSocket URL for the notification hub.
///
/// `notifications_url` can be either a service base URL (`https://host/notifications`)
/// or a complete hub URL (`wss://host/notifications/hub`). Complete `/hub` and
/// `/anonymous-hub` URLs are used as-is after converting the scheme.
fn build_ws_url(notifications_url: &str, access_token: &str) -> anyhow::Result<String> {
    let base = notifications_url.trim_end_matches('/');
    let ws_base = to_ws_scheme(base);
    let hub = if ws_base.ends_with("/hub") || ws_base.ends_with("/anonymous-hub") {
        ws_base
    } else {
        format!("{}/hub", ws_base)
    };
    Ok(format!("{}?access_token={}", hub, access_token))
}

fn to_ws_scheme(url: &str) -> String {
    if url.starts_with("https://") {
        url.replacen("https://", "wss://", 1)
    } else if url.starts_with("http://") {
        url.replacen("http://", "ws://", 1)
    } else if url.starts_with("wss://") || url.starts_with("ws://") {
        url.to_string()
    } else {
        format!("wss://{url}")
    }
}

fn is_handshake_response(message: &Message) -> bool {
    match message {
        Message::Text(text) => is_handshake_bytes(text.as_bytes()),
        Message::Binary(bytes) => is_handshake_bytes(bytes.as_ref()),
        _ => false,
    }
}

fn is_handshake_bytes(bytes: &[u8]) -> bool {
    let bytes = bytes.strip_suffix(&[RECORD_SEP]).unwrap_or(bytes);
    bytes == b"{}"
}

/// Create a SignalR MessagePack ping frame: VarInt length prefix + `[6]`.
fn create_signalr_ping() -> Vec<u8> {
    let value = rmpv::Value::Array(vec![6.into()]);
    encode_signalr_message(&value)
}

fn encode_signalr_message(value: &rmpv::Value) -> Vec<u8> {
    let mut payload = Vec::new();
    rmpv::encode::write_value(&mut payload, value).expect("MessagePack encoding should not fail");

    let mut size = payload.len();
    let mut frame = Vec::new();
    loop {
        let mut size_part = size & 0x7f;
        size >>= 7;
        if size > 0 {
            size_part |= 0x80;
        }
        frame.push(size_part as u8);
        if size == 0 {
            break;
        }
    }
    frame.extend(payload);
    frame
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_ws_url_appends_hub_to_notifications_base() {
        let url = build_ws_url("https://example.com/notifications", "token").unwrap();
        assert_eq!(
            url,
            "wss://example.com/notifications/hub?access_token=token"
        );
    }

    #[test]
    fn build_ws_url_uses_complete_hub_url() {
        let url = build_ws_url("wss://example.com/notifications/hub", "token").unwrap();
        assert_eq!(
            url,
            "wss://example.com/notifications/hub?access_token=token"
        );
    }

    #[test]
    fn handshake_response_accepts_binary() {
        assert!(is_handshake_response(&Message::Binary(
            Vec::from(b"{}\x1e".as_slice()).into()
        )));
    }

    #[test]
    fn signalr_ping_frame_is_messagepack_ping() {
        assert_eq!(create_signalr_ping(), vec![2, 0x91, 6]);
    }
}
