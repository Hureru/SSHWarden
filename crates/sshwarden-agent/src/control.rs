use serde::{Deserialize, Serialize};
use tracing::{error, info};

#[derive(Debug, Serialize, Deserialize)]
pub struct ControlCommand {
    pub cmd: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ControlResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_count: Option<usize>,
}

impl ControlResponse {
    pub fn ok(message: &str) -> Self {
        Self {
            ok: true,
            message: Some(message.to_string()),
            error: None,
            locked: None,
            key_count: None,
        }
    }

    pub fn err(error: &str) -> Self {
        Self {
            ok: false,
            message: None,
            error: Some(error.to_string()),
            locked: None,
            key_count: None,
        }
    }

    pub fn status(locked: bool, key_count: usize) -> Self {
        Self {
            ok: true,
            message: Some(if locked {
                "Vault is locked".to_string()
            } else {
                "Vault is unlocked".to_string()
            }),
            error: None,
            locked: Some(locked),
            key_count: Some(key_count),
        }
    }
}

pub const CONTROL_PIPE_NAME: &str = r"\\.\pipe\sshwarden-control";

/// A request sent from the control server to the main loop.
pub struct ControlRequest {
    pub action: ControlAction,
    pub reply: tokio::sync::oneshot::Sender<ControlResponse>,
}

/// Actions that can be performed via the control channel.
pub enum ControlAction {
    Lock,
    Unlock,
    UnlockPin { pin: String },
    UnlockHello,
    UnlockPassword { password: String },
    Status,
    Sync,
    SetPin { pin: String },
}

/// Start the control pipe server (daemon side).
///
/// Listens on the named pipe and forwards parsed commands to the main loop
/// via the provided `tx` channel. Each command gets a oneshot channel for
/// the response.
#[cfg(windows)]
pub async fn start_control_server(
    tx: tokio::sync::mpsc::Sender<ControlRequest>,
    cancel: tokio_util::sync::CancellationToken,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ServerOptions;

    info!("Control server starting on {}", CONTROL_PIPE_NAME);

    loop {
        // Create a new pipe instance for each connection
        let server = match ServerOptions::new()
            .first_pipe_instance(false)
            .create(CONTROL_PIPE_NAME)
        {
            Ok(s) => s,
            Err(e) => {
                // If this is the very first instance, try with first_pipe_instance(true)
                match ServerOptions::new()
                    .first_pipe_instance(true)
                    .create(CONTROL_PIPE_NAME)
                {
                    Ok(s) => s,
                    Err(e2) => {
                        error!("Failed to create control pipe: {} / {}", e, e2);
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
                }
            }
        };

        // Wait for a client to connect, or cancellation
        tokio::select! {
            result = server.connect() => {
                if let Err(e) = result {
                    error!("Control pipe connect error: {}", e);
                    continue;
                }
            }
            _ = cancel.cancelled() => {
                info!("Control server shutting down");
                return;
            }
        }

        // Read one line from the client
        let (reader, mut writer) = tokio::io::split(server);
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();

        match buf_reader.read_line(&mut line).await {
            Ok(0) => {
                // Client disconnected without sending anything
                continue;
            }
            Ok(_) => {}
            Err(e) => {
                error!("Control pipe read error: {}", e);
                continue;
            }
        }

        let line = line.trim();
        let cmd: ControlCommand = match serde_json::from_str(line) {
            Ok(c) => c,
            Err(e) => {
                let resp = ControlResponse::err(&format!("Invalid command: {}", e));
                let resp_json = serde_json::to_string(&resp).unwrap_or_default();
                let _ = writer
                    .write_all(format!("{}\n", resp_json).as_bytes())
                    .await;
                let _ = writer.flush().await;
                continue;
            }
        };

        let action = match cmd.cmd.as_str() {
            "lock" => ControlAction::Lock,
            "unlock" => ControlAction::Unlock,
            "unlock-hello" => ControlAction::UnlockHello,
            "status" => ControlAction::Status,
            "sync" => ControlAction::Sync,
            s if s.starts_with("unlock-pin:") => {
                let pin = s.strip_prefix("unlock-pin:").unwrap_or("").to_string();
                ControlAction::UnlockPin { pin }
            }
            s if s.starts_with("unlock-password:") => {
                let password = s.strip_prefix("unlock-password:").unwrap_or("").to_string();
                ControlAction::UnlockPassword { password }
            }
            s if s.starts_with("set-pin:") => {
                let pin = s.strip_prefix("set-pin:").unwrap_or("").to_string();
                ControlAction::SetPin { pin }
            }
            other => {
                let resp = ControlResponse::err(&format!("Unknown command: {}", other));
                let resp_json = serde_json::to_string(&resp).unwrap_or_default();
                let _ = writer
                    .write_all(format!("{}\n", resp_json).as_bytes())
                    .await;
                let _ = writer.flush().await;
                continue;
            }
        };

        // Send to main loop and wait for response
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let request = ControlRequest {
            action,
            reply: reply_tx,
        };

        if tx.send(request).await.is_err() {
            let resp = ControlResponse::err("Agent is shutting down");
            let resp_json = serde_json::to_string(&resp).unwrap_or_default();
            let _ = writer
                .write_all(format!("{}\n", resp_json).as_bytes())
                .await;
            let _ = writer.flush().await;
            continue;
        }

        let response = match reply_rx.await {
            Ok(resp) => resp,
            Err(_) => ControlResponse::err("Internal error: no reply from agent"),
        };

        let resp_json = serde_json::to_string(&response).unwrap_or_default();
        let _ = writer
            .write_all(format!("{}\n", resp_json).as_bytes())
            .await;
        let _ = writer.flush().await;
    }
}

/// Send a control command to the running daemon (client side).
#[cfg(windows)]
pub async fn send_control_command(cmd: &str) -> anyhow::Result<ControlResponse> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ClientOptions;

    // Try to connect to the control pipe
    let client = ClientOptions::new().open(CONTROL_PIPE_NAME).map_err(|e| {
        anyhow::anyhow!(
            "Failed to connect to SSHWarden daemon (is it running?): {}",
            e
        )
    })?;

    let (reader, mut writer) = tokio::io::split(client);

    // Send command
    let command = ControlCommand {
        cmd: cmd.to_string(),
    };
    let cmd_json = serde_json::to_string(&command)?;
    writer
        .write_all(format!("{}\n", cmd_json).as_bytes())
        .await?;
    writer.shutdown().await?;

    // Read response
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    buf_reader.read_line(&mut line).await?;

    let response: ControlResponse = serde_json::from_str(line.trim())?;
    Ok(response)
}
