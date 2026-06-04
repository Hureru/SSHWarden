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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ControlResponse {
    pub fn ok(message: &str) -> Self {
        Self {
            ok: true,
            message: Some(message.to_string()),
            error: None,
            locked: None,
            key_count: None,
            details: None,
        }
    }

    pub fn err(error: &str) -> Self {
        Self {
            ok: false,
            message: None,
            error: Some(error.to_string()),
            locked: None,
            key_count: None,
            details: None,
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
            details: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

pub const CONTROL_PIPE_NAME: &str = r"\\.\pipe\sshwarden-control";

/// Maximum number of bytes accepted for a single control command line on the
/// daemon side. The control protocol is one short JSON object per connection,
/// so anything larger is malformed or hostile; capping the read avoids
/// unbounded buffering from a local process flooding the channel (EH-08).
const MAX_CONTROL_LINE_BYTES: u64 = 64 * 1024;

/// A request sent from the control server to the main loop.
pub struct ControlRequest {
    pub action: ControlAction,
    pub reply: tokio::sync::oneshot::Sender<ControlResponse>,
}

/// Actions that can be performed via the control channel.
pub enum ControlAction {
    Lock,
    Unlock,
    UnlockPin {
        pin: String,
    },
    UnlockHello,
    UnlockNative,
    UnlockPassword {
        password: String,
    },
    Status {
        json: bool,
    },
    Sync,
    SetPin {
        pin: String,
    },
    Forget,
    /// Open the host-binding management dialog. The daemon dispatches a
    /// `UIRequest::BindHostsDialog` and responds once the dialog closes.
    BindHostsDialog,
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
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
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

        // Read one line from the client (bounded; EH-08)
        let (reader, mut writer) = tokio::io::split(server);
        let mut buf_reader = BufReader::new(reader.take(MAX_CONTROL_LINE_BYTES));
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

        let response = handle_control_line(line.trim(), &tx).await;
        write_control_response(&mut writer, &response).await;
    }
}

async fn dispatch_control_command(
    cmd: ControlCommand,
    tx: &tokio::sync::mpsc::Sender<ControlRequest>,
) -> ControlResponse {
    let action = match cmd.cmd.as_str() {
        "lock" => ControlAction::Lock,
        "unlock" => ControlAction::Unlock,
        "unlock-hello" => ControlAction::UnlockHello,
        "unlock-native" => ControlAction::UnlockNative,
        "status" => ControlAction::Status { json: false },
        "status-json" => ControlAction::Status { json: true },
        "sync" => ControlAction::Sync,
        "forget" => ControlAction::Forget,
        "bind-hosts-dialog" => ControlAction::BindHostsDialog,
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
        other => return ControlResponse::err(&format!("Unknown command: {other}")),
    };

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = ControlRequest {
        action,
        reply: reply_tx,
    };

    if tx.send(request).await.is_err() {
        return ControlResponse::err("Agent is shutting down");
    }

    match reply_rx.await {
        Ok(resp) => resp,
        Err(_) => ControlResponse::err("Internal error: no reply from agent"),
    }
}

async fn handle_control_line(
    line: &str,
    tx: &tokio::sync::mpsc::Sender<ControlRequest>,
) -> ControlResponse {
    let cmd: ControlCommand = match serde_json::from_str(line) {
        Ok(c) => c,
        Err(e) => return ControlResponse::err(&format!("Invalid command: {e}")),
    };

    dispatch_control_command(cmd, tx).await
}

async fn write_control_response<W>(writer: &mut W, response: &ControlResponse)
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let resp_json = serde_json::to_string(response).unwrap_or_default();
    let _ = writer.write_all(format!("{resp_json}\n").as_bytes()).await;
    let _ = writer.flush().await;
}

/// Start the Unix control socket server (daemon side).
#[cfg(not(windows))]
pub async fn start_control_server(
    tx: tokio::sync::mpsc::Sender<ControlRequest>,
    cancel: tokio_util::sync::CancellationToken,
) {
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
    use tokio::net::UnixListener;

    let path = match sshwarden_config::default_control_socket_path() {
        Ok(path) => path,
        Err(e) => {
            error!(error = %e, "Failed to resolve control socket path");
            return;
        }
    };

    if let Some(parent) = path.parent() {
        let parent_existed = parent.exists();
        if let Err(e) = std::fs::create_dir_all(parent) {
            error!(error = %e, ?parent, "Failed to create control socket directory");
            return;
        }
        if !parent_existed {
            if let Err(e) = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            {
                error!(error = %e, ?parent, "Failed to set control socket directory permissions");
                return;
            }
        }
    }

    if path.exists() {
        if let Err(e) = std::fs::remove_file(&path) {
            error!(error = %e, ?path, "Failed to remove stale control socket");
            return;
        }
    }

    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(e) => {
            error!(error = %e, ?path, "Failed to bind control socket");
            return;
        }
    };

    if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
        error!(error = %e, ?path, "Failed to set control socket permissions");
    }

    info!(?path, "Control server starting on Unix socket");

    loop {
        let (stream, _addr) = tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok(value) => value,
                    Err(e) => {
                        error!(error = %e, "Control socket accept error");
                        continue;
                    }
                }
            }
            _ = cancel.cancelled() => {
                info!(?path, "Control server shutting down");
                let _ = std::fs::remove_file(&path);
                return;
            }
        };

        let tx = tx.clone();
        tokio::spawn(async move {
            let (reader, mut writer) = tokio::io::split(stream);
            let mut buf_reader = BufReader::new(reader.take(MAX_CONTROL_LINE_BYTES));
            let mut line = String::new();

            match buf_reader.read_line(&mut line).await {
                Ok(0) => return,
                Ok(_) => {}
                Err(e) => {
                    error!(error = %e, "Control socket read error");
                    return;
                }
            }

            let response = handle_control_line(line.trim(), &tx).await;
            write_control_response(&mut writer, &response).await;
        });
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

/// Send a control command to the running daemon (client side).
#[cfg(not(windows))]
pub async fn send_control_command(cmd: &str) -> anyhow::Result<ControlResponse> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let path = sshwarden_config::default_control_socket_path()?;
    let stream = UnixStream::connect(&path).await.map_err(|e| {
        anyhow::anyhow!(
            "Failed to connect to SSHWarden daemon at {} (is it running?): {}",
            path.display(),
            e
        )
    })?;

    let (reader, mut writer) = tokio::io::split(stream);

    let command = ControlCommand {
        cmd: cmd.to_string(),
    };
    let cmd_json = serde_json::to_string(&command)?;
    writer.write_all(format!("{cmd_json}\n").as_bytes()).await?;
    writer.shutdown().await?;

    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    buf_reader.read_line(&mut line).await?;

    let response: ControlResponse = serde_json::from_str(line.trim())?;
    Ok(response)
}
