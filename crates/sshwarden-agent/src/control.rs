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

/// SEC-01 (Windows): build a security descriptor restricting the control pipe
/// to the current user + LocalSystem, so the named pipe is not created with the
/// default DACL (which grants Everyone read access). Best-effort: callers fall
/// back to the default DACL if the descriptor cannot be built.
#[cfg(windows)]
mod win_security {
    use windows::core::{HSTRING, PWSTR};
    use windows::Win32::Foundation::LocalFree;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// Owns the security descriptor and the SECURITY_ATTRIBUTES referencing it;
    /// frees the descriptor on drop.
    pub struct PipeSecurity {
        sd: PSECURITY_DESCRIPTOR,
        sa: SECURITY_ATTRIBUTES,
    }

    impl PipeSecurity {
        /// Build a DACL granting only the current user and LocalSystem full
        /// control. Returns None on any failure (caller uses the default DACL).
        pub fn current_user_only() -> Option<Self> {
            unsafe {
                let sid = current_user_sid_string()?;
                let sddl = format!("D:P(A;;GA;;;{sid})(A;;GA;;;SY)");
                let mut sd = PSECURITY_DESCRIPTOR(core::ptr::null_mut());
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    &HSTRING::from(&sddl),
                    SDDL_REVISION_1,
                    &mut sd,
                    None,
                )
                .ok()?;
                if sd.0.is_null() {
                    return None;
                }
                let sa = SECURITY_ATTRIBUTES {
                    nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: sd.0,
                    bInheritHandle: false.into(),
                };
                Some(Self { sd, sa })
            }
        }

        /// Raw pointer to the SECURITY_ATTRIBUTES for
        /// `create_with_security_attributes_raw`. Valid while `self` is alive.
        pub fn as_attrs_ptr(&mut self) -> *mut core::ffi::c_void {
            &mut self.sa as *mut _ as *mut core::ffi::c_void
        }
    }

    impl Drop for PipeSecurity {
        fn drop(&mut self) {
            if !self.sd.0.is_null() {
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(self.sd.0)));
                }
            }
        }
    }

    // SAFETY: the owned security descriptor is process-global heap memory
    // (LocalAlloc'd) accessed only for pipe creation and freed on drop, so the
    // owning value is safe to move between tokio worker threads.
    unsafe impl Send for PipeSecurity {}

    unsafe fn current_user_sid_string() -> Option<String> {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;

        // First call sizes the buffer, the second fills it.
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        if len == 0 {
            let _ = CloseHandle(token);
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        let res = GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            len,
            &mut len,
        );
        let _ = CloseHandle(token);
        res.ok()?;

        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut pwstr = PWSTR::null();
        ConvertSidToStringSidW(token_user.User.Sid, &mut pwstr).ok()?;
        if pwstr.is_null() {
            return None;
        }
        let sid = pwstr.to_string().ok();
        let _ = LocalFree(Some(HLOCAL(pwstr.0 as *mut core::ffi::c_void)));
        sid
    }
}

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

    // SEC-01: restrict the control pipe to the current user + SYSTEM. If the
    // descriptor cannot be built, fall back to the default DACL.
    let mut pipe_security = win_security::PipeSecurity::current_user_only();
    if pipe_security.is_none() {
        error!("Could not build control pipe security descriptor; using default DACL");
    }

    // SEC-01: we must create the FIRST instance of the pipe ourselves so OUR
    // security descriptor governs the DACL. Windows derives every additional
    // instance's DACL from whoever created the first one, so attaching to a
    // pre-existing pipe would silently inherit a (possibly hostile) DACL. Claim
    // the first instance with FILE_FLAG_FIRST_PIPE_INSTANCE; once we own it,
    // subsequent instances must drop the flag (the first instance still exists).
    let mut first_instance = true;

    loop {
        // Create a new pipe instance for each connection. The SECURITY_ATTRIBUTES
        // pointer is derived and consumed entirely within this (await-free) block
        // so it is never held across an await point (which would make the task
        // non-Send). sa_ptr is null (default DACL) or points to pipe_security's
        // SECURITY_ATTRIBUTES, which outlives the call.
        let created = {
            let sa_ptr = pipe_security
                .as_mut()
                .map(|s| s.as_attrs_ptr())
                .unwrap_or(std::ptr::null_mut());
            unsafe {
                ServerOptions::new()
                    .first_pipe_instance(first_instance)
                    .create_with_security_attributes_raw(CONTROL_PIPE_NAME, sa_ptr)
            }
        };
        let server = match created {
            Ok(s) => s,
            Err(e) => {
                if first_instance {
                    // SEC-01: fail closed. We could not claim the first instance,
                    // so another process already owns the name and would dictate
                    // the DACL for any instance we attach to. Refuse rather than
                    // inherit a foreign descriptor.
                    error!(
                        "Refusing to attach to existing control pipe (could not claim first instance): {}",
                        e
                    );
                    return;
                }
                error!("Failed to create control pipe: {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };
        // We own the first instance; further instances must not set the flag.
        first_instance = false;

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

        // SEC-01: only the owning user may drive the control channel. The 0600
        // socket already blocks other users at the filesystem layer; this is a
        // defence-in-depth check rejecting any peer whose uid differs from ours
        // (e.g. if the socket permissions were somehow widened).
        match stream.peer_cred() {
            Ok(cred) => {
                let our_uid = unsafe { libc::geteuid() };
                if cred.uid() != our_uid {
                    error!(
                        peer_uid = cred.uid(),
                        our_uid, "Rejecting control connection from a different uid"
                    );
                    continue;
                }
            }
            Err(e) => {
                error!(error = %e, "Could not read control peer credentials; rejecting");
                continue;
            }
        }

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
