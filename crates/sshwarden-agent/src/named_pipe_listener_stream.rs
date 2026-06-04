use std::{
    io,
    os::windows::prelude::AsRawHandle as _,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use futures::Stream;
use tokio::{
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
    select,
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use windows::Win32::{Foundation::HANDLE, System::Pipes::GetNamedPipeClientProcessId};

use crate::peerinfo::{self, models::PeerInfo};

const PIPE_NAME: &str = r"\\.\pipe\openssh-ssh-agent";

#[pin_project::pin_project]
pub struct NamedPipeServerStream {
    rx: tokio::sync::mpsc::Receiver<(NamedPipeServer, PeerInfo)>,
}

impl NamedPipeServerStream {
    pub fn new(
        endpoint: Option<std::path::PathBuf>,
        cancellation_token: CancellationToken,
        is_running: Arc<AtomicBool>,
        fatal_tx: Arc<tokio::sync::watch::Sender<Option<String>>>,
    ) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            let pipe_name = endpoint
                .as_ref()
                .and_then(|path| path.to_str())
                .unwrap_or(PIPE_NAME)
                .to_string();
            info!("Creating named pipe server on {}", pipe_name);
            // RT-01: claim exclusive ownership of the endpoint with
            // first_pipe_instance(true). If another SSH agent (most commonly the
            // Windows OpenSSH `ssh-agent` service) already owns the pipe, create()
            // fails here instead of silently coexisting as a second instance and
            // stealing half of the client connections.
            let mut listener = match ServerOptions::new()
                .first_pipe_instance(true)
                .create(&pipe_name)
            {
                Ok(pipe) => pipe,
                Err(e) => {
                    let reason = format!(
                        "Failed to claim SSH agent endpoint {pipe_name}: {e}. Another SSH agent \
                         already owns it (most likely the Windows OpenSSH 'ssh-agent' service). \
                         Stop and disable it (admin PowerShell: Stop-Service ssh-agent; \
                         Set-Service ssh-agent -StartupType Disabled), or set [socket] path to a \
                         custom endpoint, then restart SSHWarden."
                    );
                    error!(error = %e, "{reason}");
                    is_running.store(false, Ordering::Relaxed);
                    cancellation_token.cancel();
                    let _ = fatal_tx.send(Some(reason));
                    return;
                }
            };
            loop {
                info!("Waiting for connection");
                select! {
                    _ = cancellation_token.cancelled() => {
                        info!("[SSH Agent] Cancellation token triggered, stopping named pipe server");
                        break;
                    }
                    _ = listener.connect() => {
                        info!("[SSH Agent] Incoming connection");
                        let handle = HANDLE(listener.as_raw_handle());
                        let mut pid = 0;
                        unsafe {
                            if let Err(e) = GetNamedPipeClientProcessId(handle, &mut pid) {
                                error!(error = %e, pid, "Failed to get named pipe client process id");
                                continue
                            }
                        };

                        let peer_info = peerinfo::gather::get_peer_info(pid);
                        let peer_info = match peer_info {
                            Err(e) => {
                                error!(error = %e, pid = %pid, "Failed getting process info");
                                continue
                            },
                            Ok(info) => info,
                        };

                        if tx.send((listener, peer_info)).await.is_err() {
                            // Consumer (the served stream) was dropped, e.g. the
                            // agent is stopping. Exit the listener cleanly.
                            return;
                        }

                        listener = match ServerOptions::new().create(&pipe_name) {
                            Ok(pipe) => pipe,
                            Err(e) => {
                                let reason = format!(
                                    "SSH agent pipe {pipe_name} could not be recreated: {e}"
                                );
                                error!(error = %e, "{reason}");
                                is_running.store(false, Ordering::Relaxed);
                                cancellation_token.cancel();
                                let _ = fatal_tx.send(Some(reason));
                                return;
                            }
                        };
                    }
                }
            }
        });
        Self { rx }
    }
}

impl Stream for NamedPipeServerStream {
    type Item = io::Result<(NamedPipeServer, PeerInfo)>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<(NamedPipeServer, PeerInfo)>>> {
        let this = self.project();
        this.rx.poll_recv(cx).map(|v| v.map(Ok))
    }
}
