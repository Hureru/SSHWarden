use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc};

use anyhow::anyhow;
use bitwarden_russh::ssh_agent;
use homedir::my_home;
use tokio::net::UnixListener;
use tracing::{error, info};

use super::agent::{SshAgentUIRequest, SshWardenAgent};
use crate::peercred_unix_listener_stream::PeercredUnixListenerStream;

const ENV_SSHWARDEN_SSH_AUTH_SOCK: &str = "SSHWARDEN_SSH_AUTH_SOCK";

const SOCKFILE_NAME: &str = ".sshwarden-agent.sock";

impl SshWardenAgent {
    pub fn start_server(
        auth_request_tx: tokio::sync::mpsc::Sender<SshAgentUIRequest>,
        auth_response_tx: Arc<tokio::sync::broadcast::Sender<(u32, bool)>>,
    ) -> Result<Self, anyhow::Error> {
        let agent_state = SshWardenAgent::new(auth_request_tx, auth_response_tx);

        let socket_path = get_socket_path()?;

        remove_path(&socket_path)?;

        info!(?socket_path, "Starting SSH Agent server");

        match UnixListener::bind(socket_path.clone()) {
            Ok(listener) => {
                set_user_permissions(&socket_path)?;

                let stream = PeercredUnixListenerStream::new(listener);

                let cloned_agent_state = agent_state.clone();
                let cloned_keystore = cloned_agent_state.keystore_clone();
                let cloned_cancellation_token = cloned_agent_state.cancellation_token();

                tokio::spawn(async move {
                    let _ = ssh_agent::serve(
                        stream,
                        cloned_agent_state.clone(),
                        cloned_keystore,
                        cloned_cancellation_token,
                    )
                    .await;

                    cloned_agent_state.set_running(false);

                    info!("SSH Agent server exited");
                });

                agent_state.set_running(true);

                info!(?socket_path, "SSH Agent is running.");
            }
            Err(error) => {
                error!(%error, ?socket_path, "Unable to start agent server");
                return Err(error.into());
            }
        }

        Ok(agent_state)
    }
}

fn get_socket_path() -> Result<PathBuf, anyhow::Error> {
    if let Ok(path) = std::env::var(ENV_SSHWARDEN_SSH_AUTH_SOCK) {
        Ok(PathBuf::from(path))
    } else {
        info!("SSHWARDEN_SSH_AUTH_SOCK not set, using default path");
        get_default_socket_path()
    }
}

fn get_default_socket_path() -> Result<PathBuf, anyhow::Error> {
    let Ok(Some(mut ssh_agent_directory)) = my_home() else {
        error!("Could not determine home directory");
        return Err(anyhow!("Could not determine home directory."));
    };

    ssh_agent_directory = ssh_agent_directory.join(SOCKFILE_NAME);
    Ok(ssh_agent_directory)
}

fn set_user_permissions(path: &PathBuf) -> Result<(), anyhow::Error> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| anyhow!("Could not set socket permissions for {path:?}: {e}"))
}

fn remove_path(path: &PathBuf) -> Result<(), anyhow::Error> {
    if let Ok(true) = std::fs::exists(path) {
        std::fs::remove_file(path).map_err(|e| anyhow!("Error removing socket {path:?}: {e}"))?;
    }
    Ok(())
}
