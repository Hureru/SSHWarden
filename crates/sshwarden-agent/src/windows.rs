use bitwarden_russh::ssh_agent;
pub mod named_pipe_listener_stream;

use std::sync::Arc;

use super::agent::{SshAgentUIRequest, SshWardenAgent};

impl SshWardenAgent {
    pub fn start_server(
        auth_request_tx: tokio::sync::mpsc::Sender<SshAgentUIRequest>,
        auth_response_tx: Arc<tokio::sync::broadcast::Sender<(u32, bool)>>,
    ) -> Result<Self, anyhow::Error> {
        let agent_state = SshWardenAgent::new(auth_request_tx, auth_response_tx);

        let stream = named_pipe_listener_stream::NamedPipeServerStream::new(
            agent_state.cancellation_token(),
            agent_state.is_running_flag(),
        );

        let cloned_agent_state = agent_state.clone();
        agent_state.set_running(true);
        tokio::spawn(async move {
            let _ = ssh_agent::serve(
                stream,
                cloned_agent_state.clone(),
                cloned_agent_state.keystore_clone(),
                cloned_agent_state.cancellation_token(),
            )
            .await;
            cloned_agent_state
                .set_running(false);
        });
        Ok(agent_state)
    }
}
