use anyhow::Result;
use chilli_core::SessionManager;
use chilli_ipc::{Command, Response};
use chilli_net::{radius::{RadiusClient, ACCT_TERMINATE_CAUSE_ADMIN_RESET}, Firewall};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info, warn};

async fn handle_disconnect(
    ip: Ipv4Addr,
    session_manager: Arc<SessionManager>,
    radius_client: Arc<RadiusClient>,
    firewall: Arc<Firewall>,
) -> Result<Response> {
    info!("Received Disconnect command for IP {}", ip);

    if let Some(session) = session_manager.get_session(&ip).await {
        if session.state.authenticated {
            // Send Acct-Stop
            if let Err(e) = radius_client.send_acct_stop(&session, Some(ACCT_TERMINATE_CAUSE_ADMIN_RESET)).await {
                warn!(
                    "Failed to send Acct-Stop for session {}: {}",
                    session.state.sessionid, e
                );
                // Continue with disconnection anyway
            }

            // Remove firewall rule
            if let Err(e) = firewall.remove_authenticated_ip(ip) {
                warn!("Failed to remove firewall rule for {}: {}", ip, e);
                // Continue with disconnection anyway
            }
        }

        // Remove session from manager
        session_manager.remove_session(&ip).await;
        info!("Session for {} disconnected and removed.", ip);
        Ok(Response::Success)
    } else {
        let msg = format!("Session not found for IP {}", ip);
        warn!("{}", msg);
        Ok(Response::Error(msg))
    }
}

async fn handle_connection(
    mut stream: UnixStream,
    session_manager: Arc<SessionManager>,
    radius_client: Arc<RadiusClient>,
    firewall: Arc<Firewall>,
) -> Result<()> {
    info!("Accepted new cmdsock connection");

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await?;

    let response = match serde_json::from_slice::<Command>(&buffer) {
        Ok(Command::List) => {
            info!("Received List command");
            let sessions = session_manager.get_all_sessions().await;
            Response::List(sessions)
        }
        Ok(Command::Disconnect { ip }) => {
            match handle_disconnect(ip, session_manager, radius_client, firewall).await {
                Ok(resp) => resp,
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Err(e) => {
            warn!("Failed to deserialize command: {}", e);
            Response::Error(format!("Deserialization failed: {}", e))
        }
    };

    let serialized = serde_json::to_vec(&response)?;
    stream.write_all(&serialized).await?;
    stream.shutdown().await?;

    Ok(())
}

pub async fn run_cmdsock_listener(
    path: String,
    session_manager: Arc<SessionManager>,
    radius_client: Arc<RadiusClient>,
    firewall: Arc<Firewall>,
) -> Result<()> {
    let socket_path = Path::new(&path);

    // Remove the socket file if it already exists
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(&path)?;
    info!("Cmdsock listener started on {}", path);

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let session_manager = session_manager.clone();
                let radius_client = radius_client.clone();
                let firewall = firewall.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_connection(stream, session_manager, radius_client, firewall).await
                    {
                        error!("Error handling cmdsock connection: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Cmdsock accept error: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chilli_core::Config;
    use std::fs;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::watch;
    use tokio::net::UnixStream;

    // Helper to create a default config for testing
    fn default_test_config() -> Config {
        let mut config = Config::default();
        config.cmdsocket = Some("/tmp/chilli-test.sock".to_string());
        config.coaport = 0; // Use a random port for testing
        config
    }

    async fn send_test_command(path: &str, command: Command) -> Result<Response> {
        let mut stream = UnixStream::connect(path).await?;
        let serialized = serde_json::to_vec(&command)?;
        stream.write_all(&serialized).await?;
        stream.shutdown().await?;
        let mut buffer = Vec::new();
        stream.read_to_end(&mut buffer).await?;
        Ok(serde_json::from_slice(&buffer)?)
    }

    #[tokio::test]
    async fn test_cmdsock_list_and_disconnect() -> Result<()> {
        let config = Arc::new(default_test_config());
        let socket_path = config.cmdsocket.as_ref().unwrap().clone();

        let (_config_tx, config_rx) = watch::channel(config.clone());

        let session_manager = Arc::new(SessionManager::new());
        let radius_client = Arc::new(RadiusClient::new(config_rx).await?);
        let firewall = Arc::new(Firewall::new(config.as_ref().clone()));

        let listener_task = tokio::spawn(run_cmdsock_listener(
            socket_path.clone(),
            session_manager.clone(),
            radius_client.clone(),
            firewall.clone(),
        ));

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // 1. List sessions, should be empty
        let response = send_test_command(&socket_path, Command::List).await?;
        match response {
            Response::List(sessions) => assert!(sessions.is_empty()),
            _ => panic!("Expected Response::List"),
        }

        // 2. Create a session
        let test_ip: Ipv4Addr = "192.168.1.10".parse()?;
        let test_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        session_manager
            .create_session(test_ip, test_mac, &config)
            .await;
        session_manager.authenticate_session(&test_ip).await;

        // 3. List sessions, should have one
        let response = send_test_command(&socket_path, Command::List).await?;
        match response {
            Response::List(sessions) => {
                assert_eq!(sessions.len(), 1);
                assert_eq!(sessions[0].hisip, test_ip);
            }
            _ => panic!("Expected Response::List with one session"),
        }

        // 4. Disconnect the session
        let response = send_test_command(&socket_path, Command::Disconnect { ip: test_ip }).await?;
        match response {
            Response::Success => {} // Expected
            _ => panic!("Expected Response::Success"),
        }

        // 5. List sessions, should be empty again
        let response = send_test_command(&socket_path, Command::List).await?;
        match response {
            Response::List(sessions) => assert!(sessions.is_empty()),
            _ => panic!("Expected Response::List to be empty after disconnect"),
        }

        // Cleanup
        listener_task.abort();
        fs::remove_file(&socket_path)?;

        Ok(())
    }
}
