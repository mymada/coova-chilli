mod config;

use anyhow::Result;
use chilli_core::{AuthType, SessionManager};
use chilli_http::server;
use chilli_net::dhcp::DhcpServer;
use chilli_net::eap_mschapv2::EapMschapV2Machine;
use chilli_net::radius::{
    AuthResult, RadiusAttributeType, RadiusClient, ACCT_TERMINATE_CAUSE_SESSION_TIMEOUT,
};
use chilli_net::tun;
use chilli_net::Firewall;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};
use chilli_net::AsyncDevice;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting CoovaChilli-Rust");

    let config = match config::load_config() {
        Ok(config) => Arc::new(config),
        Err(e) => {
            eprintln!("Error loading config: {}", e);
            std::process::exit(1);
        }
    };

    info!("Config loaded: {:?}", config);

    let firewall = Arc::new(Firewall::new((*config).clone()));
    if let Err(e) = firewall.initialize() {
        error!("Error initializing firewall: {}", e);
        std::process::exit(1);
    }

    let iface = match tun::create_tun(&config).await {
        Ok(iface) => iface,
        Err(e) => {
            error!("Error creating TUN interface: {}", e);
            firewall.cleanup().ok();
            std::process::exit(1);
        }
    };

    let session_manager = Arc::new(SessionManager::new());

    let (auth_tx, auth_rx) = tokio::sync::mpsc::channel(100);

    let config_clone_http = config.clone();
    let _http_server_handle = tokio::spawn(async move {
        if let Err(e) = server::run_server(&config_clone_http, auth_tx).await {
            error!("HTTP server error: {}", e);
        }
    });

    let dhcp_server = Arc::new(DhcpServer::new(config.clone(), session_manager.clone()).await?);
    let dhcp_server_run = dhcp_server.clone();
    let _dhcp_server_handle = tokio::spawn(async move {
        if let Err(e) = dhcp_server_run.run().await {
            error!("DHCP server error: {}", e);
        }
    });

    let dhcp_reaper_handle = tokio::spawn(dhcp_reaper_loop(dhcp_server.clone()));

    let radius_client = Arc::new(RadiusClient::new(config.clone()).await?);
    let radius_run_client = radius_client.clone();
    let _radius_client_handle = tokio::spawn(async move {
        radius_run_client.run().await;
    });

    let packet_loop_handle = tokio::spawn(packet_loop(
        iface,
        session_manager.clone(),
        config.clone(),
    ));

    let auth_loop_handle = tokio::spawn(auth_loop(
        auth_rx,
        radius_client.clone(),
        session_manager.clone(),
        firewall.clone(),
    ));

    let interim_update_handle = tokio::spawn(interim_update_loop(
        radius_client.clone(),
        session_manager.clone(),
        config.clone(),
        firewall.clone(),
    ));

    tokio::select! {
        res = packet_loop_handle => {
            if let Err(e) = res.unwrap() {
                error!("Packet loop failed: {}", e);
            }
        }
        _ = auth_loop_handle => {
            info!("Auth loop finished.");
        }
        _ = interim_update_handle => {
            info!("Interim update loop finished.");
        }
        _ = dhcp_reaper_handle => {
            info!("DHCP reaper loop finished.");
        }
        _ = _http_server_handle => {
            info!("HTTP server finished.");
        }
        _ = _dhcp_server_handle => {
            info!("DHCP server finished.");
        }
        _ = _radius_client_handle => {
            info!("RADIUS client finished.");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl-C, shutting down.");
        }
    }

    firewall.cleanup().ok();

    info!("Sending Acct-Stop for all active sessions...");
    for session in session_manager.get_all_sessions().await {
        if session.state.authenticated {
            if let Err(e) = radius_client.send_acct_stop(&session, None).await {
                warn!(
                    "Failed to send Acct-Stop for session {}: {}",
                    session.state.sessionid, e
                );
            }
        }
    }

    info!("Shutdown complete.");

    Ok(())
}

async fn dhcp_reaper_loop(dhcp_server: Arc<DhcpServer>) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
    loop {
        interval.tick().await;
        dhcp_server.reap_leases().await;
    }
}

async fn interim_update_loop(
    radius_client: Arc<RadiusClient>,
    session_manager: Arc<SessionManager>,
    config: Arc<chilli_core::Config>,
    firewall: Arc<Firewall>,
) {
    let interval_secs = config.interval as u64;
    if interval_secs == 0 {
        info!("Interim updates disabled.");
        return;
    }
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;
        info!("Sending interim updates for all active sessions...");
        for session in session_manager.get_all_sessions().await {
            if session.state.authenticated {
                let mut terminate = false;
                if session.params.sessiontimeout > 0 {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    if session.state.start_time + session.params.sessiontimeout <= now {
                        info!(
                            "Session {} for user {:?} has expired due to Session-Timeout. Terminating.",
                            session.state.sessionid, session.state.redir.username
                        );
                        terminate = true;
                    }
                }

                if terminate {
                    if let Err(e) = radius_client
                        .send_acct_stop(&session, Some(ACCT_TERMINATE_CAUSE_SESSION_TIMEOUT))
                        .await
                    {
                        warn!(
                            "Failed to send Acct-Stop for session {}: {}",
                            session.state.sessionid, e
                        );
                    }
                    session_manager.remove_session(&session.hisip).await;
                    if let Err(e) = firewall.remove_authenticated_ip(session.hisip) {
                        error!(
                            "Failed to remove authenticated IP from firewall for session {}: {}",
                            session.state.sessionid, e
                        );
                    }
                } else {
                    if let Err(e) = radius_client.send_acct_interim_update(&session).await {
                        warn!(
                            "Failed to send Acct-Interim-Update for session {}: {}",
                            session.state.sessionid, e
                        );
                    }
                }
            }
        }
    }
}

async fn handle_pap_auth(
    req: chilli_core::AuthRequest,
    radius_client: Arc<RadiusClient>,
    session_manager: Arc<SessionManager>,
    firewall: Arc<Firewall>,
) {
    info!("Processing PAP auth request for user '{}'", req.username);
    match radius_client
        .send_access_request(&req.username, &req.password.unwrap_or_default())
        .await
    {
        Ok(Some(attributes)) => {
            info!("Authentication successful for user '{}'", req.username);
            session_manager.authenticate_session(&req.ip).await;

            if let Some(session_timeout_val) = attributes.get(&RadiusAttributeType::SessionTimeout)
            {
                if session_timeout_val.len() == 4 {
                    let timeout =
                        u32::from_be_bytes(session_timeout_val.clone().try_into().unwrap());
                    info!(
                        "Session-Timeout for user '{}' is {}",
                        req.username, timeout
                    );
                    session_manager
                        .update_session(&req.ip, |session| {
                            session.params.sessiontimeout = timeout as u64;
                        })
                        .await;
                }
            }

            if let Err(e) = firewall.add_authenticated_ip(req.ip) {
                error!("Failed to add authenticated IP to firewall: {}", e);
            }
            if let Some(session) = session_manager.get_session(&req.ip).await {
                if let Err(e) = radius_client.send_acct_start(&session).await {
                    warn!(
                        "Failed to send Acct-Start for user '{}': {}",
                        req.username, e
                    );
                }
            }
            req.tx.send(true).ok();
        }
        Ok(None) => {
            info!("Authentication failed for user '{}'", req.username);
            req.tx.send(false).ok();
        }
        Err(e) => {
            warn!("RADIUS request failed for user '{}': {}", req.username, e);
            req.tx.send(false).ok();
        }
    }
}

async fn handle_eap_auth(
    req: chilli_core::AuthRequest,
    radius_client: Arc<RadiusClient>,
    session_manager: Arc<SessionManager>,
    firewall: Arc<Firewall>,
) {
    info!("Processing EAP auth request for user '{}'", req.username);
    let mut eap_machine = EapMschapV2Machine::new();

    // 1. Send EAP-Response/Identity
    let mut eap_data = vec![chilli_net::eap::EapType::Identity as u8];
    eap_data.extend_from_slice(req.username.as_bytes());
    let eap_packet = chilli_net::eap::EapPacket {
        code: chilli_net::eap::EapCode::Response,
        identifier: 1, // This should come from the EAP-Request/Identity
        data: &eap_data,
    };
    let eap_response = eap_packet.to_bytes();

    let mut state = None;
    let mut result = radius_client.send_eap_response(&eap_response, state.as_deref()).await;

    loop {
        match result {
            Ok(AuthResult::Challenge(eap_message, new_state)) => {
                state = new_state;
                let password = req.password.as_deref().unwrap_or_default();
                if let Some(response) = eap_machine.step(&eap_message, password) {
                    result = radius_client.send_eap_response(&response, state.as_deref()).await;
                } else {
                    break;
                }
            }
            Ok(AuthResult::Success(attributes)) => {
                info!("EAP Authentication successful for user '{}'", req.username);
                session_manager.authenticate_session(&req.ip).await;

                if let Some(session_timeout_val) =
                    attributes.get(&RadiusAttributeType::SessionTimeout)
                {
                    if session_timeout_val.len() == 4 {
                        let timeout =
                            u32::from_be_bytes(session_timeout_val.clone().try_into().unwrap());
                        info!(
                            "Session-Timeout for user '{}' is {}",
                            req.username, timeout
                        );
                        session_manager
                            .update_session(&req.ip, |session| {
                                session.params.sessiontimeout = timeout as u64;
                            })
                            .await;
                    }
                }

                if let Err(e) = firewall.add_authenticated_ip(req.ip) {
                    error!("Failed to add authenticated IP to firewall: {}", e);
                }
                if let Some(session) = session_manager.get_session(&req.ip).await {
                    if let Err(e) = radius_client.send_acct_start(&session).await {
                        warn!(
                            "Failed to send Acct-Start for user '{}': {}",
                            req.username, e
                        );
                    }
                }
                req.tx.send(true).ok();
                return;
            }
            _ => {
                info!("EAP Authentication failed for user '{}'", req.username);
                req.tx.send(false).ok();
                return;
            }
        }
    }
    info!("EAP Authentication failed for user '{}'", req.username);
    req.tx.send(false).ok();
}

async fn auth_loop(
    mut rx: tokio::sync::mpsc::Receiver<chilli_core::AuthRequest>,
    radius_client: Arc<RadiusClient>,
    session_manager: Arc<SessionManager>,
    firewall: Arc<Firewall>,
) {
    while let Some(req) = rx.recv().await {
        match req.auth_type {
            AuthType::Pap => {
                handle_pap_auth(
                    req,
                    radius_client.clone(),
                    session_manager.clone(),
                    firewall.clone(),
                )
                .await;
            }
            AuthType::Eap => {
                handle_eap_auth(
                    req,
                    radius_client.clone(),
                    session_manager.clone(),
                    firewall.clone(),
                )
                .await;
            }
        }
    }
}

async fn packet_loop(
    iface: AsyncDevice,
    session_manager: Arc<SessionManager>,
    config: Arc<chilli_core::Config>,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 1504];
    loop {
        let n = iface.recv(&mut buf).await?;
        let packet_slice = &buf[..n];

        if let Ok(packet) = etherparse::SlicedPacket::from_ip(packet_slice) {
            let (src_addr, dest_addr, len) =
                if let Some(etherparse::NetSlice::Ipv4(ipv4)) = packet.net {
                    (
                        ipv4.header().source_addr(),
                        ipv4.header().destination_addr(),
                        ipv4.header().total_len() as u64,
                    )
                } else {
                    continue;
                };

            let src_session = session_manager.get_session(&src_addr).await;
            let dest_session = session_manager.get_session(&dest_addr).await;

            if let Some(session) = src_session {
                // Outgoing packet from a client
                if session.state.authenticated {
                    session_manager.update_counters(&src_addr, len, 0).await;
                    iface.send(packet_slice).await?;
                    continue;
                } else {
                    // Unauthenticated client, try DNS hijack
                    if let Some(etherparse::TransportSlice::Udp(udp)) = packet.transport {
                        if udp.destination_port() == 53 {
                            if let Ok(request) =
                                trust_dns_proto::op::Message::from_vec(udp.payload())
                            {
                                if request.message_type() == trust_dns_proto::op::MessageType::Query {
                                    info!("Intercepted DNS query from {}", src_addr);
                                    let mut response = trust_dns_proto::op::Message::new();
                                    response
                                        .set_id(request.id())
                                        .set_message_type(trust_dns_proto::op::MessageType::Response)
                                        .set_op_code(trust_dns_proto::op::OpCode::Query)
                                        .set_response_code(trust_dns_proto::op::ResponseCode::NoError)
                                        .add_queries(request.queries().to_vec());
                                    for query in request.queries() {
                                        let record = trust_dns_proto::rr::Record::from_rdata(
                                            query.name().clone(),
                                            60,
                                            trust_dns_proto::rr::RData::A(config.uamlisten),
                                        );
                                        response.add_answer(record);
                                    }
                                    let mut response_bytes = Vec::new();
                                    let mut encoder = trust_dns_proto::serialize::binary::BinEncoder::new(&mut response_bytes);
                                    trust_dns_proto::serialize::binary::BinEncodable::emit(&response, &mut encoder)?;
                                    let builder = etherparse::PacketBuilder::ipv4(
                                        dest_addr.octets(),
                                        src_addr.octets(),
                                        20,
                                    )
                                    .udp(udp.destination_port(), udp.source_port());
                                    let mut result = Vec::new();
                                    builder.write(&mut result, &response_bytes)?;
                                    iface.send(&result).await?;
                                    continue;
                                }
                            }
                        }
                    }
                }
            } else if let Some(session) = dest_session {
                // Incoming packet to a client
                if session.state.authenticated {
                    session_manager
                        .update_counters(&dest_addr, 0, len)
                        .await;
                    iface.send(packet_slice).await?;
                    continue;
                }
            }
        }
    }
}
