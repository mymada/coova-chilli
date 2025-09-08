mod config;
mod cmdsock;

use anyhow::Result;
use chilli_core::{AuthType, Session, SessionManager};
use chilli_http::server;
use chilli_net::dhcp::DhcpServer;
use chilli_net::eap_mschapv2;
use chilli_net::mschapv2;
use chilli_net::radius::{
    AuthResult, RadiusAttributeType, RadiusClient,
    ACCT_TERMINATE_CAUSE_ADMIN_RESET, ACCT_TERMINATE_CAUSE_IDLE_TIMEOUT,
    ACCT_TERMINATE_CAUSE_SESSION_TIMEOUT,
};
use chilli_net::tun;
use chilli_net::Firewall;
use std::collections::HashSet;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use chilli_net::eap::{EapPacket, EapType};
use chilli_net::AsyncDevice;

fn load_status(
    status_file: &Option<String>,
    session_manager: &Arc<SessionManager>,
) -> Result<()> {
    if let Some(path) = status_file {
        if Path::new(path).exists() {
            info!("Loading status from {}", path);
            let data = fs::read(path)?;
            let sessions: Vec<Session> = serde_json::from_slice(&data)?;
            session_manager.load_sessions(sessions);
        }
    }
    Ok(())
}

fn save_status(
    status_file: &Option<String>,
    session_manager: &Arc<SessionManager>,
) -> Result<()> {
    if let Some(path) = status_file {
        info!("Saving status to {}", path);
        let sessions = session_manager.get_all_sessions_sync();
        let data = serde_json::to_vec_pretty(&sessions)?;
        fs::write(path, data)?;
    }
    Ok(())
}

async fn run_script(script_path: String, session: &Session) {
    info!("Running script {} for session {}", script_path, session.state.sessionid);
    let mut cmd = Command::new(&script_path);
    cmd.env("FRAMED_IP_ADDRESS", session.hisip.to_string());
    cmd.env("CALLING_STATION_ID", hex::encode(session.hismac));
    if let Some(username) = &session.state.redir.username {
        cmd.env("USER_NAME", username);
    }
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

    match cmd.spawn() {
        Ok(mut child) => {
            tokio::spawn(async move {
                if let Err(e) = child.wait().await {
                    warn!("Script {} failed: {}", script_path, e);
                }
            });
        }
        Err(e) => {
            warn!("Failed to spawn script {}: {}", script_path, e);
        }
    }
}

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
    if let Err(e) = load_status(&config.statusfile, &session_manager) {
        warn!("Failed to load status file: {}", e);
    }

    let walled_garden_ips = Arc::new(Mutex::new(HashSet::new()));

    let (auth_tx, auth_rx) = tokio::sync::mpsc::channel(100);

    let config_clone_http = config.clone();
    let auth_tx_http = auth_tx.clone();
    let _http_server_handle = tokio::spawn(async move {
        if let Err(e) = server::run_server(&config_clone_http, auth_tx_http).await {
            error!("HTTP server error: {}", e);
        }
    });

    let dhcp_server = Arc::new(
        DhcpServer::new(config.clone(), session_manager.clone(), auth_tx.clone()).await?,
    );
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

    let coa_listener_handle = {
        let radius_client = radius_client.clone();
        let session_manager = session_manager.clone();
        let firewall = firewall.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match radius_client.coa_socket.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        if let Some(packet) = chilli_net::radius::RadiusPacket::from_bytes(&buf[..len]) {
                            if let Err(e) = radius_client.handle_coa_request(packet, src, &session_manager, &firewall).await {
                                error!("Error handling CoA request: {}", e);
                            }
                        }
                    }
                    Err(e) => error!("CoA socket error: {}", e),
                }
            }
        })
    };

    let walled_garden_resolver_handle = tokio::spawn(walled_garden_resolver_loop(
        config.clone(),
        walled_garden_ips.clone(),
    ));

    let proxy_listener_handle = if let Some(listen_ip) = config.proxylisten {
        let config = config.clone();
        Some(tokio::spawn(async move {
            let addr = format!("{}:{}", listen_ip, config.proxyport);
            match UdpSocket::bind(&addr).await {
                Ok(socket) => {
                    info!("RADIUS proxy listening on {}", addr);
                    let proxy_socket = Arc::new(socket);
                    match chilli_net::radius_proxy::ProxyManager::new(config, proxy_socket.clone()).await {
                        Ok(proxy_manager) => {
                            let manager = Arc::new(proxy_manager);
                            let req_handle = tokio::spawn(async move { manager.clone().run_request_listener().await; });
                            // let res_handle = tokio::spawn(async move { manager.run_response_listener().await; });
                            req_handle.await.ok();
                            // res_handle.await.ok();
                        }
                        Err(e) => {
                            error!("Failed to create RADIUS proxy manager: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to bind RADIUS proxy socket on {}: {}", addr, e);
                }
            }
        }))
    } else {
        None
    };

    let cmdsock_handle = if let Some(path) = config.cmdsocket.clone() {
        let session_manager = session_manager.clone();
        let radius_client = radius_client.clone();
        let firewall = firewall.clone();
        Some(tokio::spawn(async move {
            if let Err(e) =
                cmdsock::run_cmdsock_listener(path, session_manager, radius_client, firewall).await
            {
                error!("Cmdsock listener error: {}", e);
            }
        }))
    } else {
        None
    };

    let packet_loop_handle = tokio::spawn(packet_loop(
        iface,
        session_manager.clone(),
        config.clone(),
        walled_garden_ips.clone(),
    ));

    let auth_loop_handle = tokio::spawn(auth_loop(
        auth_rx,
        radius_client.clone(),
        session_manager.clone(),
        firewall.clone(),
        config.clone(),
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
        _ = walled_garden_resolver_handle => {
            info!("Walled garden resolver loop finished.");
        }
        _ = async { if let Some(h) = proxy_listener_handle { h.await.ok(); } } => {
            info!("RADIUS proxy listener finished.");
        }
        _ = coa_listener_handle => {
            info!("CoA listener finished.");
        }
        _ = async { if let Some(h) = cmdsock_handle { h.await.ok(); } } => {
            info!("Cmdsock listener finished.");
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

    if let Err(e) = save_status(&config.statusfile, &session_manager) {
        warn!("Failed to save status file: {}", e);
    }

    firewall.cleanup().ok();

    info!("Sending Acct-Stop for all active sessions...");
    for session in session_manager.get_all_sessions().await {
        if session.state.authenticated {
            firewall.remove_user_filter(session.hisip).ok();
            if let Some(ref condown) = config.condown {
                run_script(condown.clone(), &session).await;
            }
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

async fn walled_garden_resolver_loop(
    config: Arc<chilli_core::Config>,
    walled_garden_ips: Arc<Mutex<HashSet<Ipv4Addr>>>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        info!("Resolving walled garden domains...");
        let mut new_ips = HashSet::new();
        for domain in &config.walled_garden {
            match tokio::net::lookup_host(format!("{}:0", domain)).await {
                Ok(addresses) => {
                    for addr in addresses {
                        if let std::net::SocketAddr::V4(v4_addr) = addr {
                            new_ips.insert(*v4_addr.ip());
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to resolve walled garden domain {}: {}", domain, e);
                }
            }
        }
        let mut wg_ips = walled_garden_ips.lock().await;
        *wg_ips = new_ips;
        info!("Walled garden IPs updated: {:?}", wg_ips);
        interval.tick().await;
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
                let mut terminate_cause = None;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                if session.params.sessiontimeout > 0 {
                    if session.state.start_time + session.params.sessiontimeout <= now {
                        info!(
                            "Session {} for user {:?} has expired due to Session-Timeout. Terminating.",
                            session.state.sessionid, session.state.redir.username
                        );
                        terminate_cause = Some(ACCT_TERMINATE_CAUSE_SESSION_TIMEOUT);
                    }
                }

                if terminate_cause.is_none() && session.params.idletimeout > 0 {
                    if session.state.last_up_time + (session.params.idletimeout as u64) <= now {
                        info!(
                            "Session {} for user {:?} has expired due to Idle-Timeout. Terminating.",
                            session.state.sessionid, session.state.redir.username
                        );
                        terminate_cause = Some(ACCT_TERMINATE_CAUSE_IDLE_TIMEOUT);
                    }
                }

                if let Some(cause) = terminate_cause {
                    if let Some(ref condown) = config.condown {
                        run_script(condown.clone(), &session).await;
                    }
                    if let Err(e) = radius_client
                        .send_acct_stop(&session, Some(cause))
                        .await
                    {
                        warn!(
                            "Failed to send Acct-Stop for session {}: {}",
                            session.state.sessionid, e
                        );
                    }
                    firewall.remove_user_filter(session.hisip).ok();
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
    config: Arc<chilli_core::Config>,
) {
    info!("Processing PAP auth request for user '{}'", req.username);
    match radius_client
        .send_access_request(&req.username, &req.password.unwrap_or_default())
        .await
    {
        Ok(Some(attributes)) => {
            info!("Authentication successful for user '{}'", req.username);
            session_manager.authenticate_session(&req.ip).await;

            chilli_net::radius::apply_radius_attributes(&attributes, &session_manager, &firewall, &req.ip).await;

            if let Some(session) = session_manager.get_session(&req.ip).await {
                if let Some(ref conup) = config.conup {
                    run_script(conup.clone(), &session).await;
                }
                if let Err(e) = firewall.add_authenticated_ip(req.ip) {
                    error!("Failed to add authenticated IP to firewall: {}", e);
                }
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
    config: Arc<chilli_core::Config>,
) {
    info!("Processing EAP auth request for user '{}'", req.username);

    let mut eap_state = None;

    // 1. Start with an EAP-Response/Identity
    let eap_packet = eap_mschapv2::create_identity_response(1, &req.username);
    info!("Sending EAP Identity Response: {:?}", eap_packet);
    let mut result = radius_client.send_eap_response(&eap_packet.to_bytes(), eap_state.as_deref()).await;

    loop {
        info!("EAP loop, result: {:?}", result);
        match result {
            Ok(AuthResult::Challenge(ref eap_message, ref new_state)) => {
                eap_state = new_state.clone();
                if let Some(eap_request) = EapPacket::from_bytes(eap_message) {
                    info!("Received EAP Challenge: {:?}", eap_request);
                    if let Some((challenge, identifier)) = eap_mschapv2::parse_challenge_request(&eap_request) {
                        let password = req.password.as_deref().unwrap_or_default();
                        let peer_challenge = mschapv2::generate_challenge();
                        if let Some(nt_response) = mschapv2::verify_response_and_generate_nt_response(&challenge, &peer_challenge, &req.username, password) {
                            let response_packet = eap_mschapv2::create_challenge_response_packet(identifier, &peer_challenge, &nt_response, &req.username);
                            info!("Sending EAP Challenge Response: {:?}", response_packet);
                            result = radius_client.send_eap_response(&response_packet.to_bytes(), eap_state.as_deref()).await;
                        } else {
                            info!("Password verification failed");
                            break;
                        }
                    } else if let Some(_auth_response) = eap_mschapv2::parse_success_request(&eap_request) {
                        info!("Received EAP Success Request");
                        // Success case is handled by Access-Accept
                    } else {
                        info!("Unknown EAP packet in Challenge");
                        break;
                    }
                } else {
                    info!("Failed to parse EAP packet from Challenge");
                    break;
                }
            }
            Ok(AuthResult::Success(attributes)) => {
                info!("EAP Authentication successful for user '{}'", req.username);
                session_manager.authenticate_session(&req.ip).await;

                chilli_net::radius::apply_radius_attributes(&attributes, &session_manager, &firewall, &req.ip).await;

                if let Some(session) = session_manager.get_session(&req.ip).await {
                    if let Some(ref conup) = config.conup {
                        run_script(conup.clone(), &session).await;
                    }
                    if let Err(e) = firewall.add_authenticated_ip(req.ip) {
                        error!("Failed to add authenticated IP to firewall: {}", e);
                    }
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
    config: Arc<chilli_core::Config>,
) {
    while let Some(req) = rx.recv().await {
        match req.auth_type {
            AuthType::Pap => {
                tokio::spawn(handle_pap_auth(
                    req,
                    radius_client.clone(),
                    session_manager.clone(),
                    firewall.clone(),
                    config.clone(),
                ));
            }
            AuthType::Eap => {
                tokio::spawn(handle_eap_auth(
                    req,
                    radius_client.clone(),
                    session_manager.clone(),
                    firewall.clone(),
                    config.clone(),
                ));
            }
        }
    }
}

async fn leaky_bucket(session_manager: &Arc<SessionManager>, ip: &Ipv4Addr, is_upload: bool, len: u64) -> bool {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut drop = false;
    session_manager.update_session(ip, |session| {
        let timediff = now - session.state.last_bw_time;
        if is_upload {
            if session.params.bandwidthmaxup > 0 {
                let upbytes = (timediff * session.params.bandwidthmaxup) / 8;
                if session.state.bucketup > upbytes {
                    session.state.bucketup -= upbytes;
                } else {
                    session.state.bucketup = 0;
                }
                if (session.state.bucketup + len) > session.state.bucketupsize {
                    drop = true;
                } else {
                    session.state.bucketup += len;
                }
            }
        } else {
            if session.params.bandwidthmaxdown > 0 {
                let dnbytes = (timediff * session.params.bandwidthmaxdown) / 8;
                if session.state.bucketdown > dnbytes {
                    session.state.bucketdown -= dnbytes;
                } else {
                    session.state.bucketdown = 0;
                }
                if (session.state.bucketdown + len) > session.state.bucketdownsize {
                    drop = true;
                } else {
                    session.state.bucketdown += len;
                }
            }
        }
        session.state.last_bw_time = now;
    }).await;
    drop
}

async fn packet_loop(
    iface: AsyncDevice,
    session_manager: Arc<SessionManager>,
    config: Arc<chilli_core::Config>,
    walled_garden_ips: Arc<Mutex<HashSet<Ipv4Addr>>>,
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

            let wg_ips = walled_garden_ips.lock().await;
            if wg_ips.contains(&dest_addr) {
                iface.send(packet_slice).await?;
                continue;
            }

            if let Some(session) = session_manager.get_session(&src_addr).await {
                // Outgoing packet from a client
                if session.state.authenticated {
                    if leaky_bucket(&session_manager, &src_addr, true, len).await {
                        info!("Dropping upload packet for {} due to leaky bucket", src_addr);
                        continue;
                    }
                    session_manager.update_last_up_time(&src_addr).await;
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
                                    if let Some(query) = request.queries().iter().next() {
                                        let name = query.name().to_utf8();
                                        if config.walled_garden.iter().any(|d| name.ends_with(d)) {
                                            iface.send(packet_slice).await?;
                                            continue;
                                        }
                                    }

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
            } else if let Some(session) = session_manager.get_session(&dest_addr).await {
                // Incoming packet to a client
                if session.state.authenticated {
                    if leaky_bucket(&session_manager, &dest_addr, false, len).await {
                        info!("Dropping download packet for {} due to leaky bucket", dest_addr);
                        continue;
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use chilli_core::{AuthRequest, Config};
    use chilli_net::eap::EapCode;
    use chilli_net::radius::{RadiusAttributeValue, RadiusCode, RadiusPacket, RADIUS_AUTH_LEN};
    use std::net::Ipv4Addr;
    use tokio::net::UdpSocket;
    use tokio::sync::oneshot;

    async fn mock_radius_server(socket: UdpSocket, secret: String) {
        let mut buf = [0u8; 1504];

        // 1. Receive Identity Response, send Challenge
        let (len, src) = socket.recv_from(&mut buf).await.unwrap();
        info!("Mock RADIUS: Received Identity Response: {:?}", &buf[..len]);
        let req_packet = RadiusPacket::from_bytes(&buf[..len]).unwrap();

        let eap_payload_data = {
            let mut data = vec![EapType::MsChapV2 as u8];
            data.push(0x01); // MS-CHAPv2 Op-Code: Challenge
            data.push(req_packet.id); // MS-CHAPv2 Identifier
            data.extend_from_slice(&[0u8; 16]); // The challenge
            data
        };

        let eap_challenge_packet = EapPacket {
            code: EapCode::Request,
            identifier: req_packet.id,
            data: eap_payload_data,
        };

        let mut attributes = Vec::new();
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::EapMessage,
            value: eap_challenge_packet.to_bytes(),
        });

        let mut payload = Vec::new();
        for attr in attributes {
            payload.push(attr.type_code as u8);
            payload.push((attr.value.len() + 2) as u8);
            payload.extend_from_slice(&attr.value);
        }

        let length = (chilli_net::radius::RADIUS_HDR_LEN + payload.len()) as u16;
        let mut response_header = Vec::new();
        response_header.push(RadiusCode::AccessChallenge as u8);
        response_header.push(req_packet.id);
        response_header.extend_from_slice(&length.to_be_bytes());

        let mut to_hash = response_header.clone();
        to_hash.extend_from_slice(&req_packet.authenticator);
        to_hash.extend_from_slice(&payload);
        to_hash.extend_from_slice(secret.as_bytes());
        let response_auth = md5::compute(&to_hash);

        let mut response_buf = Vec::new();
        response_buf.extend_from_slice(&response_header);
        response_buf.extend_from_slice(&response_auth.0);
        response_buf.extend_from_slice(&payload);

        socket.send_to(&response_buf, src).await.unwrap();
        info!("Mock RADIUS: Sent Challenge");

        // 2. Receive Challenge Response, send Success
        let (len, src) = socket.recv_from(&mut buf).await.unwrap();
        info!("Mock RADIUS: Received Challenge Response: {:?}", &buf[..len]);
        let req_packet = RadiusPacket::from_bytes(&buf[..len]).unwrap();

        let mut response_header = vec![RadiusCode::AccessAccept as u8, req_packet.id, 0, 0];
        let mut to_hash = response_header.clone();
        to_hash.extend_from_slice(&req_packet.authenticator);
        to_hash.extend_from_slice(secret.as_bytes());
        let response_auth = md5::compute(&to_hash);

        let mut final_response = Vec::new();
        let length = (chilli_net::radius::RADIUS_HDR_LEN) as u16;
        response_header[2..4].copy_from_slice(&length.to_be_bytes());
        final_response.extend_from_slice(&response_header[0..2]);
        final_response.extend_from_slice(&length.to_be_bytes());
        final_response.extend_from_slice(&response_auth.0);

        socket.send_to(&final_response, src).await.unwrap();
        info!("Mock RADIUS: Sent Access-Accept");
    }

    #[tokio::test]
    async fn test_eap_flow() {
        tracing_subscriber::fmt::init();
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let mut config = Config::default();
        if let std::net::IpAddr::V4(ip) = server_addr.ip() {
            config.radiusserver1 = ip;
        }
        config.radiusauthport = server_addr.port();
        let secret = config.radiussecret.clone();
        let arc_config = Arc::new(config);

        let mock_server_handle = tokio::spawn(mock_radius_server(server_socket, secret));

        let radius_client = Arc::new(RadiusClient::new(arc_config.clone()).await.unwrap());
        let session_manager = Arc::new(SessionManager::new());
        let firewall = Arc::new(Firewall::new((**radius_client.config()).clone()));

        let (tx, rx) = oneshot::channel();
        let auth_request = chilli_core::AuthRequest {
            auth_type: AuthType::Eap,
            ip: Ipv4Addr::new(10, 0, 0, 1),
            username: "testuser".to_string(),
            password: Some("password".to_string()),
            tx,
        };

        let handle = tokio::spawn(handle_eap_auth(
            auth_request,
            radius_client.clone(),
            session_manager.clone(),
            firewall.clone(),
            arc_config.clone(),
        ));

        let client_run = tokio::spawn(async move {
            radius_client.run().await;
        });

        let result = tokio::time::timeout(tokio::time::Duration::from_secs(10), rx).await;

        assert!(result.is_ok(), "Test timed out");
        let auth_result = result.unwrap();
        assert!(auth_result.is_ok(), "Authentication channel closed");
        assert!(auth_result.unwrap(), "Authentication failed");

        handle.await.unwrap();
        mock_server_handle.await.unwrap();
        client_run.abort();
    }
}
