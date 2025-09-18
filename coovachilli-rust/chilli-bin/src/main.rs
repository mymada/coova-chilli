mod config;
mod cmdsock;

use anyhow::Result;
use chilli_core::{AuthType, Session, SessionManager};
use chilli_http::server;
use chilli_net::dhcp::DhcpServer;
use chilli_net::eap_mschapv2;
use chilli_net::mschapv1;
use chilli_net::mschapv2;
use chilli_net::radius::{
    AuthResult, RadiusClient, ACCT_TERMINATE_CAUSE_IDLE_TIMEOUT,
    ACCT_TERMINATE_CAUSE_SESSION_TIMEOUT,
};
use chilli_net::tun;
use chilli_net::Firewall;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::process::Command;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EthernetPacket, EtherType, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::vlan::VlanPacket;
use pnet::packet::Packet;
use chilli_net::radius::RadiusAttributes;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{watch, Mutex};
use tracing::{error, info, warn};
use chilli_net::eap::{EapCode, EapPacket, EapType};
use chilli_net::eapol::EapolPacket;
use chilli_net::AsyncDevice;
use pnet_base::MacAddr;

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

async fn run_script(
    script_path: String,
    session: &Session,
    config: &Arc<chilli_core::Config>,
    terminate_cause: Option<u32>,
) {
    info!(
        "Running script {} for session {}",
        script_path, session.state.sessionid
    );
    let mut cmd = Command::new(&script_path);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let session_time = now - session.state.start_time;
    let idle_time = now - session.state.last_up_time;

    cmd.env("DEV", config.tundev.as_deref().unwrap_or(""));
    cmd.env("NET", config.net.to_string());
    cmd.env("MASK", config.mask.to_string());
    cmd.env("ADDR", config.uamlisten.to_string());
    if let Some(username) = &session.state.redir.username {
        cmd.env("USER_NAME", username);
    }
    cmd.env("NAS_IP_ADDRESS", config.radiuslisten.to_string());
    cmd.env("SERVICE_TYPE", "1");
    cmd.env("FRAMED_IP_ADDRESS", session.hisip.to_string());
    if let Some(filter_id) = &session.params.filterid {
        cmd.env("FILTER_ID", filter_id);
    }
    if let Some(state) = &session.state.redir.state {
        cmd.env("STATE", hex::encode(state));
    }
    if let Some(class) = &session.state.redir.class {
        cmd.env("CLASS", hex::encode(class));
    }
    if let Some(cui) = &session.state.redir.cui {
        cmd.env("CUI", hex::encode(cui));
    }
    cmd.env(
        "SESSION_TIMEOUT",
        session.params.sessiontimeout.to_string(),
    );
    cmd.env("IDLE_TIMEOUT", session.params.idletimeout.to_string());
    cmd.env("CALLING_STATION_ID", hex::encode(session.hismac));
    // Placeholder for CALLED_STATION_ID, which should be the NAS MAC
    cmd.env("CALLED_STATION_ID", "00-00-00-00-00-00");
    if let Some(nas_id) = &config.radiusnasid {
        cmd.env("NAS_ID", nas_id);
    }
    cmd.env("NAS_PORT_TYPE", "19");
    cmd.env("ACCT_SESSION_ID", &session.state.sessionid);
    cmd.env(
        "ACCT_INTERIM_INTERVAL",
        session.params.interim_interval.to_string(),
    );
    if let Some(loc_id) = &config.radiuslocationid {
        cmd.env("WISPR_LOCATION_ID", loc_id);
    }
    if let Some(loc_name) = &config.radiuslocationname {
        cmd.env("WISPR_LOCATION_NAME", loc_name);
    }
    cmd.env(
        "WISPR_BANDWIDTH_MAX_UP",
        session.params.bandwidthmaxup.to_string(),
    );
    cmd.env(
        "WISPR_BANDWIDTH_MAX_DOWN",
        session.params.bandwidthmaxdown.to_string(),
    );
    cmd.env(
        "COOVACHILLI_MAX_INPUT_OCTETS",
        session.params.maxinputoctets.to_string(),
    );
    cmd.env(
        "COOVACHILLI_MAX_OUTPUT_OCTETS",
        session.params.maxoutputoctets.to_string(),
    );
    cmd.env(
        "COOVACHILLI_MAX_TOTAL_OCTETS",
        session.params.maxtotaloctets.to_string(),
    );
    cmd.env("INPUT_OCTETS", session.state.input_octets.to_string());
    cmd.env("OUTPUT_OCTETS", session.state.output_octets.to_string());
    cmd.env("INPUT_PACKETS", session.state.input_packets.to_string());
    cmd.env("OUTPUT_PACKETS", session.state.output_packets.to_string());
    cmd.env("SESSION_TIME", session_time.to_string());
    cmd.env("IDLE_TIME", idle_time.to_string());

    if let Some(cause) = terminate_cause {
        cmd.env("TERMINATE_CAUSE", cause.to_string());
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

use std::env;

// Constants for ioprio_set
const IOPRIO_CLASS_SHIFT: i32 = 13;
const IOPRIO_CLASS_RT: i32 = 1;
const IOPRIO_WHO_PROCESS: i32 = 1;

// Syscall numbers for ioprio_set
#[cfg(target_arch = "x86_64")]
const __NR_IOPRIO_SET: i64 = 251;
#[cfg(target_arch = "x86")]
const __NR_IOPRIO_SET: i64 = 289;
#[cfg(target_arch = "aarch64")]
const __NR_IOPRIO_SET: i64 = 59; // Common for aarch64, but may vary

fn set_process_priority() {
    if let Ok(prio_str) = env::var("CHILLI_PRIORITY") {
        if let Ok(prio) = prio_str.parse::<i32>() {
            unsafe {
                let pid = libc::getpid();
                if libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, prio) != 0 {
                    warn!("Failed to set process priority: {}", std::io::Error::last_os_error());
                } else {
                    info!("Successfully set process priority to {}", prio);
                }
            }
        }
    }
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
fn set_io_priority() {
    if let Ok(prio_str) = env::var("CHILLI_IOPRIO_RT") {
        if let Ok(prio) = prio_str.parse::<i32>() {
            if prio < 0 || prio > 7 {
                warn!("Invalid I/O priority value: {}. Must be between 0 and 7.", prio);
                return;
            }
            let ioprio = prio | (IOPRIO_CLASS_RT << IOPRIO_CLASS_SHIFT);
            unsafe {
                let pid = libc::getpid();
                let result = libc::syscall(__NR_IOPRIO_SET, IOPRIO_WHO_PROCESS, pid, ioprio);
                if result != 0 {
                    warn!("Failed to set I/O priority: {}", std::io::Error::last_os_error());
                } else {
                    info!("Successfully set I/O priority to real-time class with level {}", prio);
                }
            }
        }
    }
}

#[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64"))))]
fn set_io_priority() {
    if env::var("CHILLI_IOPRIO_RT").is_ok() {
        warn!("Setting I/O priority is only supported on Linux (x86, x86_64, aarch64).");
    }
}

async fn sighup_handler(config_tx: watch::Sender<Arc<chilli_core::Config>>) {
    let mut stream = match signal(SignalKind::hangup()) {
        Ok(stream) => stream,
        Err(e) => {
            error!("Failed to create SIGHUP listener: {}", e);
            return;
        }
    };

    while stream.recv().await.is_some() {
        info!("SIGHUP received, reloading configuration...");
        match config::load_config() {
            Ok(new_config) => {
                if config_tx.send(Arc::new(new_config)).is_err() {
                    error!("Config receiver dropped, cannot reload config.");
                    break;
                }
                info!("Configuration reloaded successfully.");
            }
            Err(e) => {
                error!("Failed to reload configuration: {}", e);
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting CoovaChilli-Rust");

    set_process_priority();
    set_io_priority();

    let initial_config = match config::load_config() {
        Ok(config) => Arc::new(config),
        Err(e) => {
            eprintln!("Error loading config: {}", e);
            std::process::exit(1);
        }
    };

    let (config_tx, config_rx) = watch::channel(initial_config);

    let config = config_rx.borrow().clone();

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

    let eapol_attribute_cache =
        Arc::new(Mutex::new(HashMap::<[u8; 6], RadiusAttributes>::new()));

    let (auth_tx, auth_rx) = tokio::sync::mpsc::channel(100);

    let config_clone_http = config.clone();
    let auth_tx_http = auth_tx.clone();
    let _http_server_handle = tokio::spawn(async move {
        if let Err(e) = server::run_server(&config_clone_http, auth_tx_http).await {
            error!("HTTP server error: {}", e);
        }
    });

    let dhcp_server = Arc::new(
        DhcpServer::new(config_rx.clone()).await?,
    );

    let dhcp_reaper_handle = tokio::spawn(dhcp_reaper_loop(dhcp_server.clone()));

    let radius_client = Arc::new(RadiusClient::new(config_rx.clone()).await?);
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
        config_rx.clone(),
        walled_garden_ips.clone(),
    ));

    let proxy_listener_handle = if let Some(listen_ip) = config.proxylisten {
        let config_rx = config_rx.clone();
        Some(tokio::spawn(async move {
            let config = config_rx.borrow().clone();
            let auth_addr = format!("{}:{}", listen_ip, config.proxyport);
            let acct_addr = format!("{}:{}", listen_ip, config.proxyport + 1); // TODO: Make this configurable

            match UdpSocket::bind(&auth_addr).await {
                Ok(auth_socket) => {
                    info!("RADIUS proxy auth listening on {}", auth_addr);
                    match UdpSocket::bind(&acct_addr).await {
                        Ok(acct_socket) => {
                            info!("RADIUS proxy acct listening on {}", acct_addr);
                            let auth_proxy_socket = Arc::new(auth_socket);
                            let acct_proxy_socket = Arc::new(acct_socket);
                            match chilli_net::radius_proxy::ProxyManager::new(
                                config_rx.clone(),
                                auth_proxy_socket.clone(),
                                acct_proxy_socket.clone(),
                            )
                            .await
                            {
                                Ok(mut proxy_manager) => {
                                    proxy_manager.run_request_listener().await;
                                }
                                Err(e) => {
                                    error!("Failed to create RADIUS proxy manager: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to bind RADIUS proxy acct socket on {}: {}", acct_addr, e);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to bind RADIUS proxy auth socket on {}: {}", auth_addr, e);
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

    let l2_dispatcher_handle = tokio::spawn(l2_packet_dispatcher(
        session_manager.clone(),
        radius_client.clone(),
        dhcp_server.clone(),
        firewall.clone(),
        config_rx.clone(),
        walled_garden_ips.clone(),
        eapol_attribute_cache.clone(),
        auth_tx.clone(),
    ));

    let tun_loop_handle = tokio::spawn(tun_packet_loop(
        iface.clone(),
        session_manager.clone(),
        config_rx.clone(),
    ));

    let auth_loop_handle = tokio::spawn(auth_loop(
        auth_rx,
        radius_client.clone(),
        session_manager.clone(),
        firewall.clone(),
        config_rx.clone(),
    ));

    let interim_update_handle = tokio::spawn(interim_update_loop(
        radius_client.clone(),
        session_manager.clone(),
        config_rx.clone(),
        firewall.clone(),
    ));

    tokio::select! {
        res = l2_dispatcher_handle => {
            if let Err(e) = res.unwrap() {
                error!("L2 dispatcher failed: {}", e);
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
        _ = tun_loop_handle => {
            info!("TUN loop finished.");
        }
        _ = _radius_client_handle => {
            info!("RADIUS client finished.");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl-C, shutting down.");
        }
        _ = sighup_handler(config_tx) => {
            info!("SIGHUP handler finished.");
        }
    }

    let config = config_rx.borrow().clone();
    if let Err(e) = save_status(&config.statusfile, &session_manager) {
        warn!("Failed to save status file: {}", e);
    }

    firewall.cleanup().ok();

    info!("Sending Acct-Stop for all active sessions...");
    for session in session_manager.get_all_sessions().await {
        if session.state.authenticated {
            firewall.remove_user_filter(session.hisip).ok();
            if let Some(ref condown) = config.condown {
                run_script(condown.clone(), &session, &config, None).await;
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
    mut config_rx: watch::Receiver<Arc<chilli_core::Config>>,
    walled_garden_ips: Arc<Mutex<HashSet<Ipv4Addr>>>,
) {
    loop {
        let config = config_rx.borrow().clone();
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

        let sleep_duration = Duration::from_secs(config.interval as u64);
        tokio::select! {
            _ = tokio::time::sleep(sleep_duration) => {},
            res = config_rx.changed() => {
                if res.is_err() {
                    info!("Config channel closed, ending walled garden resolver loop.");
                    return;
                }
            }
        }
    }
}

async fn interim_update_loop(
    radius_client: Arc<RadiusClient>,
    session_manager: Arc<SessionManager>,
    mut config_rx: watch::Receiver<Arc<chilli_core::Config>>,
    firewall: Arc<Firewall>,
) {
    loop {
        let config = config_rx.borrow().clone();
        let interval_secs = config.interval as u64;

        if interval_secs > 0 {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval_secs)) => {},
                res = config_rx.changed() => {
                    if res.is_err() {
                        info!("Config channel closed, ending interim update loop.");
                        return;
                    }
                    // Config changed, loop will restart and use new interval
                    continue;
                }
            }
        } else {
            // Interval is 0, wait for config change
            if config_rx.changed().await.is_err() {
                info!("Config channel closed, ending interim update loop.");
                return;
            }
            // Loop to get new config
            continue;
        }

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
                        run_script(condown.clone(), &session, &config, Some(cause)).await;
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
                    run_script(conup.clone(), &session, &config, None).await;
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
                        run_script(conup.clone(), &session, &config, None).await;
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

async fn handle_mschapv1_auth(
    req: chilli_core::AuthRequest,
    radius_client: Arc<RadiusClient>,
    session_manager: Arc<SessionManager>,
    firewall: Arc<Firewall>,
    config: Arc<chilli_core::Config>,
) {
    info!("Processing MS-CHAPv1 auth request for user '{}'", req.username);

    let result = radius_client.send_chap_access_request(&req.username).await;

    match result {
        Ok(AuthResult::ChapChallenge(challenge_data, state)) => {
            if challenge_data.len() < 9 {
                error!("Invalid CHAP challenge received from RADIUS server.");
                req.tx.send(false).ok();
                return;
            }
            let identifier = challenge_data[0];
            let challenge: [u8; 8] = challenge_data[1..9].try_into().unwrap();

            let password = req.password.as_deref().unwrap_or_default();
            let response = mschapv1::mschap_lanman_response(&challenge, password);

            let result = radius_client
                .send_chap_response(identifier, &response, state.as_deref())
                .await;

            match result {
                Ok(AuthResult::Success(attributes)) => {
                    info!("MS-CHAPv1 Authentication successful for user '{}'", req.username);
                    session_manager.authenticate_session(&req.ip).await;
                    chilli_net::radius::apply_radius_attributes(
                        &attributes,
                        &session_manager,
                        &firewall,
                        &req.ip,
                    )
                    .await;
                    if let Some(session) = session_manager.get_session(&req.ip).await {
                        if let Some(ref conup) = config.conup {
                            run_script(conup.clone(), &session, &config, None).await;
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
                _ => {
                    info!("MS-CHAPv1 Authentication failed for user '{}'", req.username);
                    req.tx.send(false).ok();
                }
            }
        }
        _ => {
            info!("MS-CHAPv1 Authentication failed for user '{}'", req.username);
            req.tx.send(false).ok();
        }
    }
}


async fn auth_loop(
    mut rx: tokio::sync::mpsc::Receiver<chilli_core::AuthRequest>,
    radius_client: Arc<RadiusClient>,
    session_manager: Arc<SessionManager>,
    firewall: Arc<Firewall>,
    config_rx: watch::Receiver<Arc<chilli_core::Config>>,
) {
    while let Some(req) = rx.recv().await {
        let config = config_rx.borrow().clone();
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
            AuthType::MsChapV1 => {
                tokio::spawn(handle_mschapv1_auth(
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

//
// FIXME: Architectural Limitation for EAPOL/VLAN support
//
// The current packet processing architecture, which relies on a TUN/TAP interface
// for handling IP packets, is not suitable for implementing features that
// require access to raw Ethernet frames from the physical interface, such as
// 802.1x (EAPOL) and 802.1q (VLAN).
//
// The original C implementation of CoovaChilli uses raw sockets (pcap or SOCK_PACKET)
// to capture all traffic on the physical interface (`dhcpif`). This allows it
// to inspect Ethernet headers and handle non-IP protocols like EAPOL and ARP,
// as well as VLAN tags.
//
// The current Rust implementation's `DhcpServer` uses a `UdpSocket`, which
// operates at a higher level and does not provide access to the Ethernet layer.
// The `packet_loop` in this file only sees IP packets that have been routed
// through the TUN/TAP device.
//
// To properly implement EAPOL and VLAN support, a significant refactoring is
// required to introduce a raw packet capture mechanism. This would likely involve:
// 1. Using a crate like `pnet` to open a raw socket on the `dhcpif`.
// 2. Creating a new packet processing loop that receives raw Ethernet frames.
// 3. Dispatching frames based on their EtherType (e.g., to an EAPOL handler,
//    an ARP handler, or an IP handler).
// 4. Modifying the `DhcpServer` to integrate with this new packet capture
//    mechanism instead of using a `UdpSocket`.
//
// This work has been postponed in favor of completing other features.
//

//
// FIXME: Architectural Limitation for EAPOL/VLAN support
//
// The current packet processing architecture, which relies on a TUN/TAP interface
// for handling IP packets, is not suitable for implementing features that
// require access to raw Ethernet frames from the physical interface, such as
// 802.1x (EAPOL) and 802.1q (VLAN).
//
// The original C implementation of CoovaChilli uses raw sockets (pcap or SOCK_PACKET)
// to capture all traffic on the physical interface (`dhcpif`). This allows it
// to inspect Ethernet headers and handle non-IP protocols like EAPOL and ARP,
// as well as VLAN tags.
//
// The current Rust implementation's `DhcpServer` uses a `UdpSocket`, which
// operates at a higher level and does not provide access to the Ethernet layer.
// The `packet_loop` in this file only sees IP packets that have been routed
// through the TUN/TAP device.
//
// To properly implement EAPOL and VLAN support, a significant refactoring is
// required to introduce a raw packet capture mechanism. This would likely involve:
// 1. Using a crate like `pnet` to open a raw socket on the `dhcpif`.
// 2. Creating a new packet processing loop that receives raw Ethernet frames.
// 3. Dispatching frames based on their EtherType (e.g., to an EAPOL handler,
//    an ARP handler, or an IP handler).
// 4. Modifying the `DhcpServer` to integrate with this new packet capture
//    mechanism instead of using a `UdpSocket`.
//
// This work has been postponed in favor of completing other features.
//

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

async fn handle_ethernet_frame(
    tx: &mut Box<dyn pnet::datalink::DataLinkSender>,
    our_mac: MacAddr,
    ethernet_packet: &EthernetPacket<'_>,
    vlan_id: Option<u16>,
    session_manager: &Arc<SessionManager>,
    radius_client: &Arc<RadiusClient>,
    dhcp_server: &Arc<DhcpServer>,
    firewall: &Arc<Firewall>,
    config: &Arc<chilli_core::Config>,
    eapol_attribute_cache: &Arc<Mutex<HashMap<[u8; 6], RadiusAttributes>>>,
    auth_tx: &tokio::sync::mpsc::Sender<chilli_core::AuthRequest>,
) {
    match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                if ipv4_packet.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Udp {
                    if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                        if udp_packet.get_destination() == 67 {
                            if let Some(dhcp_packet) =
                                chilli_net::dhcp::DhcpPacket::from_bytes(udp_packet.payload())
                            {
                                let src_addr = std::net::SocketAddr::new(
                                    std::net::IpAddr::V4(ipv4_packet.get_source()),
                                    udp_packet.get_source(),
                                );
                                if let Ok(action) = dhcp_server
                                    .handle_dhcp_packet(dhcp_packet, src_addr, vlan_id)
                                    .await
                                {
                                    use chilli_net::dhcp::DhcpAction;
                                    match action {
                                        DhcpAction::Ack { response, client_ip, client_mac } => {
                                            let _ = tx.send_to(&response, None);
                                            session_manager.create_session(client_ip, client_mac, &config, vlan_id).await;

                                            let mut cache = eapol_attribute_cache.lock().await;
                                            if let Some(attributes) = cache.remove(&client_mac) {
                                                info!("Applying cached EAPOL attributes to session for {}", client_ip);
                                                chilli_net::radius::apply_radius_attributes(&attributes, &session_manager, &firewall, &client_ip).await;
                                            } else {
                                                // MAC Auth logic moved from DhcpServer
                                                if config.macauth {
                                                    let mac_str = hex::encode(client_mac);
                                                    if config.macallowed.contains(&mac_str) {
                                                        info!("MAC {} is in macallowed list, authenticating.", &mac_str);
                                                        session_manager.authenticate_session(&client_ip).await;
                                                    } else {
                                                        let (tx_auth, _rx_auth) = tokio::sync::oneshot::channel();
                                                        let auth_req = chilli_core::AuthRequest {
                                                            auth_type: chilli_core::AuthType::Pap,
                                                            ip: client_ip,
                                                            username: mac_str.clone(),
                                                            password: config.macpasswd.clone(),
                                                            tx: tx_auth,
                                                        };
                                                        auth_tx.send(auth_req).await.ok();
                                                        // We don't block here, but macauthdeny is effectively handled
                                                        // by not sending an ACK if the auth fails later.
                                                        // This is a simplification. A real implementation might need to
                                                        // delay the ACK or handle NAKs.
                                                    }
                                                }
                                            }
                                        }
                                        DhcpAction::Offer(response) => {
                                            let _ = tx.send_to(&response, None);
                                        }
                                        DhcpAction::Nak(response) => {
                                            let _ = tx.send_to(&response, None);
                                        }
                                        DhcpAction::NoResponse => {}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        EtherTypes::Arp => {
            // TODO: Handle ARP packets with vlan_id
        }
        ethertype if ethertype == EtherType(0x888E) => {
            if let Some(eapol_packet) = EapolPacket::from_bytes(ethernet_packet.payload()) {
                if let Ok(Some(response_payload)) = handle_eapol_frame(
                    &eapol_packet,
                    ethernet_packet.get_source(),
                    vlan_id,
                    session_manager,
                    radius_client,
                    eapol_attribute_cache,
                )
                .await
                {
                    let mut ethernet_buffer = vec![0u8; 14 + response_payload.len()];
                    let mut new_ethernet_packet = pnet::packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
                    new_ethernet_packet.set_destination(ethernet_packet.get_source());
                    new_ethernet_packet.set_source(our_mac);
                    new_ethernet_packet.set_ethertype(EtherType(0x888E));
                    new_ethernet_packet.set_payload(&response_payload);
                    let _ = tx.send_to(new_ethernet_packet.packet(), None);
                }
            }
        }
        _ => {}
    }
}

async fn tun_packet_loop(
    iface: Arc<AsyncDevice>,
    session_manager: Arc<SessionManager>,
    mut config_rx: watch::Receiver<Arc<chilli_core::Config>>,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 1504];
    loop {
        let n = iface.recv(&mut buf).await?;
        if let Some(ipv4_packet) = Ipv4Packet::new(&buf[..n]) {
            let src_ip = ipv4_packet.get_source();
            let dst_ip = ipv4_packet.get_destination();

            if let Some(session) = session_manager.get_session(&src_ip).await {
                // Handle packet for existing session
                // TODO: Update counters, leaky bucket, etc.
                iface.send(ipv4_packet.packet()).await?;
            } else {
                // Handle packet for unknown session
                let config = config_rx.borrow().clone();
                if config.uamanyip {
                    info!("[uamanyip] Creating session for unknown IP {}", src_ip);
                    // TODO: ARP lookup to find MAC address
                    let dummy_mac = [0; 6];
                    session_manager.create_session(src_ip, dummy_mac, &config, None).await;
                    // Drop the packet, the next one will be redirected
                }
            }
        }
    }
}

async fn handle_eapol_frame(
    eapol_packet: &EapolPacket<'_>,
    src_mac: MacAddr,
    vlan_id: Option<u16>,
    session_manager: &Arc<SessionManager>,
    radius_client: &Arc<RadiusClient>,
    eapol_attribute_cache: &Arc<Mutex<HashMap<[u8; 6], RadiusAttributes>>>,
) -> Result<Option<Vec<u8>>> {
    info!(
        "Handling EAPOL {:?} frame from {} on vlan {:?}",
        eapol_packet.packet_type, src_mac, vlan_id
    );

    match eapol_packet.packet_type {
        chilli_net::eapol::EapolType::Start => {
            info!("Received EAPOL-Start from {}", src_mac);
            session_manager.create_eapol_session(src_mac.octets()).await;

            // Respond with EAP-Request/Identity
            let eap_payload = vec![EapType::Identity as u8];
            let eap_packet = EapPacket {
                code: EapCode::Request,
                identifier: 1, // Start with ID 1
                data: eap_payload,
            };
            let eap_bytes = eap_packet.to_bytes();

            let mut eapol_response = vec![0u8; 4 + eap_bytes.len()];
            eapol_response[0] = 1; // Version
            eapol_response[1] = chilli_net::eapol::EapolType::Eap as u8;
            let length_bytes = (eap_bytes.len() as u16).to_be_bytes();
            eapol_response[2..4].copy_from_slice(&length_bytes);
            eapol_response[4..].copy_from_slice(&eap_bytes);

            return Ok(Some(eapol_response));
        }
        chilli_net::eapol::EapolType::Eap => {
            let mut eapol_session = match session_manager.get_eapol_session(&src_mac.octets()).await {
                Some(s) => s,
                None => {
                    warn!("Received EAP packet from {} without an EAPOL session", src_mac);
                    return Ok(None);
                }
            };

            if let Some(eap_packet) = EapPacket::from_bytes(eapol_packet.payload) {
                if eap_packet.code == EapCode::Response {
                    let result = radius_client.send_eap_response(&eap_packet.data, eapol_session.radius_state.as_deref()).await?;
                    match result {
                        chilli_net::radius::AuthResult::Challenge(eap_message, state) => {
                            eapol_session.radius_state = state;
                            session_manager.update_eapol_session(&src_mac.octets(), |s| *s = eapol_session).await;

                            let mut eapol_response = vec![0u8; 4 + eap_message.len()];
                            eapol_response[0] = 1; // Version
                            eapol_response[1] = chilli_net::eapol::EapolType::Eap as u8;
                            let length_bytes = (eap_message.len() as u16).to_be_bytes();
                            eapol_response[2..4].copy_from_slice(&length_bytes);
                            eapol_response[4..].copy_from_slice(&eap_message);
                            return Ok(Some(eapol_response));
                        }
                        chilli_net::radius::AuthResult::Success(attributes) => {
                            info!("EAPOL authentication successful for {}", src_mac);
                            session_manager.remove_eapol_session(&src_mac.octets()).await;

                            eapol_attribute_cache.lock().await.insert(src_mac.octets(), attributes);

                            let eap_packet = EapPacket {
                                code: EapCode::Success,
                                identifier: eap_packet.identifier,
                                data: vec![],
                            };
                            let eap_bytes = eap_packet.to_bytes();

                            let mut eapol_response = vec![0u8; 4 + eap_bytes.len()];
                            eapol_response[0] = 1; // Version
                            eapol_response[1] = chilli_net::eapol::EapolType::Eap as u8;
                            let length_bytes = (eap_bytes.len() as u16).to_be_bytes();
                            eapol_response[2..4].copy_from_slice(&length_bytes);
                            eapol_response[4..].copy_from_slice(&eap_bytes);
                            return Ok(Some(eapol_response));
                        }
                        chilli_net::radius::AuthResult::Failure => {
                            info!("EAPOL authentication failed for {}", src_mac);
                            session_manager.remove_eapol_session(&src_mac.octets()).await;

                            let eap_packet = EapPacket {
                                code: EapCode::Failure,
                                identifier: eap_packet.identifier,
                                data: vec![],
                            };
                            let eap_bytes = eap_packet.to_bytes();

                            let mut eapol_response = vec![0u8; 4 + eap_bytes.len()];
                            eapol_response[0] = 1; // Version
                            eapol_response[1] = chilli_net::eapol::EapolType::Eap as u8;
                            let length_bytes = (eap_bytes.len() as u16).to_be_bytes();
                            eapol_response[2..4].copy_from_slice(&length_bytes);
                            eapol_response[4..].copy_from_slice(&eap_bytes);
                            return Ok(Some(eapol_response));
                        }
                        _ => {}
                    }
                }
            }
        }
        chilli_net::eapol::EapolType::Logoff => {
            info!("Received EAPOL-Logoff from {}", src_mac);
            if let Some(session) = session_manager.get_session_by_mac(&src_mac.octets()).await {
                info!("Tearing down session for IP {}", session.hisip);
                // TODO: Need firewall and radius_client here to do a full teardown
                session_manager.remove_session(&session.hisip).await;
            }
            session_manager.remove_eapol_session(&src_mac.octets()).await;
        }
        _ => {}
    }

    Ok(None)
}

async fn l2_packet_dispatcher(
    session_manager: Arc<SessionManager>,
    radius_client: Arc<RadiusClient>,
    dhcp_server: Arc<DhcpServer>,
    firewall: Arc<Firewall>,
    config_rx: watch::Receiver<Arc<chilli_core::Config>>,
    _walled_garden_ips: Arc<Mutex<HashSet<Ipv4Addr>>>,
    eapol_attribute_cache: Arc<Mutex<HashMap<[u8; 6], RadiusAttributes>>>,
    auth_tx: tokio::sync::mpsc::Sender<chilli_core::AuthRequest>,
) -> anyhow::Result<()> {
    let config = config_rx.borrow().clone();

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface: &NetworkInterface| iface.name == config.dhcpif)
        .expect("Failed to find interface");

    let our_mac = interface.mac.expect("Failed to get MAC address from interface");
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    if ethernet_packet.get_ethertype() == EtherTypes::Vlan {
                        if let Some(vlan_packet) = VlanPacket::new(ethernet_packet.payload()) {
                            let vlan_id = vlan_packet.get_vlan_identifier();
                            if let Some(inner_ethernet_packet) =
                                EthernetPacket::new(vlan_packet.payload())
                            {
                                handle_ethernet_frame(
                                    &mut tx,
                                    our_mac,
                                    &inner_ethernet_packet,
                                    Some(vlan_id),
                                    &session_manager,
                                    &radius_client,
                                    &dhcp_server,
                                    &firewall,
                                    &config,
                                    &eapol_attribute_cache,
                                    &auth_tx,
                                )
                                .await;
                            }
                        }
                    } else {
                        handle_ethernet_frame(
                            &mut tx,
                            our_mac,
                            &ethernet_packet,
                            None,
                            &session_manager,
                            &radius_client,
                            &dhcp_server,
                            &firewall,
                            &config,
                            &eapol_attribute_cache,
                            &auth_tx,
                        )
                        .await;
                    }
                }
            }
            Err(e) => {
                error!("An error occurred while reading: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chilli_core::Config;
    use chilli_net::eap::{EapCode, EapType};
    use chilli_net::radius::{RadiusAttributeType, RadiusAttributeValue, RadiusCode, RadiusPacket};
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

        let (_config_tx, config_rx) = watch::channel(arc_config.clone());

        let mock_server_handle = tokio::spawn(mock_radius_server(server_socket, secret));

        let radius_client = Arc::new(RadiusClient::new(config_rx).await.unwrap());
        let session_manager = Arc::new(SessionManager::new());
        let firewall = Arc::new(Firewall::new(arc_config.as_ref().clone()));

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
