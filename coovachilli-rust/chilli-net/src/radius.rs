use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ByteOrder};
use chilli_core::{Config, Session, SessionManager};
use md5::{Digest, Md5};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, watch};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

// RADIUS Packet Codes
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum RadiusCode {
    AccessRequest = 1,
    AccessAccept = 2,
    AccessReject = 3,
    AccountingRequest = 4,
    AccountingResponse = 5,
    AccessChallenge = 11,
    StatusServer = 12,
    StatusClient = 13,
    DisconnectRequest = 40,
    DisconnectAck = 41,
    DisconnectNak = 42,
    CoaRequest = 43,
    CoaAck = 44,
    CoaNak = 45,
}

impl RadiusCode {
    fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::AccessRequest),
            2 => Some(Self::AccessAccept),
            3 => Some(Self::AccessReject),
            4 => Some(Self::AccountingRequest),
            5 => Some(Self::AccountingResponse),
            11 => Some(Self::AccessChallenge),
            40 => Some(Self::DisconnectRequest),
            41 => Some(Self::DisconnectAck),
            42 => Some(Self::DisconnectNak),
            43 => Some(Self::CoaRequest),
            44 => Some(Self::CoaAck),
            45 => Some(Self::CoaNak),
            _ => None,
        }
    }
}

// RADIUS Attributes
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, FromPrimitive)]
#[repr(u8)]
pub enum RadiusAttributeType {
    UserName = 1,
    UserPassword = 2,
    ChapPassword = 3,
    FramedIpAddress = 8,
    FilterId = 11,
    State = 24,
    Class = 25,
    VendorSpecific = 26,
    SessionTimeout = 27,
    IdleTimeout = 28,
    NasIdentifier = 32,
    ProxyState = 33,
    ChapChallenge = 60,
    EapMessage = 79,
    MessageAuthenticator = 80,
    AcctStatusType = 40,
    AcctDelayTime = 41,
    AcctInputOctets = 42,
    AcctOutputOctets = 43,
    AcctSessionId = 44,
    AcctAuthentic = 45,
    AcctSessionTime = 46,
    AcctInputPackets = 47,
    AcctOutputPackets = 48,
    AcctTerminateCause = 49,
    AcctInputGigawords = 52,
    AcctOutputGigawords = 53,
}

// VSA Constants
pub const VENDOR_ID_WISPR: u32 = 14122;
pub const WISPR_BANDWIDTH_MAX_UP: u8 = 7;
pub const WISPR_BANDWIDTH_MAX_DOWN: u8 = 8;
pub const VENDOR_ID_COOVA: u32 = 14559;
pub const COOVA_MAX_INPUT_OCTETS: u8 = 1;
pub const COOVA_MAX_OUTPUT_OCTETS: u8 = 2;
pub const COOVA_MAX_TOTAL_OCTETS: u8 = 3;

// Acct-Status-Type values
pub const ACCT_STATUS_TYPE_START: u32 = 1;
pub const ACCT_STATUS_TYPE_STOP: u32 = 2;
pub const ACCT_STATUS_TYPE_INTERIM_UPDATE: u32 = 3;

// Acct-Terminate-Cause values
pub const ACCT_TERMINATE_CAUSE_USER_REQUEST: u32 = 1;
pub const ACCT_TERMINATE_CAUSE_IDLE_TIMEOUT: u32 = 4;
pub const ACCT_TERMINATE_CAUSE_SESSION_TIMEOUT: u32 = 5;
pub const ACCT_TERMINATE_CAUSE_ADMIN_RESET: u32 = 6;
pub const ACCT_TERMINATE_CAUSE_QUOTA_EXCEEDED: u32 = 100;


pub const RADIUS_HDR_LEN: usize = 20;
pub const RADIUS_MAX_LEN: usize = 4096;
pub const RADIUS_AUTH_LEN: usize = 16;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RadiusPacket {
    pub code: u8,
    pub id: u8,
    pub length: u16,
    pub authenticator: [u8; RADIUS_AUTH_LEN],
    pub payload: [u8; RADIUS_MAX_LEN - RADIUS_HDR_LEN],
}

impl RadiusPacket {
    pub fn from_bytes(data: &[u8]) -> Option<&RadiusPacket> {
        if data.len() < RADIUS_HDR_LEN {
            return None;
        }
        let len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < len {
            return None;
        }
        Some(unsafe { &*(data.as_ptr() as *const RadiusPacket) })
    }
}

#[derive(Debug, Default, Clone)]
pub struct RadiusAttributes {
    pub standard: HashMap<RadiusAttributeType, Vec<Vec<u8>>>,
    pub vsas: HashMap<(u32, u8), Vec<Vec<u8>>>,
}

use super::Firewall;

pub async fn apply_radius_attributes(
    attributes: &RadiusAttributes,
    session_manager: &Arc<SessionManager>,
    firewall: &Arc<Firewall>,
    ip: &Ipv4Addr,
) {
    if let Some(session_timeout_val) = attributes.get_standard(RadiusAttributeType::SessionTimeout)
    {
        if session_timeout_val.len() == 4 {
            let timeout = BigEndian::read_u32(session_timeout_val);
            info!("Session-Timeout for {} is {}", ip, timeout);
            session_manager
                .update_session(ip, |session| {
                    session.params.sessiontimeout = timeout as u64;
                })
                .await;
        }
    }

    if let Some(idle_timeout_val) = attributes.get_standard(RadiusAttributeType::IdleTimeout) {
        if idle_timeout_val.len() == 4 {
            let timeout = BigEndian::read_u32(idle_timeout_val);
            info!("Idle-Timeout for {} is {}", ip, timeout);
            session_manager
                .update_session(ip, |session| {
                    session.params.idletimeout = timeout;
                })
                .await;
        }
    }

    if let Some(filter_id_val) = attributes.get_standard(RadiusAttributeType::FilterId) {
        if let Ok(filter_id) = String::from_utf8(filter_id_val.clone()) {
            info!("Filter-Id for {} is {}", ip, filter_id);
            if !filter_id.is_empty() {
                if let Err(e) = firewall.apply_user_filter(*ip, &filter_id) {
                    error!("Failed to apply user filter for {}: {}", ip, e);
                }
                session_manager
                    .update_session(ip, |session| {
                        session.params.filterid = Some(filter_id);
                    })
                    .await;
            } else {
                // Empty Filter-Id, remove any existing filter
                if let Err(e) = firewall.remove_user_filter(*ip) {
                    error!("Failed to remove user filter for {}: {}", ip, e);
                }
                session_manager
                    .update_session(ip, |session| {
                        session.params.filterid = None;
                    })
                    .await;
            }
        }
    } else {
        // No Filter-Id attribute, ensure no filter is applied
        if let Err(e) = firewall.remove_user_filter(*ip) {
            error!("Failed to remove user filter for {}: {}", ip, e);
        }
        session_manager
            .update_session(ip, |session| {
                session.params.filterid = None;
            })
            .await;
    }

    if let Some(class_val) = attributes.get_standard(RadiusAttributeType::Class) {
        info!("Class for {} is {:?}", ip, class_val);
        session_manager
            .update_session(ip, |session| {
                session.params.class = Some(class_val.clone());
            })
            .await;
    }

    if let Some(bw_up_val) = attributes.get_vsa(VENDOR_ID_WISPR, WISPR_BANDWIDTH_MAX_UP) {
        if bw_up_val.len() == 4 {
            let bw = BigEndian::read_u32(bw_up_val);
            info!("WISPr-Bandwidth-Max-Up for {} is {}", ip, bw);
            session_manager
                .update_session(ip, |session| {
                    session.params.bandwidthmaxup = bw as u64;
                    session.state.bucketupsize = (bw as u64) / 8 * 2; // BUCKET_TIME
                })
                .await;
        }
    }

    if let Some(bw_down_val) = attributes.get_vsa(VENDOR_ID_WISPR, WISPR_BANDWIDTH_MAX_DOWN) {
        if bw_down_val.len() == 4 {
            let bw = BigEndian::read_u32(bw_down_val);
            info!("WISPr-Bandwidth-Max-Down for {} is {}", ip, bw);
            session_manager
                .update_session(ip, |session| {
                    session.params.bandwidthmaxdown = bw as u64;
                    session.state.bucketdownsize = (bw as u64) / 8 * 2; // BUCKET_TIME
                })
                .await;
        }
    }

    if let Some(val) = attributes.get_vsa(VENDOR_ID_COOVA, COOVA_MAX_INPUT_OCTETS) {
        if val.len() == 4 {
            let octets = BigEndian::read_u32(val) as u64;
            info!("CoovaChilli-Max-Input-Octets for {} is {}", ip, octets);
            session_manager
                .update_session(ip, |session| {
                    session.params.maxinputoctets = octets;
                })
                .await;
        }
    }

    if let Some(val) = attributes.get_vsa(VENDOR_ID_COOVA, COOVA_MAX_OUTPUT_OCTETS) {
        if val.len() == 4 {
            let octets = BigEndian::read_u32(val) as u64;
            info!("CoovaChilli-Max-Output-Octets for {} is {}", ip, octets);
            session_manager
                .update_session(ip, |session| {
                    session.params.maxoutputoctets = octets;
                })
                .await;
        }
    }

    if let Some(val) = attributes.get_vsa(VENDOR_ID_COOVA, COOVA_MAX_TOTAL_OCTETS) {
        if val.len() == 4 {
            let octets = BigEndian::read_u32(val) as u64;
            info!("CoovaChilli-Max-Total-Octets for {} is {}", ip, octets);
            session_manager
                .update_session(ip, |session| {
                    session.params.maxtotaloctets = octets;
                })
                .await;
        }
    }
}

impl RadiusAttributes {
    pub fn get_standard(&self, t: RadiusAttributeType) -> Option<&Vec<u8>> {
        self.standard.get(&t).and_then(|v| v.first())
    }

    pub fn get_vsa(&self, vendor_id: u32, vsa_type: u8) -> Option<&Vec<u8>> {
        self.vsas.get(&(vendor_id, vsa_type)).and_then(|v| v.first())
    }
}

pub fn parse_attributes(payload: &[u8]) -> RadiusAttributes {
    let mut attributes = RadiusAttributes::default();
    let mut offset = 0;
    while offset < payload.len() {
        let type_code_u8 = payload[offset];
        let length = payload[offset + 1] as usize;

        if length < 2 || offset + length > payload.len() {
            warn!("Invalid RADIUS attribute length");
            break;
        }

        let value = &payload[offset + 2..offset + length];

        if let Some(type_code) = FromPrimitive::from_u8(type_code_u8) {
            if type_code == RadiusAttributeType::VendorSpecific {
                if value.len() >= 6 {
                    let vendor_id = BigEndian::read_u32(&value[0..4]);
                    let vsa_type = value[4];
                    let vsa_len = value[5] as usize;
                    if value.len() >= vsa_len && vsa_len >= 2 {
                        let vsa_value = &value[6..vsa_len + 4];
                        attributes
                            .vsas
                            .entry((vendor_id, vsa_type))
                            .or_default()
                            .push(vsa_value.to_vec());
                    }
                }
            } else {
                attributes
                    .standard
                    .entry(type_code)
                    .or_default()
                    .push(value.to_vec());
            }
        } else {
            warn!("Unknown RADIUS attribute type: {}", type_code_u8);
        }

        offset += length;
    }
    attributes
}

pub fn serialize_attributes(attributes: &RadiusAttributes) -> Vec<u8> {
    let mut payload = Vec::new();
    for (type_code, values) in &attributes.standard {
        for value in values {
            payload.push(*type_code as u8);
            payload.push((value.len() + 2) as u8);
            payload.extend_from_slice(value);
        }
    }
    for ((vendor_id, vsa_type), values) in &attributes.vsas {
        for value in values {
            let mut vsa_payload = Vec::new();
            vsa_payload.extend_from_slice(&vendor_id.to_be_bytes());
            vsa_payload.push(*vsa_type);
            vsa_payload.push((value.len() + 2) as u8);
            vsa_payload.extend_from_slice(value);

            payload.push(RadiusAttributeType::VendorSpecific as u8);
            payload.push((vsa_payload.len() + 2) as u8);
            payload.extend_from_slice(&vsa_payload);
        }
    }
    payload
}


pub struct RadiusAttributeValue {
    pub type_code: RadiusAttributeType,
    pub value: Vec<u8>,
}

#[derive(Debug)]
pub enum AuthResult {
    Success(RadiusAttributes),
    Challenge(Vec<u8>, Option<Vec<u8>>), // EAP Message, State
    ChapChallenge(Vec<u8>, Option<Vec<u8>>), // CHAP Challenge, State
    Failure,
}

struct PendingRequest {
    packet: Vec<u8>,
    tx: Option<oneshot::Sender<Result<AuthResult>>>,
    is_acct_packet: bool,

    // Retry state
    next_attempt_at: SystemTime,
    attempt_count: u8,
    current_server_index: usize,
}

fn encrypt_password(password: &[u8], secret: &[u8], authenticator: &[u8; 16]) -> Vec<u8> {
    // Per RFC 2865, the password must be padded to a multiple of 16 octets.
    let mut padded_password = password.to_vec();
    if padded_password.len() % 16 != 0 {
        let new_len = (padded_password.len() + 15) & !15;
        padded_password.resize(new_len, 0);
    }

    // The first block is a special case. If the password is empty, it should be treated as a 16-byte zero block.
    if padded_password.is_empty() {
        padded_password.resize(16, 0);
    }

    let mut encrypted_password = Vec::new();
    let mut last_block = authenticator.to_vec();

    for chunk in padded_password.chunks(16) {
        let mut hasher = Md5::new();
        hasher.update(secret);
        hasher.update(&last_block);
        let hash = hasher.finalize();

        let mut encrypted_chunk = [0u8; 16];
        for i in 0..16 {
            encrypted_chunk[i] = chunk[i] ^ hash[i];
        }

        encrypted_password.extend_from_slice(&encrypted_chunk);
        last_block = encrypted_chunk.to_vec();
    }

    encrypted_password
}

pub struct RadiusClient {
    socket: Arc<UdpSocket>,
    pub coa_socket: Arc<UdpSocket>,
    config_rx: watch::Receiver<Arc<Config>>,
    next_id: Arc<Mutex<u8>>,
    pending_requests: Arc<Mutex<HashMap<u8, PendingRequest>>>,
}

impl RadiusClient {
    pub async fn new(config_rx: watch::Receiver<Arc<Config>>) -> Result<Self> {
        let config = config_rx.borrow().clone();
        let addr = format!("{}:0", config.radiuslisten);
        let socket = UdpSocket::bind(&addr).await?;
        info!("RADIUS client listening on {}", socket.local_addr()?);

        let coa_addr = format!("{}:{}", config.radiuslisten, config.coaport);
        let coa_socket = UdpSocket::bind(&coa_addr).await?;
        info!("RADIUS CoA listener on {}", coa_addr);

        Ok(RadiusClient {
            socket: Arc::new(socket),
            coa_socket: Arc::new(coa_socket),
            config_rx,
            next_id: Arc::new(Mutex::new(0)),
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn run(&self) {
        let mut buf = [0u8; RADIUS_MAX_LEN];
        let mut interval = tokio::time::interval(Duration::from_secs(1));

        loop {
            tokio::select! {
                res = self.socket.recv_from(&mut buf) => {
                    if let Ok((len, _src)) = res {
                        if let Some(packet) = RadiusPacket::from_bytes(&buf[..len]) {
                            if let Some(code) = RadiusCode::from_u8(packet.code) {
                                let mut pending = self.pending_requests.lock().await;
                                if let Some(sender) = pending.remove(&packet.id) {
                                    let result = match code {
                                        RadiusCode::AccessAccept => {
                                            let payload_len = (u16::from_be(packet.length) as usize) - RADIUS_HDR_LEN;
                                            let attributes = parse_attributes(&packet.payload[..payload_len]);
                                            Ok(AuthResult::Success(attributes))
                                        }
                                        RadiusCode::AccessChallenge => {
                                            let payload_len = (u16::from_be(packet.length) as usize) - RADIUS_HDR_LEN;
                                            let attributes = parse_attributes(&packet.payload[..payload_len]);
                                            let eap_message = attributes.get_standard(RadiusAttributeType::EapMessage).cloned();
                                            let chap_challenge = attributes.get_standard(RadiusAttributeType::ChapChallenge).cloned();
                                            let state = attributes.get_standard(RadiusAttributeType::State).cloned();
                                            if let Some(eap) = eap_message {
                                                Ok(AuthResult::Challenge(eap, state))
                                            } else if let Some(chap) = chap_challenge {
                                                Ok(AuthResult::ChapChallenge(chap, state))
                                            } else {
                                                Ok(AuthResult::Failure)
                                            }
                                        }
                                        _ => Ok(AuthResult::Failure),
                                    };
                                    if let Some(tx) = sender.tx {
                                        if tx.send(result).is_err() {
                                            warn!("Failed to send RADIUS response to waiting task for id {}", packet.id);
                                        }
                                    }
                                } else if code == RadiusCode::AccountingResponse {
                                    info!("Received Accounting-Response for packet id {}", packet.id);
                                    // This acknowledges the packet, so we can remove it from the queue.
                                    let mut pending = self.pending_requests.lock().await;
                                    pending.remove(&packet.id);
                                }
                            }
                        }
                    } else if let Err(e) = res {
                        warn!("RADIUS socket error: {}", e);
                    }
                }
                _ = interval.tick() => {
                    let now = SystemTime::now();
                    let mut packets_to_send = Vec::new();
                    let mut timed_out_senders = Vec::new();
                    let config = self.config_rx.borrow().clone();

                    let mut auth_servers = vec![config.radiusserver1.to_string()];
                    if let Some(s2) = &config.radiusserver2 {
                        auth_servers.push(s2.to_string());
                    }
                    let acct_servers = auth_servers.clone(); // In this implementation, they are the same.

                    let mut pending = self.pending_requests.lock().await;

                    pending.retain(|id, req| {
                        if now < req.next_attempt_at {
                            return true; // Not time yet, keep it.
                        }

                        let (servers, port) = if req.is_acct_packet {
                            (&acct_servers, config.radiusacctport)
                        } else {
                            (&auth_servers, config.radiusauthport)
                        };

                        // Check if we've exhausted all servers
                        if req.current_server_index >= servers.len() {
                            warn!("RADIUS request id {} timed out completely.", id);
                            if let Some(tx) = req.tx.take() {
                                timed_out_senders.push(tx);
                            }
                            return false; // Remove from pending requests
                        }

                        let server_ip = &servers[req.current_server_index];
                        let addr = format!("{}:{}", server_ip, port);
                        packets_to_send.push((addr, req.packet.clone()));

                        req.attempt_count += 1;

                        let max_retries = config.radiusretry as u8;
                        let base_timeout = Duration::from_secs(config.radiustimeout as u64);

                        if req.attempt_count > max_retries {
                            // Move to next server
                            req.current_server_index += 1;
                            req.attempt_count = 0;
                            // Try next server immediately
                            req.next_attempt_at = now;
                        } else {
                            // Exponential backoff for next attempt on the *same* server
                            let backoff_factor = 2u64.pow(req.attempt_count as u32 - 1);
                            let next_delay = base_timeout * backoff_factor as u32;
                            req.next_attempt_at = now + next_delay;
                        }

                        true // Keep request in pending map
                    });

                    drop(pending); // Release lock before I/O

                    for (addr, packet) in packets_to_send {
                        let socket = self.socket.clone();
                        let id = packet[1];
                        tokio::spawn(async move {
                            if let Err(e) = socket.send_to(&packet, &addr).await {
                                error!("Failed to send RADIUS request id {}: {}", id, e);
                            } else {
                                info!("Sent RADIUS request id {} to {}", id, addr);
                            }
                        });
                    }

                    for tx in timed_out_senders {
                        if tx.send(Err(anyhow!("RADIUS request timed out"))).is_err() {
                             warn!("Failed to send timeout to waiting task (receiver dropped).");
                        }
                    }
                }
            }
        }
    }

    pub async fn handle_coa_request(&self, packet: &RadiusPacket, src: SocketAddr, session_manager: &Arc<SessionManager>, firewall: &Arc<Firewall>) -> Result<()> {
        let config = self.config_rx.borrow().clone();
        info!("Handling CoA/Disconnect request from {}", src);

        if !config.coanoipcheck {
            let is_server_ip = config.radiusserver1 == src.ip() || config.radiusserver2.map_or(false, |s| s == src.ip());
            if !is_server_ip {
                warn!("CoA/Disconnect request from non-RADIUS-server IP {}, dropping.", src.ip());
                return Ok(());
            }
        }

        let payload_len = u16::from_be(packet.length) as usize - RADIUS_HDR_LEN;
        let attributes = parse_attributes(&packet.payload[..payload_len]);

        let all_sessions = session_manager.get_all_sessions().await;
        let mut target_session: Option<Session> = None;

        // Find session by Framed-IP-Address
        if let Some(ip_vec) = attributes.get_standard(RadiusAttributeType::FramedIpAddress) {
            if ip_vec.len() == 4 {
                let ip = Ipv4Addr::new(ip_vec[0], ip_vec[1], ip_vec[2], ip_vec[3]);
                target_session = all_sessions.iter().find(|s| s.hisip == ip).cloned();
            }
        }

        // Find session by Acct-Session-Id
        if target_session.is_none() {
            if let Some(session_id_vec) = attributes.get_standard(RadiusAttributeType::AcctSessionId) {
                if let Ok(session_id) = String::from_utf8(session_id_vec.clone()) {
                    target_session = all_sessions.iter().find(|s| s.state.sessionid == session_id).cloned();
                }
            }
        }

        // Find session by User-Name
        if target_session.is_none() {
            if let Some(user_name_vec) = attributes.get_standard(RadiusAttributeType::UserName) {
                 if let Ok(user_name) = String::from_utf8(user_name_vec.clone()) {
                    target_session = all_sessions.iter().find(|s| s.state.redir.username == Some(user_name.clone())).cloned();
                }
            }
        }

        let response_code;
        let mut response_attributes = Vec::new();

        if let Some(session) = target_session {
            match RadiusCode::from_u8(packet.code) {
                Some(RadiusCode::DisconnectRequest) => {
                    info!("Disconnecting session for IP {}", session.hisip);
                    self.send_acct_stop(&session, Some(ACCT_TERMINATE_CAUSE_ADMIN_RESET)).await?;
                    firewall.remove_user_filter(session.hisip).ok();
                    session_manager.remove_session(&session.hisip).await;
                    response_code = RadiusCode::DisconnectAck;
                }
                Some(RadiusCode::CoaRequest) => {
                    info!("Applying CoA for session on IP {}", session.hisip);
                    apply_radius_attributes(&attributes, session_manager, firewall, &session.hisip).await;
                    response_code = RadiusCode::CoaAck;
                }
                _ => {
                    response_code = RadiusCode::CoaNak;
                    let error_message = "Unsupported request code".as_bytes();
                    response_attributes.push(RadiusAttributeValue { type_code: RadiusAttributeType::MessageAuthenticator, value: error_message.to_vec() });
                }
            }
        } else {
            warn!("No session found for CoA/Disconnect request");
            response_code = match RadiusCode::from_u8(packet.code) {
                Some(RadiusCode::DisconnectRequest) => RadiusCode::DisconnectNak,
                _ => RadiusCode::CoaNak,
            };
            let error_message = "Session-Context-Not-Found".as_bytes();
            response_attributes.push(RadiusAttributeValue { type_code: RadiusAttributeType::MessageAuthenticator, value: error_message.to_vec() });
        }

        let mut response_payload = Vec::new();
        for attr in &response_attributes {
            response_payload.push(attr.type_code as u8);
            response_payload.push((attr.value.len() + 2) as u8);
            response_payload.extend_from_slice(&attr.value);
        }

        let length = (RADIUS_HDR_LEN + response_payload.len()) as u16;

        let mut response_header_for_auth = Vec::new();
        response_header_for_auth.push(response_code as u8);
        response_header_for_auth.push(packet.id);
        response_header_for_auth.extend_from_slice(&length.to_be_bytes());

        let mut to_hash = Vec::new();
        to_hash.extend_from_slice(&response_header_for_auth);
        to_hash.extend_from_slice(&packet.authenticator);
        to_hash.extend_from_slice(&response_payload);
        to_hash.extend_from_slice(config.radiussecret.as_bytes());

        let mut hasher = Md5::new();
        hasher.update(&to_hash);
        let response_auth = hasher.finalize();

        let mut final_packet = Vec::new();
        final_packet.extend_from_slice(&response_header_for_auth);
        final_packet.extend_from_slice(&response_auth);
        final_packet.extend_from_slice(&response_payload);

        self.coa_socket.send_to(&final_packet, src).await?;

        Ok(())
    }

    async fn send_request(
        &self,
        packet_bytes: Vec<u8>,
        tx: Option<oneshot::Sender<Result<AuthResult>>>,
        is_acct_packet: bool,
    ) -> Result<()> {
        let packet_id = packet_bytes[1];

        let pending_request = PendingRequest {
            packet: packet_bytes,
            tx,
            is_acct_packet,
            next_attempt_at: SystemTime::now(), // Send immediately
            attempt_count: 0,
            current_server_index: 0,
        };

        self.pending_requests
            .lock()
            .await
            .insert(packet_id, pending_request);

        Ok(())
    }

    pub async fn send_access_request(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthResult> {
        let packet_id = {
            let mut id = self.next_id.lock().await;
            let packet_id = *id;
            *id = id.wrapping_add(1);
            packet_id
        };

        let (tx, rx) = oneshot::channel();

        let mut authenticator = [0u8; RADIUS_AUTH_LEN];
        getrandom::getrandom(&mut authenticator)
            .map_err(|e| anyhow::anyhow!("getrandom failed: {}", e))?;

        let mut attributes = Vec::new();
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::UserName,
            value: username.as_bytes().to_vec(),
        });
        let config = self.config_rx.borrow().clone();
        let encrypted_pass = encrypt_password(
            password.as_bytes(),
            config.radiussecret.as_bytes(),
            &authenticator,
        );
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::UserPassword,
            value: encrypted_pass,
        });

        let mut payload = Vec::new();
        for attr in attributes {
            payload.push(attr.type_code as u8);
            payload.push((attr.value.len() + 2) as u8);
            payload.extend_from_slice(&attr.value);
        }

        let length = (RADIUS_HDR_LEN + payload.len()) as u16;

        let mut packet_bytes = Vec::with_capacity(length as usize);
        packet_bytes.push(RadiusCode::AccessRequest as u8);
        packet_bytes.push(packet_id);
        packet_bytes.extend_from_slice(&length.to_be_bytes());
        packet_bytes.extend_from_slice(&authenticator);
        packet_bytes.extend_from_slice(&payload);

        self.send_request(packet_bytes, Some(tx), false).await?;

        rx.await?
    }

    pub async fn send_preencrypted_access_request(
        &self,
        username: &str,
        encrypted_password: Vec<u8>,
    ) -> Result<AuthResult> {
        let packet_id = {
            let mut id = self.next_id.lock().await;
            let packet_id = *id;
            *id = id.wrapping_add(1);
            packet_id
        };

        let (tx, rx) = oneshot::channel();

        let mut authenticator = [0u8; RADIUS_AUTH_LEN];
        getrandom::getrandom(&mut authenticator)
            .map_err(|e| anyhow::anyhow!("getrandom failed: {}", e))?;

        let mut attributes = Vec::new();
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::UserName,
            value: username.as_bytes().to_vec(),
        });
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::UserPassword,
            value: encrypted_password,
        });

        let mut payload = Vec::new();
        for attr in attributes {
            payload.push(attr.type_code as u8);
            payload.push((attr.value.len() + 2) as u8);
            payload.extend_from_slice(&attr.value);
        }

        let length = (RADIUS_HDR_LEN + payload.len()) as u16;

        let mut packet_bytes = Vec::with_capacity(length as usize);
        packet_bytes.push(RadiusCode::AccessRequest as u8);
        packet_bytes.push(packet_id);
        packet_bytes.extend_from_slice(&length.to_be_bytes());
        packet_bytes.extend_from_slice(&authenticator);
        packet_bytes.extend_from_slice(&payload);

        self.send_request(packet_bytes, Some(tx), false).await?;

        rx.await?
    }

    pub async fn send_eap_response(
        &self,
        eap_message: &[u8],
        state: Option<&[u8]>,
    ) -> Result<AuthResult> {
        let packet_id = {
            let mut id = self.next_id.lock().await;
            let packet_id = *id;
            *id = id.wrapping_add(1);
            packet_id
        };

        let (tx, rx) = oneshot::channel();

        let mut authenticator = [0u8; RADIUS_AUTH_LEN];
        getrandom::getrandom(&mut authenticator)
            .map_err(|e| anyhow::anyhow!("getrandom failed: {}", e))?;

        let mut attributes = Vec::new();
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::EapMessage,
            value: eap_message.to_vec(),
        });
        if let Some(s) = state {
            attributes.push(RadiusAttributeValue {
                type_code: RadiusAttributeType::State,
                value: s.to_vec(),
            });
        }

        let mut payload = Vec::new();
        for attr in attributes {
            payload.push(attr.type_code as u8);
            payload.push((attr.value.len() + 2) as u8);
            payload.extend_from_slice(&attr.value);
        }

        let length = (RADIUS_HDR_LEN + payload.len()) as u16;

        let mut packet_bytes = Vec::with_capacity(length as usize);
        packet_bytes.push(RadiusCode::AccessRequest as u8);
        packet_bytes.push(packet_id);
        packet_bytes.extend_from_slice(&length.to_be_bytes());
        packet_bytes.extend_from_slice(&authenticator);
        packet_bytes.extend_from_slice(&payload);

        self.send_request(packet_bytes, Some(tx), false).await?;

        rx.await?
    }

    pub async fn send_chap_access_request(&self, username: &str) -> Result<AuthResult> {
        let packet_id = {
            let mut id = self.next_id.lock().await;
            let packet_id = *id;
            *id = id.wrapping_add(1);
            packet_id
        };

        let (tx, rx) = oneshot::channel();

        let mut authenticator = [0u8; RADIUS_AUTH_LEN];
        getrandom::getrandom(&mut authenticator)
            .map_err(|e| anyhow::anyhow!("getrandom failed: {}", e))?;

        let mut attributes = Vec::new();
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::UserName,
            value: username.as_bytes().to_vec(),
        });

        let mut payload = Vec::new();
        for attr in attributes {
            payload.push(attr.type_code as u8);
            payload.push((attr.value.len() + 2) as u8);
            payload.extend_from_slice(&attr.value);
        }

        let length = (RADIUS_HDR_LEN + payload.len()) as u16;

        let mut packet_bytes = Vec::with_capacity(length as usize);
        packet_bytes.push(RadiusCode::AccessRequest as u8);
        packet_bytes.push(packet_id);
        packet_bytes.extend_from_slice(&length.to_be_bytes());
        packet_bytes.extend_from_slice(&authenticator);
        packet_bytes.extend_from_slice(&payload);

        self.send_request(packet_bytes, Some(tx), false).await?;

        rx.await?
    }

    pub async fn send_chap_response(
        &self,
        identifier: u8,
        response: &[u8; 24],
        state: Option<&[u8]>,
    ) -> Result<AuthResult> {
        let packet_id = {
            let mut id = self.next_id.lock().await;
            let packet_id = *id;
            *id = id.wrapping_add(1);
            packet_id
        };

        let (tx, rx) = oneshot::channel();

        let mut authenticator = [0u8; RADIUS_AUTH_LEN];
        getrandom::getrandom(&mut authenticator)
            .map_err(|e| anyhow::anyhow!("getrandom failed: {}", e))?;

        let mut chap_password = vec![identifier];
        chap_password.extend_from_slice(response);

        let mut attributes = Vec::new();
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::ChapPassword,
            value: chap_password,
        });
        if let Some(s) = state {
            attributes.push(RadiusAttributeValue {
                type_code: RadiusAttributeType::State,
                value: s.to_vec(),
            });
        }

        let mut payload = Vec::new();
        for attr in attributes {
            payload.push(attr.type_code as u8);
            payload.push((attr.value.len() + 2) as u8);
            payload.extend_from_slice(&attr.value);
        }

        let length = (RADIUS_HDR_LEN + payload.len()) as u16;

        let mut packet_bytes = Vec::with_capacity(length as usize);
        packet_bytes.push(RadiusCode::AccessRequest as u8);
        packet_bytes.push(packet_id);
        packet_bytes.extend_from_slice(&length.to_be_bytes());
        packet_bytes.extend_from_slice(&authenticator);
        packet_bytes.extend_from_slice(&payload);

        self.send_request(packet_bytes, Some(tx), false).await?;

        rx.await?
    }

    pub async fn send_acct_start(&self, session: &chilli_core::Session) -> Result<()> {
        self.send_acct_packet(session, ACCT_STATUS_TYPE_START, None)
            .await
    }

    pub async fn send_acct_stop(
        &self,
        session: &chilli_core::Session,
        terminate_cause: Option<u32>,
    ) -> Result<()> {
        self.send_acct_packet(session, ACCT_STATUS_TYPE_STOP, terminate_cause)
            .await
    }

    pub async fn send_acct_interim_update(&self, session: &chilli_core::Session) -> Result<()> {
        self.send_acct_packet(session, ACCT_STATUS_TYPE_INTERIM_UPDATE, None)
            .await
    }

    async fn send_acct_packet(
        &self,
        session: &Session,
        status_type: u32,
        terminate_cause: Option<u32>,
    ) -> Result<()> {
        let packet_id = {
            let mut id = self.next_id.lock().await;
            let packet_id = *id;
            *id = id.wrapping_add(1);
            packet_id
        };

        let mut attributes = Vec::new();

        let status_type_bytes = status_type.to_be_bytes();
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::AcctStatusType,
            value: status_type_bytes.to_vec(),
        });
        if let Some(cause) = terminate_cause {
            let cause_bytes = cause.to_be_bytes();
            attributes.push(RadiusAttributeValue {
                type_code: RadiusAttributeType::AcctTerminateCause,
                value: cause_bytes.to_vec(),
            });
        }
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::AcctSessionId,
            value: session.state.sessionid.as_bytes().to_vec(),
        });
        let framed_ip_bytes = session.hisip.octets();
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::FramedIpAddress,
            value: framed_ip_bytes.to_vec(),
        });
        if let Some(username) = &session.state.redir.username {
            attributes.push(RadiusAttributeValue {
                type_code: RadiusAttributeType::UserName,
                value: username.as_bytes().to_vec(),
            });
        }

        let input_octets = session.state.input_octets;
        let output_octets = session.state.output_octets;

        let input_gigawords = (input_octets >> 32) as u32;
        let output_gigawords = (output_octets >> 32) as u32;

        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::AcctInputOctets,
            value: (input_octets as u32).to_be_bytes().to_vec(),
        });
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::AcctOutputOctets,
            value: (output_octets as u32).to_be_bytes().to_vec(),
        });

        if input_gigawords > 0 {
            attributes.push(RadiusAttributeValue {
                type_code: RadiusAttributeType::AcctInputGigawords,
                value: input_gigawords.to_be_bytes().to_vec(),
            });
        }
        if output_gigawords > 0 {
            attributes.push(RadiusAttributeValue {
                type_code: RadiusAttributeType::AcctOutputGigawords,
                value: output_gigawords.to_be_bytes().to_vec(),
            });
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let session_time_bytes =
            ((now.as_secs() - session.state.start_time) as u32).to_be_bytes();
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::AcctSessionTime,
            value: session_time_bytes.to_vec(),
        });

        let mut payload = Vec::new();
        for attr in attributes {
            payload.push(attr.type_code as u8);
            payload.push((attr.value.len() + 2) as u8);
            payload.extend_from_slice(&attr.value);
        }

        let length = (RADIUS_HDR_LEN + payload.len()) as u16;

        let mut packet_header = Vec::new();
        packet_header.push(RadiusCode::AccountingRequest as u8);
        packet_header.push(packet_id);
        packet_header.extend_from_slice(&length.to_be_bytes());

        let config = self.config_rx.borrow().clone();
        let mut to_hash = Vec::new();
        to_hash.extend_from_slice(&packet_header);
        to_hash.extend_from_slice(&[0; 16]); // Request Authenticator is zeroed for Acct-Request
        to_hash.extend_from_slice(&payload);
        to_hash.extend_from_slice(config.radiussecret.as_bytes());

        let mut hasher = Md5::new();
        hasher.update(&to_hash);
        let authenticator = hasher.finalize();

        let mut final_packet = Vec::new();
        final_packet.extend_from_slice(&packet_header);
        final_packet.extend_from_slice(&authenticator);
        final_packet.extend_from_slice(&payload);

        // Accounting packets are 'fire and forget' from the caller's perspective,
        // but the client will handle retries internally.
        self.send_request(final_packet, None, true).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_password() {
        let secret = "testing123";
        let password = "password";
        let authenticator: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        ];

    // This expected value is the correct one, calculated manually from RFC 2865.
        let expected_encrypted: [u8; 16] = [
            227, 93, 130, 33, 82, 175, 4, 243, 88, 209, 244, 159, 218, 142, 201, 22,
        ];

        let encrypted = encrypt_password(password.as_bytes(), secret.as_bytes(), &authenticator);

        assert_eq!(encrypted, expected_encrypted);
    }

    #[test]
    fn test_xor_isolation() {
        let p1 = [0xFF; 16];
        let h1 = [0xAA; 16];
        let mut c1 = [0u8; 16];
        for i in 0..16 {
            c1[i] = p1[i] ^ h1[i];
        }
        assert_eq!(c1, [0x55; 16]);

        let password_bytes = b"password";
        let mut p2 = [0u8; 16];
        p2[..8].copy_from_slice(password_bytes);
        let h2 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let mut c2 = [0u8; 16];
        for i in 0..16 {
            c2[i] = p2[i] ^ h2[i];
        }
        assert_eq!(c2[0], b'p' ^ 0x01);
        assert_eq!(c2[1], b'a' ^ 0x02);
        assert_eq!(c2[8], 0x00 ^ 0x09);
    }

    #[test]
    fn test_parse_attributes() {
        // Standard attribute
        let mut payload = vec![
            RadiusAttributeType::SessionTimeout as u8, 6, 0, 0, 14, 16, // Session-Timeout: 3600
        ];
        // VSA
        payload.extend_from_slice(&[
            RadiusAttributeType::VendorSpecific as u8, 12,
            0, 0, 0x37, 0x2a, // Vendor ID: 14122 (WISPr)
            WISPR_BANDWIDTH_MAX_UP, 6,
            0, 0, 0xfa, 0, // 64000
        ]);

        let attributes = parse_attributes(&payload);

        assert_eq!(attributes.standard.len(), 1);
        assert_eq!(attributes.vsas.len(), 1);

        let session_timeout = attributes
            .get_standard(RadiusAttributeType::SessionTimeout)
            .expect("Session-Timeout attribute not found");
        assert_eq!(session_timeout, &vec![0, 0, 14, 16]);
        let session_timeout_val = u32::from_be_bytes(
            session_timeout
                .clone()
                .try_into()
                .expect("Session-Timeout value has incorrect length"),
        );
        assert_eq!(session_timeout_val, 3600);

        let bw_up = attributes
            .get_vsa(VENDOR_ID_WISPR, WISPR_BANDWIDTH_MAX_UP)
            .expect("WISPr-Bandwidth-Max-Up VSA not found");
        assert_eq!(bw_up, &vec![0, 0, 0xfa, 0]);
        let bw_up_val = u32::from_be_bytes(
            bw_up
                .clone()
                .try_into()
                .expect("WISPr-Bandwidth-Max-Up value has incorrect length"),
        );
        assert_eq!(bw_up_val, 64000);
    }
}
