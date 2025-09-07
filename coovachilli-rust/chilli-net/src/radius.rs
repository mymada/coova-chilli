use anyhow::{anyhow, Result};
use chilli_core::Config;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tracing::{info, warn};

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
            _ => None,
        }
    }
}

// RADIUS Attributes
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[repr(u8)]
pub enum RadiusAttributeType {
    UserName = 1,
    UserPassword = 2,
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
    FramedIpAddress = 8,
}

// Acct-Status-Type values
pub const ACCT_STATUS_TYPE_START: u32 = 1;
pub const ACCT_STATUS_TYPE_STOP: u32 = 2;
pub const ACCT_STATUS_TYPE_INTERIM_UPDATE: u32 = 3;

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

pub struct RadiusAttributeValue<'a> {
    pub type_code: RadiusAttributeType,
    pub value: &'a [u8],
}

type PendingRequest = oneshot::Sender<bool>;

pub struct RadiusClient {
    socket: Arc<UdpSocket>,
    config: Arc<Config>,
    next_id: Arc<Mutex<u8>>,
    pending_requests: Arc<Mutex<HashMap<u8, PendingRequest>>>,
}

impl RadiusClient {
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        let addr = format!("{}:0", config.radiuslisten);
        let socket = UdpSocket::bind(&addr).await?;
        info!("RADIUS client listening on {}", socket.local_addr()?);
        Ok(RadiusClient {
            socket: Arc::new(socket),
            config,
            next_id: Arc::new(Mutex::new(0)),
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn run(&self) {
        let mut buf = [0u8; RADIUS_MAX_LEN];
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, _src)) => {
                    if let Some(packet) = RadiusPacket::from_bytes(&buf[..len]) {
                        if let Some(code) = RadiusCode::from_u8(packet.code) {
                            let mut pending = self.pending_requests.lock().unwrap();
                            if let Some(sender) = pending.remove(&packet.id) {
                                let result = code == RadiusCode::AccessAccept;
                                if let Err(_) = sender.send(result) {
                                    warn!("Failed to send RADIUS response to waiting task");
                                }
                            } else if code == RadiusCode::AccountingResponse {
                                info!("Received Accounting-Response for packet id {}", packet.id);
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("RADIUS socket error: {}", e);
                }
            }
        }
    }

    pub async fn send_access_request(&self, username: &str, password: &str) -> Result<bool> {
        let packet_id = {
            let mut id = self.next_id.lock().unwrap();
            let packet_id = *id;
            *id = id.wrapping_add(1);
            packet_id
        };

        let (tx, rx) = oneshot::channel();
        self.pending_requests.lock().unwrap().insert(packet_id, tx);

        let mut authenticator = [0u8; RADIUS_AUTH_LEN];
        getrandom::getrandom(&mut authenticator)
            .map_err(|e| anyhow::anyhow!("getrandom failed: {}", e))?;

        let mut attributes = Vec::new();
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::UserName,
            value: username.as_bytes(),
        });
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::UserPassword,
            value: password.as_bytes(),
        });

        let mut payload = Vec::new();
        for attr in attributes {
            payload.push(attr.type_code as u8);
            payload.push((attr.value.len() + 2) as u8);
            payload.extend_from_slice(attr.value);
        }

        let length = (RADIUS_HDR_LEN + payload.len()) as u16;

        let mut packet_bytes = Vec::with_capacity(length as usize);
        packet_bytes.push(RadiusCode::AccessRequest as u8);
        packet_bytes.push(packet_id);
        packet_bytes.extend_from_slice(&length.to_be_bytes());
        packet_bytes.extend_from_slice(&authenticator);
        packet_bytes.extend_from_slice(&payload);

        let server_addr = format!("{}:{}", self.config.radiusserver1, self.config.radiusauthport);
        self.socket.send_to(&packet_bytes, &server_addr).await?;

        info!("Sent Access-Request for user '{}' to {}", username, server_addr);

        match tokio::time::timeout(Duration::from_secs(5), rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Err(anyhow!("RADIUS request channel closed unexpectedly")),
            Err(_) => Err(anyhow!("RADIUS request timed out")),
        }
    }

    pub async fn send_acct_start(&self, session: &chilli_core::Connection) -> Result<()> {
        self.send_acct_packet(session, ACCT_STATUS_TYPE_START)
            .await
    }

    pub async fn send_acct_stop(&self, session: &chilli_core::Connection) -> Result<()> {
        self.send_acct_packet(session, ACCT_STATUS_TYPE_STOP).await
    }

    pub async fn send_acct_interim_update(&self, session: &chilli_core::Connection) -> Result<()> {
        self.send_acct_packet(session, ACCT_STATUS_TYPE_INTERIM_UPDATE)
            .await
    }

    async fn send_acct_packet(
        &self,
        session: &chilli_core::Connection,
        status_type: u32,
    ) -> Result<()> {
        let packet_id = {
            let mut id = self.next_id.lock().unwrap();
            let packet_id = *id;
            *id = id.wrapping_add(1);
            packet_id
        };

        let mut attributes = Vec::new();

        let status_type_bytes = status_type.to_be_bytes();
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::AcctStatusType,
            value: &status_type_bytes,
        });
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::AcctSessionId,
            value: session.state.sessionid.as_bytes(),
        });
        let framed_ip_bytes = session.hisip.octets();
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::FramedIpAddress,
            value: &framed_ip_bytes,
        });
        if let Some(username) = &session.state.redir.username {
            attributes.push(RadiusAttributeValue {
                type_code: RadiusAttributeType::UserName,
                value: username.as_bytes(),
            });
        }
        let input_octets_bytes = (session.state.input_octets as u32).to_be_bytes();
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::AcctInputOctets,
            value: &input_octets_bytes,
        });
        let output_octets_bytes = (session.state.output_octets as u32).to_be_bytes();
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::AcctOutputOctets,
            value: &output_octets_bytes,
        });
        let session_time_bytes = ((SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - session.state.start_time) as u32)
            .to_be_bytes();
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::AcctSessionTime,
            value: &session_time_bytes,
        });

        let mut payload = Vec::new();
        for attr in attributes {
            payload.push(attr.type_code as u8);
            payload.push((attr.value.len() + 2) as u8);
            payload.extend_from_slice(attr.value);
        }

        let length = (RADIUS_HDR_LEN + payload.len()) as u16;

        let mut packet_bytes = Vec::with_capacity(length as usize);
        packet_bytes.push(RadiusCode::AccountingRequest as u8);
        packet_bytes.push(packet_id);
        packet_bytes.extend_from_slice(&length.to_be_bytes());
        // Authenticator is calculated differently for accounting requests
        let mut authenticator = [0u8; RADIUS_AUTH_LEN];
        let mut to_hash = Vec::new();
        to_hash.extend_from_slice(&packet_bytes);
        to_hash.extend_from_slice(&payload);
        to_hash.extend_from_slice(self.config.radiussecret.as_bytes());
        authenticator.copy_from_slice(&md5::compute(&to_hash).0);
        packet_bytes.extend_from_slice(&authenticator);
        packet_bytes.extend_from_slice(&payload);

        let server_addr =
            format!("{}:{}", self.config.radiusserver1, self.config.radiusacctport);
        self.socket.send_to(&packet_bytes, &server_addr).await?;

        Ok(())
    }
}
