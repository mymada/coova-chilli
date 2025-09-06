use anyhow::Result;
use chilli_core::Config;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tracing::{info, warn};

// ... (existing enums and structs)

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

// RADIUS Attributes
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[repr(u8)]
pub enum RadiusAttributeType {
    UserName = 1,
    UserPassword = 2,
    ChapPassword = 3,
    NasIpAddress = 4,
    NasPort = 5,
    ServiceType = 6,
    FramedProtocol = 7,
    FramedIpAddress = 8,
    FramedIpNetmask = 9,
    FilterId = 11,
    FramedMtu = 12,
    State = 24,
    Class = 25,
    VendorSpecific = 26,
    SessionTimeout = 27,
    IdleTimeout = 28,
    CalledStationId = 30,
    CallingStationId = 31,
    NasIdentifier = 32,
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
    EventTimestamp = 55,
    EapMessage = 79,
    MessageAuthenticator = 80,
    AcctInterimInterval = 85,
    NasPortId = 87,
}

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

    pub fn attributes(&self) -> &[u8] {
        let len = u16::from_be(self.length) as usize;
        &self.payload[..len - RADIUS_HDR_LEN]
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RadiusAttribute {
    pub type_code: u8,
    pub length: u8,
    // The value is of variable length, so we can't define it here.
    // We'll have a slice to the value instead.
}

pub struct RadiusAttributeValue<'a> {
    pub type_code: RadiusAttributeType,
    pub value: &'a [u8],
}

pub struct RadiusClient {
    socket: UdpSocket,
    config: Config,
    next_id: Arc<Mutex<u8>>,
}

impl RadiusClient {
    pub async fn new(config: Config) -> Result<Self> {
        let addr = format!("{}:0", config.radiuslisten);
        let socket = UdpSocket::bind(&addr).await?;
        info!("RADIUS client listening on {}", socket.local_addr()?);
        Ok(RadiusClient {
            socket,
            config,
            next_id: Arc::new(Mutex::new(0)),
        })
    }

    pub async fn run(&self) -> Result<()> {
        let mut buf = [0u8; RADIUS_MAX_LEN];
        loop {
            let (len, src) = self.socket.recv_from(&mut buf).await?;
            info!("Received {} bytes from {}", len, src);

            if let Some(packet) = RadiusPacket::from_bytes(&buf[..len]) {
                self.handle_packet(packet, src).await?;
            } else {
                warn!("Received invalid RADIUS packet from {}", src);
            }
        }
    }

    async fn handle_packet(&self, packet: &RadiusPacket, src: std::net::SocketAddr) -> Result<()> {
        // Placeholder for packet handling logic
        info!("Handling RADIUS packet from {}", src);
        Ok(())
    }

    pub async fn send_access_request(&self, username: &str, password: &str) -> Result<()> {
        let mut id = self.next_id.lock().unwrap();
        let packet_id = *id;
        *id = id.wrapping_add(1);

        let mut authenticator = [0u8; RADIUS_AUTH_LEN];
        // In a real implementation, this should be a random value.
        getrandom::getrandom(&mut authenticator)?;

        let mut attributes = Vec::new();
        attributes.push(RadiusAttributeValue {
            type_code: RadiusAttributeType::UserName,
            value: username.as_bytes(),
        });
        // In a real implementation, the password would be encrypted.
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

        // In a real implementation, the Message-Authenticator would be calculated here.

        let server_addr = format!("{}:{}", self.config.radiusserver1, self.config.radiusauthport);
        self.socket.send_to(&packet_bytes, &server_addr).await?;

        info!("Sent Access-Request for user '{}' to {}", username, server_addr);

        Ok(())
    }
}
