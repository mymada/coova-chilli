use anyhow::Result;
use chilli_core::Config;
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;
use tracing::{info, warn};

/// DHCP Message Types (RFC 2132)
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
    ForceRenew = 9,
}

/// BOOTP Message Types
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum BootpMessageType {
    BootRequest = 1,
    BootReply = 2,
}

// DHCP Options
pub const DHCP_OPTION_PAD: u8 = 0;
pub const DHCP_OPTION_SUBNET_MASK: u8 = 1;
pub const DHCP_OPTION_ROUTER_OPTION: u8 = 3;
pub const DHCP_OPTION_DNS: u8 = 6;
pub const DHCP_OPTION_HOSTNAME: u8 = 12;
pub const DHCP_OPTION_DOMAIN_NAME: u8 = 15;
pub const DHCP_OPTION_REQUESTED_IP: u8 = 50;
pub const DHCP_OPTION_LEASE_TIME: u8 = 51;
pub const DHCP_OPTION_MESSAGE_TYPE: u8 = 53;
pub const DHCP_OPTION_SERVER_ID: u8 = 54;
pub const DHCP_OPTION_PARAMETER_REQUEST_LIST: u8 = 55;
pub const DHCP_OPTION_END: u8 = 255;

pub const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// Represents a DHCP packet.
///
/// This struct is a direct mapping of the DHCP packet structure as defined in
/// RFC 2131. It uses `#[repr(C, packed)]` to ensure that the memory layout
/// matches the network packet format.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct DhcpPacket {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: u32,
    pub yiaddr: u32,
    pub siaddr: u32,
    pub giaddr: u32,
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub options: [u8; 312],
}

impl DhcpPacket {
    /// Creates a `DhcpPacket` from a byte slice.
    ///
    /// This function performs some basic validation to ensure that the byte slice
    /// is a valid DHCP packet.
    pub fn from_bytes(data: &[u8]) -> Option<&DhcpPacket> {
        if data.len() < std::mem::size_of::<DhcpPacket>() {
            return None;
        }
        // Safety: We've checked the length. The caller must ensure the
        // data is correctly aligned. For network packets, this is usually fine.
        let packet = unsafe { &*(data.as_ptr() as *const DhcpPacket) };

        if packet.options[0..4] != DHCP_MAGIC_COOKIE {
            return None;
        }

        Some(packet)
    }

    pub fn ciaddr(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_be(self.ciaddr))
    }

    pub fn yiaddr(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_be(self.yiaddr))
    }

    pub fn siaddr(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_be(self.siaddr))
    }

    pub fn giaddr(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_be(self.giaddr))
    }

    /// Returns a slice to the DHCP options.
    pub fn options(&self) -> &[u8] {
        &self.options[4..]
    }
}

/// Represents a parsed DHCP option.
pub struct DhcpOption<'a> {
    pub code: u8,
    pub len: u8,
    pub data: &'a [u8],
}

/// The DHCP server.
pub struct DhcpServer {
    socket: UdpSocket,
    config: Config,
}

impl DhcpServer {
    /// Creates a new `DhcpServer`.
    pub async fn new(config: Config) -> Result<Self> {
        let addr = format!("{}:67", config.dhcplisten);
        let socket = UdpSocket::bind(&addr).await?;
        socket.set_broadcast(true)?;
        info!("DHCP server listening on {}", addr);
        Ok(DhcpServer { socket, config })
    }

    /// Runs the DHCP server.
    ///
    /// This function contains the main loop for the DHCP server. It listens for
    /// incoming packets on the DHCP port and handles them accordingly.
    pub async fn run(&self) -> Result<()> {
        let mut buf = [0u8; 1500];
        loop {
            let (len, src) = self.socket.recv_from(&mut buf).await?;
            info!("Received {} bytes from {}", len, src);

            if let Some(packet) = DhcpPacket::from_bytes(&buf[..len]) {
                self.handle_packet(packet, src).await?;
            } else {
                warn!("Received invalid DHCP packet from {}", src);
            }
        }
    }

    async fn handle_packet(&self, packet: &DhcpPacket, src: std::net::SocketAddr) -> Result<()> {
        // Placeholder for packet handling logic
        info!("Handling DHCP packet from {}", src);
        Ok(())
    }
}
