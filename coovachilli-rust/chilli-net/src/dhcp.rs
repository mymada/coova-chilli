use anyhow::Result;
use chilli_core::{Config, SessionManager};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

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
pub const DHCP_OPTION_REQUESTED_IP: u8 = 50;
pub const DHCP_OPTION_LEASE_TIME: u8 = 51;
pub const DHCP_OPTION_MESSAGE_TYPE: u8 = 53;
pub const DHCP_OPTION_SERVER_ID: u8 = 54;
pub const DHCP_OPTION_END: u8 = 255;

pub const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// Represents a DHCP packet.
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
    pub fn from_bytes(data: &[u8]) -> Option<&DhcpPacket> {
        if data.len() < 240 {
            // Minimum DHCP packet size
            return None;
        }
        let packet = unsafe { &*(data.as_ptr() as *const DhcpPacket) };
        if packet.options[0..4] != DHCP_MAGIC_COOKIE {
            return None;
        }
        Some(packet)
    }

    pub fn from_bytes_mut(data: &mut [u8]) -> Option<&mut DhcpPacket> {
        if data.len() < 240 {
            return None;
        }
        let packet = unsafe { &mut *(data.as_mut_ptr() as *mut DhcpPacket) };
        if packet.options[0..4] != DHCP_MAGIC_COOKIE {
            // Let's assume we will write it
            return Some(packet);
        }
        Some(packet)
    }

    pub fn get_option(&self, code: u8) -> Option<&[u8]> {
        let mut options = &self.options[4..];
        while !options.is_empty() {
            let option_code = options[0];
            if option_code == DHCP_OPTION_PAD {
                options = &options[1..];
                continue;
            }
            if option_code == DHCP_OPTION_END {
                break;
            }
            if options.len() < 2 {
                break;
            }
            let len = options[1] as usize;
            if options.len() < 2 + len {
                break;
            }
            if option_code == code {
                return Some(&options[2..2 + len]);
            }
            options = &options[2 + len..];
        }
        None
    }

    pub fn get_message_type(&self) -> Option<DhcpMessageType> {
        self.get_option(DHCP_OPTION_MESSAGE_TYPE)
            .and_then(|data| data.get(0))
            .and_then(|&byte| match byte {
                1 => Some(DhcpMessageType::Discover),
                2 => Some(DhcpMessageType::Offer),
                3 => Some(DhcpMessageType::Request),
                4 => Some(DhcpMessageType::Decline),
                5 => Some(DhcpMessageType::Ack),
                6 => Some(DhcpMessageType::Nak),
                7 => Some(DhcpMessageType::Release),
                8 => Some(DhcpMessageType::Inform),
                _ => None,
            })
    }

    pub fn get_mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.chaddr[..6]);
        mac
    }

    pub fn ciaddr(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_be(self.ciaddr))
    }
}

#[derive(Debug, Clone)]
struct Lease {
    ip: Ipv4Addr,
    mac: [u8; 6],
    expires: SystemTime,
}

/// The DHCP server.
pub struct DhcpServer {
    socket: Arc<UdpSocket>,
    config: Arc<Config>,
    ip_pool: Arc<Mutex<Vec<Ipv4Addr>>>,
    leases: Arc<Mutex<HashMap<[u8; 6], Lease>>>,
    session_manager: Arc<SessionManager>,
}

impl DhcpServer {
    pub async fn new(config: Arc<Config>, session_manager: Arc<SessionManager>) -> Result<Self> {
        let addr = format!("{}:67", config.dhcplisten);
        let socket = UdpSocket::bind(&addr).await?;
        socket.set_broadcast(true)?;
        info!("DHCP server listening on {}", addr);

        let mut ip_pool = Vec::new();
        let start_ip = u32::from(config.dhcpstart);
        let end_ip = u32::from(config.dhcpend);
        for ip in start_ip..=end_ip {
            ip_pool.push(Ipv4Addr::from(ip));
        }

        Ok(DhcpServer {
            socket: Arc::new(socket),
            config,
            ip_pool: Arc::new(Mutex::new(ip_pool)),
            leases: Arc::new(Mutex::new(HashMap::new())),
            session_manager,
        })
    }

    pub async fn reap_leases(&self) {
        let mut leases = self.leases.lock().await;
        let mut pool = self.ip_pool.lock().await;
        let now = SystemTime::now();

        let mut expired = Vec::new();
        for lease in leases.values() {
            if lease.expires < now {
                expired.push(lease.clone());
            }
        }

        for lease in expired {
            info!("Reaping expired lease for IP {}", lease.ip);
            leases.remove(&lease.mac);
            pool.push(lease.ip);
        }
    }

    pub async fn run(&self) -> Result<()> {
        let mut buf = [0u8; 1500];
        loop {
            let (len, src) = self.socket.recv_from(&mut buf).await?;
            if let Some(packet) = DhcpPacket::from_bytes(&buf[..len]) {
                if let Err(e) = self.handle_packet(packet, src).await {
                    error!("Error handling DHCP packet: {}", e);
                }
            } else {
                warn!("Received invalid DHCP packet from {}", src);
            }
        }
    }

    async fn handle_packet(&self, packet: &DhcpPacket, src: SocketAddr) -> Result<()> {
        let msg_type = match packet.get_message_type() {
            Some(t) => t,
            None => {
                warn!("Received DHCP packet with no message type from {}", src);
                return Ok(());
            }
        };

        info!("Handling DHCP {:?} from MAC {}", msg_type, hex::encode(packet.get_mac()));

        match msg_type {
            DhcpMessageType::Discover => self.handle_discover(packet).await,
            DhcpMessageType::Request => self.handle_request(packet).await,
            _ => {
                warn!("Unhandled DHCP message type: {:?}", msg_type);
                Ok(())
            }
        }
    }

    async fn handle_discover(&self, req_packet: &DhcpPacket) -> Result<()> {
        let mac = req_packet.get_mac();
        let leases = self.leases.lock().await;
        let mut pool = self.ip_pool.lock().await;

        let ip_to_offer = match leases.get(&mac) {
            Some(lease) => lease.ip,
            None => match pool.pop() {
                Some(ip) => ip,
                None => {
                    error!("DHCP IP pool is empty!");
                    return Ok(());
                }
            },
        };

        info!("Offering IP {} to MAC {}", ip_to_offer, hex::encode(mac));

        let response = self.build_response(
            req_packet,
            DhcpMessageType::Offer,
            self.config.dhcplisten,
            ip_to_offer,
        );

        self.socket
            .send_to(&response, "255.255.255.255:68")
            .await?;
        Ok(())
    }

    async fn handle_request(&self, req_packet: &DhcpPacket) -> Result<()> {
        let mac = req_packet.get_mac();
        let mut leases = self.leases.lock().await;

        // Check if it's a renewal
        let client_ip = req_packet.ciaddr();
        if !client_ip.is_unspecified() {
            if let Some(lease) = leases.get(&mac) {
                if lease.ip == client_ip {
                    info!("Renewing lease for IP {} for MAC {}", client_ip, hex::encode(mac));
                    // Renew lease time
                    let lease_duration = Duration::from_secs(self.config.lease as u64);
                    let new_lease = Lease {
                        ip: client_ip,
                        mac,
                        expires: SystemTime::now() + lease_duration,
                    };
                    leases.insert(mac, new_lease);

                    let response = self.build_response(
                        req_packet,
                        DhcpMessageType::Ack,
                        self.config.dhcplisten,
                        client_ip,
                    );
                    self.socket.send_to(&response, "255.255.255.255:68").await?;
                    return Ok(());
                }
            }
        }

        // Otherwise, it's a request for a new lease
        let requested_ip_opt = req_packet
            .get_option(DHCP_OPTION_REQUESTED_IP)
            .and_then(|d| TryInto::<[u8; 4]>::try_into(d).ok())
            .map(Ipv4Addr::from);

        let server_id_opt = req_packet
            .get_option(DHCP_OPTION_SERVER_ID)
            .and_then(|d| TryInto::<[u8; 4]>::try_into(d).ok())
            .map(Ipv4Addr::from);

        // Must be a request for our server
        if server_id_opt != Some(self.config.dhcplisten) {
             warn!("DHCPREQUEST not for us (server_id: {:?})", server_id_opt);
             return Ok(());
        }

        let requested_ip = match requested_ip_opt {
            Some(ip) => ip,
            None => {
                warn!("DHCPREQUEST from {} with no requested IP", hex::encode(mac));
                return Ok(());
            }
        };

        // This is simplified. A real server would check if the IP is valid and offered.
        info!(
            "Acknowledging IP {} for MAC {}",
            requested_ip,
            hex::encode(mac)
        );

        let lease_duration = Duration::from_secs(self.config.lease as u64);
        let lease = Lease {
            ip: requested_ip,
            mac,
            expires: SystemTime::now() + lease_duration,
        };
        leases.insert(mac, lease.clone());

        self.session_manager
            .create_session(requested_ip, mac, &self.config)
            .await;

        let response = self.build_response(
            req_packet,
            DhcpMessageType::Ack,
            self.config.dhcplisten,
            requested_ip,
        );

        self.socket
            .send_to(&response, "255.255.255.255:68")
            .await?;
        Ok(())
    }

    fn build_response(
        &self,
        req_packet: &DhcpPacket,
        msg_type: DhcpMessageType,
        server_ip: Ipv4Addr,
        offered_ip: Ipv4Addr,
    ) -> Vec<u8> {
        let mut response_buf = vec![0u8; 512];
        let packet = DhcpPacket::from_bytes_mut(&mut response_buf).unwrap();

        packet.op = BootpMessageType::BootReply as u8;
        packet.htype = req_packet.htype;
        packet.hlen = req_packet.hlen;
        packet.xid = req_packet.xid;
        packet.yiaddr = u32::from(offered_ip).to_be();
        packet.siaddr = u32::from(server_ip).to_be();
        packet.chaddr = req_packet.chaddr;
        packet.flags = req_packet.flags;

        packet.options[0..4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        let mut cursor = 4;

        // Message Type
        response_buf[cursor..cursor + 3].copy_from_slice(&[DHCP_OPTION_MESSAGE_TYPE, 1, msg_type as u8]);
        cursor += 3;

        // Server ID
        response_buf[cursor..cursor + 2].copy_from_slice(&[DHCP_OPTION_SERVER_ID, 4]);
        response_buf[cursor + 2..cursor + 6].copy_from_slice(&server_ip.octets());
        cursor += 6;

        // Lease Time
        let lease_time_bytes = (self.config.lease as u32).to_be_bytes();
        response_buf[cursor..cursor + 2].copy_from_slice(&[DHCP_OPTION_LEASE_TIME, 4]);
        response_buf[cursor + 2..cursor + 6].copy_from_slice(&lease_time_bytes);
        cursor += 6;

        // Subnet Mask
        let netmask = self.config.mask;
        response_buf[cursor..cursor + 2].copy_from_slice(&[DHCP_OPTION_SUBNET_MASK, 4]);
        response_buf[cursor + 2..cursor + 6].copy_from_slice(&netmask.octets());
        cursor += 6;

        // Router
        response_buf[cursor..cursor + 2].copy_from_slice(&[DHCP_OPTION_ROUTER_OPTION, 4]);
        response_buf[cursor + 2..cursor + 6].copy_from_slice(&self.config.uamlisten.octets());
        cursor += 6;

        // DNS Server
        response_buf[cursor..cursor + 2].copy_from_slice(&[DHCP_OPTION_DNS, 8]);
        response_buf[cursor + 2..cursor + 6].copy_from_slice(&self.config.dns1.octets());
        response_buf[cursor + 6..cursor + 10].copy_from_slice(&self.config.dns2.octets());
        cursor += 10;

        response_buf[cursor] = DHCP_OPTION_END;
        cursor += 1;

        // The actual packet is from the start of the op code to the DHCP_OPTION_END
        let final_len = 236 + cursor;
        response_buf.truncate(final_len);
        response_buf
    }
}
