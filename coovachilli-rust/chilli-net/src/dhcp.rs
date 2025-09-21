use anyhow::Result;
use chilli_core::{Config};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{watch};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

/// Actions for the DHCP server to take.
pub enum DhcpAction {
    Offer {
        response: Vec<u8>,
        client_ip: Ipv4Addr,
        client_mac: [u8; 6],
    },
    Ack {
        response: Vec<u8>,
        client_ip: Ipv4Addr,
        client_mac: [u8; 6],
    },
    Nak(Vec<u8>),
    NoResponse,
}

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
    config: Arc<Mutex<Arc<Config>>>,
    ip_pool: Arc<Mutex<Vec<Ipv4Addr>>>,
    leases: Arc<Mutex<HashMap<[u8; 6], Lease>>>,
}

impl DhcpServer {
    pub async fn new(
        config_rx: watch::Receiver<Arc<Config>>,
    ) -> Result<Self> {
        let config = config_rx.borrow().clone();
        info!("DHCP server initialized");

        let mut ip_pool = Vec::new();
        let start_ip = u32::from(config.dhcpstart);
        let end_ip = u32::from(config.dhcpend);
        for ip in start_ip..=end_ip {
            ip_pool.push(Ipv4Addr::from(ip));
        }

        Ok(DhcpServer {
            config: Arc::new(Mutex::new(config)),
            ip_pool: Arc::new(Mutex::new(ip_pool)),
            leases: Arc::new(Mutex::new(HashMap::new())),
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

    pub async fn handle_dhcp_packet(
        &self,
        packet: &DhcpPacket,
        src: SocketAddr,
        _vlan_id: Option<u16>,
    ) -> Result<DhcpAction> {
        let msg_type = match packet.get_message_type() {
            Some(t) => t,
            None => {
                warn!("Received DHCP packet with no message type from {}", src);
                return Ok(DhcpAction::NoResponse);
            }
        };

        info!(
            "Handling DHCP {:?} from MAC {}",
            msg_type,
            hex::encode(packet.get_mac())
        );

        match msg_type {
            DhcpMessageType::Discover => self.handle_discover(packet).await,
            DhcpMessageType::Request => self.handle_request(packet).await,
            DhcpMessageType::Release => self.handle_release(packet).await,
            _ => {
                warn!("Unhandled DHCP message type: {:?}", msg_type);
                Ok(DhcpAction::NoResponse)
            }
        }
    }

    async fn handle_discover(
        &self,
        req_packet: &DhcpPacket,
    ) -> Result<DhcpAction> {
        let mac = req_packet.get_mac();
        let leases = self.leases.lock().await;
        let pool = self.ip_pool.lock().await;

        let ip_to_offer = match leases.get(&mac) {
            Some(lease) => lease.ip,
            None => match pool.last().cloned() {
                Some(ip) => ip,
                None => {
                    error!("DHCP IP pool is empty!");
                    return Ok(DhcpAction::NoResponse);
                }
            },
        };

        info!("Offering IP {} to MAC {}", ip_to_offer, hex::encode(mac));

        let config = self.config.lock().await;
        let response = self.build_response(
            &config,
            req_packet,
            DhcpMessageType::Offer,
            config.dhcplisten,
            ip_to_offer,
        )?;

        Ok(DhcpAction::Offer {
            response,
            client_ip: ip_to_offer,
            client_mac: mac,
        })
    }

    async fn handle_request(
        &self,
        req_packet: &DhcpPacket,
    ) -> Result<DhcpAction> {
        let mac = req_packet.get_mac();
        let mac_str = hex::encode(mac);
        let mut leases = self.leases.lock().await;

        // Check if it's a renewal
        let client_ip = req_packet.ciaddr();
        let config = self.config.lock().await;
        if !client_ip.is_unspecified() {
            if let Some(lease) = leases.get(&mac) {
                if lease.ip == client_ip {
                    info!("Renewing lease for IP {} for MAC {}", client_ip, &mac_str);
                    // Renew lease time
                    let lease_duration = Duration::from_secs(config.lease as u64);
                    let new_lease = Lease {
                        ip: client_ip,
                        mac,
                        expires: SystemTime::now() + lease_duration,
                    };
                    leases.insert(mac, new_lease);

                    let response = self.build_response(
                        &config,
                        req_packet,
                        DhcpMessageType::Ack,
                        config.dhcplisten,
                        client_ip,
                    )?;
                    return Ok(DhcpAction::Ack {
                        response,
                        client_ip,
                        client_mac: mac,
                    });
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
        if server_id_opt != Some(config.dhcplisten) {
            warn!(
                "DHCPREQUEST not for us (server_id: {:?})",
                server_id_opt
            );
            return Ok(DhcpAction::NoResponse);
        }

        let requested_ip = match requested_ip_opt {
            Some(ip) => ip,
            None => {
                warn!("DHCPREQUEST from {} with no requested IP", &mac_str);
                return Ok(DhcpAction::NoResponse);
            }
        };

        // This is simplified. A real server would check if the IP is valid and offered.
        info!(
            "Acknowledging IP {} for MAC {}",
            requested_ip, &mac_str
        );

        let lease_duration = Duration::from_secs(config.lease as u64);
        let lease = Lease {
            ip: requested_ip,
            mac,
            expires: SystemTime::now() + lease_duration,
        };
        leases.insert(mac, lease.clone());

        // Now that the lease is confirmed, remove the IP from the available pool
        let mut pool = self.ip_pool.lock().await;
        pool.retain(|&x| x != requested_ip);
        drop(pool);

        let response = self.build_response(
            &config,
            req_packet,
            DhcpMessageType::Ack,
            config.dhcplisten,
            requested_ip,
        )?;

        Ok(DhcpAction::Ack {
            response,
            client_ip: requested_ip,
            client_mac: mac,
        })
    }

    async fn handle_release(
        &self,
        req_packet: &DhcpPacket,
    ) -> Result<DhcpAction> {
        let mac = req_packet.get_mac();
        let mut leases = self.leases.lock().await;
        if let Some(lease) = leases.remove(&mac) {
            info!("DHCPRELEASE: Released IP {} for MAC {}", lease.ip, hex::encode(mac));
            let mut pool = self.ip_pool.lock().await;
            pool.push(lease.ip);
        } else {
            warn!("DHCPRELEASE: Received for unknown MAC {}", hex::encode(mac));
        }
        Ok(DhcpAction::NoResponse)
    }

    fn build_response(
        &self,
        config: &Config,
        req_packet: &DhcpPacket,
        msg_type: DhcpMessageType,
        server_ip: Ipv4Addr,
        offered_ip: Ipv4Addr,
    ) -> Result<Vec<u8>> {
        let mut response_buf = vec![0u8; 512];
        let packet = DhcpPacket::from_bytes_mut(&mut response_buf)
            .ok_or_else(|| anyhow::anyhow!("Failed to create DHCP response buffer"))?;

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
        packet.options[cursor..cursor + 3].copy_from_slice(&[DHCP_OPTION_MESSAGE_TYPE, 1, msg_type as u8]);
        cursor += 3;

        // Server ID
        packet.options[cursor..cursor + 2].copy_from_slice(&[DHCP_OPTION_SERVER_ID, 4]);
        packet.options[cursor + 2..cursor + 6].copy_from_slice(&server_ip.octets());
        cursor += 6;

        // Lease Time
        let lease_time_bytes = (config.lease as u32).to_be_bytes();
        packet.options[cursor..cursor + 2].copy_from_slice(&[DHCP_OPTION_LEASE_TIME, 4]);
        packet.options[cursor + 2..cursor + 6].copy_from_slice(&lease_time_bytes);
        cursor += 6;

        // Subnet Mask
        let netmask = config.mask;
        packet.options[cursor..cursor + 2].copy_from_slice(&[DHCP_OPTION_SUBNET_MASK, 4]);
        packet.options[cursor + 2..cursor + 6].copy_from_slice(&netmask.octets());
        cursor += 6;

        // Router
        packet.options[cursor..cursor + 2].copy_from_slice(&[DHCP_OPTION_ROUTER_OPTION, 4]);
        packet.options[cursor + 2..cursor + 6].copy_from_slice(&config.uamlisten.octets());
        cursor += 6;

        // DNS Server
        packet.options[cursor..cursor + 2].copy_from_slice(&[DHCP_OPTION_DNS, 8]);
        packet.options[cursor + 2..cursor + 6].copy_from_slice(&config.dns1.octets());
        packet.options[cursor + 6..cursor + 10].copy_from_slice(&config.dns2.octets());
        cursor += 10;

        packet.options[cursor] = DHCP_OPTION_END;
        cursor += 1;

        // The actual packet is from the start of the op code to the DHCP_OPTION_END
        let final_len = 236 + cursor;
        response_buf.truncate(final_len);
        Ok(response_buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chilli_core::Config;
    use tokio::sync::watch;

    #[tokio::test]
    async fn test_handle_discover_and_request() {
        let config = Arc::new(Config::default());
        let (_config_tx, config_rx) = watch::channel(config);
        let dhcp_server = DhcpServer::new(config_rx)
            .await
            .expect("Failed to create test DHCP server");

        // 1. Discover
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut discover_buf = [0u8; 512];
        let discover_packet = DhcpPacket::from_bytes_mut(&mut discover_buf)
            .expect("Failed to create discover packet buffer");
        discover_packet.op = BootpMessageType::BootRequest as u8;
        discover_packet.chaddr[..6].copy_from_slice(&mac);
        discover_packet.options[0..4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        discover_packet.options[4..7].copy_from_slice(&[DHCP_OPTION_MESSAGE_TYPE, 1, DhcpMessageType::Discover as u8]);
        discover_packet.options[7] = DHCP_OPTION_END;

        let src_addr = "0.0.0.0:68".parse().expect("Failed to parse source address");
        let action = dhcp_server
            .handle_dhcp_packet(discover_packet, src_addr, None)
            .await
            .expect("Handling discover packet failed");

        let offered_ip = if let DhcpAction::Offer { response, .. } = action {
            let offer_packet =
                DhcpPacket::from_bytes(&response).expect("Failed to parse offer packet");
            assert_eq!(
                offer_packet.get_message_type(),
                Some(DhcpMessageType::Offer)
            );
            Ipv4Addr::from(u32::from_be(offer_packet.yiaddr))
        } else {
            panic!("Expected DhcpAction::Offer");
        };

        // 2. Request
        let mut request_buf = [0u8; 512];
        let request_packet = DhcpPacket::from_bytes_mut(&mut request_buf)
            .expect("Failed to create request packet buffer");
        request_packet.op = BootpMessageType::BootRequest as u8;
        request_packet.chaddr[..6].copy_from_slice(&mac);
        request_packet.options[0..4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        let mut cursor = 4;
        request_packet.options[cursor..cursor + 3].copy_from_slice(&[DHCP_OPTION_MESSAGE_TYPE, 1, DhcpMessageType::Request as u8]);
        cursor += 3;
        request_packet.options[cursor..cursor + 6].copy_from_slice(&[DHCP_OPTION_REQUESTED_IP, 4, offered_ip.octets()[0], offered_ip.octets()[1], offered_ip.octets()[2], offered_ip.octets()[3]]);
        cursor += 6;
        let server_id = dhcp_server.config.lock().await.dhcplisten;
        request_packet.options[cursor..cursor + 6].copy_from_slice(&[DHCP_OPTION_SERVER_ID, 4, server_id.octets()[0], server_id.octets()[1], server_id.octets()[2], server_id.octets()[3]]);
        cursor += 6;
        request_packet.options[cursor] = DHCP_OPTION_END;

        let action = dhcp_server
            .handle_dhcp_packet(request_packet, src_addr, None)
            .await
            .expect("Handling request packet failed");

        if let DhcpAction::Ack { response, client_ip, client_mac } = action {
            let ack_packet =
                DhcpPacket::from_bytes(&response).expect("Failed to parse ack packet");
            assert_eq!(ack_packet.get_message_type(), Some(DhcpMessageType::Ack));
            assert_eq!(client_ip, offered_ip);
            assert_eq!(client_mac, mac);
        } else {
            panic!("Expected DhcpAction::Ack");
        }
    }

    fn build_discover_packet(buf: &mut [u8; 512], mac: [u8; 6]) -> &DhcpPacket {
        let packet = DhcpPacket::from_bytes_mut(buf).unwrap();
        packet.op = BootpMessageType::BootRequest as u8;
        packet.chaddr[..6].copy_from_slice(&mac);
        packet.options[0..4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        packet.options[4..7].copy_from_slice(&[DHCP_OPTION_MESSAGE_TYPE, 1, DhcpMessageType::Discover as u8]);
        packet.options[7] = DHCP_OPTION_END;
        packet
    }

    fn build_request_packet<'a>(buf: &'a mut [u8; 512], mac: [u8; 6], requested_ip: Ipv4Addr, server_id: Ipv4Addr) -> &'a DhcpPacket {
        let packet = DhcpPacket::from_bytes_mut(buf).unwrap();
        packet.op = BootpMessageType::BootRequest as u8;
        packet.chaddr[..6].copy_from_slice(&mac);
        packet.options[0..4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        let mut cursor = 4;
        packet.options[cursor..cursor + 3].copy_from_slice(&[DHCP_OPTION_MESSAGE_TYPE, 1, DhcpMessageType::Request as u8]);
        cursor += 3;
        packet.options[cursor..cursor + 6].copy_from_slice(&[DHCP_OPTION_REQUESTED_IP, 4, requested_ip.octets()[0], requested_ip.octets()[1], requested_ip.octets()[2], requested_ip.octets()[3]]);
        cursor += 6;
        packet.options[cursor..cursor + 6].copy_from_slice(&[DHCP_OPTION_SERVER_ID, 4, server_id.octets()[0], server_id.octets()[1], server_id.octets()[2], server_id.octets()[3]]);
        cursor += 6;
        packet.options[cursor] = DHCP_OPTION_END;
        packet
    }

    #[tokio::test]
    async fn test_discover_offers_available_ip() {
        let config = Arc::new(Config::default());
        let (_config_tx, config_rx) = watch::channel(config);
        let dhcp_server = DhcpServer::new(config_rx).await.unwrap();
        let mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let mut packet_buf = [0u8; 512];
        let discover_packet = build_discover_packet(&mut packet_buf, mac);

        let action = dhcp_server.handle_dhcp_packet(discover_packet, "0.0.0.0:68".parse().unwrap(), None).await.unwrap();

        match action {
            DhcpAction::Offer { response, client_ip, .. } => {
                let offer_packet = DhcpPacket::from_bytes(&response).unwrap();
                assert_eq!(offer_packet.get_message_type(), Some(DhcpMessageType::Offer));
                assert_eq!(client_ip, Ipv4Addr::new(192, 168, 182, 254)); // The last IP in the default pool
            },
            _ => panic!("Expected DhcpAction::Offer"),
        }
    }

    #[tokio::test]
    async fn test_discover_when_pool_is_full() {
        let mut config = Config::default();
        config.dhcpstart = "192.168.1.10".parse().unwrap();
        config.dhcpend = "192.168.1.10".parse().unwrap(); // Pool of 1
        let config = Arc::new(config);
        let (_config_tx, config_rx) = watch::channel(config);
        let dhcp_server = DhcpServer::new(config_rx).await.unwrap();

        // Take the only IP
        dhcp_server.ip_pool.lock().await.pop();

        let mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x07];
        let mut packet_buf = [0u8; 512];
        let discover_packet = build_discover_packet(&mut packet_buf, mac);

        let action = dhcp_server.handle_dhcp_packet(discover_packet, "0.0.0.0:68".parse().unwrap(), None).await.unwrap();

        match action {
            DhcpAction::NoResponse => { /* This is the correct behavior */ },
            _ => panic!("Expected DhcpAction::NoResponse when pool is empty"),
        }
    }

    #[tokio::test]
    async fn test_request_allocates_ip() {
        let config = Arc::new(Config::default());
        let server_id = config.dhcplisten;
        let (_config_tx, config_rx) = watch::channel(config);
        let dhcp_server = DhcpServer::new(config_rx).await.unwrap();
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let offered_ip = dhcp_server.ip_pool.lock().await.last().unwrap().clone();

        let mut request_buf = [0u8; 512];
        let request_packet = build_request_packet(&mut request_buf, mac, offered_ip, server_id);

        let action = dhcp_server.handle_dhcp_packet(request_packet, "0.0.0.0:68".parse().unwrap(), None).await.unwrap();

        match action {
            DhcpAction::Ack { client_ip, .. } => {
                assert_eq!(client_ip, offered_ip);
            },
            _ => panic!("Expected DhcpAction::Ack"),
        }

        // Verify the IP is no longer in the pool
        let pool = dhcp_server.ip_pool.lock().await;
        assert!(!pool.contains(&offered_ip));

        // Verify a lease was created
        let leases = dhcp_server.leases.lock().await;
        assert!(leases.contains_key(&mac));
        assert_eq!(leases.get(&mac).unwrap().ip, offered_ip);
    }

    fn build_release_packet(buf: &mut [u8; 512], mac: [u8; 6], client_ip: Ipv4Addr) -> &DhcpPacket {
        let packet = DhcpPacket::from_bytes_mut(buf).unwrap();
        packet.op = BootpMessageType::BootRequest as u8;
        packet.chaddr[..6].copy_from_slice(&mac);
        packet.ciaddr = u32::from(client_ip).to_be();
        packet.options[0..4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        packet.options[4..7].copy_from_slice(&[DHCP_OPTION_MESSAGE_TYPE, 1, DhcpMessageType::Release as u8]);
        packet.options[7] = DHCP_OPTION_END;
        packet
    }

    #[tokio::test]
    async fn test_release_returns_ip_to_pool() {
        let config = Arc::new(Config::default());
        let (_config_tx, config_rx) = watch::channel(config);
        let dhcp_server = DhcpServer::new(config_rx).await.unwrap();
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let ip_to_lease = dhcp_server.ip_pool.lock().await.last().unwrap().clone();

        // Manually create a lease and remove IP from pool
        let lease_duration = Duration::from_secs(3600);
        let lease = Lease { ip: ip_to_lease, mac, expires: SystemTime::now() + lease_duration };
        dhcp_server.leases.lock().await.insert(mac, lease);
        dhcp_server.ip_pool.lock().await.pop();

        let pool_size_before = dhcp_server.ip_pool.lock().await.len();

        // Send release packet
        let mut release_buf = [0u8; 512];
        let release_packet = build_release_packet(&mut release_buf, mac, ip_to_lease);
        let action = dhcp_server.handle_dhcp_packet(release_packet, "0.0.0.0:68".parse().unwrap(), None).await.unwrap();

        assert!(matches!(action, DhcpAction::NoResponse));

        // Verify the lease is gone
        assert!(!dhcp_server.leases.lock().await.contains_key(&mac));

        // Verify the IP is back in the pool
        let pool = dhcp_server.ip_pool.lock().await;
        assert_eq!(pool.len(), pool_size_before + 1);
        assert!(pool.contains(&ip_to_lease));
    }
}
