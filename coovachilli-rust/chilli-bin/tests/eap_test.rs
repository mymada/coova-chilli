use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::info;

use pnet::datalink::{self, MacAddr, NetworkInterface};
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, MutableIpv4Packet};
use pnet::packet::udp::{self, MutableUdpPacket};
use pnet::packet::Packet;
use tokio::net::UdpSocket;

use chilli_bin::{initialize_services, process_ethernet_frame};
use chilli_net::dhcp::{
    BootpMessageType, DhcpMessageType, DhcpPacket, DHCP_MAGIC_COOKIE,
    DHCP_OPTION_END, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_REQUESTED_IP, DHCP_OPTION_SERVER_ID,
};
use chilli_net::eap::{EapCode, EapPacket, EapType};
use chilli_net::eapol::{EapolPacket, EapolType};
use chilli_net::radius::{RadiusAttributeType, RadiusAttributes, RadiusCode, RadiusPacket, RADIUS_HDR_LEN};

// A mock sender that captures packets instead of sending them to a real network interface.
struct MockDataLinkSender {
    packets: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl datalink::DataLinkSender for MockDataLinkSender {
    fn send_to(
        &mut self,
        packet: &[u8],
        _dst_iface: Option<NetworkInterface>,
    ) -> Option<std::io::Result<()>> {
        self.packets.lock().unwrap().push(packet.to_vec());
        Some(Ok(()))
    }

    fn build_and_send(
        &mut self,
        _num_packets: usize,
        _packet_size: usize,
        _func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<std::io::Result<()>> {
        todo!()
    }
}

fn build_dhcp_payload(
    chaddr: MacAddr,
    xid: u32,
    msg_type: DhcpMessageType,
    requested_ip: Option<Ipv4Addr>,
    server_ip: Option<Ipv4Addr>,
) -> Vec<u8> {
    let mut dhcp_buf = vec![0u8; 512];
    let packet = DhcpPacket::from_bytes_mut(&mut dhcp_buf).unwrap();

    packet.op = BootpMessageType::BootRequest as u8;
    packet.htype = 1; // Ethernet
    packet.hlen = 6;
    packet.xid = xid.to_be();
    packet.chaddr[..6].copy_from_slice(&chaddr.octets());

    packet.options[0..4].copy_from_slice(&DHCP_MAGIC_COOKIE);
    let mut cursor = 4;

    // Message Type
    packet.options[cursor..cursor + 3]
        .copy_from_slice(&[DHCP_OPTION_MESSAGE_TYPE, 1, msg_type as u8]);
    cursor += 3;

    if let Some(ip) = requested_ip {
        packet.options[cursor..cursor + 2].copy_from_slice(&[DHCP_OPTION_REQUESTED_IP, 4]);
        packet.options[cursor + 2..cursor + 6].copy_from_slice(&ip.octets());
        cursor += 6;
    }

    if let Some(ip) = server_ip {
        packet.options[cursor..cursor + 2].copy_from_slice(&[DHCP_OPTION_SERVER_ID, 4]);
        packet.options[cursor + 2..cursor + 6].copy_from_slice(&ip.octets());
        cursor += 6;
    }

    packet.options[cursor] = DHCP_OPTION_END;
    cursor += 1;

    let final_len = 236 + cursor;
    dhcp_buf.truncate(final_len);
    dhcp_buf
}

fn build_full_dhcp_packet(chaddr: MacAddr, payload: Vec<u8>) -> Vec<u8> {
    let mut udp_buf = vec![0u8; 8 + payload.len()];
    let mut udp_packet = MutableUdpPacket::new(&mut udp_buf).unwrap();
    udp_packet.set_source(68);
    udp_packet.set_destination(67);
    udp_packet.set_length((8 + payload.len()) as u16);
    udp_packet.set_payload(&payload);

    let mut ip_buf = vec![0u8; 20 + udp_packet.packet().len()];
    let mut ip_packet = MutableIpv4Packet::new(&mut ip_buf).unwrap();
    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length((20 + udp_packet.packet().len()) as u16);
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ip_packet.set_source(Ipv4Addr::new(0, 0, 0, 0));
    ip_packet.set_destination(Ipv4Addr::new(255, 255, 255, 255));
    ip_packet.set_payload(udp_packet.packet());
    let checksum = ipv4::checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(checksum);
    let udp_checksum = udp::ipv4_checksum(&udp_packet.to_immutable(), &ip_packet.get_source(), &ip_packet.get_destination());
    udp_packet.set_checksum(udp_checksum);

    let mut eth_buf = vec![0u8; 14 + ip_packet.packet().len()];
    let mut eth_packet = MutableEthernetPacket::new(&mut eth_buf).unwrap();
    eth_packet.set_destination(MacAddr::broadcast());
    eth_packet.set_source(chaddr);
    eth_packet.set_ethertype(EtherTypes::Ipv4);
    eth_packet.set_payload(ip_packet.packet());

    eth_packet.packet().to_vec()
}

// Helper to build a basic EAPOL packet
fn build_eapol_packet(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    eapol_type: EapolType,
    eap_payload: Option<Vec<u8>>,
) -> Vec<u8> {
    let payload = eap_payload.unwrap_or_default();
    let eapol_len = payload.len();
    let mut eapol_buf = vec![0u8; 4 + eapol_len];
    eapol_buf[0] = 1; // Version
    eapol_buf[1] = eapol_type as u8;
    eapol_buf[2..4].copy_from_slice(&(eapol_len as u16).to_be_bytes());
    if eapol_len > 0 {
        eapol_buf[4..].copy_from_slice(&payload);
    }

    let mut eth_buf = vec![0u8; 14 + eapol_buf.len()];
    let mut eth_packet = MutableEthernetPacket::new(&mut eth_buf).unwrap();
    eth_packet.set_destination(dst_mac);
    eth_packet.set_source(src_mac);
    eth_packet.set_ethertype(EtherType(0x888E));
    eth_packet.set_payload(&eapol_buf);

    eth_packet.packet().to_vec()
}

fn create_radius_response(code: RadiusCode, id: u8, req_authenticator: &[u8; 16], payload: &[u8], secret: &str) -> Vec<u8> {
    let length = (RADIUS_HDR_LEN + payload.len()) as u16;
    let mut response_header = Vec::new();
    response_header.push(code as u8);
    response_header.push(id);
    response_header.extend_from_slice(&length.to_be_bytes());

    let mut to_hash = Vec::new();
    to_hash.extend_from_slice(&response_header);
    to_hash.extend_from_slice(req_authenticator);
    to_hash.extend_from_slice(payload);
    to_hash.extend_from_slice(secret.as_bytes());

    let response_auth = md5::compute(&to_hash);

    let mut final_packet = Vec::new();
    final_packet.extend_from_slice(&response_header);
    final_packet.extend_from_slice(&response_auth.0);
    final_packet.extend_from_slice(payload);

    final_packet
}

async fn mock_radius_server_eap_md5(socket: UdpSocket, secret: String) {
    let mut buf = [0u8; 1504];
    let password = "password123";

    // 1. Receive Identity Response, send MD5 Challenge
    info!("[mock_radius] waiting for Identity-Response");
    let (len, src) = socket.recv_from(&mut buf).await.unwrap();
    info!("[mock_radius] received Identity-Response, sending Challenge");
    let req_packet = RadiusPacket::from_bytes(&buf[..len]).unwrap();

    let challenge_value = b"thisisthechallenge";
    let mut eap_md5_challenge_data = vec![EapType::Md5Challenge as u8];
    eap_md5_challenge_data.push(challenge_value.len() as u8);
    eap_md5_challenge_data.extend_from_slice(challenge_value);

    let eap_challenge_packet = EapPacket {
        code: EapCode::Request,
        identifier: req_packet.id,
        data: eap_md5_challenge_data,
    };

    let mut attributes = RadiusAttributes::default();
    attributes.standard.insert(RadiusAttributeType::EapMessage, vec![eap_challenge_packet.to_bytes()]);
    attributes.standard.insert(RadiusAttributeType::State, vec![b"eap_state_123".to_vec()]);

    let response_payload = chilli_net::radius::serialize_attributes(&attributes);
    let mut response = create_radius_response(RadiusCode::AccessChallenge, req_packet.id, &req_packet.authenticator, &response_payload, &secret);
    socket.send_to(&mut response, src).await.unwrap();
    info!("[mock_radius] sent Challenge");

    // 2. Receive MD5 Challenge Response, send Success
    info!("[mock_radius] waiting for Challenge-Response");
    let (len, src) = socket.recv_from(&mut buf).await.unwrap();
    info!("[mock_radius] received Challenge-Response, sending Success");
    let req_packet = RadiusPacket::from_bytes(&buf[..len]).unwrap();

    let req_attributes = chilli_net::radius::parse_attributes(&req_packet.payload[..len - 20]);
    let eap_response_msg = req_attributes.get_standard(RadiusAttributeType::EapMessage).unwrap();
    let eap_response_packet = EapPacket::from_bytes(eap_response_msg).unwrap();

    let mut to_hash = Vec::new();
    to_hash.push(eap_response_packet.identifier);
    to_hash.extend_from_slice(password.as_bytes());
    to_hash.extend_from_slice(challenge_value);
    let expected_hash = {
        let mut ctx = md5::Context::new();
        ctx.consume(&to_hash);
        ctx.finalize()
    };

    let value_len = eap_response_packet.data[1] as usize;
    let client_hash = &eap_response_packet.data[2..2+value_len];

    assert_eq!(client_hash, &expected_hash.0[..], "EAP-MD5 Response from client did not match expected hash");

    let success_attributes = RadiusAttributes::default();
    let success_payload = chilli_net::radius::serialize_attributes(&success_attributes);
    let mut success_response = create_radius_response(RadiusCode::AccessAccept, req_packet.id, &req_packet.authenticator, &success_payload, &secret);
    socket.send_to(&mut success_response, src).await.unwrap();
    info!("[mock_radius] sent Success");
}


#[tokio::test]
async fn test_eap_md5_flow() {
    tracing_subscriber::fmt::try_init().ok();
    info!("Starting test_eap_md5_flow");

    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let (config, session_manager, radius_client, dhcp_server, firewall, eapol_attribute_cache, auth_tx, _auth_rx, _config_tx) = initialize_services(Some(server_addr)).await;
    let (upload_tx, _upload_rx) = tokio::sync::mpsc::channel(100);
    let secret = config.radiussecret.clone();

    let mock_server_handle = tokio::spawn(mock_radius_server_eap_md5(server_socket, secret));
    let radius_run_client = radius_client.clone();
    let radius_client_handle = tokio::spawn(async move { radius_run_client.run().await; });

    let our_mac = MacAddr::new(0x00, 0x01, 0x02, 0x03, 0x04, 0x05);
    let client_mac = MacAddr::new(0x20, 0x21, 0x22, 0x23, 0x24, 0x25);
    let xid = 0x87654321;

    let sent_packets = Arc::new(Mutex::new(Vec::new()));
    let mut tx: Box<dyn datalink::DataLinkSender> = Box::new(MockDataLinkSender {
        packets: Arc::clone(&sent_packets),
    });

    info!("Starting DHCP Flow");
    let discover_payload = build_dhcp_payload(client_mac, xid, DhcpMessageType::Discover, None, None);
    let discover_packet = build_full_dhcp_packet(client_mac, discover_payload);
    process_ethernet_frame(&mut tx, our_mac, &discover_packet, &session_manager, &radius_client, &dhcp_server, &firewall, &config, &eapol_attribute_cache, &auth_tx, &upload_tx).await;
    sent_packets.lock().unwrap().clear();

    let offered_ip = Ipv4Addr::new(10, 1, 0, 1);
    let request_payload = build_dhcp_payload(client_mac, xid, DhcpMessageType::Request, Some(offered_ip), Some(config.net));
    let request_packet = build_full_dhcp_packet(client_mac, request_payload);
    process_ethernet_frame(&mut tx, our_mac, &request_packet, &session_manager, &radius_client, &dhcp_server, &firewall, &config, &eapol_attribute_cache, &auth_tx, &upload_tx).await;
    sent_packets.lock().unwrap().clear();

    assert!(session_manager.get_session(&offered_ip).await.is_some(), "Session should exist after DHCP");
    info!("DHCP Flow complete, session created for {}", offered_ip);

    info!("Sending EAPOL-Start");
    let start_packet = build_eapol_packet(client_mac, our_mac, EapolType::Start, None);
    process_ethernet_frame(&mut tx, our_mac, &start_packet, &session_manager, &radius_client, &dhcp_server, &firewall, &config, &eapol_attribute_cache, &auth_tx, &upload_tx).await;

    info!("Verifying EAP-Request/Identity");
    let packets = sent_packets.lock().unwrap();
    assert_eq!(packets.len(), 1, "Expected one packet (EAP-Request/Identity)");
    let identity_req_eth = EthernetPacket::new(&packets[0]).unwrap();
    assert_eq!(identity_req_eth.get_destination(), client_mac);
    let identity_req_eapol = EapolPacket::from_bytes(identity_req_eth.payload()).unwrap();
    assert_eq!(identity_req_eapol.packet_type, EapolType::Eap);
    let identity_req_eap = EapPacket::from_bytes(identity_req_eapol.payload).unwrap();
    assert_eq!(identity_req_eap.code, EapCode::Request);
    assert_eq!(identity_req_eap.data[0], EapType::Identity as u8);
    let identity_req_id = identity_req_eap.identifier;
    drop(packets);

    info!("Sending EAP-Response/Identity");
    sent_packets.lock().unwrap().clear();
    let username = "test-eap-user";
    let mut identity_resp_payload = vec![EapType::Identity as u8];
    identity_resp_payload.extend_from_slice(username.as_bytes());
    let identity_resp_eap = EapPacket {
        code: EapCode::Response,
        identifier: identity_req_id,
        data: identity_resp_payload,
    };
    let identity_resp_packet = build_eapol_packet(client_mac, our_mac, EapolType::Eap, Some(identity_resp_eap.to_bytes()));
    process_ethernet_frame(&mut tx, our_mac, &identity_resp_packet, &session_manager, &radius_client, &dhcp_server, &firewall, &config, &eapol_attribute_cache, &auth_tx, &upload_tx).await;

    info!("Waiting for EAP-Request/MD5-Challenge...");
    tokio::time::sleep(Duration::from_millis(500)).await;

    info!("Verifying EAP-Request/MD5-Challenge");
    let packets = sent_packets.lock().unwrap();
    assert_eq!(packets.len(), 1, "Expected one packet (EAP-Request/MD5-Challenge)");
    let md5_req_eth = EthernetPacket::new(&packets[0]).unwrap();
    let md5_req_eapol = EapolPacket::from_bytes(md5_req_eth.payload()).unwrap();
    let md5_req_eap = EapPacket::from_bytes(md5_req_eapol.payload).unwrap();
    assert_eq!(md5_req_eap.code, EapCode::Request);
    assert_eq!(md5_req_eap.data[0], EapType::Md5Challenge as u8);
    let md5_req_id = md5_req_eap.identifier;
    let challenge_len = md5_req_eap.data[1] as usize;
    let challenge_val = &md5_req_eap.data[2..2+challenge_len];
    drop(packets);

    info!("Sending EAP-Response/MD5-Challenge");
    sent_packets.lock().unwrap().clear();
    let mut to_hash = Vec::new();
    to_hash.push(md5_req_id);
    to_hash.extend_from_slice(b"password123");
    to_hash.extend_from_slice(challenge_val);
    let md5_hash = {
        let mut ctx = md5::Context::new();
        ctx.consume(&to_hash);
        ctx.finalize()
    };

    let mut md5_resp_payload = vec![EapType::Md5Challenge as u8];
    md5_resp_payload.push(md5_hash.0.len() as u8);
    md5_resp_payload.extend_from_slice(&md5_hash.0);

    let md5_resp_eap = EapPacket {
        code: EapCode::Response,
        identifier: md5_req_id,
        data: md5_resp_payload,
    };
    let md5_resp_packet = build_eapol_packet(client_mac, our_mac, EapolType::Eap, Some(md5_resp_eap.to_bytes()));
    process_ethernet_frame(&mut tx, our_mac, &md5_resp_packet, &session_manager, &radius_client, &dhcp_server, &firewall, &config, &eapol_attribute_cache, &auth_tx, &upload_tx).await;

    info!("Waiting for EAP-Success...");
    tokio::time::sleep(Duration::from_millis(500)).await;

    info!("Verifying EAP-Success");
    let packets = sent_packets.lock().unwrap();
    assert_eq!(packets.len(), 1, "Expected one packet (EAP-Success)");
    let success_eth = EthernetPacket::new(&packets[0]).unwrap();
    let success_eapol = EapolPacket::from_bytes(success_eth.payload()).unwrap();
    let success_eap = EapPacket::from_bytes(success_eapol.payload).unwrap();
    assert_eq!(success_eap.code, EapCode::Success);
    drop(packets);

    info!("Verifying session state");
    let eapol_session = session_manager.get_eapol_session(&client_mac.octets()).await.unwrap();
    assert_eq!(eapol_session.state, chilli_core::eapol_session::EapolState::Authenticated);

    mock_server_handle.abort();
    radius_client_handle.abort();
}
