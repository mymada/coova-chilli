use tokio::net::TcpListener;
use tokio::sync::mpsc;
use reqwest;
// TODO: THIS TEST IS KNOWN TO BE BROKEN AND CAUSES A PANIC.
//
// The code review for this feature identified several critical issues:
// 1. The test panics with `called Result::unwrap() on an Err value: Os { code: 2, kind: NotFound, ... }`.
//    This is because interactions with the firewall or network interfaces are not correctly
//    mocked or handled in the test environment.
// 2. The overall UAM feature implementation is incomplete and considered non-functional.
// 3. This test, and the feature it covers, was part of a large, single refactoring
//    that left the code in an unstable state.
//
// This code is being submitted at the user's request with the understanding that it is
// not functional and will be fixed in a future commit.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use pnet::datalink::{self, MacAddr, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, MutableIpv4Packet};
use pnet::packet::udp::{self, MutableUdpPacket};
use pnet::packet::Packet;
use chilli_bin::{initialize_services, process_ethernet_frame};
use chilli_net::dhcp::{
    BootpMessageType, DhcpMessageType, DhcpPacket, DHCP_MAGIC_COOKIE,
    DHCP_OPTION_END, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_REQUESTED_IP, DHCP_OPTION_SERVER_ID,
};
use tracing::info;

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
        self.packets
            .lock()
            .expect("Failed to lock mock sender packets")
            .push(packet.to_vec());
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
    let packet =
        DhcpPacket::from_bytes_mut(&mut dhcp_buf).expect("Failed to create dhcp packet buffer");

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
    let mut udp_packet =
        MutableUdpPacket::new(&mut udp_buf).expect("Failed to create udp packet buffer");
    udp_packet.set_source(68);
    udp_packet.set_destination(67);
    udp_packet.set_length((8 + payload.len()) as u16);
    udp_packet.set_payload(&payload);

    let mut ip_buf = vec![0u8; 20 + udp_packet.packet().len()];
    let mut ip_packet =
        MutableIpv4Packet::new(&mut ip_buf).expect("Failed to create ipv4 packet buffer");
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
    let udp_checksum = udp::ipv4_checksum(
        &udp_packet.to_immutable(),
        &ip_packet.get_source(),
        &ip_packet.get_destination(),
    );
    udp_packet.set_checksum(udp_checksum);

    let mut eth_buf = vec![0u8; 14 + ip_packet.packet().len()];
    let mut eth_packet =
        MutableEthernetPacket::new(&mut eth_buf).expect("Failed to create ethernet packet buffer");
    eth_packet.set_destination(MacAddr::broadcast());
    eth_packet.set_source(chaddr);
    eth_packet.set_ethertype(EtherTypes::Ipv4);
    eth_packet.set_payload(ip_packet.packet());

    eth_packet.packet().to_vec()
}

#[tokio::test]
async fn test_uam_flow() {
    println!("[UAM_TEST] Start of test");
    tracing_subscriber::fmt::try_init().ok();
    info!("Starting test_uam_flow");

    println!("[UAM_TEST] Initializing services...");
    let (config, session_manager, radius_client, dhcp_server, firewall, eapol_attribute_cache, core_tx, _core_rx, _config_tx) = initialize_services(None, Some(0)).await.expect("initialize_services failed");
    println!("[UAM_TEST] Services initialized.");
    let (upload_tx, mut upload_rx) = tokio::sync::mpsc::channel(100);

    let our_mac = MacAddr::new(0x00, 0x01, 0x02, 0x03, 0x04, 0x05);
    let client_mac = MacAddr::new(0x20, 0x21, 0x22, 0x23, 0x24, 0x25);
    let xid = 0x12345678;

    let sent_packets = Arc::new(Mutex::new(Vec::new()));
    let mut tx: Box<dyn datalink::DataLinkSender> = Box::new(MockDataLinkSender {
        packets: Arc::clone(&sent_packets),
    });

    println!("[UAM_TEST] Processing DHCP Discover...");
    let discover_payload = build_dhcp_payload(client_mac, xid, DhcpMessageType::Discover, None, None);
    let discover_packet = build_full_dhcp_packet(client_mac, discover_payload);
    process_ethernet_frame(&mut tx, our_mac, &discover_packet, &session_manager, &radius_client, &dhcp_server, &firewall, &config, &eapol_attribute_cache, &core_tx, &upload_tx).await;
    sent_packets.lock().unwrap().clear();
    println!("[UAM_TEST] DHCP Discover processed.");

    println!("[UAM_TEST] Processing DHCP Request...");
    let offered_ip = Ipv4Addr::new(10, 1, 0, 1);
    let request_payload = build_dhcp_payload(client_mac, xid, DhcpMessageType::Request, Some(offered_ip), Some(config.net));
    let request_packet = build_full_dhcp_packet(client_mac, request_payload);
    process_ethernet_frame(&mut tx, our_mac, &request_packet, &session_manager, &radius_client, &dhcp_server, &firewall, &config, &eapol_attribute_cache, &core_tx, &upload_tx).await;
    sent_packets.lock().unwrap().clear();
    println!("[UAM_TEST] DHCP Request processed.");

    assert!(session_manager.get_session(&offered_ip).await.is_some(), "Session should exist after DHCP");
    info!("DHCP Flow complete, session created for {}", offered_ip);


    println!("[UAM_TEST] Processing unauthenticated HTTP GET...");
    let http_get_payload = b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n";
    let http_get_packet = build_http_packet(client_mac, our_mac, offered_ip, "8.8.8.8".parse().unwrap(), 12345, 80, http_get_payload);
    process_ethernet_frame(&mut tx, our_mac, &http_get_packet, &session_manager, &radius_client, &dhcp_server, &firewall, &config, &eapol_attribute_cache, &core_tx, &upload_tx).await;
    println!("[UAM_TEST] Unauthenticated HTTP GET processed.");

    let packets = sent_packets.lock().unwrap();
    assert_eq!(packets.len(), 1, "Expected one redirect packet");
    let redirect_packet = pnet::packet::ethernet::EthernetPacket::new(&packets[0]).unwrap();
    assert_eq!(redirect_packet.get_destination(), client_mac);

    println!("[UAM_TEST] Authenticating session...");
    session_manager.authenticate_session(&offered_ip).await;
    firewall.add_authenticated_ip(offered_ip).ok();
    sent_packets.lock().unwrap().clear();
    println!("[UAM_TEST] Session authenticated.");

    println!("[UAM_TEST] Processing authenticated HTTP GET...");
    let http_get_packet_authed = build_http_packet(client_mac, our_mac, offered_ip, "8.8.4.4".parse().unwrap(), 12345, 80, http_get_payload);
    process_ethernet_frame(&mut tx, our_mac, &http_get_packet_authed, &session_manager, &radius_client, &dhcp_server, &firewall, &config, &eapol_attribute_cache, &core_tx, &upload_tx).await;
    println!("[UAM_TEST] Authenticated HTTP GET processed.");

    println!("[UAM_TEST] Waiting for packet on upload channel...");
    let tun_packet = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        upload_rx.recv()
    ).await.expect("Test timed out waiting for TUN packet").expect("Did not receive packet on upload channel");
    println!("[UAM_TEST] Received packet on upload channel.");
    let tun_ipv4 = pnet::packet::ipv4::Ipv4Packet::new(&tun_packet).unwrap();
    assert_eq!(tun_ipv4.get_source(), offered_ip);
    assert_eq!(tun_ipv4.get_destination(), "8.8.8.8".parse::<Ipv4Addr>().unwrap());

    assert!(sent_packets.lock().unwrap().is_empty(), "No packets should be sent back to the client after authentication");

    println!("[UAM_TEST] End of test.");
}


fn build_http_packet(src_mac: MacAddr, dst_mac: MacAddr, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut tcp_buf = vec![0u8; 20 + payload.len()];
    let mut tcp_packet = pnet::packet::tcp::MutableTcpPacket::new(&mut tcp_buf).unwrap();
    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_sequence(123);
    tcp_packet.set_acknowledgement(456);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_flags(pnet::packet::tcp::TcpFlags::SYN);
    tcp_packet.set_payload(payload);
    let checksum = pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
    tcp_packet.set_checksum(checksum);

    let mut ip_buf = vec![0u8; 20 + tcp_buf.len()];
    let mut ip_packet = MutableIpv4Packet::new(&mut ip_buf).unwrap();
    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length((20 + tcp_buf.len()) as u16);
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_packet.set_source(src_ip);
    ip_packet.set_destination(dst_ip);
    ip_packet.set_payload(&tcp_buf);
    let ip_checksum = ipv4::checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(ip_checksum);

    let mut eth_buf = vec![0u8; 14 + ip_buf.len()];
    let mut eth_packet = MutableEthernetPacket::new(&mut eth_buf).unwrap();
    eth_packet.set_destination(dst_mac);
    eth_packet.set_source(src_mac);
    eth_packet.set_ethertype(EtherTypes::Ipv4);
    eth_packet.set_payload(&ip_buf);

    eth_packet.packet().to_vec()
}
