use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use pnet::datalink::{self, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{self, MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;

use chilli_bin::{initialize_services, process_ethernet_frame};
use chilli_net::dhcp::{
    BootpMessageType, DhcpMessageType, DhcpPacket, DHCP_MAGIC_COOKIE,
    DHCP_OPTION_END, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_REQUESTED_IP, DHCP_OPTION_SERVER_ID,
};

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

// Helper to build an ARP Request packet.
fn build_arp_request(
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(sender_mac);
    arp_packet.set_sender_proto_addr(sender_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(sender_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);
    ethernet_packet.set_payload(arp_packet.packet());

    ethernet_packet.packet().to_vec()
}

#[tokio::test]
async fn test_l2_dhcp_and_arp_flow() {
    // 1. Initialize all services
    let (config, session_manager, radius_client, dhcp_server, firewall, eapol_attribute_cache, auth_tx, _auth_rx) = initialize_services().await;

    let our_mac = MacAddr::new(0x00, 0x01, 0x02, 0x03, 0x04, 0x05);
    let client_mac = MacAddr::new(0x10, 0x11, 0x12, 0x13, 0x14, 0x15);
    let xid = 0x12345678;

    let sent_packets = Arc::new(Mutex::new(Vec::new()));
    let mut tx: Box<dyn datalink::DataLinkSender> = Box::new(MockDataLinkSender {
        packets: Arc::clone(&sent_packets),
    });

    // 2. Simulate DHCP Discover
    let discover_payload = build_dhcp_payload(client_mac, xid, DhcpMessageType::Discover, None, None);
    let discover_packet = build_full_dhcp_packet(client_mac, discover_payload);
    process_ethernet_frame(
        &mut tx,
        our_mac,
        &discover_packet,
        &session_manager,
        &radius_client,
        &dhcp_server,
        &firewall,
        &config,
        &eapol_attribute_cache,
        &auth_tx,
    )
    .await;

    // 3. Verify DHCP Offer
    let packets = sent_packets.lock().unwrap();
    assert_eq!(packets.len(), 1, "Expected one packet (DHCP Offer)");
    let offer_eth_packet = EthernetPacket::new(&packets[0]).unwrap();
    assert_eq!(offer_eth_packet.get_destination(), client_mac);
    assert_eq!(offer_eth_packet.get_source(), our_mac);

    let offer_ip_packet = Ipv4Packet::new(offer_eth_packet.payload()).unwrap();
    let offer_udp_packet = UdpPacket::new(offer_ip_packet.payload()).unwrap();
    let offer_dhcp_packet = DhcpPacket::from_bytes(offer_udp_packet.payload()).unwrap();

    let received_xid = offer_dhcp_packet.xid;
    assert_eq!(received_xid, xid.to_be());
    assert_eq!(offer_dhcp_packet.get_message_type(), Some(DhcpMessageType::Offer));
    let offered_ip = Ipv4Addr::from(u32::from_be(offer_dhcp_packet.yiaddr));
    assert_eq!(offered_ip, Ipv4Addr::new(10, 1, 0, 1), "First IP in the pool");
    drop(packets);

    // 4. Simulate DHCP Request
    sent_packets.lock().unwrap().clear();
    let request_payload = build_dhcp_payload(client_mac, xid, DhcpMessageType::Request, Some(offered_ip), Some(config.net));
    let request_packet = build_full_dhcp_packet(client_mac, request_payload);
    process_ethernet_frame(
        &mut tx,
        our_mac,
        &request_packet,
        &session_manager,
        &radius_client,
        &dhcp_server,
        &firewall,
        &config,
        &eapol_attribute_cache,
        &auth_tx,
    ).await;

    // 5. Verify DHCP Ack
    let packets = sent_packets.lock().unwrap();
    assert_eq!(packets.len(), 1, "Expected one packet (DHCP Ack)");
    let ack_eth_packet = EthernetPacket::new(&packets[0]).unwrap();
    let ack_ip_packet = Ipv4Packet::new(ack_eth_packet.payload()).unwrap();
    let ack_udp_packet = UdpPacket::new(ack_ip_packet.payload()).unwrap();
    let ack_dhcp_packet = DhcpPacket::from_bytes(ack_udp_packet.payload()).unwrap();

    let received_yiaddr = Ipv4Addr::from(u32::from_be(ack_dhcp_packet.yiaddr));
    assert_eq!(received_yiaddr, offered_ip);
    assert_eq!(ack_dhcp_packet.get_message_type(), Some(DhcpMessageType::Ack));
    drop(packets);

    // 6. Simulate ARP Request for the gateway
    sent_packets.lock().unwrap().clear();
    let arp_req_packet = build_arp_request(client_mac, offered_ip, config.net);
    process_ethernet_frame(
        &mut tx,
        our_mac,
        &arp_req_packet,
        &session_manager,
        &radius_client,
        &dhcp_server,
        &firewall,
        &config,
        &eapol_attribute_cache,
        &auth_tx,
    ).await;

    // 7. Verify ARP Reply
    let packets = sent_packets.lock().unwrap();
    assert_eq!(packets.len(), 1, "Expected one packet (ARP Reply)");
    let arp_reply_eth = EthernetPacket::new(&packets[0]).unwrap();
    assert_eq!(arp_reply_eth.get_destination(), client_mac);
    assert_eq!(arp_reply_eth.get_source(), our_mac);
    let arp_reply_packet = ArpPacket::new(arp_reply_eth.payload()).unwrap();
    assert_eq!(arp_reply_packet.get_operation(), ArpOperations::Reply);
    assert_eq!(arp_reply_packet.get_sender_hw_addr(), our_mac);
    assert_eq!(arp_reply_packet.get_sender_proto_addr(), config.net);
    assert_eq!(arp_reply_packet.get_target_hw_addr(), client_mac);
    assert_eq!(arp_reply_packet.get_target_proto_addr(), offered_ip);
}
