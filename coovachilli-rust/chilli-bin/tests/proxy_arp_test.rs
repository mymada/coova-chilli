use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use pnet::datalink::{self, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpOperations, ArpHardwareTypes, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;

use chilli_bin::{initialize_services, process_ethernet_frame};

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

    let mut eth_buf = vec![0u8; 14 + arp_packet.packet().len()];
    let mut eth_packet = MutableEthernetPacket::new(&mut eth_buf).unwrap();
    eth_packet.set_destination(MacAddr::broadcast());
    eth_packet.set_source(sender_mac);
    eth_packet.set_ethertype(EtherTypes::Arp);
    eth_packet.set_payload(arp_packet.packet());

    eth_packet.packet().to_vec()
}

#[tokio::test]
async fn test_proxy_arp_reply() {
    tracing_subscriber::fmt::try_init().ok();

    let (config, session_manager, radius_client, dhcp_server, firewall, eapol_attribute_cache, auth_tx, _auth_rx, _config_tx) = initialize_services(None).await;

    let our_mac = MacAddr::new(0x00, 0x01, 0x02, 0x03, 0x04, 0x05);
    let client_a_mac = MacAddr::new(0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA);
    let client_a_ip = "10.1.0.10".parse().unwrap();
    let client_b_ip = "10.1.0.1".parse().unwrap(); // The IP in the default DHCP range

    let sent_packets = Arc::new(Mutex::new(Vec::new()));
    let mut tx: Box<dyn datalink::DataLinkSender> = Box::new(MockDataLinkSender {
        packets: Arc::clone(&sent_packets),
    });

    // Simulate Client A sending an ARP request for Client B's IP
    let arp_request_packet = build_arp_request(client_a_mac, client_a_ip, client_b_ip);

    let (upload_tx, _) = tokio::sync::mpsc::channel(1);
    process_ethernet_frame(&mut tx, our_mac, &arp_request_packet, &session_manager, &radius_client, &dhcp_server, &firewall, &config, &eapol_attribute_cache, &auth_tx, &upload_tx).await;

    // Verify that we sent a reply
    let packets = sent_packets.lock().unwrap();
    assert_eq!(packets.len(), 1, "Expected one packet (ARP reply)");

    // Verify the ARP reply
    let reply_eth = EthernetPacket::new(&packets[0]).unwrap();
    assert_eq!(reply_eth.get_destination(), client_a_mac, "ARP reply should be sent to Client A");
    assert_eq!(reply_eth.get_source(), our_mac, "ARP reply should come from our MAC");
    assert_eq!(reply_eth.get_ethertype(), EtherTypes::Arp);

    let reply_arp = pnet::packet::arp::ArpPacket::new(reply_eth.payload()).unwrap();
    assert_eq!(reply_arp.get_operation(), ArpOperations::Reply, "Packet should be an ARP reply");
    assert_eq!(reply_arp.get_sender_hw_addr(), our_mac, "Sender MAC in ARP payload should be our MAC");
    assert_eq!(reply_arp.get_sender_proto_addr(), client_b_ip, "Sender IP in ARP payload should be the requested IP (Client B)");
    assert_eq!(reply_arp.get_target_hw_addr(), client_a_mac);
    assert_eq!(reply_arp.get_target_proto_addr(), client_a_ip);
}
