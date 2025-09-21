use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use pnet::datalink::{self, MacAddr};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, MutableIpv4Packet};
use pnet::packet::udp::MutableUdpPacket;
use tokio::sync::{mpsc, Mutex};
use chilli_bin::{initialize_services, process_ethernet_frame, tun_packet_loop};
use chilli_net::PacketDevice;
use async_trait::async_trait;
use anyhow::Result;


// Corrected helper to create a dummy IPv4 packet wrapped in Ethernet for upload
fn create_upload_packet(our_mac: MacAddr, src_mac: MacAddr, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, total_len: usize) -> Vec<u8> {
    const ETH_HDR_LEN: usize = 14;
    const IPV4_HDR_LEN: usize = 20;
    const UDP_HDR_LEN: usize = 8;
    const HDRS_LEN: usize = ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN;

    let udp_payload_len = total_len.saturating_sub(HDRS_LEN);
    let ip_len = IPV4_HDR_LEN + UDP_HDR_LEN + udp_payload_len;
    let udp_len = UDP_HDR_LEN + udp_payload_len;

    let mut udp_buf = vec![0u8; udp_len];
    {
        let mut udp_packet =
            MutableUdpPacket::new(&mut udp_buf).expect("Failed to create udp packet buffer");
        udp_packet.set_source(12345);
        udp_packet.set_destination(80);
        udp_packet.set_length(udp_len as u16);
        let udp_checksum = pnet::packet::udp::ipv4_checksum(&udp_packet.to_immutable(), &src_ip, &dst_ip);
        udp_packet.set_checksum(udp_checksum);
    }

    let mut ip_buf = vec![0u8; ip_len];
    {
        let mut ip_packet =
            MutableIpv4Packet::new(&mut ip_buf).expect("Failed to create ipv4 packet buffer");
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(ip_len as u16);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip_packet.set_ttl(64);
        ip_packet.set_source(src_ip);
        ip_packet.set_destination(dst_ip);
        let ip_checksum = ipv4::checksum(&ip_packet.to_immutable());
        ip_packet.set_checksum(ip_checksum);
        ip_packet.set_payload(&udp_buf);
    }

    let mut eth_buf = vec![0u8; total_len];
    {
        let mut eth_packet =
            MutableEthernetPacket::new(&mut eth_buf).expect("Failed to create ethernet packet buffer");
        eth_packet.set_destination(our_mac);
        eth_packet.set_source(src_mac);
        eth_packet.set_ethertype(EtherTypes::Ipv4);
        eth_packet.set_payload(&ip_buf);
    }

    eth_buf
}

// Helper to create a dummy download packet (just the IPv4 part)
fn create_download_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, total_len: usize) -> Vec<u8> {
    const IPV4_HDR_LEN: usize = 20;
    const UDP_HDR_LEN: usize = 8;
    const HDRS_LEN: usize = IPV4_HDR_LEN + UDP_HDR_LEN;

    let udp_payload_len = total_len.saturating_sub(HDRS_LEN);
    let udp_len = UDP_HDR_LEN + udp_payload_len;

    let mut udp_buf = vec![0u8; udp_len];
    {
        let mut udp_packet =
            MutableUdpPacket::new(&mut udp_buf).expect("Failed to create udp packet buffer");
        udp_packet.set_source(80);
        udp_packet.set_destination(12345);
        udp_packet.set_length(udp_len as u16);
        let udp_checksum = pnet::packet::udp::ipv4_checksum(&udp_packet.to_immutable(), &src_ip, &dst_ip);
        udp_packet.set_checksum(udp_checksum);
    }

    let mut ip_buf = vec![0u8; total_len];
    {
        let mut ip_packet =
            MutableIpv4Packet::new(&mut ip_buf).expect("Failed to create ipv4 packet buffer");
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(total_len as u16);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip_packet.set_ttl(64);
        ip_packet.set_source(src_ip);
        ip_packet.set_destination(dst_ip);
        let ip_checksum = ipv4::checksum(&ip_packet.to_immutable());
        ip_packet.set_checksum(ip_checksum);
        ip_packet.set_payload(&udp_buf);
    }

    ip_buf
}


// Mock DataLinkSender that does nothing
struct MockDataLinkSender;
impl datalink::DataLinkSender for MockDataLinkSender {
    fn send_to(&mut self, _packet: &[u8], _dst_iface: Option<datalink::NetworkInterface>) -> Option<std::io::Result<()>> {
        Some(Ok(()))
    }
    fn build_and_send(&mut self, _num_packets: usize, _packet_size: usize, _func: &mut dyn FnMut(&mut [u8])) -> Option<std::io::Result<()>> {
        unimplemented!()
    }
}

// Mock Tun Device that implements PacketDevice
struct MockTun {
    rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    tx: mpsc::Sender<Vec<u8>>,
}

#[async_trait]
impl PacketDevice for MockTun {
    async fn send(&self, buf: &[u8]) -> Result<usize> {
        self.tx.send(buf.to_vec()).await.map_err(|e| anyhow::anyhow!(e.to_string()))?;
        Ok(buf.len())
    }
    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        match self.rx.lock().await.recv().await {
            Some(packet) => {
                let len = std::cmp::min(buf.len(), packet.len());
                buf[..len].copy_from_slice(&packet[..len]);
                Ok(len)
            },
            None => Err(anyhow::anyhow!("No more packets"))
        }
    }
}

async fn setup_test_session(
    quota_type: &str,
    quota_value: u64,
) -> (
    Arc<chilli_core::Config>,
    Arc<chilli_core::SessionManager>,
    Ipv4Addr,
    MacAddr,
) {
    let (config, session_manager, ..) =
        initialize_services(None, Some(0)).await.expect("initialize_services failed");

    let client_ip = "10.1.0.10".parse().expect("Failed to parse IP");
    let client_mac_arr = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15];
    let client_mac = MacAddr::from(client_mac_arr);

    session_manager
        .create_session(client_ip, client_mac_arr, &config, None)
        .await;
    session_manager.authenticate_session(&client_ip).await;
    session_manager
        .update_session(&client_ip, |session| {
            match quota_type {
                "input" => session.params.maxinputoctets = quota_value,
                "output" => session.params.maxoutputoctets = quota_value,
                "total" => session.params.maxtotaloctets = quota_value,
                _ => {}
            }
        })
        .await
        .expect("Failed to update session");

    (config, session_manager, client_ip, client_mac)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_upload_quota_exceeded() {
    let quota = 1000;
    let (config, session_manager, client_ip, client_mac) = setup_test_session("input", quota).await;

    let (_, _, radius_client, dhcp_server, firewall, eapol_attribute_cache, auth_tx, _, _) =
        initialize_services(None, Some(0)).await.expect("initialize_services failed");

    let (upload_tx, _upload_rx) = mpsc::channel(100);

    let our_mac = MacAddr::new(0x00, 0x01, 0x02, 0x03, 0x04, 0x05);
    let mut mock_tx: Box<dyn datalink::DataLinkSender> = Box::new(MockDataLinkSender);

    let packet_len = 150;
    let packet = create_upload_packet(
        our_mac,
        client_mac,
        client_ip,
        "8.8.8.8".parse().expect("Failed to parse IP"),
        packet_len,
    );
    let num_packets_to_exceed = (quota as usize / packet.len()) + 1;

    for i in 0..num_packets_to_exceed {
        process_ethernet_frame(
            &mut mock_tx, our_mac, &packet,
            &session_manager, &radius_client, &dhcp_server,
            &firewall, &config, &eapol_attribute_cache, &auth_tx, &upload_tx
        ).await;
        if session_manager.get_session(&client_ip).await.is_none() {
            break;
        }
        if i == num_packets_to_exceed -1 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    assert!(session_manager.get_session(&client_ip).await.is_none(), "Session should be terminated after upload quota is exceeded");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_download_quota_exceeded() {
    let quota = 1000;
    let (_config, session_manager, client_ip, _) = setup_test_session("output", quota).await;

    let (_, _, radius_client, _, firewall, _, _, _, config_tx) =
        initialize_services(None, Some(0)).await.expect("initialize_services failed");

    let (tun_tx, tun_rx) = mpsc::channel(100);
    let (upload_rx_tx, upload_rx_rx) = mpsc::channel(100);
    let (download_tx, _) = mpsc::channel(100);

    let mock_tun = Arc::new(MockTun {
        rx: Arc::new(Mutex::new(tun_rx)),
        tx: upload_rx_tx,
    });

    let tun_loop_handle = tokio::spawn(tun_packet_loop(
        mock_tun,
        session_manager.clone(),
        config_tx.subscribe(),
        radius_client,
        firewall,
        upload_rx_rx,
        download_tx,
    ));

    let packet_len = 150;
    let packet =
        create_download_packet("8.8.8.8".parse().expect("Failed to parse IP"), client_ip, packet_len);
    let num_packets_to_exceed = (quota as usize / packet.len()) + 1;

    for _ in 0..num_packets_to_exceed {
        tun_tx
            .send(packet.clone())
            .await
            .expect("Failed to send packet to mock tun");
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(session_manager.get_session(&client_ip).await.is_none(), "Session should be terminated after download quota is exceeded");

    tun_loop_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_total_quota_exceeded() {
    let quota = 1000;
    let (config, session_manager, client_ip, client_mac) = setup_test_session("total", quota).await;

    let (_, _, radius_client, dhcp_server, firewall, eapol_attribute_cache, auth_tx, _, config_tx) =
        initialize_services(None, Some(0)).await.expect("initialize_services failed");

    let (upload_tx, upload_rx) = mpsc::channel(100);
    let (download_tx, _) = mpsc::channel(100);

    let our_mac = MacAddr::new(0x00, 0x01, 0x02, 0x03, 0x04, 0x05);
    let mut mock_tx: Box<dyn datalink::DataLinkSender> = Box::new(MockDataLinkSender);

    let (tun_tx, tun_rx) = mpsc::channel(100);
    let mock_tun = Arc::new(MockTun {
        rx: Arc::new(Mutex::new(tun_rx)),
        tx: upload_tx.clone(),
    });

    let tun_loop_handle = tokio::spawn(tun_packet_loop(
        mock_tun,
        session_manager.clone(),
        config_tx.subscribe(),
        radius_client.clone(),
        firewall.clone(),
        upload_rx,
        download_tx.clone(),
    ));

    let packet_len = 80;
    let upload_packet = create_upload_packet(
        our_mac,
        client_mac,
        client_ip,
        "8.8.8.8".parse().expect("Failed to parse IP"),
        packet_len,
    );
    let download_packet =
        create_download_packet("8.8.8.8".parse().expect("Failed to parse IP"), client_ip, packet_len);

    let num_packets = (quota as usize / (packet_len * 2)) + 1;

    for i in 0..num_packets {
        process_ethernet_frame(
            &mut mock_tx, our_mac, &upload_packet,
            &session_manager, &radius_client, &dhcp_server,
            &firewall, &config, &eapol_attribute_cache, &auth_tx, &upload_tx
        ).await;
        tun_tx
            .send(download_packet.clone())
            .await
            .expect("Failed to send download packet to mock tun");

        if i == num_packets -1 {
             tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if session_manager.get_session(&client_ip).await.is_none() {
            break;
        }
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(session_manager.get_session(&client_ip).await.is_none(), "Session should be terminated after total quota is exceeded");

    tun_loop_handle.abort();
}
