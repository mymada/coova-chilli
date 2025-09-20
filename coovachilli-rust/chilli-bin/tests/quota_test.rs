use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, MutableIpv4Packet};
use pnet::packet::Packet;
use tokio::sync::{mpsc, Mutex};

use chilli_bin::{initialize_services, tun_packet_loop};
use chilli_net::PacketDevice;

// Helper to create a dummy IPv4 packet
fn create_ipv4_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let mut ip_packet = MutableIpv4Packet::new(&mut buf).unwrap();
    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(len as u16);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ip_packet.set_source(src_ip);
    ip_packet.set_destination(dst_ip);
    let checksum = ipv4::checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(checksum);
    ip_packet.packet().to_vec()
}

struct MockTunDevice {
    pub sent_packets_tx: mpsc::Sender<Vec<u8>>,
    pub packets_to_recv_rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
}

#[async_trait]
impl PacketDevice for MockTunDevice {
    async fn recv(&self, buf: &mut [u8]) -> anyhow::Result<usize> {
        let mut rx = self.packets_to_recv_rx.lock().await;
        match rx.recv().await {
            Some(packet) => {
                let len = packet.len();
                if buf.len() < len {
                    return Err(anyhow::anyhow!("Buffer too small"));
                }
                buf[..len].copy_from_slice(&packet);
                Ok(len)
            }
            None => {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(0)
            }
        }
    }

    async fn send(&self, buf: &[u8]) -> anyhow::Result<usize> {
        self.sent_packets_tx.send(buf.to_vec()).await.unwrap();
        Ok(buf.len())
    }
}

#[tokio::test]
async fn test_quota_exceeded() {
    let (config, session_manager, radius_client, _dhcp_server, firewall, _eapol_attribute_cache, _auth_tx, _auth_rx, config_tx) =
        initialize_services(None).await;

    let client_ip = "10.1.0.10".parse().unwrap();
    let client_mac = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
    let quota = 1000;

    session_manager
        .create_session(client_ip, client_mac, &config, None)
        .await;
    session_manager.authenticate_session(&client_ip).await;

    session_manager
        .update_session(&client_ip, |session| {
            session.params.maxoutputoctets = quota;
        })
        .await
        .unwrap();

    let (sent_tx, _sent_rx) = mpsc::channel(100);
    let (to_recv_tx, to_recv_rx) = mpsc::channel(100);
    let (_upload_tx, upload_rx) = mpsc::channel(100);
    let (download_tx, _download_rx) = mpsc::channel(100);

    let mock_iface = Arc::new(MockTunDevice {
        sent_packets_tx: sent_tx,
        packets_to_recv_rx: Arc::new(Mutex::new(to_recv_rx)),
    });

    let tun_loop_handle = tokio::spawn(tun_packet_loop(
        mock_iface,
        session_manager.clone(),
        config_tx.subscribe(),
        radius_client.clone(),
        firewall.clone(),
        upload_rx,
        download_tx,
    ));

    let packet = create_ipv4_packet("8.8.8.8".parse().unwrap(), client_ip, 150);
    let num_packets_to_exceed = (quota / packet.len() as u64) + 1;

    for _ in 0..num_packets_to_exceed {
        to_recv_tx.send(packet.clone()).await.unwrap();
    }

    let result = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if session_manager.get_session(&client_ip).await.is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    assert!(
        result.is_ok(),
        "Timed out waiting for session to be terminated"
    );

    assert!(
        session_manager.get_session(&client_ip).await.is_none(),
        "Session should be terminated and removed after exceeding quota"
    );

    tun_loop_handle.abort();
}
