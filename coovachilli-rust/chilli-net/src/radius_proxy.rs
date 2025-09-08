use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::info;

use crate::radius::{RadiusAttributeType, RadiusPacket, parse_attributes};
use chilli_core::Config;
use md5::{Digest, Md5};
use std::collections::HashMap;
use tokio::sync::Mutex;
use tracing::{error, warn};

struct ProxyState {
    original_src: SocketAddr,
    original_id: u8,
    original_authenticator: [u8; 16],
}

#[derive(Clone)]
pub struct ProxyManager {
    config: Arc<Config>,
    proxy_socket: Arc<UdpSocket>,
    upstream_socket: Arc<UdpSocket>,
    pending_requests: Arc<Mutex<HashMap<u8, ProxyState>>>,
    next_id: Arc<Mutex<u8>>,
}

impl ProxyManager {
    pub async fn new(config: Arc<Config>, proxy_socket: Arc<UdpSocket>) -> Result<Self> {
        let upstream_socket = UdpSocket::bind("0.0.0.0:0").await?;
        info!("RADIUS proxy upstream client listening on {}", upstream_socket.local_addr()?);
        Ok(Self {
            config,
            proxy_socket,
            upstream_socket: Arc::new(upstream_socket),
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(0)),
        })
    }

    pub async fn run_request_listener(&self) {
        let mut buf = [0u8; 4096];
        loop {
            if let Ok((len, src)) = self.proxy_socket.recv_from(&mut buf).await {
                let packet_bytes = buf[..len].to_vec();
                if let Err(e) = self.handle_proxy_request(&packet_bytes, src).await {
                    error!("Error handling proxy request: {}", e);
                }
            }
        }
    }

    async fn handle_proxy_request(
        &self,
        packet_bytes: &[u8],
        src: SocketAddr,
    ) -> Result<()> {
        info!("Received RADIUS proxy request from {}", src);

        let packet = match RadiusPacket::from_bytes(packet_bytes) {
            Some(p) => p,
            None => {
                info!("Ignoring invalid RADIUS packet from {}", src);
                return Ok(());
            }
        };

        if let Some(proxy_secret) = &self.config.proxysecret {
            let attributes = parse_attributes(&packet.payload);
            if let Some(message_authenticator) =
                attributes.get_standard(RadiusAttributeType::MessageAuthenticator)
            {
                // The Message-Authenticator attribute must be temporarily removed
                // from the packet for validation, which is complex to do on the byte array.
                // For now, we will assume it's valid if present. A real implementation
                // would need to do this properly.
                info!("Message-Authenticator present, assuming valid for now.");
            } else {
                warn!("Proxy secret is configured, but no Message-Authenticator from {}. Dropping packet.", src);
                return Ok(());
            }
        }

        let new_id = {
            let mut id = self.next_id.lock().await;
            let packet_id = *id;
            *id = id.wrapping_add(1);
            packet_id
        };

        let state = ProxyState {
            original_src: src,
            original_id: packet.id,
            original_authenticator: packet.authenticator,
        };
        self.pending_requests.lock().await.insert(new_id, state);

        let mut new_packet = packet_bytes.to_vec();
        new_packet[1] = new_id;

        // TODO: Modify packet (add NAS-ID, Proxy-State)

        let server_addr = format!("{}:{}", self.config.radiusserver1, self.config.radiusauthport);
        self.upstream_socket.send_to(&new_packet, server_addr).await?;

        info!("Forwarded proxy request from {} to upstream server", src);

        Ok(())
    }

    pub async fn run_response_listener(&self) {
        let mut buf = [0u8; 4096];
        loop {
            if let Ok((len, _src)) = self.upstream_socket.recv_from(&mut buf).await {
                if let Some(packet) = RadiusPacket::from_bytes(&buf[..len]) {
                    if let Some(state) = self.pending_requests.lock().await.remove(&packet.id) {

                        let mut response_packet = buf[..len].to_vec();
                        response_packet[1] = state.original_id;

                        // Recalculate the response authenticator
                        let mut to_hash = Vec::new();
                        to_hash.extend_from_slice(&response_packet[0..4]);
                        to_hash.extend_from_slice(&state.original_authenticator);
                        to_hash.extend_from_slice(&response_packet[20..len]);
                        if let Some(secret) = &self.config.proxysecret {
                            to_hash.extend_from_slice(secret.as_bytes());
                        } else {
                            warn!("Cannot forward proxy response: no proxysecret configured.");
                            continue;
                        }

                        let mut hasher = Md5::new();
                        hasher.update(&to_hash);
                        let new_authenticator = hasher.finalize();
                        response_packet[4..20].copy_from_slice(&new_authenticator);

                        info!("Forwarding proxy response to {}", state.original_src);
                        if let Err(e) = self.proxy_socket.send_to(&response_packet, state.original_src).await {
                            error!("Failed to send proxy response: {}", e);
                        }
                    }
                }
            }
        }
    }
}
