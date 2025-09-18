use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::info;

use crate::radius::{RadiusAttributeType, RadiusPacket, parse_attributes};
use chilli_core::Config;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use std::collections::HashMap;
use tokio::sync::{watch, Mutex};
use tracing::{error, warn};

struct ProxyState {
    original_src: SocketAddr,
    original_id: u8,
    original_authenticator: [u8; 16],
}

#[derive(Clone)]
pub struct ProxyManager {
    config: Arc<Mutex<Arc<Config>>>,
    config_rx: watch::Receiver<Arc<Config>>,
    auth_proxy_socket: Arc<UdpSocket>,
    acct_proxy_socket: Arc<UdpSocket>,
    upstream_socket: Arc<UdpSocket>,
    pending_requests: Arc<Mutex<HashMap<u8, ProxyState>>>,
    next_id: Arc<Mutex<u8>>,
}

impl ProxyManager {
    pub async fn new(
        config_rx: watch::Receiver<Arc<Config>>,
        auth_proxy_socket: Arc<UdpSocket>,
        acct_proxy_socket: Arc<UdpSocket>,
    ) -> Result<Self> {
        let upstream_socket = UdpSocket::bind("0.0.0.0:0").await?;
        info!(
            "RADIUS proxy upstream client listening on {}",
            upstream_socket.local_addr()?
        );
        let initial_config = config_rx.borrow().clone();
        Ok(Self {
            config: Arc::new(Mutex::new(initial_config)),
            config_rx,
            auth_proxy_socket,
            acct_proxy_socket,
            upstream_socket: Arc::new(upstream_socket),
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(0)),
        })
    }

    pub async fn run_request_listener(&mut self) {
        let mut auth_buf = [0u8; 4096];
        let mut acct_buf = [0u8; 4096];
        loop {
            tokio::select! {
                res = self.auth_proxy_socket.recv_from(&mut auth_buf) => {
                    if let Ok((len, src)) = res {
                        let packet_bytes = auth_buf[..len].to_vec();
                        if let Err(e) = self.handle_proxy_request(&packet_bytes, src, false).await {
                            error!("Error handling auth proxy request: {}", e);
                        }
                    }
                }
                res = self.acct_proxy_socket.recv_from(&mut acct_buf) => {
                    if let Ok((len, src)) = res {
                        let packet_bytes = acct_buf[..len].to_vec();
                        if let Err(e) = self.handle_proxy_request(&packet_bytes, src, true).await {
                            error!("Error handling acct proxy request: {}", e);
                        }
                    }
                }
                res = self.config_rx.changed() => {
                     if res.is_ok() {
                        let new_config = self.config_rx.borrow().clone();
                        let mut config = self.config.lock().await;
                        *config = new_config;
                        info!("RADIUS proxy reloaded configuration.");
                    } else {
                        info!("Config channel closed, ending RADIUS proxy listener loop.");
                        return;
                    }
                }
            }
        }
    }

    async fn handle_proxy_request(
        &self,
        packet_bytes: &[u8],
        src: SocketAddr,
        is_acct: bool,
    ) -> Result<()> {
        info!("Received RADIUS proxy request from {}", src);

        let packet = match RadiusPacket::from_bytes(packet_bytes) {
            Some(p) => p,
            None => {
                info!("Ignoring invalid RADIUS packet from {}", src);
                return Ok(());
            }
        };

        let config = self.config.lock().await;
        if let Some(proxy_secret) = &config.proxysecret {
            if !validate_message_authenticator(packet_bytes, proxy_secret.as_bytes()) {
                warn!("Invalid Message-Authenticator from {}. Dropping packet.", src);
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

        let mut attributes = parse_attributes(&packet.payload);
        attributes
            .standard
            .entry(RadiusAttributeType::ProxyState)
            .or_default()
            .push(new_id.to_be_bytes().to_vec());
        if let Some(nas_id) = &config.proxynasid {
            attributes
                .standard
                .entry(RadiusAttributeType::NasIdentifier)
                .or_default()
                .push(nas_id.as_bytes().to_vec());
        }

        let new_payload = crate::radius::serialize_attributes(&attributes);
        let new_length = crate::radius::RADIUS_HDR_LEN + new_payload.len();
        let mut new_packet = Vec::with_capacity(new_length);

        new_packet.push(packet.code);
        new_packet.push(new_id);
        new_packet.extend_from_slice(&(new_length as u16).to_be_bytes());
        new_packet.extend_from_slice(&packet.authenticator);
        new_packet.extend_from_slice(&new_payload);

        let server_addr = if is_acct {
            format!("{}:{}", config.radiusserver1, config.radiusacctport)
        } else {
            format!("{}:{}", config.radiusserver1, config.radiusauthport)
        };
        self.upstream_socket
            .send_to(&new_packet, server_addr)
            .await?;

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

                        let config = self.config.lock().await;
                        // Recalculate the response authenticator
                        let mut to_hash = Vec::new();
                        to_hash.extend_from_slice(&response_packet[0..4]);
                        to_hash.extend_from_slice(&state.original_authenticator);
                        to_hash.extend_from_slice(&response_packet[20..len]);
                        if let Some(secret) = &config.proxysecret {
                            to_hash.extend_from_slice(secret.as_bytes());
                        } else {
                            warn!("Cannot forward proxy response: no proxysecret configured.");
                            continue;
                        }

                        // TODO: Recalculate Message-Authenticator if present in response
                        let mut hasher = Md5::new();
                        hasher.update(&to_hash);
                        let new_authenticator = hasher.finalize();
                        response_packet[4..20].copy_from_slice(&new_authenticator);

                        info!("Forwarding proxy response to {}", state.original_src);
                        if let Err(e) = self.auth_proxy_socket.send_to(&response_packet, state.original_src).await {
                            error!("Failed to send proxy response: {}", e);
                        }
                    }
                }
            }
        }
    }
}

fn validate_message_authenticator(packet_bytes: &[u8], secret: &[u8]) -> bool {
    let packet = match RadiusPacket::from_bytes(packet_bytes) {
        Some(p) => p,
        None => return false,
    };

    let payload_len = u16::from_be(packet.length) as usize - crate::radius::RADIUS_HDR_LEN;
    let payload = &packet.payload[..payload_len];
    let mut authenticator_pos = None;
    let mut offset = 0;

    while offset < payload.len() {
        let type_code = payload[offset];
        if type_code == 0 {
            offset += 1;
            continue;
        }
        if payload.len() < offset + 2 {
            break;
        }
        let length = payload[offset + 1] as usize;

        if type_code == RadiusAttributeType::MessageAuthenticator as u8 {
            authenticator_pos = Some(offset);
            break;
        }

        if length == 0 {
            // Avoid infinite loop on malformed attribute
            return false;
        }
        offset += length;
    }

    let authenticator_pos = match authenticator_pos {
        Some(pos) => pos,
        None => {
            warn!("Message-Authenticator validation failed: attribute not found");
            return false;
        }
    };

    let mut packet_for_hmac = packet_bytes.to_vec();
    let authenticator_in_packet = &packet_bytes
        [crate::radius::RADIUS_HDR_LEN + authenticator_pos + 2..crate::radius::RADIUS_HDR_LEN + authenticator_pos + 2 + 16].to_vec();

    // Zero out the Message-Authenticator value for the HMAC calculation
    for byte in &mut packet_for_hmac
        [crate::radius::RADIUS_HDR_LEN + authenticator_pos + 2..crate::radius::RADIUS_HDR_LEN + authenticator_pos + 2 + 16]
    {
        *byte = 0;
    }

    type HmacMd5 = Hmac<Md5>;
    let mut mac = HmacMd5::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(&packet_for_hmac);
    let result = mac.finalize();
    let code_bytes = result.into_bytes();

    code_bytes.as_slice() == authenticator_in_packet.as_slice()
}
