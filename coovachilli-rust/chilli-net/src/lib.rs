pub mod eap;
pub mod eap_mschapv2;
// pub mod mschapv1; // Disabled: MS-CHAPv1 is a legacy protocol with known cryptographic weaknesses.
                   // The underlying DES implementation was also incompatible with standard test vectors.
pub mod mschapv2;
pub mod radius_proxy;
pub mod tun;
pub mod eapol;
pub mod dhcp;
pub mod radius;
pub mod firewall;

pub use firewall::Firewall;
use async_trait::async_trait;
use anyhow::Result;
use std::sync::Arc;

#[async_trait]
pub trait PacketDevice: Send + Sync {
    async fn send(&self, buf: &[u8]) -> Result<usize>;
    async fn recv(&self, buf: &mut [u8]) -> Result<usize>;
}

pub struct TunWrapper(pub Arc<tun_rs::AsyncDevice>);

#[async_trait]
impl PacketDevice for TunWrapper {
    async fn send(&self, buf: &[u8]) -> Result<usize> {
        self.0.send(buf).await.map_err(anyhow::Error::from)
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        self.0.recv(buf).await.map_err(anyhow::Error::from)
    }
}
