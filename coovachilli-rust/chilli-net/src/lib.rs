pub mod eap;
pub mod eap_mschapv2;
pub mod mschapv1;
pub mod mschapv2;
pub mod radius_proxy;
pub mod tun;
pub mod eapol;
pub mod dhcp;
pub mod radius;
pub mod firewall;

use async_trait::async_trait;
use std::sync::Arc;
use tun_rs::AsyncDevice as TunAsyncDevice;

pub use firewall::Firewall;

#[async_trait]
pub trait PacketDevice: Send + Sync {
    async fn recv(&self, buf: &mut [u8]) -> anyhow::Result<usize>;
    async fn send(&self, buf: &[u8]) -> anyhow::Result<usize>;
}

pub struct TunWrapper(pub Arc<TunAsyncDevice>);

#[async_trait]
impl PacketDevice for TunWrapper {
    async fn recv(&self, buf: &mut [u8]) -> anyhow::Result<usize> {
        Ok(self.0.recv(buf).await?)
    }

    async fn send(&self, buf: &[u8]) -> anyhow::Result<usize> {
        Ok(self.0.send(buf).await?)
    }
}
