pub mod config;
pub mod session;

use std::net::Ipv4Addr;

pub use config::Config;
pub use session::{RedirState, Session, SessionManager, SessionParams, SessionState};

use tokio::sync::oneshot;

#[derive(Debug)]
pub struct AuthRequest {
    pub ip: Ipv4Addr,
    pub username: String,
    pub password: String,
    pub tx: oneshot::Sender<bool>,
}
