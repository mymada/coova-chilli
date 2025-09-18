pub mod config;
pub mod session;

use std::net::Ipv4Addr;

pub use config::{Config, LogLevel};
pub use session::{RedirState, Session, SessionManager, SessionParams, SessionState};

use tokio::sync::oneshot;

#[derive(Debug)]
pub enum AuthType {
    Pap,
    Eap,
    MsChapV1,
}

#[derive(Debug)]
pub struct AuthRequest {
    pub auth_type: AuthType,
    pub ip: Ipv4Addr,
    pub username: String,
    pub password: Option<String>,
    pub tx: oneshot::Sender<bool>,
}
