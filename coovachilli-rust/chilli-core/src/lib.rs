pub mod config;
pub mod session;
pub mod eapol_session;

use std::net::Ipv4Addr;

pub use config::{Config, LogLevel};
pub use session::{RedirState, Session, SessionManager, SessionParams, SessionState};

use tokio::sync::oneshot;

#[derive(Debug)]
pub enum AuthType {
    Pap,
    Eap,
    UamPap,
}

#[derive(Debug)]
pub struct AuthRequest {
    pub auth_type: AuthType,
    pub ip: Ipv4Addr,
    pub username: String,
    pub password: Option<Vec<u8>>,
    pub tx: oneshot::Sender<bool>,
}

#[derive(Debug)]
pub struct LogoffRequest {
    pub ip: Ipv4Addr,
    pub tx: oneshot::Sender<bool>,
}

#[derive(Debug)]
pub enum CoreRequest {
    Auth(AuthRequest),
    Logoff(LogoffRequest),
}
