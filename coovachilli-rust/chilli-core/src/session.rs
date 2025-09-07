use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionParams {
    pub url: Option<String>,
    pub filterid: Option<String>,
    pub routeidx: u8,
    pub bandwidthmaxup: u64,
    pub bandwidthmaxdown: u64,
    pub maxinputoctets: u64,
    pub maxoutputoctets: u64,
    pub maxtotaloctets: u64,
    pub sessiontimeout: u64,
    pub idletimeout: u32,
    pub interim_interval: u16,
    pub sessionterminatetime: u64,
    pub flags: u16,
}

impl Default for SessionParams {
    fn default() -> Self {
        Self {
            url: None,
            filterid: None,
            routeidx: 0,
            bandwidthmaxup: 0,
            bandwidthmaxdown: 0,
            maxinputoctets: 0,
            maxoutputoctets: 0,
            maxtotaloctets: 0,
            sessiontimeout: 0,
            idletimeout: 0,
            interim_interval: 0,
            sessionterminatetime: 0,
            flags: 0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RedirState {
    pub username: Option<String>,
    pub userurl: Option<String>,
    pub uamchal: [u8; 16],
    pub class: Option<Vec<u8>>,
    pub cui: Option<Vec<u8>>,
    pub state: Option<Vec<u8>>,
    pub eap_identity: u8,
    pub uamprotocol: u8,
}

impl Default for RedirState {
    fn default() -> Self {
        Self {
            username: None,
            userurl: None,
            uamchal: [0; 16],
            class: None,
            cui: None,
            state: None,
            eap_identity: 0,
            uamprotocol: 0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionState {
    pub redir: RedirState,
    pub authenticated: bool,
    pub sessionid: String,
    pub start_time: u64,
    pub interim_time: u64,
    pub last_bw_time: u64,
    pub last_up_time: u64,
    pub last_time: u64,
    pub uamtime: u64,
    pub input_packets: u64,
    pub output_packets: u64,
    pub input_octets: u64,
    pub output_octets: u64,
    pub terminate_cause: u32,
    pub session_id: u32,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            redir: RedirState::default(),
            authenticated: false,
            sessionid: "".to_string(),
            start_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            interim_time: 0,
            last_bw_time: 0,
            last_up_time: 0,
            last_time: 0,
            uamtime: 0,
            input_packets: 0,
            output_packets: 0,
            input_octets: 0,
            output_octets: 0,
            terminate_cause: 0,
            session_id: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Connection {
    pub next: Option<Box<Connection>>,
    pub prev: Option<Box<Connection>>,
    pub uplink: (), // Placeholder
    pub dnlink: (), // Placeholder
    pub inuse: bool,
    pub is_adminsession: bool,
    pub uamabort: bool,
    pub uamexit: bool,
    pub unit: i32,
    pub dnprot: i32,
    pub rt: i64,
    pub params: SessionParams,
    pub state: SessionState,
    pub hismac: [u8; 6],
    pub ourip: Ipv4Addr,
    pub hisip: Ipv4Addr,
    pub hismask: Ipv4Addr,
    pub reqip: Ipv4Addr,
    pub net: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub dns1: Ipv4Addr,
    pub dns2: Ipv4Addr,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Session {
    pub inuse: bool,
    pub is_adminsession: bool,
    pub uamabort: bool,
    pub uamexit: bool,
    pub unit: i32,
    pub dnprot: i32,
    pub rt: i64,
    pub params: SessionParams,
    pub state: SessionState,
    pub hismac: [u8; 6],
    pub ourip: Ipv4Addr,
    pub hisip: Ipv4Addr,
    pub hismask: Ipv4Addr,
    pub reqip: Ipv4Addr,
    pub net: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub dns1: Ipv4Addr,
    pub dns2: Ipv4Addr,
}

impl From<&Connection> for Session {
    fn from(conn: &Connection) -> Self {
        Self {
            inuse: conn.inuse,
            is_adminsession: conn.is_adminsession,
            uamabort: conn.uamabort,
            uamexit: conn.uamexit,
            unit: conn.unit,
            dnprot: conn.dnprot,
            rt: conn.rt,
            params: conn.params.clone(),
            state: conn.state.clone(),
            hismac: conn.hismac,
            ourip: conn.ourip,
            hisip: conn.hisip,
            hismask: conn.hismask,
            reqip: conn.reqip,
            net: conn.net,
            mask: conn.mask,
            dns1: conn.dns1,
            dns2: conn.dns2,
        }
    }
}

pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<Ipv4Addr, Connection>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        SessionManager {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn create_session(&self, ip: Ipv4Addr, mac: [u8; 6], config: &super::Config) {
        let mut sessions = self.sessions.lock().await;
        let connection = Connection {
            next: None,
            prev: None,
            uplink: (),
            dnlink: (),
            inuse: true,
            is_adminsession: false,
            uamabort: false,
            uamexit: false,
            unit: 0,
            dnprot: 0,
            rt: 0,
            params: SessionParams::default(),
            state: SessionState::default(),
            hismac: mac,
            ourip: config.uamlisten,
            hisip: ip,
            hismask: Ipv4Addr::new(0, 0, 0, 0),
            reqip: Ipv4Addr::new(0, 0, 0, 0),
            net: config.net,
            mask: config.mask,
            dns1: config.dns1,
            dns2: config.dns2,
        };
        sessions.insert(ip, connection);
    }

    pub async fn get_session(&self, ip: &Ipv4Addr) -> Option<Session> {
        let sessions = self.sessions.lock().await;
        sessions.get(ip).map(Session::from)
    }

    pub async fn get_all_sessions(&self) -> Vec<Session> {
        let sessions = self.sessions.lock().await;
        sessions.values().map(Session::from).collect()
    }

    pub async fn update_session<F>(&self, ip: &Ipv4Addr, update_fn: F)
    where
        F: FnOnce(&mut Connection),
    {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(ip) {
            update_fn(session);
        }
    }

    pub async fn authenticate_session(&self, ip: &Ipv4Addr) -> bool {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(ip) {
            session.state.authenticated = true;
            true
        } else {
            false
        }
    }

    pub async fn remove_session(&self, ip: &Ipv4Addr) -> Option<Session> {
        let mut sessions = self.sessions.lock().await;
        sessions.remove(ip).map(|conn| Session::from(&conn))
    }

    pub async fn update_counters(
        &self,
        ip: &Ipv4Addr,
        input_octets_delta: u64,
        output_octets_delta: u64,
    ) {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(ip) {
            if input_octets_delta > 0 {
                session.state.input_octets += input_octets_delta;
                session.state.input_packets += 1;
            }
            if output_octets_delta > 0 {
                session.state.output_octets += output_octets_delta;
                session.state.output_packets += 1;
            }
        }
    }
}
