use crate::eapol_session::EapolSession;
use rand::Rng;
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
    pub class: Option<Vec<u8>>,
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
            class: None,
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
    pub chilli_sessionid: String,
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
    pub bucketup: u64,
    pub bucketdown: u64,
    pub bucketupsize: u64,
    pub bucketdownsize: u64,
    pub vlan_id: Option<u16>,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            redir: RedirState::default(),
            authenticated: false,
            sessionid: "".to_string(),
            chilli_sessionid: "".to_string(),
            start_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("System time is before the UNIX epoch, which is not supported.")
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
            bucketup: 0,
            bucketdown: 0,
            bucketupsize: 0,
            bucketdownsize: 0,
            vlan_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
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

pub type Session = Connection;

pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<Ipv4Addr, Connection>>>,
    eapol_sessions: Arc<Mutex<HashMap<[u8; 6], EapolSession>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        SessionManager {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            eapol_sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn create_eapol_session(&self, mac: [u8; 6]) {
        let mut eapol_sessions = self.eapol_sessions.lock().await;
        if !eapol_sessions.contains_key(&mac) {
            let session = EapolSession::new(mac);
            eapol_sessions.insert(mac, session);
        }
    }

    pub async fn get_eapol_session(&self, mac: &[u8; 6]) -> Option<EapolSession> {
        let eapol_sessions = self.eapol_sessions.lock().await;
        eapol_sessions.get(mac).cloned()
    }

    pub async fn update_eapol_session<F>(&self, mac: &[u8; 6], update_fn: F)
    where
        F: FnOnce(&mut EapolSession),
    {
        let mut eapol_sessions = self.eapol_sessions.lock().await;
        if let Some(session) = eapol_sessions.get_mut(mac) {
            update_fn(session);
        }
    }

    pub async fn remove_eapol_session(&self, mac: &[u8; 6]) -> Option<EapolSession> {
        let mut eapol_sessions = self.eapol_sessions.lock().await;
        eapol_sessions.remove(mac)
    }

    pub fn load_sessions(&self, sessions_to_load: Vec<Session>) {
        let mut sessions = self.sessions.blocking_lock();
        for session in sessions_to_load {
            sessions.insert(session.hisip, session);
        }
    }

    pub fn get_all_sessions_sync(&self) -> Vec<Session> {
        self.sessions.blocking_lock().values().cloned().collect()
    }

    pub async fn create_session(
        &self,
        ip: Ipv4Addr,
        mac: [u8; 6],
        config: &super::Config,
        vlan_id: Option<u16>,
    ) {
        let mut sessions = self.sessions.lock().await;

        let rt = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let unit: u32 = rand::thread_rng().gen();

        let sessionid = format!("{:08x}{:08x}", rt, unit);

        // This is a placeholder. In the C code, this is the MAC of the NAS interface.
        let called_mac = [0u8; 6];

        let chilli_sessionid = format!(
            "SES-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}-{:08x}{:08x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            called_mac[0], called_mac[1], called_mac[2], called_mac[3], called_mac[4], called_mac[5],
            rt, unit
        );

        let mut state = SessionState::default();
        state.sessionid = sessionid;
        state.chilli_sessionid = chilli_sessionid;
        state.vlan_id = vlan_id;

        let connection = Connection {
            inuse: true,
            is_adminsession: false,
            uamabort: false,
            uamexit: false,
            unit: unit as i32,
            dnprot: 0,
            rt: rt as i64,
            params: SessionParams::default(),
            state,
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
        sessions.get(ip).cloned()
    }

    pub async fn get_session_by_mac(&self, mac: &[u8; 6]) -> Option<Session> {
        let sessions = self.sessions.lock().await;
        sessions.values().find(|s| &s.hismac == mac).cloned()
    }

    pub async fn get_all_sessions(&self) -> Vec<Session> {
        let sessions = self.sessions.lock().await;
        sessions.values().cloned().collect()
    }

    pub async fn update_session<F>(&self, ip: &Ipv4Addr, update_fn: F) -> Option<Session>
    where
        F: FnOnce(&mut Connection),
    {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(ip) {
            update_fn(session);
            Some(session.clone())
        } else {
            None
        }
    }

    pub async fn authenticate_session(&self, ip: &Ipv4Addr) -> bool {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(ip) {
            session.state.authenticated = true;
            session.state.last_up_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("System time is before the UNIX epoch, which is not supported.")
                .as_secs();
            true
        } else {
            false
        }
    }

    pub async fn remove_session(&self, ip: &Ipv4Addr) -> Option<Session> {
        let mut sessions = self.sessions.lock().await;
        sessions.remove(ip)
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

    pub async fn update_last_up_time(&self, ip: &Ipv4Addr) {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(ip) {
            session.state.last_up_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("System time is before the UNIX epoch, which is not supported.")
                .as_secs();
        }
    }
}
