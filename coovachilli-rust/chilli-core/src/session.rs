use std::net::Ipv4Addr;

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
