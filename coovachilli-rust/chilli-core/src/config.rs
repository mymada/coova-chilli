use serde::Deserialize;
use std::net::Ipv4Addr;

/// The log level for the application, corresponding to syslog levels.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Emerg,
    Alert,
    Crit,
    Err,
    Warning,
    Notice,
    Info,
    Debug,
}

// Helper functions for default values
fn default_foreground() -> bool { true }
fn default_debug() -> bool { true }
fn default_logfacility() -> i32 { 3 }
fn default_loglevel() -> LogLevel { LogLevel::Info }
fn default_interval() -> i32 { 3600 }
fn default_pidfile() -> String { "/var/run/chilli.pid".to_string() }
fn default_statedir() -> String { "/var/run".to_string() }
fn default_net() -> Ipv4Addr { "192.168.182.0".parse().unwrap() }
fn default_mask() -> Ipv4Addr { "255.255.255.0".parse().unwrap() }
fn default_dns1() -> Ipv4Addr { "8.8.8.8".parse().unwrap() }
fn default_dns2() -> Ipv4Addr { "8.8.4.4".parse().unwrap() }
fn default_radiuslisten() -> Ipv4Addr { "0.0.0.0".parse().unwrap() }
fn default_radiusserver1() -> Ipv4Addr { "127.0.0.1".parse().unwrap() }
fn default_radiussecret() -> String { "testing123".to_string() }
fn default_radiusauthport() -> u16 { 1812 }
fn default_radiusacctport() -> u16 { 1813 }
fn default_coaport() -> u16 { 3799 }
fn default_radiustimeout() -> u32 { 10 }
fn default_radiusretry() -> u32 { 3 }
fn default_dhcpif() -> String { "eth0".to_string() }
fn default_dhcplisten() -> Ipv4Addr { "192.168.182.1".parse().unwrap() }
fn default_dhcpstart() -> Ipv4Addr { "192.168.182.10".parse().unwrap() }
fn default_dhcpend() -> Ipv4Addr { "192.168.182.254".parse().unwrap() }
fn default_lease() -> i32 { 3600 }
fn default_uamlisten() -> Ipv4Addr { "192.168.182.1".parse().unwrap() }
fn default_uamport() -> u16 { 3990 }
fn default_max_clients() -> i32 { 1024 }
fn default_proxyport() -> u16 { 1814 }

/// The main configuration for the CoovaChilli application.
#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct Config {
    #[serde(default = "default_foreground")]
    pub foreground: bool,
    #[serde(default = "default_debug")]
    pub debug: bool,
    #[serde(default = "default_logfacility")]
    pub logfacility: i32,
    #[serde(default = "default_loglevel")]
    pub loglevel: LogLevel,
    #[serde(default = "default_interval")]
    pub interval: i32,
    #[serde(default = "default_pidfile")]
    pub pidfile: String,
    #[serde(default = "default_statedir")]
    pub statedir: String,

    #[serde(default)]
    pub radconf: Option<String>,
    #[serde(default)]
    pub radconf_url: Option<String>,
    #[serde(default)]
    pub radconf_user: Option<String>,
    #[serde(default)]
    pub radconf_pwd: Option<String>,

    #[serde(default = "default_net")]
    pub net: Ipv4Addr,
    #[serde(default = "default_mask")]
    pub mask: Ipv4Addr,
    pub tundev: Option<String>,
    pub dynip: Option<String>,
    pub statip: Option<String>,

    #[serde(default = "default_dns1")]
    pub dns1: Ipv4Addr,
    #[serde(default = "default_dns2")]
    pub dns2: Ipv4Addr,
    pub domain: Option<String>,

    #[serde(default = "default_radiuslisten")]
    pub radiuslisten: Ipv4Addr,
    #[serde(default = "default_radiusserver1")]
    pub radiusserver1: Ipv4Addr,
    pub radiusserver2: Option<Ipv4Addr>,
    #[serde(default = "default_radiussecret")]
    pub radiussecret: String,
    #[serde(default = "default_radiusauthport")]
    pub radiusauthport: u16,
    #[serde(default = "default_radiusacctport")]
    pub radiusacctport: u16,
    #[serde(default = "default_coaport")]
    pub coaport: u16,
    #[serde(default)]
    pub coanoipcheck: bool,
    #[serde(default = "default_radiustimeout")]
    pub radiustimeout: u32,
    #[serde(default = "default_radiusretry")]
    pub radiusretry: u32,

    #[serde(default = "default_dhcpif")]
    pub dhcpif: String,
    #[serde(default = "default_dhcplisten")]
    pub dhcplisten: Ipv4Addr,
    #[serde(default = "default_dhcpstart")]
    pub dhcpstart: Ipv4Addr,
    #[serde(default = "default_dhcpend")]
    pub dhcpend: Ipv4Addr,
    #[serde(default = "default_lease")]
    pub lease: i32,

    pub uamsecret: Option<String>,
    pub uamurl: Option<String>,
    #[serde(default = "default_uamlisten")]
    pub uamlisten: Ipv4Addr,
    #[serde(default = "default_uamport")]
    pub uamport: u16,
    #[serde(default)]
    pub uamanyip: bool,

    #[serde(default = "default_max_clients")]
    pub max_clients: i32,

    #[serde(default)]
    pub walled_garden: Vec<String>,

    #[serde(default)]
    pub macauth: bool,
    #[serde(default)]
    pub macauthdeny: bool,
    #[serde(default)]
    pub macallowed: Vec<String>,
    pub macpasswd: Option<String>,
    pub cmdsocket: Option<String>,
    pub statusfile: Option<String>,

    pub conup: Option<String>,
    pub condown: Option<String>,

    #[serde(default)]
    pub proxylisten: Option<Ipv4Addr>,
    #[serde(default = "default_proxyport")]
    pub proxyport: u16,
    #[serde(default)]
    pub proxysecret: Option<String>,
    #[serde(default)]
    pub proxynasid: Option<String>,

    #[serde(default)]
    pub radiusnasid: Option<String>,
    #[serde(default)]
    pub radiuslocationid: Option<String>,
    #[serde(default)]
    pub radiuslocationname: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            foreground: default_foreground(),
            debug: default_debug(),
            logfacility: default_logfacility(),
            loglevel: default_loglevel(),
            interval: default_interval(),
            pidfile: default_pidfile(),
            statedir: default_statedir(),
            radconf: Some("off".to_string()), // This has a custom default not easily representable by a function
            radconf_url: None,
            radconf_user: None,
            radconf_pwd: None,
            net: default_net(),
            mask: default_mask(),
            tundev: Some("tun0".to_string()), // Custom default
            dynip: None,
            statip: None,
            dns1: default_dns1(),
            dns2: default_dns2(),
            domain: Some("coova.org".to_string()), // Custom default
            radiuslisten: default_radiuslisten(),
            radiusserver1: default_radiusserver1(),
            radiusserver2: Some("127.0.0.1".parse().unwrap()), // Custom default
            radiussecret: default_radiussecret(),
            radiusauthport: default_radiusauthport(),
            radiusacctport: default_radiusacctport(),
            coaport: default_coaport(),
            coanoipcheck: false,
            radiustimeout: default_radiustimeout(),
            radiusretry: default_radiusretry(),
            dhcpif: default_dhcpif(),
            dhcplisten: default_dhcplisten(),
            dhcpstart: default_dhcpstart(),
            dhcpend: default_dhcpend(),
            lease: default_lease(),
            uamsecret: Some("uamsecret".to_string()), // Custom default
            uamurl: Some("http://127.0.0.1:3990/login".to_string()), // Custom default
            uamlisten: default_uamlisten(),
            uamport: default_uamport(),
            uamanyip: false,
            max_clients: default_max_clients(),
            walled_garden: Vec::new(),
            macauth: false,
            macauthdeny: false,
            macallowed: Vec::new(),
            macpasswd: None,
            cmdsocket: Some("/var/run/chilli.sock".to_string()), // Custom default
            statusfile: Some("/var/run/chilli.status".to_string()), // Custom default
            conup: None,
            condown: None,
            proxylisten: None,
            proxyport: default_proxyport(),
            proxysecret: None,
            proxynasid: None,
            radiusnasid: None,
            radiuslocationid: None,
            radiuslocationname: None,
        }
    }
}
