use serde::Deserialize;
use std::net::Ipv4Addr;

/// The main configuration for the CoovaChilli application.
///
/// This struct holds all the configuration options for the application,
/// which are loaded from a TOML file and command-line arguments.
#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    /// Run the application in the foreground.
    pub foreground: bool,
    /// Enable debug logging.
    pub debug: bool,
    /// The syslog facility to use for logging.
    pub logfacility: i32,
    /// The log level to use.
    pub loglevel: i32,
    /// The interval at which to re-read the configuration file.
    pub interval: i32,
    /// The path to the PID file.
    pub pidfile: String,
    /// The path to the state directory.
    pub statedir: String,

    /// The network address of the TUN/TAP interface.
    pub net: Ipv4Addr,
    /// The netmask of the TUN/TAP interface.
    pub mask: Ipv4Addr,
    /// The name of the TUN/TAP device.
    pub tundev: Option<String>,
    /// The dynamic IP address pool.
    pub dynip: Option<String>,
    /// The static IP address pool.
    pub statip: Option<String>,

    /// The primary DNS server IP address.
    pub dns1: Ipv4Addr,
    /// The secondary DNS server IP address.
    pub dns2: Ipv4Addr,
    /// The domain to use for DNS lookups.
    pub domain: Option<String>,

    /// The IP address to listen on for RADIUS requests.
    pub radiuslisten: Ipv4Addr,
    /// The IP address of the primary RADIUS server.
    pub radiusserver1: Ipv4Addr,
    /// The IP address of the secondary RADIUS server.
    pub radiusserver2: Option<Ipv4Addr>,
    /// The shared secret for the RADIUS server.
    pub radiussecret: String,
    /// The UDP port for RADIUS authentication.
    pub radiusauthport: u16,
    /// The UDP port for RADIUS accounting.
    pub radiusacctport: u16,
    /// The UDP port for RADIUS CoA/Disconnect.
    pub coaport: u16,
    /// Do not check the source IP of CoA/Disconnect requests.
    #[serde(default)]
    pub coanoipcheck: bool,

    /// The network interface to use for DHCP.
    pub dhcpif: String,
    /// The IP address to listen on for DHCP requests.
    pub dhcplisten: Ipv4Addr,
    /// The starting IP address of the DHCP pool.
    pub dhcpstart: Ipv4Addr,
    /// The ending IP address of the DHCP pool.
    pub dhcpend: Ipv4Addr,
    /// The DHCP lease time in seconds.
    pub lease: i32,

    /// The shared secret for the UAM server.
    pub uamsecret: Option<String>,
    /// The URL of the UAM server.
    pub uamurl: Option<String>,
    /// The IP address to listen on for UAM requests.
    pub uamlisten: Ipv4Addr,
    /// The TCP port to listen on for UAM requests.
    pub uamport: u16,

    /// The maximum number of clients to allow.
    pub max_clients: i32,

    /// A list of domains to allow access to before authentication.
    #[serde(default)]
    pub walled_garden: Vec<String>,

    /// Enable MAC authentication.
    #[serde(default)]
    pub macauth: bool,
    /// Deny access if MAC authentication fails.
    #[serde(default)]
    pub macauthdeny: bool,
    /// A list of allowed MAC addresses.
    #[serde(default)]
    pub macallowed: Vec<String>,
    /// The password to use for MAC authentication.
    pub macpasswd: Option<String>,
    /// The path to the command socket.
    pub cmdsocket: Option<String>,
    /// The path to the status file.
    pub statusfile: Option<String>,

    /// The path to the connection up script.
    pub conup: Option<String>,
    /// The path to the connection down script.
    pub condown: Option<String>,

    // RADIUS Proxy settings
    /// The IP address to listen on for proxy requests.
    #[serde(default)]
    pub proxylisten: Option<Ipv4Addr>,
    /// The UDP port to listen on for proxy requests.
    #[serde(default)]
    pub proxyport: u16,
    /// The shared secret for proxy clients.
    #[serde(default)]
    pub proxysecret: Option<String>,
    /// The NAS-Identifier for the proxy.
    #[serde(default)]
    pub proxynasid: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            foreground: true,
            debug: true,
            logfacility: 3,
            loglevel: 7,
            interval: 3600,
            pidfile: "/var/run/chilli.pid".to_string(),
            statedir: "/var/run".to_string(),
            net: "192.168.182.0".parse().unwrap(),
            mask: "255.255.255.0".parse().unwrap(),
            tundev: Some("tun0".to_string()),
            dynip: None,
            statip: None,
            dns1: "8.8.8.8".parse().unwrap(),
            dns2: "8.8.4.4".parse().unwrap(),
            domain: Some("coova.org".to_string()),
            radiuslisten: "0.0.0.0".parse().unwrap(),
            radiusserver1: "127.0.0.1".parse().unwrap(),
            radiusserver2: Some("127.0.0.1".parse().unwrap()),
            radiussecret: "testing123".to_string(),
            radiusauthport: 1812,
            radiusacctport: 1813,
            coaport: 3799,
            coanoipcheck: false,
            dhcpif: "eth0".to_string(),
            dhcplisten: "192.168.182.1".parse().unwrap(),
            dhcpstart: "192.168.182.10".parse().unwrap(),
            dhcpend: "192.168.182.254".parse().unwrap(),
            lease: 3600,
            uamsecret: Some("uamsecret".to_string()),
            uamurl: Some("http://127.0.0.1:3990/login".to_string()),
            uamlisten: "192.168.182.1".parse().unwrap(),
            uamport: 3990,
            max_clients: 1024,
            walled_garden: Vec::new(),
            macauth: false,
            macauthdeny: false,
            macallowed: Vec::new(),
            macpasswd: None,
            cmdsocket: Some("/var/run/chilli.sock".to_string()),
            statusfile: Some("/var/run/chilli.status".to_string()),
            conup: None,
            condown: None,
            proxylisten: None,
            proxyport: 1814,
            proxysecret: None,
            proxynasid: None,
        }
    }
}
