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
    pub radiusserver2: Ipv4Addr,
    /// The shared secret for the RADIUS server.
    pub radiussecret: String,
    /// The UDP port for RADIUS authentication.
    pub radiusauthport: u16,
    /// The UDP port for RADIUS accounting.
    pub radiusacctport: u16,

    /// The network interface to use for DHCP.
    pub dhcpif: String,
    /// The IP address to listen on for DHCP requests.
    pub dhcplisten: Ipv4Addr,
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
}
