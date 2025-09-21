use chilli_core::{Config, LogLevel};
use std::net::Ipv4Addr;

fn load_test_config() -> Config {
    let config_contents =
        std::fs::read_to_string("tests/chilli.toml").expect("Failed to read config file");
    toml::from_str(&config_contents).expect("Failed to parse config file")
}

#[test]
fn test_load_general_config() {
    let config = load_test_config();
    assert_eq!(config.foreground, true);
    assert_eq!(config.debug, true);
    assert_eq!(config.logfacility, 1);
    assert_eq!(config.loglevel, LogLevel::Debug);
    assert_eq!(config.interval, 3600);
    assert_eq!(config.pidfile, "/var/run/chilli.pid");
    assert_eq!(config.statedir, "/var/lib/chilli");
}

#[test]
fn test_load_network_config() {
    let config = load_test_config();
    assert_eq!(config.net, Ipv4Addr::new(192, 168, 182, 0));
    assert_eq!(config.mask, Ipv4Addr::new(255, 255, 255, 0));
    assert_eq!(config.tundev, Some("tun0".to_string()));
    assert_eq!(config.dynip, Some("192.168.182.0/24".to_string()));
    assert_eq!(config.statip, Some("10.1.0.0/16".to_string()));
}

#[test]
fn test_load_dns_config() {
    let config = load_test_config();
    assert_eq!(config.dns1, Ipv4Addr::new(8, 8, 8, 8));
    assert_eq!(config.dns2, Ipv4Addr::new(8, 8, 4, 4));
    assert_eq!(config.domain, Some("coova.org".to_string()));
}

#[test]
fn test_load_radius_config() {
    let config = load_test_config();
    assert_eq!(config.radiuslisten, Ipv4Addr::new(127, 0, 0, 1));
    assert_eq!(config.radiusserver1, Ipv4Addr::new(127, 0, 0, 1));
    assert_eq!(config.radiusserver2, Some(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(config.radiussecret, "testing123");
    assert_eq!(config.radiusauthport, 1812);
    assert_eq!(config.radiusacctport, 1813);
    assert_eq!(config.coaport, 3799);
}

#[test]
fn test_load_dhcp_config() {
    let config = load_test_config();
    assert_eq!(config.dhcpif, "eth1");
    assert_eq!(config.dhcplisten, Ipv4Addr::new(192, 168, 182, 1));
    assert_eq!(config.lease, 86400);
}

#[test]
fn test_load_uam_config() {
    let config = load_test_config();
    assert_eq!(config.uamsecret, Some("uamsecret".to_string()));
    assert_eq!(config.uamurl, Some("http://127.0.0.1/uam".to_string()));
    assert_eq!(config.uamlisten, Ipv4Addr::new(192, 168, 182, 1));
    assert_eq!(config.uamport, 3990);
}

#[test]
fn test_load_client_config() {
    let config = load_test_config();
    assert_eq!(config.max_clients, 256);
}

#[test]
fn test_config_defaults() {
    // Parsing an empty string should now work because of the field-level defaults
    let config: Config = toml::from_str("").expect("Failed to parse empty config");

    // We can't directly compare with Config::default() because some defaults are not trivial
    // (e.g. `Some("off".to_string())`) and aren't easily represented as function paths for serde.
    // So we test a few key default values.
    assert_eq!(config.foreground, true);
    assert_eq!(config.radiusauthport, 1812);
    assert_eq!(config.lease, 3600);
    assert_eq!(config.max_clients, 1024);
    assert_eq!(config.proxyport, 1814);
    assert_eq!(config.radconf, None); // The default for an Option field is None
}

#[test]
fn test_config_invalid_values() {
    let invalid_config = r#"
        # This config has an invalid IP address
        dns1 = "not-a-valid-ip"
    "#;

    let result: Result<Config, _> = toml::from_str(invalid_config);
    assert!(result.is_err(), "Parsing should fail for invalid IP");
}
