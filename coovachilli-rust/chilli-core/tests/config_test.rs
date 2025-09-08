use chilli_core::{Config, LogLevel};
use std::fs;
use std::net::Ipv4Addr;

#[test]
fn test_load_config() {
    let config_contents = fs::read_to_string("tests/chilli.toml").unwrap();
    let config: Config = toml::from_str(&config_contents).unwrap();

    assert_eq!(config.foreground, true);
    assert_eq!(config.debug, true);
    assert_eq!(config.logfacility, 1);
    assert_eq!(config.loglevel, LogLevel::Debug);
    assert_eq!(config.interval, 3600);
    assert_eq!(config.pidfile, "/var/run/chilli.pid");
    assert_eq!(config.statedir, "/var/lib/chilli");

    assert_eq!(config.net, Ipv4Addr::new(192, 168, 182, 0));
    assert_eq!(config.mask, Ipv4Addr::new(255, 255, 255, 0));
    assert_eq!(config.tundev, Some("tun0".to_string()));
    assert_eq!(config.dynip, Some("192.168.182.0/24".to_string()));
    assert_eq!(config.statip, Some("10.1.0.0/16".to_string()));

    assert_eq!(config.dns1, Ipv4Addr::new(8, 8, 8, 8));
    assert_eq!(config.dns2, Ipv4Addr::new(8, 8, 4, 4));
    assert_eq!(config.domain, Some("coova.org".to_string()));

    assert_eq!(config.radiuslisten, Ipv4Addr::new(127, 0, 0, 1));
    assert_eq!(config.radiusserver1, Ipv4Addr::new(127, 0, 0, 1));
    assert_eq!(config.radiusserver2, Some(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(config.radiussecret, "testing123");
    assert_eq!(config.radiusauthport, 1812);
    assert_eq!(config.radiusacctport, 1813);
    assert_eq!(config.coaport, 3799);

    assert_eq!(config.dhcpif, "eth1");
    assert_eq!(config.dhcplisten, Ipv4Addr::new(192, 168, 182, 1));
    assert_eq!(config.lease, 86400);

    assert_eq!(config.uamsecret, Some("uamsecret".to_string()));
    assert_eq!(config.uamurl, Some("http://127.0.0.1/uam".to_string()));
    assert_eq!(config.uamlisten, Ipv4Addr::new(192, 168, 182, 1));
    assert_eq!(config.uamport, 3990);

    assert_eq!(config.max_clients, 256);
}
