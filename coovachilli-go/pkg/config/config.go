package config

import (
	"fmt"
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

// LoggingConfig holds the configuration for the logging system.
type LoggingConfig struct {
	Destination string `yaml:"dest"`      // "stdout", "syslog", or a file path
	Level       string `yaml:"level"`       // "debug", "info", "warn", "error"
	SyslogTag   string `yaml:"syslog_tag"`  // Tag for syslog messages
}

// Config holds the application configuration.
type Config struct {
	// General settings
	Foreground bool   `yaml:"foreground"`
	PIDFile    string `yaml:"pidfile"`
	User       string `yaml:"user"`
	Group      string `yaml:"group"`
	Interval   time.Duration `yaml:"interval"`
	Logging    LoggingConfig `yaml:"logging"`

	// TUN/TAP settings
	TUNDev  string `yaml:"tundev"`
	TUNDevices int `yaml:"tundevices"`

	// Network settings
	NetStr string    `yaml:"net"`
	Net    net.IPNet `yaml:"-"` // Parsed from NetStr

	// IPv6 Network Settings
	IPv6Enable bool    `yaml:"ipv6enable"` // Master switch for IPv6 functionality
	NetV6Str   string  `yaml:"net_v6"`
	NetV6      net.IPNet `yaml:"-"` // Parsed from NetV6Str
	UAMListen net.IP `yaml:"uamlisten"`
	UAMListenV6 net.IP `yaml:"uamlisten_v6"`
	DHCPListen net.IP `yaml:"dhcplisten"`
	DHCPListenV6 net.IP `yaml:"dhcplisten_v6"`

	// DHCP settings
	DHCPIf         string   `yaml:"dhcpif"`
	MoreIF         []string `yaml:"moreif"`
	DHCPRelay      bool     `yaml:"dhcprelay"`
	DHCPUpstream   string   `yaml:"dhcpupstream"`
	DHCPStart      net.IP   `yaml:"dhcpstart"`
	DHCPEnd        net.IP   `yaml:"dhcpend"`
	DHCPStartV6    net.IP   `yaml:"dhcpstart_v6"`
	DHCPEndV6      net.IP   `yaml:"dhcpend_v6"`
	Lease          time.Duration `yaml:"lease"`
	DNS1           net.IP   `yaml:"dns1"`
	DNS2           net.IP   `yaml:"dns2"`
	DNS1V6         net.IP   `yaml:"dns1_v6"`
	DNS2V6         net.IP   `yaml:"dns2_v6"`

	// RADIUS settings
	RadiusListen       net.IP `yaml:"radiuslisten"`
	RadiusListenV6     net.IP `yaml:"radiuslisten_v6"`
	RadiusServer1      string `yaml:"radiusserver1"`
	RadiusServer2      string `yaml:"radiusserver2"`
	RadiusAuthPort     int    `yaml:"radiusauthport"`
	RadiusAcctPort     int    `yaml:"radiusacctport"`
	RadiusSecret       string `yaml:"radiussecret"`
	RadiusNASID        string `yaml:"radiusnasid"`
	CoaPort            int    `yaml:"coaport"`
	RadSecEnable       bool   `yaml:"radsecenable"`
	RadSecPort         int    `yaml:"radsecport"`
	RadSecCertFile     string `yaml:"radseccertfile"`
	RadSecKeyFile      string `yaml:"radseckeyfile"`
	RadSecCAFile       string `yaml:"radseccafile"`
	ProxyEnable        bool   `yaml:"proxyenable"`
	ProxyListen        string `yaml:"proxylisten"`
	ProxyPort          int    `yaml:"proxyport"`
	ProxySecret        string `yaml:"proxysecret"`

	// UAM/Captive Portal settings
	UAMPort             int      `yaml:"uamport"`
	UAMUIPort           int      `yaml:"uamuiport"`
	UAMSecret           string   `yaml:"uamsecret"`
	UseLocalUsers       bool     `yaml:"uselocalusers"`
	LocalUsersFile      string   `yaml:"localusersfile"`
	CertFile            string   `yaml:"certfile"`
	KeyFile             string   `yaml:"keyfile"`
	WWWDir              string   `yaml:"wwwdir"`
	WWWBin              string   `yaml:"wwwbin"`
	UAMAllowed          []string `yaml:"uamallowed"`
	UAMAllowedV6        []string `yaml:"uamallowed_v6"`
	UAMDomains          []string `yaml:"uamdomains"`
	UAMUrl              string   `yaml:"uamurl"`
	UAMAnyIP            bool     `yaml:"uamanyip"`
	UAMAnyDNS           bool     `yaml:"uamanydns"`
	MACAuth             bool     `yaml:"macauth"`
	MACSuffix           string   `yaml:"macsuffix"`
	MACPasswd           string   `yaml:"macpasswd"`
	EAPOL               bool     `yaml:"eapol"`
	IEEE8021Q           bool     `yaml:"ieee8021q"`
	VLANs               []int    `yaml:"vlans"`
	DefSessionTimeout   uint32   `yaml:"defsessiontimeout"`
	DefIdleTimeout      uint32   `yaml:"defidletimeout"`
	DefBandwidthMaxDown uint64   `yaml:"defbandwidthmaxdown"`
	DefBandwidthMaxUp   uint64   `yaml:"defbandwidthmaxup"`
	BwBucketUpSize      uint64   `yaml:"bwbucketupsize"`
	BwBucketDnSize      uint64   `yaml:"bwbucketdnsize"`
	BwBucketMinSize     uint64   `yaml:"bwbucketminsize"`

	// Firewall settings
	FirewallBackend   string   `yaml:"firewallbackend"`
	ExtIf             string   `yaml:"extif"`
	ClientIsolation   bool     `yaml:"clientisolation"`
	IPTables          string   `yaml:"iptables"`
	IP6Tables         string   `yaml:"ip6tables"`
	TCPPorts          []int    `yaml:"tcpports"`
	UDPPorts          []int    `yaml:"udpports"`

	// Scripts
	ConUp   string `yaml:"conup"`
	ConDown string `yaml:"condown"`
	IPUp    string `yaml:"ipup"`
	IPDown  string `yaml:"ipdown"`

	// Management
	StateFile   string `yaml:"statefile"`
	CmdSocket   string `yaml:"cmdsocket"`

	// Cluster settings
	Cluster ClusterConfig `yaml:"cluster"`
	// Metrics settings
	Metrics MetricsConfig `yaml:"metrics"`
	// Admin API settings
	AdminAPI AdminAPIConfig `yaml:"admin_api"`
}

// AdminAPIConfig holds the configuration for the admin API.
type AdminAPIConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Listen    string `yaml:"listen"`
	AuthToken string `yaml:"auth_token"`
}

// MetricsConfig holds the configuration for the metrics system.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Backend string `yaml:"backend"`
	Listen  string `yaml:"listen"`
}

// ClusterConfig holds the cluster-specific settings.
type ClusterConfig struct {
	Enabled   bool   `yaml:"enabled"`
	PeerID    int    `yaml:"peerid"`
	PeerKey   string `yaml:"peerkey"`
	Interface string `yaml:"interface"`
}

// Load loads the configuration from a YAML file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config data: %w", err)
	}

	// Manual parsing for CIDR notation fields
	if cfg.NetStr != "" {
		_, ipnet, err := net.ParseCIDR(cfg.NetStr)
		if err != nil {
			return nil, fmt.Errorf("invalid 'net' CIDR value: %w", err)
		}
		cfg.Net = *ipnet
	}

	if cfg.NetV6Str != "" {
		_, ipnet, err := net.ParseCIDR(cfg.NetV6Str)
		if err != nil {
			return nil, fmt.Errorf("invalid 'net_v6' CIDR value: %w", err)
		}
		cfg.NetV6 = *ipnet
	}

	// Default RadSec port if not provided
	if cfg.RadSecEnable && cfg.RadSecPort == 0 {
		cfg.RadSecPort = 2083
	}

	if cfg.FirewallBackend == "" {
		cfg.FirewallBackend = "auto"
	}

	return &cfg, nil
}