package config

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"time"

	"coovachilli-go/pkg/securestore"
	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v2"
)

// LoggingConfig holds the configuration for the logging system.
type LoggingConfig struct {
	Destination string `yaml:"dest" envconfig:"DEST"`
	Level       string `yaml:"level" envconfig:"LEVEL"`
	SyslogTag   string `yaml:"syslog_tag" envconfig:"SYSLOG_TAG"`
}

// Config holds the application configuration.
type Config struct {
	// General settings
	Foreground bool          `yaml:"foreground" envconfig:"FOREGROUND"`
	PIDFile    string        `yaml:"pidfile" envconfig:"PIDFILE"`
	User       string        `yaml:"user" envconfig:"USER"`
	Group      string        `yaml:"group" envconfig:"GROUP"`
	Interval   time.Duration `yaml:"interval" envconfig:"INTERVAL"`
	Logging    LoggingConfig `yaml:"logging"`

	// TUN/TAP settings
	TUNDev     string `yaml:"tundev" envconfig:"TUNDEV"`
	TUNDevices int    `yaml:"tundevices" envconfig:"TUNDEVICES"`

	// Network settings
	NetStr string    `yaml:"net" envconfig:"NET"`
	Net    net.IPNet `yaml:"-"` // Parsed from NetStr

	// IPv6 Network Settings
	IPv6Enable  bool    `yaml:"ipv6enable" envconfig:"IPV6ENABLE"`
	NetV6Str    string  `yaml:"net_v6" envconfig:"NET_V6"`
	NetV6       net.IPNet `yaml:"-"` // Parsed from NetV6Str
	UAMListen   net.IP  `yaml:"uamlisten" envconfig:"UAMLISTEN"`
	UAMListenV6 net.IP  `yaml:"uamlisten_v6" envconfig:"UAMLISTEN_V6"`
	DHCPListen  net.IP  `yaml:"dhcplisten" envconfig:"DHCPLISTEN"`
	DHCPListenV6 net.IP `yaml:"dhcplisten_v6" envconfig:"DHCPLISTEN_V6"`

	// DHCP settings
	DHCPIf       string        `yaml:"dhcpif" envconfig:"DHCPIF"`
	MoreIf       []string      `yaml:"moreif" envconfig:"MOREIF"`
	DHCPRelay    bool          `yaml:"dhcprelay" envconfig:"DHCPRELAY"`
	DHCPUpstream string        `yaml:"dhcpupstream" envconfig:"DHCPUPSTREAM"`
	DHCPStart    net.IP        `yaml:"dhcpstart" envconfig:"DHCPSTART"`
	DHCPEnd      net.IP        `yaml:"dhcpend" envconfig:"DHCPEND"`
	DHCPStartV6  net.IP        `yaml:"dhcpstart_v6" envconfig:"DHCPSTART_V6"`
	DHCPEndV6    net.IP        `yaml:"dhcpend_v6" envconfig:"DHCPEND_V6"`
	Lease        time.Duration `yaml:"lease" envconfig:"LEASE"`
	DNS1         net.IP        `yaml:"dns1" envconfig:"DNS1"`
	DNS2         net.IP        `yaml:"dns2" envconfig:"DNS2"`
	DNS1V6       net.IP        `yaml:"dns1_v6" envconfig:"DNS1_V6"`
	DNS2V6       net.IP        `yaml:"dns2_v6" envconfig:"DNS2_V6"`

	// RADIUS settings
	RadiusListen        net.IP              `yaml:"radiuslisten" envconfig:"RADIUSLISTEN"`
	RadiusListenV6      net.IP              `yaml:"radiuslisten_v6" envconfig:"RADIUSLISTEN_V6"`
	RadiusServer1       string              `yaml:"radiusserver1" envconfig:"RADIUSSERVER1"`
	RadiusServer2       string              `yaml:"radiusserver2" envconfig:"RADIUSSERVER2"`
	RadiusAcctServer1   string              `yaml:"radiusacctserver1" envconfig:"RADIUSACCTSERVER1"`
	RadiusAcctServer2   string              `yaml:"radiusacctserver2" envconfig:"RADIUSACCTSERVER2"`
	RadiusAuthPort      int                 `yaml:"radiusauthport" envconfig:"RADIUSAUTHPORT"`
	RadiusAcctPort      int                 `yaml:"radiusacctport" envconfig:"RADIUSACCTPORT"`
	RadiusSecretStr     string              `yaml:"radiussecret" envconfig:"RADIUSSECRET"`
	RadiusSecret        *securestore.Secret `yaml:"-"`
	RadiusAcctSecretStr string              `yaml:"radiusacctsecret" envconfig:"RADIUSACCTSECRET"`
	RadiusAcctSecret    *securestore.Secret `yaml:"-"`
	RadiusNASID         string              `yaml:"radiusnasid" envconfig:"RADIUSNASID"`
	RadiusTimeout       time.Duration       `yaml:"radiustimeout" envconfig:"RADIUSTIMEOUT"`
	RadSecIdleTimeout   time.Duration       `yaml:"radsecidletimeout" envconfig:"RADSECIDLETIMEOUT"`
	CoaPort             int                 `yaml:"coaport" envconfig:"COAPORT"`
	RadSecEnable        bool                `yaml:"radsecenable" envconfig:"RADSECENABLE"`
	RadSecPort          int                 `yaml:"radsecport" envconfig:"RADSECPORT"`
	RadSecCertFile      string              `yaml:"radseccertfile" envconfig:"RADSECCERTFILE"`
	RadSecKeyFile       string              `yaml:"radseckeyfile" envconfig:"RADSECKEYFILE"`
	RadSecCAFile        string              `yaml:"radseccafile" envconfig:"RADSECCAFILE"`
	ProxyEnable         bool                `yaml:"proxyenable" envconfig:"PROXYENABLE"`
	ProxyListen         string              `yaml:"proxylisten" envconfig:"PROXYLISTEN"`
	ProxyPort           int                 `yaml:"proxyport" envconfig:"PROXYPORT"`
	ProxySecretStr      string              `yaml:"proxysecret" envconfig:"PROXYSECRET"`
	ProxySecret         *securestore.Secret `yaml:"-"`

	// UAM/Captive Portal settings
	UAMPort             int               `yaml:"uamport" envconfig:"UAMPORT"`
	UAMUIPort           int               `yaml:"uamuiport" envconfig:"UAMUIPORT"`
	UAMSecret           string            `yaml:"uamsecret" envconfig:"UAMSECRET"`
	UseLocalUsers       bool              `yaml:"uselocalusers" envconfig:"USELOCALUSERS"`
	LocalUsersFile      string            `yaml:"localusersfile" envconfig:"LOCALUSERSFILE"`
	CertFile            string            `yaml:"certfile" envconfig:"CERTFILE"`
	KeyFile             string            `yaml:"keyfile" envconfig:"KEYFILE"`
	WWWDir              string            `yaml:"wwwdir" envconfig:"WWWDIR"`
	WWWBin              string            `yaml:"wwwbin" envconfig:"WWWBIN"`
	UAMAllowed          []string          `yaml:"uamallowed" envconfig:"UAMALLOWED"`
	UAMAllowedV6        []string          `yaml:"uamallowed_v6" envconfig:"UAMALLOWED_V6"`
	UAMDomains          []string          `yaml:"uamdomains" envconfig:"UAMDOMAINS"`
	UAMRegex            []string          `yaml:"uamregex" envconfig:"UAMREGEX"`
	UAMRegexCompiled    []*regexp.Regexp  `yaml:"-"`
	UAMUrl              string            `yaml:"uamurl" envconfig:"UAMURL"`
	UAMAnyDNS           bool              `yaml:"uamanydns" envconfig:"UAMANYDNS"`
	UAMAnyIP            bool              `yaml:"uamanyip" envconfig:"UAMANYIP"`
	UAMReadTimeout      time.Duration     `yaml:"uam_read_timeout" envconfig:"UAM_READ_TIMEOUT"`
	UAMWriteTimeout     time.Duration     `yaml:"uam_write_timeout" envconfig:"UAM_WRITE_TIMEOUT"`
	UAMIdleTimeout      time.Duration     `yaml:"uam_idle_timeout" envconfig:"UAM_IDLE_TIMEOUT"`
	UAMRateLimitEnabled bool              `yaml:"uam_rate_limit_enabled" envconfig:"UAM_RATE_LIMIT_ENABLED"`
	UAMRateLimit        float64           `yaml:"uam_rate_limit" envconfig:"UAM_RATE_LIMIT"`
	UAMRateLimitBurst   int               `yaml:"uam_rate_limit_burst" envconfig:"UAM_RATE_LIMIT_BURST"`
	MACAuth             bool              `yaml:"macauth" envconfig:"MACAUTH"`
	MACSuffix           string            `yaml:"macsuffix" envconfig:"MACSUFFIX"`
	MACPasswd           string            `yaml:"macpasswd" envconfig:"MACPASSWD"`
	EAPOL               bool              `yaml:"eapol" envconfig:"EAPOL"`
	IEEE8021Q           bool              `yaml:"ieee8021q" envconfig:"IEEE8021Q"`
	VLANs               []int             `yaml:"vlans" envconfig:"VLANS"`
	DefSessionTimeout   uint32            `yaml:"defsessiontimeout" envconfig:"DEFSESSIONTIMEOUT"`
	DefIdleTimeout      uint32            `yaml:"defidletimeout" envconfig:"DEFIDLETIMEOUT"`
	DefBandwidthMaxDown uint64            `yaml:"defbandwidthmaxdown" envconfig:"DEFBANDWIDTHMAXDOWN"`
	DefBandwidthMaxUp   uint64            `yaml:"defbandwidthmaxup" envconfig:"DEFBANDWIDTHMAXUP"`
	BwBucketUpSize      uint64            `yaml:"bwbucketupsize" envconfig:"BWBUCKETUPSIZE"`
	BwBucketDnSize      uint64            `yaml:"bwbucketdnsize" envconfig:"BWBUCKETDNSIZE"`
	BwBucketMinSize     uint64            `yaml:"bwbucketminsize" envconfig:"BWBUCKETMINSIZE"`

	// Firewall settings
	FirewallBackend string   `yaml:"firewallbackend" envconfig:"FIREWALLBACKEND"`
	ExtIf           string   `yaml:"extif" envconfig:"EXTIF"`
	ClientIsolation bool     `yaml:"clientisolation" envconfig:"CLIENTISOLATION"`
	IPTables        string   `yaml:"iptables" envconfig:"IPTABLES"`
	IP6Tables       string   `yaml:"ip6tables" envconfig:"IP6TABLES"`
	TCPPorts        []int    `yaml:"tcpports" envconfig:"TCPPORTS"`
	UDPPorts        []int    `yaml:"udpports" envconfig:"UDPPORTS"`

	// Scripts
	ConUp   string `yaml:"conup" envconfig:"CONUP"`
	ConDown string `yaml:"condown" envconfig:"CONDOWN"`
	IPUp    string `yaml:"ipup" envconfig:"IPUP"`
	IPDown  string `yaml:"ipdown" envconfig:"IPDOWN"`

	// Management
	StateFile string `yaml:"statefile" envconfig:"STATEFILE"`
	CmdSocket string `yaml:"cmdsocket" envconfig:"CMDSOCKET"`

	// Cluster settings
	Cluster ClusterConfig `yaml:"cluster"`
	// Metrics settings
	Metrics MetricsConfig `yaml:"metrics"`
	// Admin API settings
	AdminAPI AdminAPIConfig `yaml:"admin_api"`
	// Walled Garden settings
	WalledGarden WalledGardenConfig `yaml:"walledgarden"`
}

// AdminAPIConfig holds the configuration for the admin API.
type AdminAPIConfig struct {
	Enabled          bool                `yaml:"enabled" envconfig:"ENABLED"`
	Listen           string              `yaml:"listen" envconfig:"LISTEN"`
	AuthTokenStr     string              `yaml:"auth_token" envconfig:"AUTH_TOKEN"`
	AuthToken        *securestore.Secret `yaml:"-"`
	ReadTimeout      time.Duration       `yaml:"read_timeout" envconfig:"READ_TIMEOUT"`
	WriteTimeout     time.Duration       `yaml:"write_timeout" envconfig:"WRITE_TIMEOUT"`
	IdleTimeout      time.Duration       `yaml:"idle_timeout" envconfig:"IDLE_TIMEOUT"`
	RateLimitEnabled bool                `yaml:"rate_limit_enabled" envconfig:"RATE_LIMIT_ENABLED"`
	RateLimit        float64             `yaml:"rate_limit" envconfig:"RATE_LIMIT"`
	RateLimitBurst   int                 `yaml:"rate_limit_burst" envconfig:"RATE_LIMIT_BURST"`
}

// WalledGardenConfig holds the configuration for the walled garden.
type WalledGardenConfig struct {
	AllowedDomains  []string `yaml:"allowedDomains" envconfig:"ALLOWEDDOMAINS"`
	AllowedNetworks []string `yaml:"allowedNetworks" envconfig:"ALLOWEDNETWORKS"`
}

// MetricsConfig holds the configuration for the metrics system.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled" envconfig:"ENABLED"`
	Backend string `yaml:"backend" envconfig:"BACKEND"`
	Listen  string `yaml:"listen" envconfig:"LISTEN"`
}

// ClusterConfig holds the cluster-specific settings.
type ClusterConfig struct {
	Enabled   bool   `yaml:"enabled" envconfig:"ENABLED"`
	PeerID    int    `yaml:"peerid" envconfig:"PEERID"`
	PeerKey   string `yaml:"peerkey" envconfig:"PEERKEY"`
	Interface string `yaml:"interface" envconfig:"INTERFACE"`
}

// Load loads the configuration from a YAML file, and then overrides with environment variables.
func Load(path string) (*Config, error) {
	var cfg Config

	// Load configuration from YAML file first
	data, err := os.ReadFile(path)
	if err != nil {
		// If the file doesn't exist, we can proceed, as config might be fully provided by env vars.
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	// Unmarshal YAML data if the file was read
	if len(data) > 0 {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to unmarshal config data: %w", err)
		}
	}

	// Override with environment variables. The prefix for env vars is "COOVACHILLI".
	// For example, Logging.Level can be set with COOVACHILLI_LOGGING_LEVEL.
	if err := envconfig.Process("coovachilli", &cfg); err != nil {
		return nil, fmt.Errorf("failed to process environment variables: %w", err)
	}

	// Convert secrets to secure buffers
	if cfg.RadiusSecretStr != "" {
		cfg.RadiusSecret = securestore.NewSecret(cfg.RadiusSecretStr)
		cfg.RadiusSecretStr = "" // Clear the plaintext secret
	}
	if cfg.ProxySecretStr != "" {
		cfg.ProxySecret = securestore.NewSecret(cfg.ProxySecretStr)
		cfg.ProxySecretStr = ""
	}
	if cfg.AdminAPI.AuthTokenStr != "" {
		cfg.AdminAPI.AuthToken = securestore.NewSecret(cfg.AdminAPI.AuthTokenStr)
		cfg.AdminAPI.AuthTokenStr = ""
	}
	if cfg.RadiusAcctSecretStr != "" {
		cfg.RadiusAcctSecret = securestore.NewSecret(cfg.RadiusAcctSecretStr)
		cfg.RadiusAcctSecretStr = ""
	}

	// Compile UAM regexes
	if len(cfg.UAMRegex) > 0 {
		cfg.UAMRegexCompiled = make([]*regexp.Regexp, len(cfg.UAMRegex))
		for i, reStr := range cfg.UAMRegex {
			re, err := regexp.Compile(reStr)
			if err != nil {
				return nil, fmt.Errorf("failed to compile uamregex '%s': %w", reStr, err)
			}
			cfg.UAMRegexCompiled[i] = re
		}
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