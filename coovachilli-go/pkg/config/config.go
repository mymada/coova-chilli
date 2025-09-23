package config

import (
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"gopkg.in/yaml.v2"
)

// Config holds the application configuration.
type Config struct {
	// General settings
	Foreground bool   `yaml:"foreground"`
	PIDFile    string `yaml:"pidfile"`
	Interval   time.Duration `yaml:"interval"`

	// TUN/TAP settings
	TUNDev  string `yaml:"tundev"`
	TUNDevices int `yaml:"tundevices"`

	// Network settings
	Net    net.IPNet `yaml:"net"`
	NetV6  net.IPNet `yaml:"net_v6"`
	UAMListen net.IP `yaml:"uamlisten"`
	UAMListenV6 net.IP `yaml:"uamlisten_v6"`
	DHCPListen net.IP `yaml:"dhcplisten"`
	DHCPListenV6 net.IP `yaml:"dhcplisten_v6"`

	// DHCP settings
	DHCPIf         string `yaml:"dhcpif"`
	DHCPStart      net.IP `yaml:"dhcpstart"`
	DHCPEnd        net.IP `yaml:"dhcpend"`
	DHCPStartV6    net.IP `yaml:"dhcpstart_v6"`
	DHCPEndV6      net.IP `yaml:"dhcpend_v6"`
	Lease          time.Duration `yaml:"lease"`
	DNS1           net.IP `yaml:"dns1"`
	DNS2           net.IP `yaml:"dns2"`
	DNS1V6         net.IP `yaml:"dns1_v6"`
	DNS2V6         net.IP `yaml:"dns2_v6"`

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

	// UAM/Captive Portal settings
	UAMPort       int      `yaml:"uamport"`
	UAMUIPort     int      `yaml:"uamuiport"`
	UAMSecret     string   `yaml:"uamsecret"`
	UAMAllowed    []string `yaml:"uamallowed"`
	UAMDomains    []string `yaml:"uamdomains"`
	UAMUrl        string   `yaml:"uamurl"`

	// Firewall settings
	ExtIf      string `yaml:"extif"`
	IPTables   string `yaml:"iptables"`
	IP6Tables  string `yaml:"ip6tables"`

	// Scripts
	ConUp   string `yaml:"conup"`
	ConDown string `yaml:"condown"`
}

// Load loads the configuration from a YAML file.
func Load(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config data: %w", err)
	}

	return &cfg, nil
}
