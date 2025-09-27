package firewall

import (
	"fmt"
	"net"
	"strings"

	"coovachilli-go/pkg/config"
	"github.com/coreos/go-iptables/iptables"
	"github.com/rs/zerolog"
)

// UserRuleRemover defines the interface for removing firewall rules for a user.
type UserRuleRemover interface {
	RemoveAuthenticatedUser(ip net.IP) error
}

const (
	chainChilli       = "chilli"
	chainWalledGarden = "chilli_walled_garden"
)

// IPTables is an interface that wraps the go-iptables methods used by the firewall.
// This allows for mocking in tests.
type IPTables interface {
	Append(table, chain string, rulespec ...string) error
	Insert(table, chain string, pos int, rulespec ...string) error
	Delete(table, chain string, rulespec ...string) error
	NewChain(table, chain string) error
	ClearChain(table, chain string) error
	DeleteChain(table, chain string) error
	Exists(table, chain string, rulespec ...string) (bool, error)
	ListChains(table string) ([]string, error)
}

// Firewall manages the system's firewall rules.
type Firewall struct {
	cfg    *config.Config
	ipt    IPTables
	ip6t   IPTables
	logger zerolog.Logger
}

// NewFirewall creates a new Firewall manager.
func NewFirewall(cfg *config.Config, logger zerolog.Logger) (*Firewall, error) {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, fmt.Errorf("failed to create iptables handler: %w", err)
	}

	var ip6t IPTables
	if cfg.IPv6Enable {
		// Attempt to create an ip6tables handler, but don't fail if it's not available.
		if ip6tReal, err := iptables.NewWithProtocol(iptables.ProtocolIPv6); err != nil {
			logger.Warn().Err(err).Msg("Failed to create ip6tables handler, IPv6 firewall will be disabled")
			ip6t = nil
		} else {
			logger.Info().Msg("ip6tables handler created, IPv6 firewall enabled")
			ip6t = ip6tReal
		}
	} else {
		logger.Info().Msg("IPv6 is disabled in configuration, IPv6 firewall will not be used.")
		ip6t = nil
	}

	return &Firewall{
		cfg:    cfg,
		ipt:    ipt,
		ip6t:   ip6t,
		logger: logger.With().Str("component", "firewall").Logger(),
	}, nil
}

// setupChains ensures the necessary chains exist for a given iptables handler.
func (f *Firewall) setupChains(handler IPTables, protocol string) error {
	for _, chain := range []string{chainChilli, chainWalledGarden} {
		for _, table := range []string{"nat", "filter"} {
			// Special handling for IPv6 NAT, which might not be supported.
			if protocol == "IPv6" && table == "nat" {
				// Check if the table exists at all. If not, disable ip6t and return.
				if _, err := handler.ListChains(table); err != nil {
					if strings.Contains(err.Error(), "No such file or directory") || strings.Contains(err.Error(), "table nat does not exist") {
						f.logger.Warn().Err(err).Msg("IPv6 NAT table not supported, disabling IPv6 firewall.")
						f.ip6t = nil // Permanently disable for this run.
						return nil   // Not a fatal error, just skip IPv6 setup.
					}
				}
			}

			exists, _ := handler.Exists(table, chain)
			if exists {
				if err := handler.ClearChain(table, chain); err != nil {
					return fmt.Errorf("failed to clear %s chain %s in %s table: %w", protocol, chain, table, err)
				}
			} else {
				if err := handler.NewChain(table, chain); err != nil {
					return fmt.Errorf("failed to create %s chain %s in %s table: %w", protocol, chain, table, err)
				}
			}
		}
	}
	return nil
}

// Initialize sets up the necessary firewall chains and rules.
func (f *Firewall) Initialize() error {
	f.logger.Debug().Msg("Initializing firewall rules")

	// === IPv4 Rule Setup ===
	if err := f.setupChains(f.ipt, "IPv4"); err != nil {
		return err
	}
	f.initializeIPv4Rules()

	// === IPv6 Rule Setup ===
	if f.ip6t != nil {
		if err := f.setupChains(f.ip6t, "IPv6"); err != nil {
			return err
		}
		// setupChains might disable ip6t if NAT is not supported.
		if f.ip6t != nil {
			f.initializeIPv6Rules()
		}
	}

	f.logger.Info().Msg("Firewall initialized successfully")
	return nil
}

func (f *Firewall) initializeIPv4Rules() error {
	// NAT rules
	if f.cfg.ExtIf != "" {
		f.ipt.Append("nat", "POSTROUTING", "-s", f.cfg.Net.String(), "-o", f.cfg.ExtIf, "-j", "MASQUERADE")
	}

	// Redirect unauthenticated users to the captive portal
	f.ipt.Append("nat", "PREROUTING", "-i", f.cfg.TUNDev, "-j", chainChilli)
	f.ipt.Append("nat", chainChilli, "-j", chainWalledGarden)
	for _, domain := range f.cfg.UAMAllowed {
		f.ipt.Append("nat", chainWalledGarden, "-d", domain, "-j", "RETURN")
	}
	// For everything else, redirect HTTP to the portal
	f.ipt.Append("nat", chainChilli, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", f.cfg.UAMPort))

	// Filter rules
	if f.cfg.ClientIsolation {
		f.ipt.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-o", f.cfg.TUNDev, "-j", "DROP")
	}
	f.ipt.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-j", chainChilli)
	// Open specified TCP/UDP ports for all users
	for _, port := range f.cfg.TCPPorts {
		f.ipt.Append("filter", chainChilli, "-p", "tcp", "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
	}
	for _, port := range f.cfg.UDPPorts {
		f.ipt.Append("filter", chainChilli, "-p", "udp", "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
	}
	return nil
}

func (f *Firewall) initializeIPv6Rules() error {
	// NAT rules
	if f.cfg.ExtIf != "" && f.cfg.NetV6.IP != nil {
		f.ip6t.Append("nat", "POSTROUTING", "-s", f.cfg.NetV6.String(), "-o", f.cfg.ExtIf, "-j", "MASQUERADE")
	}

	// Redirect unauthenticated users to the captive portal
	f.ip6t.Append("nat", "PREROUTING", "-i", f.cfg.TUNDev, "-j", chainChilli)
	f.ip6t.Append("nat", chainChilli, "-j", chainWalledGarden)
	for _, domain := range f.cfg.UAMAllowedV6 {
		f.ip6t.Append("nat", chainWalledGarden, "-d", domain, "-j", "RETURN")
	}
	// For everything else, redirect HTTP to the portal
	f.ip6t.Append("nat", chainChilli, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", f.cfg.UAMPort))

	// Filter rules
	if f.cfg.ClientIsolation {
		f.ip6t.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-o", f.cfg.TUNDev, "-j", "DROP")
	}
	f.ip6t.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-j", chainChilli)
	// Open specified TCP/UDP ports for all users
	for _, port := range f.cfg.TCPPorts {
		f.ip6t.Append("filter", chainChilli, "-p", "tcp", "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
	}
	for _, port := range f.cfg.UDPPorts {
		f.ip6t.Append("filter", chainChilli, "-p", "udp", "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
	}
	return nil
}

// AddAuthenticatedUser adds firewall rules to allow traffic for an authenticated user.
func (f *Firewall) AddAuthenticatedUser(ip net.IP) error {
	var handler IPTables
	if ip.To4() != nil {
		handler = f.ipt
	} else if f.ip6t != nil {
		handler = f.ip6t
	} else {
		return nil // No-op if IPv6 is not supported/enabled
	}

	if err := handler.Insert("nat", chainChilli, 1, "-s", ip.String(), "-j", "RETURN"); err != nil {
		return fmt.Errorf("failed to add nat rule for authenticated user %s: %w", ip, err)
	}
	if err := handler.Insert("filter", chainChilli, 1, "-s", ip.String(), "-j", "RETURN"); err != nil {
		return fmt.Errorf("failed to add filter rule for authenticated user %s: %w", ip, err)
	}

	f.logger.Info().Str("ip", ip.String()).Msg("Added firewall rules for authenticated user")
	return nil
}

// RemoveAuthenticatedUser removes firewall rules for a user.
func (f *Firewall) RemoveAuthenticatedUser(ip net.IP) error {
	var handler IPTables
	if ip.To4() != nil {
		handler = f.ipt
	} else if f.ip6t != nil {
		handler = f.ip6t
	} else {
		return nil // No-op if IPv6 is not supported/enabled
	}

	if err := handler.Delete("nat", chainChilli, "-s", ip.String(), "-j", "RETURN"); err != nil {
		f.logger.Warn().Err(err).Msgf("failed to delete nat rule for user %s", ip)
	}
	if err := handler.Delete("filter", chainChilli, "-s", ip.String(), "-j", "RETURN"); err != nil {
		f.logger.Warn().Err(err).Msgf("failed to delete filter rule for user %s", ip)
	}

	f.logger.Info().Str("ip", ip.String()).Msg("Removed firewall rules for user")
	return nil
}

// Cleanup removes all firewall rules and chains created by the application.
func (f *Firewall) Cleanup() {
	f.logger.Info().Msg("Cleaning up firewall rules...")
	// IPv4 cleanup
	f.cleanupHandler(f.ipt, f.cfg.Net.String(), false)

	// IPv6 cleanup
	if f.ip6t != nil {
		var netV6 string
		if f.cfg.NetV6.IP != nil {
			netV6 = f.cfg.NetV6.String()
		}
		f.cleanupHandler(f.ip6t, netV6, true)
	}
	f.logger.Info().Msg("Firewall cleanup complete.")
}

func (f *Firewall) cleanupHandler(handler IPTables, network string, isIPv6 bool) {
	// Delete main rules
	if f.cfg.ExtIf != "" && network != "" {
		handler.Delete("nat", "POSTROUTING", "-s", network, "-o", f.cfg.ExtIf, "-j", "MASQUERADE")
	}
	handler.Delete("nat", "PREROUTING", "-i", f.cfg.TUNDev, "-j", chainChilli)
	handler.Delete("filter", "FORWARD", "-i", f.cfg.TUNDev, "-j", chainChilli)
	if f.cfg.ClientIsolation {
		handler.Delete("filter", "FORWARD", "-i", f.cfg.TUNDev, "-o", f.cfg.TUNDev, "-j", "DROP")
	}

	// Clear and delete custom chains
	for _, chain := range []string{chainChilli, chainWalledGarden} {
		// For IPv6, the NAT table might not exist, so check before clearing/deleting.
		if isIPv6 {
			if _, err := handler.ListChains("nat"); err == nil {
				handler.ClearChain("nat", chain)
				handler.DeleteChain("nat", chain)
			}
		} else {
			handler.ClearChain("nat", chain)
			handler.DeleteChain("nat", chain)
		}

		handler.ClearChain("filter", chain)
		handler.DeleteChain("filter", chain)
	}
}