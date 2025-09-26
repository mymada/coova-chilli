package firewall

import (
	"fmt"
	"net"

	"coovachilli-go/pkg/config"
	"github.com/coreos/go-iptables/iptables"
	"github.com/rs/zerolog"
)

// UserRuleRemover defines the interface for removing firewall rules for a user.
type UserRuleRemover interface {
	RemoveAuthenticatedUser(ip net.IP) error
}

const (
	chainChilli   = "chilli"
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
	ip6tReal, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to create ip6tables handler, IPv6 firewall will be disabled")
		ip6t = nil // Explicitly set to nil if there's an error
	} else {
		ip6t = ip6tReal
	}

	return &Firewall{
		cfg:    cfg,
		ipt:    ipt,
		ip6t:   ip6t,
		logger: logger.With().Str("component", "firewall").Logger(),
	}, nil
}

// Initialize sets up the necessary firewall chains and rules.
func (f *Firewall) Initialize() error {
	// Create custom chains
	for _, chain := range []string{chainChilli, chainWalledGarden} {
		if err := f.ipt.NewChain("nat", chain); err != nil {
			f.logger.Warn().Str("chain", chain).Str("table", "nat").Msg("Chain already exists, clearing it")
			if err := f.ipt.ClearChain("nat", chain); err != nil {
				return fmt.Errorf("failed to clear chain %s in nat table: %w", chain, err)
			}
		}
		if err := f.ipt.NewChain("filter", chain); err != nil {
			f.logger.Warn().Str("chain", chain).Str("table", "filter").Msg("Chain already exists, clearing it")
			if err := f.ipt.ClearChain("filter", chain); err != nil {
				return fmt.Errorf("failed to clear chain %s in filter table: %w", chain, err)
			}
		}
	}

	// NAT rules
	// Set up NAT for the client subnet
	if f.cfg.ExtIf != "" {
		if err := f.ipt.Append("nat", "POSTROUTING", "-s", f.cfg.Net.String(), "-o", f.cfg.ExtIf, "-j", "MASQUERADE"); err != nil {
			return fmt.Errorf("failed to add NAT rule: %w", err)
		}
	}

	// Redirect unauthenticated users to the captive portal
	if err := f.ipt.Append("nat", "PREROUTING", "-i", f.cfg.TUNDev, "-j", chainChilli); err != nil {
		return fmt.Errorf("failed to append to PREROUTING chain: %w", err)
	}
	if err := f.ipt.Append("nat", chainChilli, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", f.cfg.UAMPort)); err != nil {
		return fmt.Errorf("failed to add redirect rule: %w", err)
	}

	// Walled garden rules
	if err := f.ipt.Append("nat", chainChilli, "-j", chainWalledGarden); err != nil {
		return fmt.Errorf("failed to append to chilli chain: %w", err)
	}
	for _, domain := range f.cfg.UAMAllowed {
		if err := f.ipt.Append("nat", chainWalledGarden, "-d", domain, "-j", "RETURN"); err != nil {
			return fmt.Errorf("failed to add walled garden rule for %s: %w", domain, err)
		}
	}

	// Open specified TCP/UDP ports for all users
	for _, port := range f.cfg.TCPPorts {
		if err := f.ipt.Append("filter", chainChilli, "-p", "tcp", "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("failed to add open TCP port rule for port %d: %w", port, err)
		}
	}
	for _, port := range f.cfg.UDPPorts {
		if err := f.ipt.Append("filter", chainChilli, "-p", "udp", "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("failed to add open UDP port rule for port %d: %w", port, err)
		}
	}

	// Filter rules
	if f.cfg.ClientIsolation {
		if err := f.ipt.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-o", f.cfg.TUNDev, "-j", "DROP"); err != nil {
			return fmt.Errorf("failed to add client isolation rule: %w", err)
		}
	}
	if err := f.ipt.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-j", chainChilli); err != nil {
		return fmt.Errorf("failed to append to FORWARD chain: %w", err)
	}

	// === IPv6 Rules ===
	if f.ip6t != nil {
		// Create custom chains for IPv6
		for _, chain := range []string{chainChilli, chainWalledGarden} {
			if err := f.ip6t.NewChain("nat", chain); err != nil {
				f.logger.Warn().Str("chain", chain).Str("table", "nat_v6").Msg("Chain already exists, clearing it")
				if err := f.ip6t.ClearChain("nat", chain); err != nil {
					return fmt.Errorf("failed to clear chain %s in nat table for ipv6: %w", chain, err)
				}
			}
			if err := f.ip6t.NewChain("filter", chain); err != nil {
				f.logger.Warn().Str("chain", chain).Str("table", "filter_v6").Msg("Chain already exists, clearing it")
				if err := f.ip6t.ClearChain("filter", chain); err != nil {
					return fmt.Errorf("failed to clear chain %s in filter table for ipv6: %w", chain, err)
				}
			}
		}

		// IPv6 NAT rules
		if f.cfg.ExtIf != "" {
			if err := f.ip6t.Append("nat", "POSTROUTING", "-s", f.cfg.NetV6.String(), "-o", f.cfg.ExtIf, "-j", "MASQUERADE"); err != nil {
				return fmt.Errorf("failed to add IPv6 NAT rule: %w", err)
			}
		}

		// IPv6 redirection and forwarding rules would go here
		// Note: IPv6 NAT is more complex than IPv4 and often not recommended.
		// For now, we'll just set up the basic chains and MASQUERADE.
	}

	f.logger.Info().Msg("Firewall initialized successfully")
	return nil
}

// AddAuthenticatedUser adds firewall rules to allow traffic for an authenticated user.
func (f *Firewall) AddAuthenticatedUser(ip net.IP) error {
	if ip.To4() != nil {
		if err := f.ipt.Insert("nat", chainChilli, 1, "-s", ip.String(), "-j", "RETURN"); err != nil {
			return fmt.Errorf("failed to add nat rule for authenticated user %s: %w", ip.String(), err)
		}
		if err := f.ipt.Insert("filter", chainChilli, 1, "-s", ip.String(), "-j", "RETURN"); err != nil {
			return fmt.Errorf("failed to add filter rule for authenticated user %s: %w", ip.String(), err)
		}
	} else if f.ip6t != nil {
		if err := f.ip6t.Insert("nat", chainChilli, 1, "-s", ip.String(), "-j", "RETURN"); err != nil {
			return fmt.Errorf("failed to add ip6tables nat rule for authenticated user %s: %w", ip.String(), err)
		}
		if err := f.ip6t.Insert("filter", chainChilli, 1, "-s", ip.String(), "-j", "RETURN"); err != nil {
			return fmt.Errorf("failed to add ip6tables filter rule for authenticated user %s: %w", ip.String(), err)
		}
	}
	f.logger.Info().Str("ip", ip.String()).Msg("Added firewall rules for authenticated user")
	return nil
}

// RemoveAuthenticatedUser removes firewall rules for a user.
func (f *Firewall) RemoveAuthenticatedUser(ip net.IP) error {
	if ip.To4() != nil {
		if err := f.ipt.Delete("nat", chainChilli, "-s", ip.String(), "-j", "RETURN"); err != nil {
			return fmt.Errorf("failed to delete nat rule for user %s: %w", ip.String(), err)
		}
		if err := f.ipt.Delete("filter", chainChilli, "-s", ip.String(), "-j", "RETURN"); err != nil {
			return fmt.Errorf("failed to delete filter rule for user %s: %w", ip.String(), err)
		}
	} else if f.ip6t != nil {
		if err := f.ip6t.Delete("nat", chainChilli, "-s", ip.String(), "-j", "RETURN"); err != nil {
			return fmt.Errorf("failed to delete ip6tables nat rule for user %s: %w", ip.String(), err)
		}
		if err := f.ip6t.Delete("filter", chainChilli, "-s", ip.String(), "-j", "RETURN"); err != nil {
			return fmt.Errorf("failed to delete ip6tables filter rule for user %s: %w", ip.String(), err)
		}
	}
	f.logger.Info().Str("ip", ip.String()).Msg("Removed firewall rules for user")
	return nil
}

// Cleanup removes all firewall rules and chains created by the application.
func (f *Firewall) Cleanup() error {
	if f.cfg.ExtIf != "" {
		if err := f.ipt.Delete("nat", "POSTROUTING", "-s", f.cfg.Net.String(), "-o", f.cfg.ExtIf, "-j", "MASQUERADE"); err != nil {
			f.logger.Error().Err(err).Msg("Failed to delete NAT rule")
		}
	}

	if err := f.ipt.Delete("nat", "PREROUTING", "-i", f.cfg.TUNDev, "-j", chainChilli); err != nil {
		f.logger.Error().Err(err).Msg("Failed to delete from PREROUTING chain")
	}
	if err := f.ipt.Delete("filter", "FORWARD", "-i", f.cfg.TUNDev, "-j", chainChilli); err != nil {
		f.logger.Error().Err(err).Msg("Failed to delete from FORWARD chain")
	}
	if f.cfg.ClientIsolation {
		if err := f.ipt.Delete("filter", "FORWARD", "-i", f.cfg.TUNDev, "-o", f.cfg.TUNDev, "-j", "DROP"); err != nil {
			f.logger.Error().Err(err).Msg("Failed to delete client isolation rule")
		}
	}

	for _, chain := range []string{chainChilli, chainWalledGarden} {
		if err := f.ipt.ClearChain("nat", chain); err != nil {
			f.logger.Error().Err(err).Str("chain", chain).Str("table", "nat").Msg("Failed to clear chain")
		}
		if err := f.ipt.DeleteChain("nat", chain); err != nil {
			f.logger.Error().Err(err).Str("chain", chain).Str("table", "nat").Msg("Failed to delete chain")
		}

		if err := f.ipt.ClearChain("filter", chain); err != nil {
			f.logger.Error().Err(err).Str("chain", chain).Str("table", "filter").Msg("Failed to clear chain")
		}
		if err := f.ipt.DeleteChain("filter", chain); err != nil {
			f.logger.Error().Err(err).Str("chain", chain).Str("table", "filter").Msg("Failed to delete chain")
		}
	}

	if f.ip6t != nil {
		if f.cfg.ExtIf != "" {
			if err := f.ip6t.Delete("nat", "POSTROUTING", "-s", f.cfg.NetV6.String(), "-o", f.cfg.ExtIf, "-j", "MASQUERADE"); err != nil {
				f.logger.Error().Err(err).Msg("Failed to delete IPv6 NAT rule")
			}
		}
		for _, chain := range []string{chainChilli, chainWalledGarden} {
			if err := f.ip6t.ClearChain("nat", chain); err != nil {
				f.logger.Error().Err(err).Str("chain", chain).Str("table", "nat_v6").Msg("Failed to clear chain")
			}
			if err := f.ip6t.DeleteChain("nat", chain); err != nil {
				f.logger.Error().Err(err).Str("chain", chain).Str("table", "nat_v6").Msg("Failed to delete chain")
			}
			if err := f.ip6t.ClearChain("filter", chain); err != nil {
				f.logger.Error().Err(err).Str("chain", chain).Str("table", "filter_v6").Msg("Failed to clear chain")
			}
			if err := f.ip6t.DeleteChain("filter", chain); err != nil {
				f.logger.Error().Err(err).Str("chain", chain).Str("table", "filter_v6").Msg("Failed to delete chain")
			}
		}
	}

	f.logger.Info().Msg("Firewall cleaned up successfully")
	return nil
}
