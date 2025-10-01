package firewall

import (
	"fmt"
	"net"
	"strings"

	"coovachilli-go/pkg/config"
	"github.com/coreos/go-iptables/iptables"
	"github.com/rs/zerolog"
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

// IPTablesFirewall manages the system's firewall rules using iptables.
type IPTablesFirewall struct {
	cfg    *config.Config
	ipt    IPTables
	ip6t   IPTables
	logger zerolog.Logger
}

var newIPTablesFirewall = func(cfg *config.Config, logger zerolog.Logger) (*IPTablesFirewall, error) {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, fmt.Errorf("failed to create iptables handler: %w", err)
	}

	var ip6t IPTables
	if cfg.IPv6Enable {
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

	return &IPTablesFirewall{
		cfg:    cfg,
		ipt:    ipt,
		ip6t:   ip6t,
		logger: logger,
	}, nil
}

func (f *IPTablesFirewall) setupChains(handler IPTables, protocol string) error {
	for _, table := range []string{"nat", "filter"} {
		// Special handling for IPv6 NAT which may not be supported
		if protocol == "IPv6" && table == "nat" {
			if _, err := handler.ListChains(table); err != nil {
				if strings.Contains(err.Error(), "No such file or directory") || strings.Contains(err.Error(), "table nat does not exist") {
					f.logger.Warn().Err(err).Msg("IPv6 NAT table not supported, skipping NAT rules for IPv6.")
					continue // Skip to the next table
				}
			}
		}

		// Get all existing chains for the current table
		existingChains, err := handler.ListChains(table)
		if err != nil {
			return fmt.Errorf("failed to list chains in %s table for %s: %w", table, protocol, err)
		}
		chainMap := make(map[string]bool)
		for _, ch := range existingChains {
			chainMap[ch] = true
		}

		// For each of our custom chains, create if not exists, or clear if it does
		for _, chainToSetup := range []string{chainChilli, chainWalledGarden} {
			if chainMap[chainToSetup] {
				if err := handler.ClearChain(table, chainToSetup); err != nil {
					return fmt.Errorf("failed to clear %s chain %s in %s table: %w", protocol, chainToSetup, table, err)
				}
				f.logger.Debug().Str("table", table).Str("chain", chainToSetup).Msg("Cleared existing chain")
			} else {
				if err := handler.NewChain(table, chainToSetup); err != nil {
					return fmt.Errorf("failed to create %s chain %s in %s table: %w", protocol, chainToSetup, table, err)
				}
				f.logger.Debug().Str("table", table).Str("chain", chainToSetup).Msg("Created new chain")
			}
		}
	}
	return nil
}

func (f *IPTablesFirewall) Initialize() error {
	f.logger.Debug().Msg("Initializing iptables rules")
	if err := f.setupChains(f.ipt, "IPv4"); err != nil {
		return err
	}
	f.initializeIPv4Rules()

	if f.ip6t != nil {
		if err := f.setupChains(f.ip6t, "IPv6"); err != nil {
			return err
		}
		if f.ip6t != nil {
			f.initializeIPv6Rules()
		}
	}
	f.logger.Info().Msg("iptables firewall initialized successfully")
	return nil
}

func (f *IPTablesFirewall) initializeIPv4Rules() error {
	if f.cfg.ExtIf != "" {
		f.ipt.Append("nat", "POSTROUTING", "-s", f.cfg.Net.String(), "-o", f.cfg.ExtIf, "-j", "MASQUERADE")
	}

	f.ipt.Append("nat", "PREROUTING", "-i", f.cfg.TUNDev, "-j", chainChilli)
	f.ipt.Append("nat", chainChilli, "-j", chainWalledGarden)
	for _, domain := range f.cfg.UAMAllowed {
		f.ipt.Append("nat", chainWalledGarden, "-d", domain, "-j", "RETURN")
	}
	f.ipt.Append("nat", chainChilli, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", f.cfg.UAMPort))

	if f.cfg.ClientIsolation {
		f.ipt.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-o", f.cfg.TUNDev, "-j", "DROP")
	}
	f.ipt.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-j", chainChilli)
	for _, port := range f.cfg.TCPPorts {
		f.ipt.Append("filter", chainChilli, "-p", "tcp", "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
	}
	for _, port := range f.cfg.UDPPorts {
		f.ipt.Append("filter", chainChilli, "-p", "udp", "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
	}
	return nil
}

func (f *IPTablesFirewall) initializeIPv6Rules() error {
	if f.cfg.ExtIf != "" && f.cfg.NetV6.IP != nil {
		f.ip6t.Append("nat", "POSTROUTING", "-s", f.cfg.NetV6.String(), "-o", f.cfg.ExtIf, "-j", "MASQUERADE")
	}

	f.ip6t.Append("nat", "PREROUTING", "-i", f.cfg.TUNDev, "-j", chainChilli)
	f.ip6t.Append("nat", chainChilli, "-j", chainWalledGarden)
	for _, domain := range f.cfg.UAMAllowedV6 {
		f.ip6t.Append("nat", chainWalledGarden, "-d", domain, "-j", "RETURN")
	}
	f.ip6t.Append("nat", chainChilli, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", f.cfg.UAMPort))

	if f.cfg.ClientIsolation {
		f.ip6t.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-o", f.cfg.TUNDev, "-j", "DROP")
	}
	f.ip6t.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-j", chainChilli)
	for _, port := range f.cfg.TCPPorts {
		f.ip6t.Append("filter", chainChilli, "-p", "tcp", "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
	}
	for _, port := range f.cfg.UDPPorts {
		f.ip6t.Append("filter", chainChilli, "-p", "udp", "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
	}
	return nil
}

func (f *IPTablesFirewall) AddAuthenticatedUser(ip net.IP) error {
	var handler IPTables
	if ip.To4() != nil {
		handler = f.ipt
	} else if f.ip6t != nil {
		handler = f.ip6t
	} else {
		return nil
	}

	if err := handler.Insert("nat", chainChilli, 1, "-s", ip.String(), "-j", "RETURN"); err != nil {
		return fmt.Errorf("failed to add nat rule for authenticated user %s: %w", ip, err)
	}
	if err := handler.Insert("filter", chainChilli, 1, "-s", ip.String(), "-j", "RETURN"); err != nil {
		return fmt.Errorf("failed to add filter rule for authenticated user %s: %w", ip, err)
	}

	f.logger.Info().Str("ip", ip.String()).Msg("Added iptables rules for authenticated user")
	return nil
}

func (f *IPTablesFirewall) RemoveAuthenticatedUser(ip net.IP) error {
	var handler IPTables
	if ip.To4() != nil {
		handler = f.ipt
	} else if f.ip6t != nil {
		handler = f.ip6t
	} else {
		return nil
	}

	if err := handler.Delete("nat", chainChilli, "-s", ip.String(), "-j", "RETURN"); err != nil {
		f.logger.Warn().Err(err).Msgf("failed to delete nat rule for user %s", ip)
	}
	if err := handler.Delete("filter", chainChilli, "-s", ip.String(), "-j", "RETURN"); err != nil {
		f.logger.Warn().Err(err).Msgf("failed to delete filter rule for user %s", ip)
	}

	f.logger.Info().Str("ip", ip.String()).Msg("Removed iptables rules for user")
	return nil
}

func (f *IPTablesFirewall) Cleanup() {
	f.logger.Info().Msg("Cleaning up iptables rules...")
	f.cleanupHandler(f.ipt, f.cfg.Net.String(), false)

	if f.ip6t != nil {
		var netV6 string
		if f.cfg.NetV6.IP != nil {
			netV6 = f.cfg.NetV6.String()
		}
		f.cleanupHandler(f.ip6t, netV6, true)
	}
}

func (f *IPTablesFirewall) cleanupHandler(handler IPTables, network string, isIPv6 bool) {
	if f.cfg.ExtIf != "" && network != "" {
		handler.Delete("nat", "POSTROUTING", "-s", network, "-o", f.cfg.ExtIf, "-j", "MASQUERADE")
	}
	handler.Delete("nat", "PREROUTING", "-i", f.cfg.TUNDev, "-j", chainChilli)
	handler.Delete("filter", "FORWARD", "-i", f.cfg.TUNDev, "-j", chainChilli)
	if f.cfg.ClientIsolation {
		handler.Delete("filter", "FORWARD", "-i", f.cfg.TUNDev, "-o", f.cfg.TUNDev, "-j", "DROP")
	}

	for _, chain := range []string{chainChilli, chainWalledGarden} {
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