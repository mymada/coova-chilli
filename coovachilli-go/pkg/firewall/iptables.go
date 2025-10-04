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

	// Main jumps to our chains
	f.ipt.Append("nat", "PREROUTING", "-i", f.cfg.TUNDev, "-j", chainChilli)
	f.ipt.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-j", chainChilli)

	// In each chilli chain, first jump to the walled garden sub-chain
	f.ipt.Append("nat", chainChilli, "-j", chainWalledGarden)
	f.ipt.Append("filter", chainChilli, "-j", chainWalledGarden)

	// --- Legacy UAMAllowed (to be deprecated) ---
	// This is for backward compatibility. New logic should use the garden service.
	for _, domain := range f.cfg.UAMAllowed {
		f.ipt.Append("nat", chainWalledGarden, "-d", domain, "-j", "RETURN")
		f.ipt.Append("filter", chainWalledGarden, "-d", domain, "-j", "ACCEPT")
	}

	// --- Portal Redirection ---
	if !f.cfg.UAMAnyIP {
		f.ipt.Append("nat", chainChilli, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", f.cfg.UAMPort))
	} else {
		f.logger.Info().Msg("UAMAnyIP enabled - allowing clients to use static IPs without redirection")
	}

	// --- Unauthenticated Access Control ---
	if f.cfg.ClientIsolation {
		f.ipt.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-o", f.cfg.TUNDev, "-j", "DROP")
	}

	// Allow access to the UAM server itself
	if f.cfg.UAMListen != nil {
		f.ipt.Append("filter", chainChilli, "-d", f.cfg.UAMListen.String(), "-p", "tcp", "--dport", fmt.Sprintf("%d", f.cfg.UAMPort), "-j", "ACCEPT")
		f.ipt.Append("filter", chainChilli, "-d", f.cfg.UAMListen.String(), "-p", "tcp", "--dport", fmt.Sprintf("%d", f.cfg.UAMUIPort), "-j", "ACCEPT")
	}

	// Allow DNS traffic if uamanydns is enabled
	if f.cfg.UAMAnyDNS {
		f.logger.Info().Msg("UAMAnyDNS enabled - allowing all DNS traffic")
		f.ipt.Append("filter", chainChilli, "-p", "udp", "--dport", "53", "-j", "ACCEPT")
		f.ipt.Append("filter", chainChilli, "-p", "tcp", "--dport", "53", "-j", "ACCEPT")
	}

	// Allow other configured ports
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
		if _, err := f.ip6t.ListChains("nat"); err == nil {
			f.ip6t.Append("nat", "POSTROUTING", "-s", f.cfg.NetV6.String(), "-o", f.cfg.ExtIf, "-j", "MASQUERADE")
		}
	}

	// Main jumps to our chains
	if _, err := f.ip6t.ListChains("nat"); err == nil {
		f.ip6t.Append("nat", "PREROUTING", "-i", f.cfg.TUNDev, "-j", chainChilli)
		f.ip6t.Append("nat", chainChilli, "-j", chainWalledGarden)
	}
	f.ip6t.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-j", chainChilli)
	f.ip6t.Append("filter", chainChilli, "-j", chainWalledGarden)

	// --- Legacy UAMAllowedV6 (to be deprecated) ---
	for _, domain := range f.cfg.UAMAllowedV6 {
		if _, err := f.ip6t.ListChains("nat"); err == nil {
			f.ip6t.Append("nat", chainWalledGarden, "-d", domain, "-j", "RETURN")
		}
		f.ip6t.Append("filter", chainWalledGarden, "-d", domain, "-j", "ACCEPT")
	}

	// --- Portal Redirection ---
	if !f.cfg.UAMAnyIP {
		if _, err := f.ip6t.ListChains("nat"); err == nil {
			f.ip6t.Append("nat", chainChilli, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", f.cfg.UAMPort))
		}
	} else {
		f.logger.Info().Msg("UAMAnyIP enabled for IPv6 - allowing clients to use static IPs without redirection")
	}

	// --- Unauthenticated Access Control ---
	if f.cfg.ClientIsolation {
		f.ip6t.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-o", f.cfg.TUNDev, "-j", "DROP")
	}

	// Allow access to the UAM server itself
	if f.cfg.UAMListenV6 != nil {
		f.ip6t.Append("filter", chainChilli, "-d", f.cfg.UAMListenV6.String(), "-p", "tcp", "--dport", fmt.Sprintf("%d", f.cfg.UAMPort), "-j", "ACCEPT")
		f.ip6t.Append("filter", chainChilli, "-d", f.cfg.UAMListenV6.String(), "-p", "tcp", "--dport", fmt.Sprintf("%d", f.cfg.UAMUIPort), "-j", "ACCEPT")
	}

	// Allow DNS traffic if uamanydns is enabled
	if f.cfg.UAMAnyDNS {
		f.logger.Info().Msg("UAMAnyDNS enabled for IPv6 - allowing all DNS traffic")
		f.ip6t.Append("filter", chainChilli, "-p", "udp", "--dport", "53", "-j", "ACCEPT")
		f.ip6t.Append("filter", chainChilli, "-p", "tcp", "--dport", "53", "-j", "ACCEPT")
	}

	// Allow other configured ports
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
	var isIPv6 bool
	if ip.To4() != nil {
		handler = f.ipt
		isIPv6 = false
	} else if f.ip6t != nil {
		handler = f.ip6t
		isIPv6 = true
	} else {
		return nil
	}

	if !isIPv6 || (isIPv6 && f.ip6t != nil) {
		if _, err := handler.ListChains("nat"); err == nil {
			if err := handler.Insert("nat", chainChilli, 1, "-s", ip.String(), "-j", "RETURN"); err != nil {
				return fmt.Errorf("failed to add nat rule for authenticated user %s: %w", ip, err)
			}
		}
	}

	if err := handler.Insert("filter", chainChilli, 1, "-s", ip.String(), "-j", "RETURN"); err != nil {
		return fmt.Errorf("failed to add filter rule for authenticated user %s: %w", ip, err)
	}

	f.logger.Info().Str("ip", ip.String()).Msg("Added iptables rules for authenticated user")
	return nil
}

func (f *IPTablesFirewall) RemoveAuthenticatedUser(ip net.IP) error {
	var handler IPTables
	var isIPv6 bool
	if ip.To4() != nil {
		handler = f.ipt
		isIPv6 = false
	} else if f.ip6t != nil {
		handler = f.ip6t
		isIPv6 = true
	} else {
		return nil
	}

	if !isIPv6 || (isIPv6 && f.ip6t != nil) {
		if _, err := handler.ListChains("nat"); err == nil {
			if err := handler.Delete("nat", chainChilli, "-s", ip.String(), "-j", "RETURN"); err != nil {
				f.logger.Warn().Err(err).Msgf("failed to delete nat rule for user %s", ip)
			}
		}
	}

	if err := handler.Delete("filter", chainChilli, "-s", ip.String(), "-j", "RETURN"); err != nil {
		f.logger.Warn().Err(err).Msgf("failed to delete filter rule for user %s", ip)
	}

	f.logger.Info().Str("ip", ip.String()).Msg("Removed iptables rules for user")
	return nil
}

// Reconfigure applies a new configuration to the firewall.
// It focuses on updating the walled garden rules.
func (f *IPTablesFirewall) Reconfigure(newConfig *config.Config) error {
	f.logger.Info().Msg("Reconfiguring firewall walled garden...")

	// Update the internal configuration reference
	f.cfg = newConfig

	// Re-apply walled garden rules for IPv4
	if err := f.ipt.ClearChain("nat", chainWalledGarden); err != nil {
		return fmt.Errorf("failed to clear IPv4 nat walled garden: %w", err)
	}
	if err := f.ipt.ClearChain("filter", chainWalledGarden); err != nil {
		return fmt.Errorf("failed to clear IPv4 filter walled garden: %w", err)
	}
	for _, domain := range f.cfg.UAMAllowed {
		if err := f.ipt.Append("nat", chainWalledGarden, "-d", domain, "-j", "RETURN"); err != nil {
			f.logger.Error().Err(err).Str("domain", domain).Msg("Failed to add IPv4 nat walled garden rule")
		}
		if err := f.ipt.Append("filter", chainWalledGarden, "-d", domain, "-j", "ACCEPT"); err != nil {
			f.logger.Error().Err(err).Str("domain", domain).Msg("Failed to add IPv4 filter walled garden rule")
		}
	}

	// Re-apply walled garden rules for IPv6
	if f.ip6t != nil {
		if _, err := f.ip6t.ListChains("nat"); err == nil {
			if err := f.ip6t.ClearChain("nat", chainWalledGarden); err != nil {
				f.logger.Error().Err(err).Msg("Failed to clear IPv6 nat walled garden")
			} else {
				for _, domain := range f.cfg.UAMAllowedV6 {
					if err := f.ip6t.Append("nat", chainWalledGarden, "-d", domain, "-j", "RETURN"); err != nil {
						f.logger.Error().Err(err).Str("domain", domain).Msg("Failed to add IPv6 nat walled garden rule")
					}
				}
			}
		}

		if err := f.ip6t.ClearChain("filter", chainWalledGarden); err != nil {
			f.logger.Error().Err(err).Msg("Failed to clear IPv6 filter walled garden")
		} else {
			for _, domain := range f.cfg.UAMAllowedV6 {
				if err := f.ip6t.Append("filter", chainWalledGarden, "-d", domain, "-j", "ACCEPT"); err != nil {
					f.logger.Error().Err(err).Str("domain", domain).Msg("Failed to add IPv6 filter walled garden rule")
				}
			}
		}
	}

	f.logger.Info().Msg("Firewall reconfigured successfully.")
	return nil
}

// AddWalledGardenNetwork adds a network (CIDR or single IP) to the walled garden.
func (f *IPTablesFirewall) AddWalledGardenNetwork(network string) error {
	ip, _, err := net.ParseCIDR(network)
	if err != nil {
		ip = net.ParseIP(network)
		if ip == nil {
			return fmt.Errorf("invalid network/IP address: %s", network)
		}
		network = ip.String()
	}

	var handler IPTables
	isIPv6 := ip.To4() == nil

	if !isIPv6 {
		handler = f.ipt
	} else if f.ip6t != nil {
		handler = f.ip6t
	} else {
		f.logger.Warn().Str("network", network).Msg("No suitable iptables handler for network, rule not added")
		return nil
	}

	f.logger.Debug().Str("network", network).Msg("Adding network to walled garden")
	if !isIPv6 || (isIPv6 && f.ip6t != nil) {
		if _, err := handler.ListChains("nat"); err == nil {
			if err := handler.Insert("nat", chainWalledGarden, 1, "-d", network, "-j", "RETURN"); err != nil {
				return fmt.Errorf("failed to add nat walled garden rule for network %s: %w", network, err)
			}
		}
	}
	if err := handler.Insert("filter", chainWalledGarden, 1, "-d", network, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to add filter walled garden rule for network %s: %w", network, err)
	}
	return nil
}

// AddWalledGardenIP adds a single IP address to the walled garden.
func (f *IPTablesFirewall) AddWalledGardenIP(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipStr)
	}

	var handler IPTables
	isIPv6 := ip.To4() == nil

	if !isIPv6 {
		handler = f.ipt
	} else if f.ip6t != nil {
		handler = f.ip6t
	} else {
		f.logger.Warn().Str("ip", ipStr).Msg("No suitable iptables handler for IP, rule not added")
		return nil
	}

	f.logger.Debug().Str("ip", ipStr).Msg("Adding IP to walled garden")
	if !isIPv6 || (isIPv6 && f.ip6t != nil) {
		if _, err := handler.ListChains("nat"); err == nil {
			if err := handler.Insert("nat", chainWalledGarden, 1, "-d", ipStr, "-j", "RETURN"); err != nil {
				return fmt.Errorf("failed to add nat walled garden rule for IP %s: %w", ipStr, err)
			}
		}
	}
	if err := handler.Insert("filter", chainWalledGarden, 1, "-d", ipStr, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to add filter walled garden rule for IP %s: %w", ipStr, err)
	}
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
		if !isIPv6 || (isIPv6 && f.ip6t != nil) {
			if _, err := handler.ListChains("nat"); err == nil {
				handler.Delete("nat", "POSTROUTING", "-s", network, "-o", f.cfg.ExtIf, "-j", "MASQUERADE")
			}
		}
	}

	if !isIPv6 || (isIPv6 && f.ip6t != nil) {
		if _, err := handler.ListChains("nat"); err == nil {
			handler.Delete("nat", "PREROUTING", "-i", f.cfg.TUNDev, "-j", chainChilli)
		}
	}
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