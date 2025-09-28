package firewall

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"coovachilli-go/pkg/config"
	"github.com/coreos/go-iptables/iptables"
	"github.com/rs/zerolog"
)

// UserRuleManager defines the interface for managing firewall rules for a user.
type UserRuleManager interface {
	AddAuthenticatedUser(ip net.IP, bandwidthMaxUp uint64, bandwidthMaxDown uint64) error
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
			if protocol == "IPv6" && table == "nat" {
				if _, err := handler.ListChains(table); err != nil {
					if strings.Contains(err.Error(), "No such file or directory") || strings.Contains(err.Error(), "table nat does not exist") {
						f.logger.Warn().Err(err).Msg("IPv6 NAT table not supported, disabling IPv6 firewall.")
						f.ip6t = nil // Permanently disable for this run.
						return nil
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

// runCommand executes a shell command and logs its output.
func (f *Firewall) runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		f.logger.Error().Err(err).Str("cmd", name+" "+strings.Join(args, " ")).Bytes("output", output).Msg("Command execution failed")
		return fmt.Errorf("command '%s' failed: %w, output: %s", cmd.String(), err, output)
	}
	f.logger.Debug().Str("cmd", name+" "+strings.Join(args, " ")).Bytes("output", output).Msg("Command executed successfully")
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
		if f.ip6t != nil {
			f.initializeIPv6Rules()
		}
	}

	// === Traffic Control (TC) Setup ===
	// Delete any existing root qdisc to start clean.
	f.runCommand("tc", "qdisc", "del", "dev", f.cfg.TUNDev, "root") // Ignore error, it might not exist
	// Add a root HTB qdisc. This is the foundation for rate limiting.
	if err := f.runCommand("tc", "qdisc", "add", "dev", f.cfg.TUNDev, "root", "handle", "1:", "htb", "default", "10"); err != nil {
		f.logger.Error().Err(err).Msg("Failed to setup root TC HTB qdisc. Bandwidth shaping will be disabled.")
		// Don't return an error, as the firewall might still be useful.
	}


	f.logger.Info().Msg("Firewall initialized successfully")
	return nil
}

func (f *Firewall) initializeIPv4Rules() error {
	// === NAT Table Rules ===
	// Standard MASQUERADE rule for outbound traffic
	if f.cfg.ExtIf != "" {
		f.ipt.Append("nat", "POSTROUTING", "-s", f.cfg.Net.String(), "-o", f.cfg.ExtIf, "-j", "MASQUERADE")
	}

	// Redirect unauthenticated web traffic to the captive portal
	f.ipt.Append("nat", "PREROUTING", "-i", f.cfg.TUNDev, "-j", chainChilli)
	// Note: Authenticated users will get a "RETURN" rule inserted at the top of this chain
	f.ipt.Append("nat", chainChilli, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", f.cfg.UAMPort))
	// Optional: Add a rule for HTTPS redirection here if needed in the future

	// === Filter Table Rules ===
	if f.cfg.ClientIsolation {
		f.ipt.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-o", f.cfg.TUNDev, "-j", "DROP")
	}

	// Main entry point for filtering traffic from clients
	f.ipt.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-j", chainChilli)

	// --- chilli chain rules (order is important) ---
	// Note: Authenticated users will get a "RETURN" rule inserted at the top of this chain

	// 1. Allow traffic to the walled garden
	f.ipt.Append("filter", chainChilli, "-j", chainWalledGarden)

	// 2. Allow traffic necessary for the captive portal to function
	f.ipt.Append("filter", chainChilli, "-p", "udp", "--dport", "53", "-j", "ACCEPT") // DNS
	f.ipt.Append("filter", chainChilli, "-p", "tcp", "--dport", "53", "-j", "ACCEPT") // DNS
	f.ipt.Append("filter", chainChilli, "-p", "udp", "--dport", "67", "-j", "ACCEPT") // DHCP
	if f.cfg.UAMListen != nil {
		f.ipt.Append("filter", chainChilli, "-d", f.cfg.UAMListen.String(), "-p", "tcp", "--dport", fmt.Sprintf("%d", f.cfg.UAMPort), "-j", "ACCEPT")
	}

	// 3. Drop all other traffic from unauthenticated users
	f.ipt.Append("filter", chainChilli, "-j", "DROP")

	// --- walled_garden chain rules ---
	// Populate the walled garden with allowed destinations
	for _, dest := range f.cfg.UAMAllowed {
		f.ipt.Append("filter", chainWalledGarden, "-d", dest, "-j", "ACCEPT")
	}
	// TODO: Add support for UAMDomains by resolving them to IPs and adding them here

	return nil
}

func (f *Firewall) initializeIPv6Rules() error {
	// === NAT Table Rules ===
	if f.cfg.ExtIf != "" && f.cfg.NetV6.IP != nil {
		f.ip6t.Append("nat", "POSTROUTING", "-s", f.cfg.NetV6.String(), "-o", f.cfg.ExtIf, "-j", "MASQUERADE")
	}
	f.ip6t.Append("nat", "PREROUTING", "-i", f.cfg.TUNDev, "-j", chainChilli)
	f.ip6t.Append("nat", chainChilli, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", f.cfg.UAMPort))

	// === Filter Table Rules ===
	if f.cfg.ClientIsolation {
		f.ip6t.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-o", f.cfg.TUNDev, "-j", "DROP")
	}
	f.ip6t.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-j", chainChilli)

	// --- chilli chain rules ---
	f.ip6t.Append("filter", chainChilli, "-j", chainWalledGarden)
	f.ip6t.Append("filter", chainChilli, "-p", "udp", "--dport", "53", "-j", "ACCEPT")
	f.ip6t.Append("filter", chainChilli, "-p", "tcp", "--dport", "53", "-j", "ACCEPT")
	f.ip6t.Append("filter", chainChilli, "-p", "udp", "--dport", "547", "-j", "ACCEPT") // DHCPv6
	if f.cfg.UAMListenV6 != nil {
		f.ip6t.Append("filter", chainChilli, "-d", f.cfg.UAMListenV6.String(), "-p", "tcp", "--dport", fmt.Sprintf("%d", f.cfg.UAMPort), "-j", "ACCEPT")
	}
	f.ip6t.Append("filter", chainChilli, "-j", "DROP")

	// --- walled_garden chain rules ---
	for _, dest := range f.cfg.UAMAllowedV6 {
		f.ip6t.Append("filter", chainWalledGarden, "-d", dest, "-j", "ACCEPT")
	}

	return nil
}

// AddAuthenticatedUser adds firewall rules to allow traffic for an authenticated user.
func (f *Firewall) AddAuthenticatedUser(ip net.IP, bandwidthMaxUp uint64, bandwidthMaxDown uint64) error {
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

	// Apply bandwidth shaping for download (egress on tun dev)
	if bandwidthMaxDown > 0 {
		ipBytes := ip.To4()
		if ipBytes != nil {
			// Use the last octet of the IP as a simple unique handle.
			handle := ipBytes[3]
			rate := bandwidthMaxDown / 1000 // tc uses kbit
			if rate == 0 {
				rate = 1 // Minimum rate of 1kbit
			}

			classID := fmt.Sprintf("1:%x", handle)
			f.logger.Debug().Str("ip", ip.String()).Str("rate", fmt.Sprintf("%dkbit", rate)).Str("classid", classID).Msg("Applying download bandwidth limit")

			// Create a new class for the user under the root HTB qdisc
			if err := f.runCommand("tc", "class", "add", "dev", f.cfg.TUNDev, "parent", "1:", "classid", classID, "htb", "rate", fmt.Sprintf("%dkbit", rate)); err != nil {
				f.logger.Error().Err(err).Msg("Failed to add TC class for user")
			}

			// Create a filter to direct packets for this user's IP to the new class
			if err := f.runCommand("tc", "filter", "add", "dev", f.cfg.TUNDev, "protocol", "ip", "parent", "1:0", "prio", "1", "u32", "match", "ip", "dst", ip.String()+"/32", "flowid", classID); err != nil {
				f.logger.Error().Err(err).Msg("Failed to add TC filter for user")
			}
		}
	}
	// Note: Upload shaping (ingress on tun dev) is more complex and requires an IFB device. Not implemented.

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
		return nil
	}

	// Remove TC rules first. Ignore errors as they might not exist if bandwidth was 0.
	ipBytes := ip.To4()
	if ipBytes != nil {
		handle := ipBytes[3]
		classID := fmt.Sprintf("1:%x", handle)
		f.logger.Debug().Str("ip", ip.String()).Str("classid", classID).Msg("Removing bandwidth limit")
		f.runCommand("tc", "filter", "del", "dev", f.cfg.TUNDev, "protocol", "ip", "parent", "1:0", "prio", "1", "u32", "match", "ip", "dst", ip.String()+"/32", "flowid", classID)
		f.runCommand("tc", "class", "del", "dev", f.cfg.TUNDev, "parent", "1:", "classid", classID)
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

	// Cleanup TC rules. Ignore errors as the qdisc might not exist.
	f.runCommand("tc", "qdisc", "del", "dev", f.cfg.TUNDev, "root")

	f.cleanupHandler(f.ipt, f.cfg.Net.String(), false)

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