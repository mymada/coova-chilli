package firewall

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"coovachilli-go/pkg/config"
	"github.com/coreos/go-iptables/iptables"
	"github.com/rs/zerolog"
)

// UserRuleManager defines the interface for managing firewall rules for a user.
type UserRuleManager interface {
	AddAuthenticatedUser(ip net.IP, bandwidthMaxUp uint64, bandwidthMaxDown uint64) error
	RemoveAuthenticatedUser(ip net.IP) error
	UpdateUserBandwidth(ip net.IP, bandwidthMaxUp uint64, bandwidthMaxDown uint64) error
	AddToWalledGarden(ip net.IP, ttl uint32) error
	RemoveFromWalledGarden(ip net.IP) error
}

const (
	chainChilli       = "chilli"
	chainWalledGarden = "chilli_walled_garden"
)

// IPTables is an interface that wraps the go-iptables methods used by the firewall.
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

// CommandRunner defines an interface for running external commands.
type CommandRunner interface {
	Run(name string, args ...string) error
}

type dynamicWalledGardenEntry struct {
	IP        net.IP
	ExpiresAt time.Time
}

// realCommandRunner is the actual implementation that executes commands.
type realCommandRunner struct {
	logger zerolog.Logger
}

func (r *realCommandRunner) Run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Don't log error for "del" commands if the object doesn't exist
		if !(strings.Contains(string(output), "No such file or directory") || strings.Contains(string(output), "does not exist")) {
			r.logger.Error().Err(err).Str("cmd", name+" "+strings.Join(args, " ")).Bytes("output", output).Msg("Command execution failed")
		}
		return fmt.Errorf("command '%s' failed: %w, output: %s", cmd.String(), err, output)
	}
	r.logger.Debug().Str("cmd", name+" "+strings.Join(args, " ")).Bytes("output", output).Msg("Command executed successfully")
	return nil
}

// Firewall manages the system's firewall rules.
type Firewall struct {
	cfg                   *config.Config
	ipt                   IPTables
	ip6t                  IPTables
	logger                zerolog.Logger
	runner                CommandRunner
	dynamicWalledGarden   map[string]dynamicWalledGardenEntry
	dynamicWalledGardenMu sync.RWMutex
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
	fwLogger := logger.With().Str("component", "firewall").Logger()
	return &Firewall{
		cfg:                   cfg,
		ipt:                   ipt,
		ip6t:                  ip6t,
		logger:                fwLogger,
		runner:                &realCommandRunner{logger: fwLogger},
		dynamicWalledGarden:   make(map[string]dynamicWalledGardenEntry),
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
						f.ip6t = nil
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

// Initialize sets up the necessary firewall chains and rules.
func (f *Firewall) Initialize() error {
	f.logger.Debug().Msg("Initializing firewall rules")
	if err := f.setupChains(f.ipt, "IPv4"); err != nil {
		return err
	}
	if err := f.initializeIPv4Rules(); err != nil {
		return err
	}
	if f.ip6t != nil {
		if err := f.setupChains(f.ip6t, "IPv6"); err != nil {
			return err
		}
		if err := f.initializeIPv6Rules(); err != nil {
			return err
		}
	}

	f.logger.Info().Msg("Setting up TC for download shaping")
	_ = f.runner.Run("tc", "qdisc", "del", "dev", f.cfg.TUNDev, "root")
	if err := f.runner.Run("tc", "qdisc", "add", "dev", f.cfg.TUNDev, "root", "handle", "1:", "htb", "default", "10"); err != nil {
		f.logger.Error().Err(err).Msg("Failed to setup root TC HTB qdisc on TUN device. Download shaping will be disabled.")
	}

	f.logger.Info().Msg("Setting up IFB device and TC for upload shaping")
	ifbDev := "ifb0"
	if err := f.runner.Run("modprobe", "ifb"); err != nil {
		f.logger.Warn().Err(err).Msg("Failed to run modprobe for ifb. Module may be built-in, continuing.")
	}
	if err := f.runner.Run("ip", "link", "set", ifbDev, "up"); err != nil {
		f.logger.Error().Err(err).Msg("Failed to bring up IFB device. Upload shaping will be disabled.")
	} else {
		_ = f.runner.Run("tc", "qdisc", "del", "dev", ifbDev, "root")
		if err := f.runner.Run("tc", "qdisc", "add", "dev", ifbDev, "root", "handle", "2:", "htb", "default", "10"); err != nil {
			f.logger.Error().Err(err).Msg("Failed to setup root TC HTB qdisc on IFB device. Upload shaping will be disabled.")
		} else {
			_ = f.runner.Run("tc", "qdisc", "del", "dev", f.cfg.TUNDev, "ingress")
			if err := f.runner.Run("tc", "qdisc", "add", "dev", f.cfg.TUNDev, "handle", "ffff:", "ingress"); err != nil {
				f.logger.Error().Err(err).Msg("Failed to add ingress qdisc to TUN device. Upload shaping will be disabled.")
			} else {
				if err := f.runner.Run("tc", "filter", "add", "dev", f.cfg.TUNDev, "parent", "ffff:", "protocol", "ip", "u32", "match", "u32", "0", "0", "action", "mirred", "egress", "redirect", "dev", ifbDev); err != nil {
					f.logger.Error().Err(err).Msg("Failed to add filter to redirect ingress traffic to IFB. Upload shaping will be disabled.")
				}
			}
		}
	}
	go f.runWalledGardenReaper()
	f.logger.Info().Msg("Firewall initialized successfully")
	return nil
}

func (f *Firewall) initializeIPv4Rules() error {
	if f.cfg.ExtIf != "" {
		_ = f.ipt.Append("nat", "POSTROUTING", "-s", f.cfg.Net.String(), "-o", f.cfg.ExtIf, "-j", "MASQUERADE")
	}
	_ = f.ipt.Append("nat", "PREROUTING", "-i", f.cfg.TUNDev, "-j", chainChilli)
	_ = f.ipt.Append("nat", chainChilli, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", f.cfg.UAMPort))
	if f.cfg.ClientIsolation {
		_ = f.ipt.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-o", f.cfg.TUNDev, "-j", "DROP")
	}
	_ = f.ipt.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-j", chainChilli)
	_ = f.ipt.Append("filter", chainChilli, "-j", chainWalledGarden)
	_ = f.ipt.Append("filter", chainChilli, "-p", "udp", "--dport", "53", "-j", "ACCEPT")
	_ = f.ipt.Append("filter", chainChilli, "-p", "tcp", "--dport", "53", "-j", "ACCEPT")
	_ = f.ipt.Append("filter", chainChilli, "-p", "udp", "--dport", "67", "-j", "ACCEPT")
	if f.cfg.UAMListen != nil {
		_ = f.ipt.Append("filter", chainChilli, "-d", f.cfg.UAMListen.String(), "-p", "tcp", "--dport", fmt.Sprintf("%d", f.cfg.UAMPort), "-j", "ACCEPT")
	}
	_ = f.ipt.Append("filter", chainChilli, "-j", "DROP")
	for _, dest := range f.cfg.UAMAllowed {
		_ = f.ipt.Append("filter", chainWalledGarden, "-d", dest, "-j", "ACCEPT")
	}
	return nil
}

func (f *Firewall) initializeIPv6Rules() error {
	if f.cfg.ExtIf != "" && f.cfg.NetV6.IP != nil {
		_ = f.ip6t.Append("nat", "POSTROUTING", "-s", f.cfg.NetV6.String(), "-o", f.cfg.ExtIf, "-j", "MASQUERADE")
	}
	_ = f.ip6t.Append("nat", "PREROUTING", "-i", f.cfg.TUNDev, "-j", chainChilli)
	_ = f.ip6t.Append("nat", chainChilli, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", f.cfg.UAMPort))
	if f.cfg.ClientIsolation {
		_ = f.ip6t.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-o", f.cfg.TUNDev, "-j", "DROP")
	}
	_ = f.ip6t.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-j", chainChilli)
	_ = f.ip6t.Append("filter", chainChilli, "-j", chainWalledGarden)
	_ = f.ip6t.Append("filter", chainChilli, "-p", "udp", "--dport", "53", "-j", "ACCEPT")
	_ = f.ip6t.Append("filter", chainChilli, "-p", "tcp", "--dport", "53", "-j", "ACCEPT")
	_ = f.ip6t.Append("filter", chainChilli, "-p", "udp", "--dport", "547", "-j", "ACCEPT")
	if f.cfg.UAMListenV6 != nil {
		_ = f.ip6t.Append("filter", chainChilli, "-d", f.cfg.UAMListenV6.String(), "-p", "tcp", "--dport", fmt.Sprintf("%d", f.cfg.UAMPort), "-j", "ACCEPT")
	}
	_ = f.ip6t.Append("filter", chainChilli, "-j", "DROP")
	for _, dest := range f.cfg.UAMAllowedV6 {
		_ = f.ip6t.Append("filter", chainWalledGarden, "-d", dest, "-j", "ACCEPT")
	}
	return nil
}

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
	if bandwidthMaxDown > 0 {
		ipBytes := ip.To4()
		if ipBytes != nil {
			handle := ipBytes[3]
			rate := bandwidthMaxDown / 1000
			if rate == 0 {
				rate = 1
			}
			classID := fmt.Sprintf("1:%x", handle)
			f.logger.Debug().Str("ip", ip.String()).Str("rate", fmt.Sprintf("%dkbit", rate)).Str("classid", classID).Msg("Applying download bandwidth limit")
			_ = f.runner.Run("tc", "class", "add", "dev", f.cfg.TUNDev, "parent", "1:", "classid", classID, "htb", "rate", fmt.Sprintf("%dkbit", rate))
			_ = f.runner.Run("tc", "filter", "add", "dev", f.cfg.TUNDev, "protocol", "ip", "parent", "1:0", "prio", "1", "u32", "match", "ip", "dst", ip.String()+"/32", "flowid", classID)
		}
	}
	if bandwidthMaxUp > 0 {
		ipBytes := ip.To4()
		if ipBytes != nil {
			ifbDev := "ifb0"
			handle := ipBytes[3]
			rate := bandwidthMaxUp / 1000
			if rate == 0 {
				rate = 1
			}
			classID := fmt.Sprintf("2:%x", handle)
			f.logger.Debug().Str("ip", ip.String()).Str("rate", fmt.Sprintf("%dkbit", rate)).Str("classid", classID).Msg("Applying upload bandwidth limit")
			_ = f.runner.Run("tc", "class", "add", "dev", ifbDev, "parent", "2:", "classid", classID, "htb", "rate", fmt.Sprintf("%dkbit", rate))
			_ = f.runner.Run("tc", "filter", "add", "dev", ifbDev, "protocol", "ip", "parent", "2:0", "prio", "1", "u32", "match", "ip", "src", ip.String()+"/32", "flowid", classID)
		}
	}
	f.logger.Info().Str("ip", ip.String()).Msg("Added firewall rules for authenticated user")
	return nil
}

func (f *Firewall) RemoveAuthenticatedUser(ip net.IP) error {
	var handler IPTables
	if ip.To4() != nil {
		handler = f.ipt
	} else if f.ip6t != nil {
		handler = f.ip6t
	} else {
		return nil
	}
	ipBytes := ip.To4()
	if ipBytes != nil {
		handle := ipBytes[3]
		classIDDown := fmt.Sprintf("1:%x", handle)
		f.logger.Debug().Str("ip", ip.String()).Str("classid", classIDDown).Msg("Removing download bandwidth limit")
		_ = f.runner.Run("tc", "filter", "del", "dev", f.cfg.TUNDev, "protocol", "ip", "parent", "1:0", "prio", "1", "u32", "match", "ip", "dst", ip.String()+"/32", "flowid", classIDDown)
		_ = f.runner.Run("tc", "class", "del", "dev", f.cfg.TUNDev, "parent", "1:", "classid", classIDDown)
		ifbDev := "ifb0"
		classIDUp := fmt.Sprintf("2:%x", handle)
		f.logger.Debug().Str("ip", ip.String()).Str("classid", classIDUp).Msg("Removing upload bandwidth limit")
		_ = f.runner.Run("tc", "filter", "del", "dev", ifbDev, "protocol", "ip", "parent", "2:0", "prio", "1", "u32", "match", "ip", "src", ip.String()+"/32", "flowid", classIDUp)
		_ = f.runner.Run("tc", "class", "del", "dev", ifbDev, "parent", "2:", "classid", classIDUp)
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

func (f *Firewall) AddToWalledGarden(ip net.IP, ttl uint32) error {
	var handler IPTables
	if ip.To4() != nil {
		handler = f.ipt
	} else if f.ip6t != nil {
		handler = f.ip6t
	} else {
		return nil
	}
	ruleSpec := []string{"-d", ip.String(), "-j", "ACCEPT"}
	exists, err := handler.Exists("filter", chainWalledGarden, ruleSpec...)
	if err != nil {
		f.logger.Warn().Err(err).Str("ip", ip.String()).Msg("Failed to check for existing walled garden rule")
	}
	if !exists {
		if err := handler.Append("filter", chainWalledGarden, ruleSpec...); err != nil {
			return fmt.Errorf("failed to add IP %s to walled garden: %w", ip.String(), err)
		}
		f.logger.Info().Str("ip", ip.String()).Uint32("ttl", ttl).Msg("Added IP to dynamic walled garden")
	}
	f.dynamicWalledGardenMu.Lock()
	defer f.dynamicWalledGardenMu.Unlock()
	f.dynamicWalledGarden[ip.String()] = dynamicWalledGardenEntry{
		IP:        ip,
		ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}
	return nil
}

// RemoveFromWalledGarden removes a single IP address from the walled garden chain.
func (f *Firewall) RemoveFromWalledGarden(ip net.IP) error {
	var handler IPTables
	if ip.To4() != nil {
		handler = f.ipt
	} else if f.ip6t != nil {
		handler = f.ip6t
	} else {
		return nil // Neither IPv4 nor IPv6, do nothing
	}

	ruleSpec := []string{"-d", ip.String(), "-j", "ACCEPT"}

	if err := handler.Delete("filter", chainWalledGarden, ruleSpec...); err != nil {
		// Don't return an error if the rule just doesn't exist, but log it.
		if !strings.Contains(err.Error(), "does not exist") {
			return fmt.Errorf("failed to remove IP %s from walled garden: %w", ip.String(), err)
		}
	}

	// Also remove from our dynamic tracking map if it's there
	f.dynamicWalledGardenMu.Lock()
	delete(f.dynamicWalledGarden, ip.String())
	f.dynamicWalledGardenMu.Unlock()

	f.logger.Info().Str("ip", ip.String()).Msg("Removed IP from walled garden")
	return nil
}

func (f *Firewall) runWalledGardenReaper() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		f.reapWalledGardenEntries()
	}
}

func (f *Firewall) reapWalledGardenEntries() {
	f.dynamicWalledGardenMu.Lock()
	defer f.dynamicWalledGardenMu.Unlock()
	now := time.Now()
	for key, entry := range f.dynamicWalledGarden {
		if now.After(entry.ExpiresAt) {
			f.logger.Info().Str("ip", entry.IP.String()).Msg("Walled garden entry expired, removing rule")
			var handler IPTables
			if entry.IP.To4() != nil {
				handler = f.ipt
			} else if f.ip6t != nil {
				handler = f.ip6t
			}
			if handler != nil {
				ruleSpec := []string{"-d", entry.IP.String(), "-j", "ACCEPT"}
				if err := handler.Delete("filter", chainWalledGarden, ruleSpec...); err != nil {
					f.logger.Warn().Err(err).Str("ip", entry.IP.String()).Msg("Failed to delete expired walled garden rule")
				}
			}
			delete(f.dynamicWalledGarden, key)
		}
	}
}

func (f *Firewall) UpdateUserBandwidth(ip net.IP, bandwidthMaxUp uint64, bandwidthMaxDown uint64) error {
	ipBytes := ip.To4()
	if ipBytes == nil {
		f.logger.Warn().Str("ip", ip.String()).Msg("Bandwidth shaping currently only supported for IPv4")
		return nil
	}
	handle := ipBytes[3]
	if bandwidthMaxDown > 0 {
		rate := bandwidthMaxDown / 1000
		if rate == 0 {
			rate = 1
		}
		classID := fmt.Sprintf("1:%x", handle)
		f.logger.Info().Str("ip", ip.String()).Str("rate", fmt.Sprintf("%dkbit", rate)).Str("classid", classID).Msg("Changing download bandwidth limit")
		if err := f.runner.Run("tc", "class", "change", "dev", f.cfg.TUNDev, "parent", "1:", "classid", classID, "htb", "rate", fmt.Sprintf("%dkbit", rate)); err != nil {
			f.logger.Error().Err(err).Msg("Failed to change TC class for user download shaping")
		}
	}
	if bandwidthMaxUp > 0 {
		ifbDev := "ifb0"
		rate := bandwidthMaxUp / 1000
		if rate == 0 {
			rate = 1
		}
		classID := fmt.Sprintf("2:%x", handle)
		f.logger.Info().Str("ip", ip.String()).Str("rate", fmt.Sprintf("%dkbit", rate)).Str("classid", classID).Msg("Changing upload bandwidth limit")
		if err := f.runner.Run("tc", "class", "change", "dev", ifbDev, "parent", "2:", "classid", classID, "htb", "rate", fmt.Sprintf("%dkbit", rate)); err != nil {
			f.logger.Error().Err(err).Msg("Failed to change TC class for user upload shaping")
		}
	}
	return nil
}

func (f *Firewall) Cleanup() {
	f.logger.Info().Msg("Cleaning up firewall and TC rules...")
	ifbDev := "ifb0"
	f.logger.Info().Msg("Deleting TC rules and qdiscs...")
	_ = f.runner.Run("tc", "qdisc", "del", "dev", f.cfg.TUNDev, "root")
	_ = f.runner.Run("tc", "qdisc", "del", "dev", f.cfg.TUNDev, "ingress")
	_ = f.runner.Run("tc", "qdisc", "del", "dev", ifbDev, "root")
	f.logger.Info().Msg("Bringing down IFB device...")
	_ = f.runner.Run("ip", "link", "set", ifbDev, "down")
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
		_ = handler.Delete("nat", "POSTROUTING", "-s", network, "-o", f.cfg.ExtIf, "-j", "MASQUERADE")
	}
	_ = handler.Delete("nat", "PREROUTING", "-i", f.cfg.TUNDev, "-j", chainChilli)
	_ = handler.Delete("filter", "FORWARD", "-i", f.cfg.TUNDev, "-j", chainChilli)
	if f.cfg.ClientIsolation {
		_ = handler.Delete("filter", "FORWARD", "-i", f.cfg.TUNDev, "-o", f.cfg.TUNDev, "-j", "DROP")
	}
	for _, chain := range []string{chainChilli, chainWalledGarden} {
		if isIPv6 {
			if _, err := handler.ListChains("nat"); err == nil {
				_ = handler.ClearChain("nat", chain)
				_ = handler.DeleteChain("nat", chain)
			}
		} else {
			_ = handler.ClearChain("nat", chain)
			_ = handler.DeleteChain("nat", chain)
		}
		_ = handler.ClearChain("filter", chain)
		_ = handler.DeleteChain("filter", chain)
	}
}