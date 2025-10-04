package firewall

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
)

// UfwFirewall manages firewall rules using the ufw command.
type UfwFirewall struct {
	cfg    *config.Config
	logger zerolog.Logger
}

func newUfwFirewall(cfg *config.Config, logger zerolog.Logger) (*UfwFirewall, error) {
	return &UfwFirewall{
		cfg:    cfg,
		logger: logger,
	}, nil
}

var ufwCommand = exec.Command

func (f *UfwFirewall) runUfwCmd(args ...string) error {
	cmd := ufwCommand("ufw", args...)
	f.logger.Debug().Str("command", cmd.String()).Msg("Executing ufw command")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ufw command failed: %s, output: %s, error: %w", cmd.String(), string(output), err)
	}
	return nil
}

func (f *UfwFirewall) Initialize() error {
	f.logger.Info().Msg("Initializing ufw firewall rules")
	f.logger.Warn().Msg("NAT/Masquerading and DNS redirection must be configured manually in /etc/ufw/before.rules for full functionality.")

	// Ensure ufw is active
	if err := f.runUfwCmd("enable"); err != nil {
		if !strings.Contains(err.Error(), "Firewall is already active") {
			return fmt.Errorf("failed to enable ufw: %w", err)
		}
	}

	// Set basic policies
	f.runUfwCmd("default", "deny", "incoming")
	f.runUfwCmd("default", "allow", "outgoing")
	f.runUfwCmd("default", "deny", "forward")

	// Allow traffic to the UAM server
	f.runUfwCmd("allow", fmt.Sprintf("%d/tcp", f.cfg.UAMPort))
	if f.cfg.UAMUIPort > 0 {
		f.runUfwCmd("allow", fmt.Sprintf("%d/tcp", f.cfg.UAMUIPort))
	}

	// --- DNS Handling ---
	// For the walled garden to work with domain names, we must intercept DNS traffic.
	// UFW doesn't support REDIRECT targets easily. This needs to be done in before.rules.
	// Example for /etc/ufw/before.rules:
	// *nat
	// :PREROUTING ACCEPT [0:0]
	// -A PREROUTING -i <tundev> -p udp --dport 53 -j REDIRECT --to-port <dns_proxy_port>
	// -A PREROUTING -i <tundev> -p tcp --dport 53 -j REDIRECT --to-port <dns_proxy_port>
	// COMMIT
	f.logger.Warn().Msg("UFW requires manual configuration in before.rules to redirect DNS for walled garden domains.")

	// Allow traffic to our DNS servers (for DNS proxying)
	if f.cfg.DNS1 != nil {
		f.runUfwCmd("allow", "out", "on", f.cfg.ExtIf, "to", f.cfg.DNS1.String(), "port", "53")
	}
	if f.cfg.DNS2 != nil {
		f.runUfwCmd("allow", "out", "on", f.cfg.ExtIf, "to", f.cfg.DNS2.String(), "port", "53")
	}

	// --- Walled garden rules (legacy) ---
	for _, domain := range f.cfg.UAMAllowed {
		f.runUfwCmd("allow", "to", domain)
	}
	for _, domain := range f.cfg.UAMAllowedV6 {
		f.runUfwCmd("allow", "to", domain)
	}

	// Allow all traffic from the TUN device to pass through the FORWARD chain initially.
	// This is a broad rule; specific authenticated/unauthenticated rules will precede it.
	f.runUfwCmd("route", "allow", "in", "on", f.cfg.TUNDev)

	f.logger.Info().Msg("ufw firewall initialized successfully")
	return nil
}

func (f *UfwFirewall) AddAuthenticatedUser(ip net.IP) error {
	// Insert rule at the top to allow all traffic from the authenticated IP
	rule := []string{"insert", "1", "route", "allow", "in", "on", f.cfg.TUNDev, "from", ip.String()}
	if err := f.runUfwCmd(rule...); err != nil {
		return fmt.Errorf("failed to add ufw rule for authenticated user %s: %w", ip, err)
	}
	f.logger.Info().Str("ip", ip.String()).Msg("Added ufw rules for authenticated user")
	return nil
}

func (f *UfwFirewall) RemoveAuthenticatedUser(ip net.IP) error {
	// Delete the corresponding rule
	rule := []string{"delete", "route", "allow", "in", "on", f.cfg.TUNDev, "from", ip.String()}
	if err := f.runUfwCmd(rule...); err != nil {
		// Don't return an error if the rule doesn't exist, just log it.
		f.logger.Warn().Err(err).Msgf("failed to delete ufw rule for user %s (it may have already been removed)", ip)
	}
	f.logger.Info().Str("ip", ip.String()).Msg("Removed ufw rules for user")
	return nil
}

// AddWalledGardenNetwork adds a network (CIDR or single IP) to the walled garden.
func (f *UfwFirewall) AddWalledGardenNetwork(network string) error {
	// ufw is generally smart enough to handle CIDR or single IPs
	if err := f.runUfwCmd("allow", "to", network); err != nil {
		return fmt.Errorf("failed to add ufw walled garden rule for network %s: %w", network, err)
	}
	f.logger.Info().Str("network", network).Msg("Added ufw walled garden network")
	return nil
}

// AddWalledGardenIP adds a single IP address to the walled garden.
func (f *UfwFirewall) AddWalledGardenIP(ipStr string) error {
	if err := f.runUfwCmd("allow", "to", ipStr); err != nil {
		return fmt.Errorf("failed to add ufw walled garden rule for IP %s: %w", ipStr, err)
	}
	f.logger.Info().Str("ip", ipStr).Msg("Added ufw walled garden IP")
	return nil
}

// Reconfigure updates the configuration for the UFW firewall.
func (f *UfwFirewall) Reconfigure(newConfig *config.Config) error {
	f.logger.Info().Msg("Reconfiguring UFW firewall...")

	// Remove old UAMAllowed rules
	for _, domain := range f.cfg.UAMAllowed {
		f.runUfwCmd("delete", "allow", "to", domain)
	}
	for _, domain := range f.cfg.UAMAllowedV6 {
		f.runUfwCmd("delete", "allow", "to", domain)
	}

	// Update the internal config reference
	f.cfg = newConfig

	// Add new UAMAllowed rules (for legacy support)
	for _, domain := range f.cfg.UAMAllowed {
		f.runUfwCmd("allow", "to", domain)
	}
	for _, domain := range f.cfg.UAMAllowedV6 {
		f.runUfwCmd("allow", "to", domain)
	}

	f.logger.Warn().Msg("UFW dynamic reconfiguration is limited. New 'walledgarden' rules are added dynamically, but old ones are not automatically removed on reconfigure. A restart may be needed for a full cleanup.")
	return nil
}

func (f *UfwFirewall) Cleanup() {
	f.logger.Info().Msg("Cleaning up ufw firewall rules...")

	// UAM ports
	f.runUfwCmd("delete", "allow", fmt.Sprintf("%d/tcp", f.cfg.UAMPort))
	if f.cfg.UAMUIPort > 0 {
		f.runUfwCmd("delete", "allow", fmt.Sprintf("%d/tcp", f.cfg.UAMUIPort))
	}

	// Walled garden
	for _, domain := range f.cfg.UAMAllowed {
		f.runUfwCmd("delete", "allow", "to", domain)
	}
	for _, domain := range f.cfg.UAMAllowedV6 {
		f.runUfwCmd("delete", "allow", "to", domain)
	}

	// General TUN rule
	f.runUfwCmd("delete", "route", "allow", "in", "on", f.cfg.TUNDev)

	f.logger.Info().Msg("ufw cleanup complete. Note: Authenticated user and dynamically added walled garden rules are not removed on general cleanup, only on disconnect or restart.")
}