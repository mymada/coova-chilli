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
	f.logger.Warn().Msg("NAT/Masquerading must be configured manually in /etc/ufw/before.rules for full functionality.")

	// Ensure ufw is active
	if err := f.runUfwCmd("enable"); err != nil {
		// This might fail if it's already enabled, which is fine.
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

	// Walled garden rules
	for _, domain := range f.cfg.UAMAllowed {
		f.runUfwCmd("allow", "to", domain)
	}
	for _, domain := range f.cfg.UAMAllowedV6 {
		f.runUfwCmd("allow", "to", domain)
	}

	// Allow all traffic from the TUN device to pass through the FORWARD chain initially.
	// Authenticated user rules will be inserted at the top to bypass this.
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

	f.logger.Info().Msg("ufw cleanup complete. Note: Authenticated user rules are not removed on cleanup, only on disconnect.")
}