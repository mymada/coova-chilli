package firewall

import (
	"fmt"
	"net"
	"os/exec"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
)

const (
	chainChilli       = "chilli"
	chainWalledGarden = "chilli_walled_garden"
)

// FirewallManager defines the interface for firewall operations.
type FirewallManager interface {
	Initialize() error
	Cleanup()
	AddAuthenticatedUser(ip net.IP) error
	RemoveAuthenticatedUser(ip net.IP) error
	Reconfigure(newConfig *config.Config) error
}

var lookPath = exec.LookPath

// New creates a new firewall manager, automatically detecting the backend.
func New(cfg *config.Config, logger zerolog.Logger) (FirewallManager, error) {
	log := logger.With().Str("component", "firewall").Logger()

	switch cfg.FirewallBackend {
	case "iptables":
		log.Info().Msg("User explicitly selected 'iptables' firewall backend")
		return newIPTablesFirewall(cfg, log)
	case "ufw":
		log.Info().Msg("User explicitly selected 'ufw' firewall backend")
		return newUfwFirewall(cfg, log)
	case "auto":
		log.Info().Msg("Using 'auto' firewall backend detection")
		if _, err := lookPath("ufw"); err == nil {
			log.Info().Msg("Found 'ufw', using as firewall backend")
			return newUfwFirewall(cfg, log)
		}
		log.Info().Msg("'ufw' not found, falling back to 'iptables'")
		return newIPTablesFirewall(cfg, log)
	default:
		return nil, fmt.Errorf("unknown firewall backend specified: %s", cfg.FirewallBackend)
	}
}