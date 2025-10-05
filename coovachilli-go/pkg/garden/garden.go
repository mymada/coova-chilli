package garden

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/firewall"
	"github.com/rs/zerolog"
)

// Garden handles the walled garden functionality, allowing unauthenticated users
// to access specific domains and networks.
type Garden struct {
	cfg        *config.WalledGardenConfig
	fw         firewall.FirewallManager
	logger     zerolog.Logger
	mu         sync.RWMutex
	allowedIPs map[string]struct{}
	resolver   *net.Resolver
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewGarden creates and initializes a new Garden service.
// It takes the walled garden configuration, a firewall manager to apply rules,
// and a logger.
func NewGarden(cfg *config.WalledGardenConfig, fw firewall.FirewallManager, logger zerolog.Logger) *Garden {
	ctx, cancel := context.WithCancel(context.Background())
	g := &Garden{
		cfg:        cfg,
		fw:         fw,
		logger:     logger.With().Str("component", "garden").Logger(),
		allowedIPs: make(map[string]struct{}),
		resolver:   net.DefaultResolver,
		ctx:        ctx,
		cancel:     cancel,
	}
	return g
}

// Start begins the Garden service.
// It performs an initial setup of firewall rules for static networks and domains,
// and then starts a background goroutine to periodically re-resolve domain names
// to keep the IP whitelist up to date.
func (g *Garden) Start() {
	g.logger.Info().Msg("Starting walled garden service")
	g.initialSetup()

	go func() {
		// Periodically re-resolve domains to catch IP changes.
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				g.resolveAndApplyDomains()
			case <-g.ctx.Done():
				g.logger.Info().Msg("Stopping walled garden service")
				return
			}
		}
	}()
}

// Stop gracefully terminates the Garden service and its background goroutines.
func (g *Garden) Stop() {
	g.cancel()
}

// initialSetup processes the static configuration (allowed networks and domains)
// at startup.
func (g *Garden) initialSetup() {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Process statically configured networks
	for _, network := range g.cfg.AllowedNetworks {
		g.logger.Debug().Str("network", network).Msg("Adding allowed network to firewall")
		if err := g.fw.AddWalledGardenNetwork(network); err != nil {
			g.logger.Error().Err(err).Str("network", network).Msg("Failed to add network to walled garden")
		}
	}

	// Initial resolution of domains
	g.resolveAndApplyDomainsLocked()
}

// resolveAndApplyDomains resolves all configured domain names and updates the firewall.
func (g *Garden) resolveAndApplyDomains() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.resolveAndApplyDomainsLocked()
}

// resolveAndApplyDomainsLocked performs the domain resolution. Must be called with the mutex held.
func (g *Garden) resolveAndApplyDomainsLocked() {
    for _, domain := range g.cfg.AllowedDomains {
		// Wildcard domains are handled by DNS proxy, not pre-resolution
		if strings.HasPrefix(domain, "*") {
			continue
		}

		g.logger.Debug().Str("domain", domain).Msg("Resolving domain for walled garden")
		ips, err := g.resolver.LookupHost(g.ctx, domain)
		if err != nil {
			g.logger.Warn().Err(err).Str("domain", domain).Msg("Failed to resolve domain")
			continue
		}

		for _, ip := range ips {
			if _, exists := g.allowedIPs[ip]; !exists {
				g.logger.Info().Str("domain", domain).Str("ip", ip).Msg("New IP resolved for domain, adding to walled garden")
				if err := g.fw.AddWalledGardenIP(ip); err != nil {
					g.logger.Error().Err(err).Str("ip", ip).Msg("Failed to add IP to walled garden firewall rule")
				} else {
					g.allowedIPs[ip] = struct{}{}
				}
			}
		}
	}
}


// HandleDNSResponse is called by the DNS proxy when a response is generated.
// If the queried domain is in the walled garden, the resulting IP is added to the firewall.
func (g *Garden) HandleDNSResponse(domain string, ips []net.IP) {
	if !g.isDomainAllowed(domain) {
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	for _, ip := range ips {
		ipStr := ip.String()
		if _, exists := g.allowedIPs[ipStr]; !exists {
			g.logger.Info().Str("domain", domain).Str("ip", ipStr).Msg("Dynamically adding IP to walled garden from DNS response")
			if err := g.fw.AddWalledGardenIP(ipStr); err != nil {
				g.logger.Error().Err(err).Str("ip", ipStr).Msg("Failed to add IP to walled garden firewall rule")
			} else {
				g.allowedIPs[ipStr] = struct{}{}
			}
		}
	}
}

// isDomainAllowed checks if a given domain matches the list of allowed domains,
// including wildcard support.
func (g *Garden) isDomainAllowed(domain string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, allowed := range g.cfg.AllowedDomains {
		if strings.HasPrefix(allowed, "*.") {
			suffix := strings.TrimPrefix(allowed, "*")
			if strings.HasSuffix(domain, suffix) {
				return true
			}
		} else if domain == allowed {
			return true
		}
	}
	return false
}