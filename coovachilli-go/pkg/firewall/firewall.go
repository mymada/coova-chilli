package firewall

import (
	"fmt"
	"log"
	"net"

	"coovachilli-go/pkg/config"
	"github.com/coreos/go-iptables/iptables"
)

const (
	chainChilli   = "chilli"
	chainWalledGarden = "chilli_walled_garden"
)

// Firewall manages the system's firewall rules.
type Firewall struct {
	cfg    *config.Config
	ipt    *iptables.IPTables
	ip6t   *iptables.IPTables
}

// NewFirewall creates a new Firewall manager.
func NewFirewall(cfg *config.Config) (*Firewall, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create iptables handler: %w", err)
	}

	// For now, we'll just create the IPv4 handler.
	// A similar handler for ip6tables will be needed for IPv6.
	return &Firewall{
		cfg:    cfg,
		ipt:    ipt,
	}, nil
}

// Initialize sets up the necessary firewall chains and rules.
func (f *Firewall) Initialize() error {
	// Create custom chains
	for _, chain := range []string{chainChilli, chainWalledGarden} {
		if err := f.ipt.NewChain("nat", chain); err != nil {
			log.Printf("Chain %s in nat table already exists, clearing it", chain)
			if err := f.ipt.ClearChain("nat", chain); err != nil {
				return fmt.Errorf("failed to clear chain %s in nat table: %w", chain, err)
			}
		}
		if err := f.ipt.NewChain("filter", chain); err != nil {
			log.Printf("Chain %s in filter table already exists, clearing it", chain)
			if err := f.ipt.ClearChain("filter", chain); err != nil {
				return fmt.Errorf("failed to clear chain %s in filter table: %w", chain, err)
			}
		}
	}

	// NAT rules
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

	// Filter rules
	if err := f.ipt.Append("filter", "FORWARD", "-i", f.cfg.TUNDev, "-j", chainChilli); err != nil {
		return fmt.Errorf("failed to append to FORWARD chain: %w", err)
	}

	log.Println("Firewall initialized successfully")
	return nil
}

// AddAuthenticatedUser adds firewall rules to allow traffic for an authenticated user.
func (f *Firewall) AddAuthenticatedUser(ip net.IP) error {
	if err := f.ipt.Insert("nat", chainChilli, 1, "-s", ip.String(), "-j", "RETURN"); err != nil {
		return fmt.Errorf("failed to add nat rule for authenticated user %s: %w", ip.String(), err)
	}
	if err := f.ipt.Insert("filter", chainChilli, 1, "-s", ip.String(), "-j", "RETURN"); err != nil {
		return fmt.Errorf("failed to add filter rule for authenticated user %s: %w", ip.String(), err)
	}
	log.Printf("Added firewall rules for authenticated user %s", ip.String())
	return nil
}

// RemoveAuthenticatedUser removes firewall rules for a user.
func (f *Firewall) RemoveAuthenticatedUser(ip net.IP) error {
	if err := f.ipt.Delete("nat", chainChilli, "-s", ip.String(), "-j", "RETURN"); err != nil {
		return fmt.Errorf("failed to delete nat rule for user %s: %w", ip.String(), err)
	}
	if err := f.ipt.Delete("filter", chainChilli, "-s", ip.String(), "-j", "RETURN"); err != nil {
		return fmt.Errorf("failed to delete filter rule for user %s: %w", ip.String(), err)
	}
	log.Printf("Removed firewall rules for user %s", ip.String())
	return nil
}

// Cleanup removes all firewall rules and chains created by the application.
func (f *Firewall) Cleanup() error {
	if err := f.ipt.Delete("nat", "PREROUTING", "-i", f.cfg.TUNDev, "-j", chainChilli); err != nil {
		log.Printf("Failed to delete from PREROUTING chain: %v", err)
	}
	if err := f.ipt.Delete("filter", "FORWARD", "-i", f.cfg.TUNDev, "-j", chainChilli); err != nil {
		log.Printf("Failed to delete from FORWARD chain: %v", err)
	}

	for _, chain := range []string{chainChilli, chainWalledGarden} {
		if err := f.ipt.ClearChain("nat", chain); err != nil {
			log.Printf("Failed to clear chain %s in nat table: %v", chain, err)
		}
		if err := f.ipt.DeleteChain("nat", chain); err != nil {
			log.Printf("Failed to delete chain %s in nat table: %v", chain, err)
		}

		if err := f.ipt.ClearChain("filter", chain); err != nil {
			log.Printf("Failed to clear chain %s in filter table: %v", chain, err)
		}
		if err := f.ipt.DeleteChain("filter", chain); err != nil {
			log.Printf("Failed to delete chain %s in filter table: %v", chain, err)
		}
	}
	log.Println("Firewall cleaned up successfully")
	return nil
}
