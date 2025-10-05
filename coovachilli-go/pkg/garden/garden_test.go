package garden

import (
	"net"
	"sync"
	"testing"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockFirewallManager is a mock implementation of the FirewallManager interface for testing.
type mockFirewallManager struct {
	mu             sync.Mutex
	addedNetworks  []string
	addedIPs       []string
	reconfigured   bool
	failAddNetwork bool
	failAddIP      bool
}

func newMockFirewallManager() *mockFirewallManager {
	return &mockFirewallManager{
		addedNetworks: make([]string, 0),
		addedIPs:      make([]string, 0),
	}
}

func (m *mockFirewallManager) Initialize() error                               { return nil }
func (m *mockFirewallManager) Cleanup()                                        {}
func (m *mockFirewallManager) AddAuthenticatedUser(ip net.IP) error            { return nil }
func (m *mockFirewallManager) RemoveAuthenticatedUser(ip net.IP) error         { return nil }
func (m *mockFirewallManager) Reconfigure(newConfig *config.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconfigured = true
	return nil
}

func (m *mockFirewallManager) AddWalledGardenNetwork(network string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failAddNetwork {
		return assert.AnError
	}
	m.addedNetworks = append(m.addedNetworks, network)
	return nil
}

func (m *mockFirewallManager) AddWalledGardenIP(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failAddIP {
		return assert.AnError
	}
	m.addedIPs = append(m.addedIPs, ip)
	return nil
}

func (m *mockFirewallManager) getAddedIPs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Return a copy
	ips := make([]string, len(m.addedIPs))
	copy(ips, m.addedIPs)
	return ips
}

func TestIsDomainAllowed(t *testing.T) {
	cfg := &config.WalledGardenConfig{
		AllowedDomains: []string{"google.com", "*.google.com", "example.org"},
	}
	g := NewGarden(cfg, newMockFirewallManager(), zerolog.Nop())

	testCases := []struct {
		name     string
		domain   string
		expected bool
	}{
		{"Exact match", "google.com", true},
		{"Wildcard subdomain", "www.google.com", true},
		{"Wildcard another subdomain", "maps.google.com", true},
		{"Direct wildcard match", "*.google.com", true},
		{"Another exact match", "example.org", true},
		{"Non-allowed domain", "facebook.com", false},
		{"Partial non-match", "notgoogle.com", false},
		{"Subdomain of non-wildcard", "www.example.org", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, g.isDomainAllowed(tc.domain))
		})
	}
}

func TestHandleDNSResponse(t *testing.T) {
	fw := newMockFirewallManager()
	cfg := &config.WalledGardenConfig{
		AllowedDomains: []string{"allowed.com", "*.wildcard.com"},
	}
	g := NewGarden(cfg, fw, zerolog.Nop())

	g.HandleDNSResponse("allowed.com", []net.IP{net.ParseIP("1.2.3.4")})
	assert.Contains(t, fw.getAddedIPs(), "1.2.3.4")

	g.HandleDNSResponse("sub.wildcard.com", []net.IP{net.ParseIP("5.6.7.8")})
	assert.Contains(t, fw.getAddedIPs(), "5.6.7.8")

	g.HandleDNSResponse("notallowed.com", []net.IP{net.ParseIP("9.9.9.9")})
	assert.NotContains(t, fw.getAddedIPs(), "9.9.9.9")

	// Test adding the same IP again. The internal logic of the garden should prevent
	// calling the firewall manager twice for the same IP.
	g.HandleDNSResponse("allowed.com", []net.IP{net.ParseIP("1.2.3.4")})
	assert.Len(t, fw.getAddedIPs(), 2, "The mock firewall will contain duplicates, but the logic should prevent redundant calls in a real scenario")
}

func TestInitialSetup(t *testing.T) {
	fw := newMockFirewallManager()
	cfg := &config.WalledGardenConfig{
		// The domain resolution part of initialSetup is not tested here as it requires
		// mocking the net.DefaultResolver, which is complex without refactoring the
		// Garden struct to accept a resolver interface.
		AllowedDomains:  []string{"static.com"},
		AllowedNetworks: []string{"10.0.0.0/24"},
	}

	g := NewGarden(cfg, fw, zerolog.Nop())

	// We can't easily mock the resolver, so we'll only test the static parts.
	g.initialSetup()

	// Check that the static network was added
	require.Contains(t, fw.addedNetworks, "10.0.0.0/24")

	t.Log("Skipping domain resolution test in initialSetup due to difficulty mocking net.DefaultResolver")
}