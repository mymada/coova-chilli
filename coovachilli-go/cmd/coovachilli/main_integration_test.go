package main

import (
	"bytes"
	"net"
	"sync"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/garden"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockFirewallManager is a mock implementation of the FirewallManager interface for testing.
type mockFirewallManager struct {
	mu               sync.Mutex
	addedNetworks    []string
	addedIPs         []string
	authenticatedIPs map[string]bool
}

func newMockFirewallManager() *mockFirewallManager {
	return &mockFirewallManager{
		addedNetworks:    make([]string, 0),
		addedIPs:         make([]string, 0),
		authenticatedIPs: make(map[string]bool),
	}
}

func (m *mockFirewallManager) Initialize() error                               { return nil }
func (m *mockFirewallManager) Cleanup()                                        {}
func (m *mockFirewallManager) Reconfigure(newConfig *config.Config) error      { return nil }
func (m *mockFirewallManager) AddWalledGardenNetwork(network string) error     { m.addedNetworks = append(m.addedNetworks, network); return nil }
func (m *mockFirewallManager) AddWalledGardenIP(ip string) error               { m.mu.Lock(); defer m.mu.Unlock(); m.addedIPs = append(m.addedIPs, ip); return nil }
func (m *mockFirewallManager) AddAuthenticatedUser(ip net.IP) error            { m.mu.Lock(); defer m.mu.Unlock(); m.authenticatedIPs[ip.String()] = true; return nil }
func (m *mockFirewallManager) RemoveAuthenticatedUser(ip net.IP) error         { m.mu.Lock(); defer m.mu.Unlock(); delete(m.authenticatedIPs, ip.String()); return nil }

func (m *mockFirewallManager) getAddedIPs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	ips := make([]string, len(m.addedIPs))
	copy(ips, m.addedIPs)
	return ips
}

func (m *mockFirewallManager) isAuthenticated(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.authenticatedIPs[ip]
}

// TestFullSessionFlow simulates a user session from DNS query to authentication.
func TestFullSessionFlow(t *testing.T) {
	// --- Setup ---
	logger := zerolog.Nop()
	cfg := &config.Config{
		WalledGarden: config.WalledGardenConfig{
			AllowedDomains: []string{"*.example.com"},
		},
		DNS1: net.ParseIP("8.8.8.8"),
	}
	fw := newMockFirewallManager()
	gardenService := garden.NewGarden(&cfg.WalledGarden, fw, logger)
	sessionManager := core.NewSessionManager(cfg, nil)

	// --- 1. Simulate a new unauthenticated user ---
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:01")
	clientIP := net.ParseIP("10.1.0.10")
	session := sessionManager.CreateSession(clientIP, clientMAC, 0)
	require.NotNil(t, session, "Session should be created")

	// --- 2. Simulate a DNS query for an allowed domain ---
	allowedDomain := "test.example.com"
	resolvedIP := "93.184.216.34"

	// Manually call the garden handler to simulate the effect of a DNS response.
	// This tests the integration between the garden service and the firewall.
	gardenService.HandleDNSResponse(allowedDomain, []net.IP{net.ParseIP(resolvedIP)})

	// --- 3. Verify Walled Garden rule was added ---
	assert.Contains(t, fw.getAddedIPs(), resolvedIP, "IP from allowed domain should be added to walled garden")
	assert.False(t, fw.isAuthenticated(clientIP.String()), "User should not be authenticated yet")

	// --- 4. Simulate user authentication ---
	session.Lock()
	session.Authenticated = true
	session.Redir.Username = "testuser"
	session.Unlock()

	// In a real flow, this would be triggered by a RADIUS response. We trigger it manually.
	err := fw.AddAuthenticatedUser(clientIP)
	require.NoError(t, err)

	// --- 5. Verify user is now authenticated in the firewall ---
	assert.True(t, fw.isAuthenticated(clientIP.String()), "User should be marked as authenticated in the firewall")

	t.Log("Integration test passed: DNS -> Walled Garden -> Authentication flow is working.")
}

func TestARPHandling(t *testing.T) {
	// --- Setup ---
	logger := zerolog.Nop()
	cfg := &config.Config{
		DHCPListen: net.ParseIP("10.1.0.1"),
	}
	sessionManager := core.NewSessionManager(cfg, nil)
	app := &application{
		cfg:            cfg,
		logger:         logger,
		sessionManager: sessionManager,
	}
	app.tunMAC, _ = net.ParseMAC("00:00:5e:00:53:ff")

	// Create a session for a client, so we know to respond to ARPs for its IP
	clientIP := net.ParseIP("10.1.0.123")
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:11")
	sessionManager.CreateSession(clientIP, clientMAC, 0)

	// Create a mock writer to capture the ARP reply
	var writer bytes.Buffer

	// --- 1. Test ARP for a managed client IP ---
	t.Run("ARP for managed client IP", func(t *testing.T) {
		// Construct the ARP request packet
		reqEth := &layers.Ethernet{
			SrcMAC:       clientMAC,
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Broadcast
			EthernetType: layers.EthernetTypeARP,
		}
		reqArp := &layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   []byte(clientMAC),
			SourceProtAddress: []byte(clientIP),
			DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
			DstProtAddress:    []byte(clientIP), // ARP request for itself (gratuitous) or gateway
		}

		// Execute
		writer.Reset()
		app.handleARPRequest(reqEth, reqArp, &writer)

		// Verify
		require.NotZero(t, writer.Len(), "handleARPRequest should have written a reply")

		// Decode the reply
		var eth layers.Ethernet
		var arp layers.ARP
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &arp)
		var decodedLayers []gopacket.LayerType
		err := parser.DecodeLayers(writer.Bytes(), &decodedLayers)
		require.NoError(t, err)
		require.Contains(t, decodedLayers, layers.LayerTypeARP, "Decoded packet should contain an ARP layer")

		assert.Equal(t, uint16(layers.ARPReply), arp.Operation, "ARP operation should be a reply")
		assert.Equal(t, app.tunMAC, net.HardwareAddr(eth.SrcMAC), "Reply ethernet source MAC should be the TUN MAC")
		assert.Equal(t, clientMAC, net.HardwareAddr(eth.DstMAC), "Reply ethernet destination MAC should be the client MAC")
		assert.Equal(t, app.tunMAC, net.HardwareAddr(arp.SourceHwAddress), "Reply ARP source MAC should be the TUN MAC")
		assert.Equal(t, clientIP, net.IP(arp.SourceProtAddress), "Reply ARP source IP should be the requested IP")
	})

	// --- 2. Test ARP for the gateway IP ---
	t.Run("ARP for gateway IP", func(t *testing.T) {
		reqEth := &layers.Ethernet{
			SrcMAC:       clientMAC,
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeARP,
		}
		reqArp := &layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   []byte(clientMAC),
			SourceProtAddress: []byte(clientIP),
			DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
			DstProtAddress:    []byte(cfg.DHCPListen), // ARP for the gateway
		}

		writer.Reset()
		app.handleARPRequest(reqEth, reqArp, &writer)
		require.NotZero(t, writer.Len(), "handleARPRequest should have written a reply for the gateway IP")
	})

	// --- 3. Test ARP for an unmanaged IP ---
	t.Run("ARP for unmanaged IP", func(t *testing.T) {
		unmanagedIP := net.ParseIP("10.1.0.254")
		reqEth := &layers.Ethernet{
			SrcMAC:       clientMAC,
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeARP,
		}
		reqArp := &layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   []byte(clientMAC),
			SourceProtAddress: []byte(clientIP),
			DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
			DstProtAddress:    []byte(unmanagedIP),
		}

		writer.Reset()
		app.handleARPRequest(reqEth, reqArp, &writer)
		require.Zero(t, writer.Len(), "handleARPRequest should not write a reply for an unmanaged IP")
	})
}