package dhcp

import (
	"net"
	"testing"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// TestDHCPv6ServerSolicit tests the standard 4-way exchange (Solicit -> Advertise)
func TestDHCPv6ServerSolicit(t *testing.T) {
	_, ipnet6, _ := net.ParseCIDR("2001:db8::/64")
	startIP := net.ParseIP("2001:db8::100")
	endIP := net.ParseIP("2001:db8::200")

	cfg := &config.Config{
		NetV6:       *ipnet6,
		DHCPStartV6: startIP,
		DHCPEndV6:   endIP,
		Lease:       3600 * time.Second,
	}

	logger := zerolog.Nop()
	sm := core.NewSessionManager(cfg, nil, logger)
	poolV6, err := NewPool(startIP, endIP)
	require.NoError(t, err)

	server := &Server{
		cfg:            cfg,
		sessionManager: sm,
		leasesV6:       make(map[string]*Lease),
		poolV6:         poolV6,
		ifaceIPv6:      net.ParseIP("fe80::1"),
		logger:         logger,
		rateLimiter:    NewDHCPRateLimiter(logger),
	}

	// Create a SOLICIT message *without* Rapid Commit
	duid := &dhcpv6.DUIDLLT{
		HWType:        iana.HWTypeEthernet,
		Time:          dhcpv6.GetTime(),
		LinkLayerAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
	}
	msg, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	msg.MessageType = dhcpv6.MessageTypeSolicit
	msg.AddOption(dhcpv6.OptClientID(duid))
	msg.AddOption(&dhcpv6.OptIANA{IaId: [4]byte{0x00, 0x00, 0x00, 0x01}})

	respBytes, resp, err := server.HandleDHCPv6(msg.ToBytes())
	require.NoError(t, err)
	require.NotNil(t, respBytes)

	// Expect an ADVERTISE message
	advMsg, ok := resp.(*dhcpv6.Message)
	require.True(t, ok)
	require.Equal(t, dhcpv6.MessageTypeAdvertise, advMsg.MessageType, "Response should be ADVERTISE for a standard Solicit")
}

// TestDHCPv6ServerRequestAck tests the second part of the 4-way exchange (Request -> Reply)
func TestDHCPv6ServerRequestAck(t *testing.T) {
	_, ipnet6, _ := net.ParseCIDR("2001:db8::/64")
	startIP := net.ParseIP("2001:db8::100")
	endIP := net.ParseIP("2001:db8::200")

	cfg := &config.Config{
		NetV6:       *ipnet6,
		DHCPStartV6: startIP,
		DHCPEndV6:   endIP,
		Lease:       3600 * time.Second,
	}

	logger := zerolog.Nop()
	sm := core.NewSessionManager(cfg, nil, logger)
	poolV6, err := NewPool(startIP, endIP)
	require.NoError(t, err)

	server := &Server{
		cfg:            cfg,
		sessionManager: sm,
		leasesV6:       make(map[string]*Lease),
		poolV6:         poolV6,
		ifaceIPv6:      net.ParseIP("fe80::1"),
		logger:         logger,
		rateLimiter:    NewDHCPRateLimiter(logger),
	}

	duid := &dhcpv6.DUIDLLT{
		HWType:        iana.HWTypeEthernet,
		Time:          dhcpv6.GetTime(),
		LinkLayerAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66},
	}
	requestedIP := net.ParseIP("2001:db8::150")

	// Create a REQUEST message
	msg, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	msg.MessageType = dhcpv6.MessageTypeRequest
	msg.AddOption(dhcpv6.OptClientID(duid))
	ianaOpt := &dhcpv6.OptIANA{IaId: [4]byte{0, 0, 0, 1}}
	ianaOpt.Options.Add(&dhcpv6.OptIAAddress{
		IPv6Addr:          requestedIP,
		PreferredLifetime: 3600 * time.Second,
		ValidLifetime:     7200 * time.Second,
	})
	msg.AddOption(ianaOpt)

	respBytes, resp, err := server.HandleDHCPv6(msg.ToBytes())
	require.NoError(t, err)
	require.NotNil(t, respBytes)

	// Expect a REPLY message
	replyMsg, ok := resp.(*dhcpv6.Message)
	require.True(t, ok)
	require.Equal(t, dhcpv6.MessageTypeReply, replyMsg.MessageType)

	// Verify lease was created
	server.RLock()
	lease, exists := server.leasesV6[duid.String()]
	server.RUnlock()
	require.True(t, exists, "Lease was not created")
	require.True(t, lease.IP.Equal(requestedIP), "Lease IP mismatch")
}

// TestDHCPv6PoolExhaustion tests the pool exhaustion logic with Rapid Commit
func TestDHCPv6PoolExhaustion(t *testing.T) {
	startIP := net.ParseIP("2001:db8::100")
	endIP := net.ParseIP("2001:db8::102") // Only 3 addresses

	_, ipnet6, _ := net.ParseCIDR("2001:db8::/64")
	cfg := &config.Config{
		NetV6:       *ipnet6,
		DHCPStartV6: startIP,
		DHCPEndV6:   endIP,
	}

	logger := zerolog.Nop()
	sm := core.NewSessionManager(cfg, nil, logger)
	poolV6, err := NewPool(startIP, endIP)
	require.NoError(t, err)

	server := &Server{
		cfg:            cfg,
		sessionManager: sm,
		leasesV6:       make(map[string]*Lease),
		poolV6:         poolV6,
		ifaceIPv6:      net.ParseIP("fe80::1"),
		logger:         logger,
		rateLimiter:    NewDHCPRateLimiter(logger),
	}

	// Request all available IPs using Rapid Commit
	for i := 0; i < 5; i++ {
		duid := &dhcpv6.DUIDLLT{
			HWType:        iana.HWTypeEthernet,
			Time:          dhcpv6.GetTime(),
			LinkLayerAddr: net.HardwareAddr{0, 0, 0, 0, 0, byte(i)},
		}
		msg, _ := dhcpv6.NewMessage()
		msg.MessageType = dhcpv6.MessageTypeSolicit
		msg.AddOption(dhcpv6.OptClientID(duid))
		msg.AddOption(&dhcpv6.OptIANA{IaId: [4]byte{0, 0, 0, byte(i)}})
		msg.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionRapidCommit})

		_, _, err := server.HandleDHCPv6(msg.ToBytes())
		if i < 3 {
			require.NoError(t, err, "Request %d should succeed", i)
		} else {
			require.Error(t, err, "Request %d should fail due to pool exhaustion", i)
			require.Contains(t, err.Error(), "no free IP addresses")
		}
	}
}

func TestDHCPv6RateLimiting(t *testing.T) {
	_, ipnet6, _ := net.ParseCIDR("2001:db8::/64")
	startIP := net.ParseIP("2001:db8::100")
	endIP := net.ParseIP("2001:db8::200")

	cfg := &config.Config{
		NetV6:       *ipnet6,
		DHCPStartV6: startIP,
		DHCPEndV6:   endIP,
		Lease:       3600 * time.Second,
	}

	logger := zerolog.Nop()
	sm := core.NewSessionManager(cfg, nil, logger)

	poolV6, err := NewPool(startIP, endIP)
	if err != nil {
		t.Fatalf("Failed to create IPv6 pool: %v", err)
	}

	rateLimiter := NewDHCPRateLimiter(logger)
	defer rateLimiter.Stop()

	server := &Server{
		cfg:            cfg,
		sessionManager: sm,
		leasesV6:       make(map[string]*Lease),
		poolV6:         poolV6,
		ifaceIPv6:      net.ParseIP("fe80::1"),
		logger:         logger,
		rateLimiter:    rateLimiter,
	}

	duid := &dhcpv6.DUIDLLT{
		HWType:        iana.HWTypeEthernet,
		Time:          dhcpv6.GetTime(),
		LinkLayerAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x77},
	}

	// Send multiple requests rapidly
	successCount := 0
	for i := 0; i < 15; i++ {
		msg, _ := dhcpv6.NewMessage()
		msg.MessageType = dhcpv6.MessageTypeSolicit
		msg.AddOption(dhcpv6.OptClientID(duid))
		msg.AddOption(&dhcpv6.OptIANA{
			IaId: [4]byte{0x00, 0x00, 0x00, byte(i)},
		})

		_, _, err := server.HandleDHCPv6(msg.ToBytes())
		if err == nil {
			successCount++
		}
	}

	// Rate limiter should have blocked some requests
	if successCount >= 15 {
		t.Errorf("Rate limiter did not block any requests: %d/15 succeeded", successCount)
	}

	t.Logf("Rate limiter allowed %d/15 requests", successCount)
}

func BenchmarkDHCPv6Solicit(b *testing.B) {
	_, ipnet6, _ := net.ParseCIDR("2001:db8::/64")
	startIP := net.ParseIP("2001:db8::100")
	endIP := net.ParseIP("2001:db8::1000")

	cfg := &config.Config{
		NetV6:       *ipnet6,
		DHCPStartV6: startIP,
		DHCPEndV6:   endIP,
		Lease:       3600 * time.Second,
	}

	logger := zerolog.Nop()
	sm := core.NewSessionManager(cfg, nil, logger)
	poolV6, _ := NewPool(startIP, endIP)

	server := &Server{
		cfg:            cfg,
		sessionManager: sm,
		leasesV6:       make(map[string]*Lease),
		poolV6:         poolV6,
		ifaceIPv6:      net.ParseIP("fe80::1"),
		logger:         logger,
		rateLimiter:    NewDHCPRateLimiter(logger),
	}

	duid := &dhcpv6.DUIDLLT{
		HWType:        iana.HWTypeEthernet,
		Time:          dhcpv6.GetTime(),
		LinkLayerAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}

	msg, _ := dhcpv6.NewMessage()
	msg.MessageType = dhcpv6.MessageTypeSolicit
	msg.AddOption(dhcpv6.OptClientID(duid))
	msg.AddOption(&dhcpv6.OptIANA{
		IaId: [4]byte{0x00, 0x00, 0x00, 0x01},
	})

	msgBytes := msg.ToBytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server.HandleDHCPv6(msgBytes)
	}
}