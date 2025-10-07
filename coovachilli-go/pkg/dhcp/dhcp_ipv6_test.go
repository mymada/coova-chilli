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
)

func TestDHCPv6ServerSolicit(t *testing.T) {
	_, ipnet6, _ := net.ParseCIDR("2001:db8::/64")
	startIP := net.ParseIP("2001:db8::100")
	endIP := net.ParseIP("2001:db8::200")

	cfg := &config.Config{
		NetV6:       *ipnet6,
		DHCPStartV6: startIP,
		DHCPEndV6:   endIP,
		Lease:       3600 * time.Second,
		DNS1V6:      net.ParseIP("2001:4860:4860::8888"),
		DNS2V6:      net.ParseIP("2001:4860:4860::8844"),
	}

	logger := zerolog.Nop()
	sm := core.NewSessionManager(cfg, nil)

	// Create pool
	poolV6, err := NewPool(startIP, endIP)
	if err != nil {
		t.Fatalf("Failed to create IPv6 pool: %v", err)
	}

	linkLocalIP := net.ParseIP("fe80::1")

	server := &Server{
		cfg:         cfg,
		sessionManager: sm,
		leasesV6:    make(map[string]*Lease),
		poolV6:      poolV6,
		ifaceIPv6:   linkLocalIP,
		logger:      logger,
	}

	// Create DHCPv6 SOLICIT message
	duid := &dhcpv6.DUIDLLT{
		HWType:        iana.HWTypeEthernet,
		Time:          dhcpv6.GetTime(),
		LinkLayerAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
	}

	msg, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatalf("Failed to create DHCPv6 message: %v", err)
	}

	msg.MessageType = dhcpv6.MessageTypeSolicit
	msg.AddOption(dhcpv6.OptClientID(duid))
	msg.AddOption(&dhcpv6.OptIANA{
		IaId: [4]byte{0x00, 0x00, 0x00, 0x01},
	})

	respBytes, resp, err := server.HandleDHCPv6(msg.ToBytes())
	if err != nil {
		t.Fatalf("HandleDHCPv6 failed: %v", err)
	}

	if respBytes == nil {
		t.Fatal("Expected ADVERTISE response, got nil")
	}

	advMsg, ok := resp.(*dhcpv6.Message)
	if !ok {
		t.Fatal("Response is not a DHCPv6 Message")
	}

	if advMsg.MessageType != dhcpv6.MessageTypeAdvertise {
		t.Errorf("Response type = %v, want ADVERTISE", advMsg.MessageType)
	}

	// Check that an IP was offered
	ianaOpt := advMsg.GetOneOption(dhcpv6.OptionIANA)
	if ianaOpt == nil {
		t.Fatal("ADVERTISE response missing IANA option")
	}

	iana, ok := ianaOpt.(*dhcpv6.OptIANA)
	if !ok {
		t.Fatal("IANA option is not OptIANA")
	}

	iaAddr := iana.Options.GetOne(dhcpv6.OptionIAAddr)
	if iaAddr == nil {
		t.Fatal("IANA missing IAAddr option")
	}

	iaAddrOpt, ok := iaAddr.(*dhcpv6.OptIAAddress)
	if !ok {
		t.Fatal("IAAddr is not OptIAAddress")
	}

	offeredIP := iaAddrOpt.IPv6Addr
	if offeredIP == nil {
		t.Fatal("Offered IP is nil")
	}

	t.Logf("Offered IPv6 address: %s", offeredIP)
}

func TestDHCPv6ServerRequestAck(t *testing.T) {
	_, ipnet6, _ := net.ParseCIDR("2001:db8::/64")
	startIP := net.ParseIP("2001:db8::100")
	endIP := net.ParseIP("2001:db8::200")

	cfg := &config.Config{
		NetV6:       *ipnet6,
		DHCPStartV6: startIP,
		DHCPEndV6:   endIP,
		Lease:       3600 * time.Second,
		DNS1V6:      net.ParseIP("2001:4860:4860::8888"),
	}

	logger := zerolog.Nop()
	sm := core.NewSessionManager(cfg, nil)

	poolV6, err := NewPool(startIP, endIP)
	if err != nil {
		t.Fatalf("Failed to create IPv6 pool: %v", err)
	}

	linkLocalIP := net.ParseIP("fe80::1")

	server := &Server{
		cfg:            cfg,
		sessionManager: sm,
		leasesV6:       make(map[string]*Lease),
		poolV6:         poolV6,
		ifaceIPv6:      linkLocalIP,
		logger:         logger,
	}

	// Create DHCPv6 REQUEST message
	duid := &dhcpv6.DUIDLLT{
		HWType:        iana.HWTypeEthernet,
		Time:          dhcpv6.GetTime(),
		LinkLayerAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66},
	}

	requestedIP := net.ParseIP("2001:db8::150")

	msg, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatalf("Failed to create DHCPv6 message: %v", err)
	}

	msg.MessageType = dhcpv6.MessageTypeRequest
	msg.AddOption(dhcpv6.OptClientID(duid))

	ianaOpt := &dhcpv6.OptIANA{
		IaId: [4]byte{0x00, 0x00, 0x00, 0x01},
	}
	ianaOpt.Options.Add(&dhcpv6.OptIAAddress{
		IPv6Addr:          requestedIP,
		PreferredLifetime: 3600 * time.Second,
		ValidLifetime:     7200 * time.Second,
	})
	msg.AddOption(ianaOpt)

	respBytes, resp, err := server.HandleDHCPv6(msg.ToBytes())
	if err != nil {
		t.Fatalf("HandleDHCPv6 failed: %v", err)
	}

	if respBytes == nil {
		t.Fatal("Expected REPLY response, got nil")
	}

	replyMsg, ok := resp.(*dhcpv6.Message)
	if !ok {
		t.Fatal("Response is not a DHCPv6 Message")
	}

	if replyMsg.MessageType != dhcpv6.MessageTypeReply {
		t.Errorf("Response type = %v, want REPLY", replyMsg.MessageType)
	}

	// Verify lease was created
	server.RLock()
	lease, exists := server.leasesV6[duid.String()]
	server.RUnlock()

	if !exists {
		t.Fatal("Lease was not created")
	}

	if !lease.IP.Equal(requestedIP) {
		t.Errorf("Lease IP = %s, want %s", lease.IP, requestedIP)
	}

	t.Logf("Lease granted for IPv6 address: %s", lease.IP)
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
	sm := core.NewSessionManager(cfg, nil)

	poolV6, err := NewPool(startIP, endIP)
	if err != nil {
		t.Fatalf("Failed to create IPv6 pool: %v", err)
	}

	rateLimiter := NewDHCPRateLimiter(logger)
	defer rateLimiter.Cleanup()

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

		respBytes, _, err := server.HandleDHCPv6(msg.ToBytes())
		if err != nil {
			t.Logf("Request %d failed: %v", i, err)
			continue
		}

		if respBytes != nil {
			successCount++
		}
	}

	// Rate limiter should have blocked some requests
	if successCount >= 15 {
		t.Errorf("Rate limiter did not block any requests: %d/15 succeeded", successCount)
	}

	t.Logf("Rate limiter allowed %d/15 requests", successCount)
}

func TestDHCPv6PoolExhaustion(t *testing.T) {
	// Test with a very small pool
	startIP := net.ParseIP("2001:db8::100")
	endIP := net.ParseIP("2001:db8::102") // Only 3 addresses

	_, ipnet6, _ := net.ParseCIDR("2001:db8::/64")

	cfg := &config.Config{
		NetV6:       *ipnet6,
		DHCPStartV6: startIP,
		DHCPEndV6:   endIP,
		Lease:       3600 * time.Second,
	}

	logger := zerolog.Nop()
	sm := core.NewSessionManager(cfg, nil)

	poolV6, err := NewPool(startIP, endIP)
	if err != nil {
		t.Fatalf("Failed to create IPv6 pool: %v", err)
	}

	server := &Server{
		cfg:            cfg,
		sessionManager: sm,
		leasesV6:       make(map[string]*Lease),
		poolV6:         poolV6,
		ifaceIPv6:      net.ParseIP("fe80::1"),
		logger:         logger,
		rateLimiter:    NewDHCPRateLimiter(logger),
	}

	// Request all available IPs
	for i := 0; i < 5; i++ {
		duid := &dhcpv6.DUIDLLT{
			HWType:        iana.HWTypeEthernet,
			Time:          dhcpv6.GetTime(),
			LinkLayerAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, byte(i), byte(i)},
		}

		msg, _ := dhcpv6.NewMessage()
		msg.MessageType = dhcpv6.MessageTypeSolicit
		msg.AddOption(dhcpv6.OptClientID(duid))
		msg.AddOption(&dhcpv6.OptIANA{
			IaId: [4]byte{0x00, 0x00, 0x00, byte(i)},
		})

		respBytes, resp, err := server.HandleDHCPv6(msg.ToBytes())
		if i < 3 {
			// First 3 should succeed
			if err != nil {
				t.Errorf("Request %d failed unexpectedly: %v", i, err)
			}
			if respBytes == nil {
				t.Errorf("Request %d got nil response", i)
			}
			if resp != nil {
				t.Logf("Request %d succeeded", i)
			}
		} else {
			// After pool exhaustion, should fail or return nil
			t.Logf("Request %d (pool exhausted): err=%v, resp=%v", i, err, resp != nil)
		}
	}
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
	sm := core.NewSessionManager(cfg, nil)
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
