package dhcp

import (
	"net"
	"testing"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestPool(t *testing.T) {
	start := net.ParseIP("10.1.0.100")
	end := net.ParseIP("10.1.0.102")

	pool, err := NewPool(start, end)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}

	// Test getFreeIP
	ip1, err := pool.getFreeIP()
	if err != nil {
		t.Fatalf("getFreeIP failed: %v", err)
	}
	if !ip1.Equal(start) {
		t.Fatalf("getFreeIP returned wrong IP: got %s, want %s", ip1, start)
	}

	ip2, err := pool.getFreeIP()
	if err != nil {
		t.Fatalf("getFreeIP failed: %v", err)
	}
	if !ip2.Equal(net.ParseIP("10.1.0.101")) {
		t.Fatalf("getFreeIP returned wrong IP: got %s, want %s", ip2, "10.1.0.101")
	}

	// Test pool exhaustion
	_, err = pool.getFreeIP()
	if err == nil {
		t.Fatal("getFreeIP should have failed when pool is exhausted")
	}
}

func TestHandleRequest_Renewal_AuthFailure(t *testing.T) {
	// Setup
	cfg := &config.Config{
		Lease: 1 * time.Hour,
	}
	sm := core.NewSessionManager()
	radiusReqChan := make(chan *core.Session, 1)
	logger := zerolog.Nop() // Disable logging for the test

	pool, err := NewPool(net.ParseIP("10.0.0.10"), net.ParseIP("10.0.0.20"))
	require.NoError(t, err)

	server := &Server{
		cfg:            cfg,
		sessionManager: sm,
		radiusReqChan:  radiusReqChan,
		leasesV4:       make(map[string]*Lease),
		poolV4:         pool,
		logger:         logger,
	}

	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:01")
	clientIP := net.ParseIP("10.0.0.12")

	// 1. Create an initial lease and session for the client
	server.leasesV4[clientMAC.String()] = &Lease{
		IP:      clientIP,
		MAC:     clientMAC,
		Expires: time.Now().Add(30 * time.Minute),
	}
	session := sm.CreateSession(clientIP, clientMAC)

	// 2. Create a DHCPREQUEST packet for renewal
	reqPacket, err := dhcpv4.New(
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithClientIP(clientIP),
		dhcpv4.WithClientHardwareAddr(clientMAC),
	)
	require.NoError(t, err)
	reqBytes := reqPacket.ToBytes()

	// 3. Goroutine to simulate RADIUS failure
	go func() {
		s := <-radiusReqChan
		require.Equal(t, session.SessionID, s.SessionID)
		s.AuthResult <- false // Signal failure
	}()

	// 4. Call the handler
	respBytes, _, err := server.HandleDHCPv4(reqBytes)
	require.NoError(t, err)

	// 5. Assert the response is a NAK
	resp, err := dhcpv4.FromBytes(respBytes)
	require.NoError(t, err)
	require.Equal(t, dhcpv4.MessageTypeNak, resp.MessageType())

	// 6. Assert the lease was removed
	_, leaseExists := server.leasesV4[clientMAC.String()]
	require.False(t, leaseExists, "Lease should be removed after failed renewal")
}

func TestHandleSolicit(t *testing.T) {
	// Setup
	cfg := &config.Config{
		DNS1V6: net.ParseIP("2001:4860:4860::8888"),
	}
	logger := zerolog.Nop()

	pool, err := NewPool(net.ParseIP("2001:db8::100"), net.ParseIP("2001:db8::200"))
	require.NoError(t, err)

	serverMAC, _ := net.ParseMAC("00:00:5e:00:53:ff")

	server := &Server{
		cfg:      cfg,
		poolV6:   pool,
		ifaceMAC: serverMAC,
		logger:   logger,
	}

	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:01")

	// Create a SOLICIT packet
	req, err := dhcpv6.NewSolicit(clientMAC)
	require.NoError(t, err)
	reqBytes := req.ToBytes()

	// Call the handler
	respBytes, _, err := server.HandleDHCPv6(reqBytes)
	require.NoError(t, err)

	// Assert the response is an ADVERTISE
	resp, err := dhcpv6.FromBytes(respBytes)
	require.NoError(t, err)
	require.Equal(t, dhcpv6.MessageTypeAdvertise, resp.Type())

	// Assert the advertised IP is from the pool
	respIana := resp.GetOneOption(dhcpv6.OptionIANA).(*dhcpv6.OptIANA)
	respAddr := respIana.Options.GetOne(dhcpv6.OptionIAAddress).(*dhcpv6.OptIAAddress)
	require.True(t, respAddr.IPv6Address.Equal(net.ParseIP("2001:db8::100")))

	// Assert DNS server is set
	dnsOpt := resp.GetOneOption(dhcpv6.OptionDNSRecursiveNameServer)
	require.NotNil(t, dnsOpt)
	dnsServers := dnsOpt.(*dhcpv6.OptDNSRecursiveNameServer).NameServers
	require.Len(t, dnsServers, 1)
	require.True(t, dnsServers[0].Equal(cfg.DNS1V6))
}
