package dhcp

import (
	"net"
	"testing"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/metrics"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
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
	sm := core.NewSessionManager(nil)
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
		recorder:       metrics.NewNoopRecorder(),
	}

	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:01")
	clientIP := net.ParseIP("10.0.0.12")

	// 1. Create an initial lease and session for the client
	server.leasesV4[clientMAC.String()] = &Lease{
		IP:      clientIP,
		MAC:     clientMAC,
		Expires: time.Now().Add(30 * time.Minute),
	}
	session := sm.CreateSession(clientIP, clientMAC, 0, cfg)

	// 2. Create a DHCPREQUEST packet for renewal
	reqPacket, err := dhcpv4.New(
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithClientIP(clientIP),
		dhcpv4.WithHwAddr(clientMAC),
	)
	require.NoError(t, err)
	reqBytes := reqPacket.ToBytes()

	// Create a dummy gopacket.Packet for the handler
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, &layers.Ethernet{}, &layers.IPv4{}, &layers.UDP{}, gopacket.Payload(reqBytes))
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// 3. Goroutine to simulate RADIUS failure
	go func() {
		s := <-radiusReqChan
		require.Equal(t, session.SessionID, s.SessionID)
		s.AuthResult <- false // Signal failure
	}()

	// 4. Call the handler
	respBytes, _, err := server.HandleDHCPv4(reqBytes, packet)
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
	req.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionRapidCommit})
	reqBytes := req.ToBytes()

	// Call the handler
	respBytes, _, err := server.HandleDHCPv6(reqBytes)
	require.NoError(t, err)

	// Assert the response is an ADVERTISE
	resp, err := dhcpv6.FromBytes(respBytes)
	require.NoError(t, err)
	msg, ok := resp.(*dhcpv6.Message)
	require.True(t, ok)
	require.Equal(t, dhcpv6.MessageTypeAdvertise, msg.MessageType)

	// Assert the advertised IP is from the pool
	respIana := msg.GetOneOption(dhcpv6.OptionIANA).(*dhcpv6.OptIANA)
	respAddr := respIana.Options.GetOne(dhcpv6.OptionIAAddr).(*dhcpv6.OptIAAddress)
	require.True(t, respAddr.IPv6Addr.Equal(net.ParseIP("2001:db8::100")))

	// Assert DNS server is set
	dnsServers := msg.Options.DNS()
	require.NotNil(t, dnsServers)
	require.Len(t, dnsServers, 1)
	require.True(t, dnsServers[0].Equal(cfg.DNS1V6))
}

func TestRelayDHCPv4(t *testing.T) {
	// 1. Setup a mock upstream DHCP server
	upstreamDone := make(chan bool)
	upstreamAddr := "127.0.0.1:1067"
	go func() {
		pc, err := net.ListenPacket("udp", upstreamAddr)
		require.NoError(t, err)
		defer pc.Close()

		buf := make([]byte, 1500)
		n, _, err := pc.ReadFrom(buf)
		require.NoError(t, err)

		// Verify the received packet
		req, err := dhcpv4.FromBytes(buf[:n])
		require.NoError(t, err)
		require.Equal(t, dhcpv4.MessageTypeDiscover, req.MessageType())
		opt82 := req.GetOneOption(dhcpv4.OptionRelayAgentInformation)
		require.NotNil(t, opt82, "Option 82 should be present")

		close(upstreamDone)
	}()
	time.Sleep(50 * time.Millisecond) // give server time to start

	// 2. Setup the relay server
	cfg := &config.Config{
		DHCPRelay:    true,
		DHCPUpstream: upstreamAddr,
		DHCPListen:   net.ParseIP("10.0.0.1"),
	}
	logger := zerolog.Nop()
	server := &Server{
		cfg:    cfg,
		logger: logger,
	}

	// 3. Create a mock DHCP packet from a client
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:03")
	discover, err := dhcpv4.NewDiscovery(clientMAC)
	require.NoError(t, err)

	ethLayer := &layers.Ethernet{SrcMAC: clientMAC, DstMAC: layers.EthernetBroadcast, EthernetType: layers.EthernetTypeIPv4}
	ipLayer := &layers.IPv4{SrcIP: net.IPv4zero, DstIP: net.IPv4bcast, Protocol: layers.IPProtocolUDP}
	udpLayer := &layers.UDP{SrcPort: 68, DstPort: 67}
	err = udpLayer.SetNetworkLayerForChecksum(ipLayer)
	require.NoError(t, err)
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ethLayer, ipLayer, udpLayer, gopacket.Payload(discover.ToBytes()))
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// 4. Call the relay function and capture any error
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.relayDHCPv4(packet)
	}()

	// 5. Assert that the upstream server received the packet, or that an error occurred
	select {
	case <-upstreamDone:
		// success
	case err := <-errChan:
		t.Fatalf("relayDHCPv4 returned an unexpected error: %v", err)
	case <-time.After(5 * time.Second): // Increased timeout for debugging
		t.Fatal("Upstream DHCP server did not receive relayed packet")
	}
}

func TestHandleRequestV6(t *testing.T) {
	// Setup
	cfg := &config.Config{
		Lease: 1 * time.Hour,
	}
	logger := zerolog.Nop()

	pool, err := NewPool(net.ParseIP("2001:db8::100"), net.ParseIP("2001:db8::200"))
	require.NoError(t, err)

	serverMAC, _ := net.ParseMAC("00:00:5e:00:53:ff")
	serverDUID := &dhcpv6.DUIDLL{
		HWType:        iana.HWTypeEthernet,
		LinkLayerAddr: serverMAC,
	}

	server := &Server{
		cfg:      cfg,
		poolV6:   pool,
		leasesV6: make(map[string]*Lease),
		ifaceMAC: serverMAC,
		logger:   logger,
	}

	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:01")
	clientDUID := &dhcpv6.DUIDLL{
		HWType:        iana.HWTypeEthernet,
		LinkLayerAddr: clientMAC,
	}
	requestedIP := net.ParseIP("2001:db8::150")

	// Create a REQUEST packet
	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	req.MessageType = dhcpv6.MessageTypeRequest
	req.AddOption(dhcpv6.OptClientID(clientDUID))
	req.AddOption(dhcpv6.OptServerID(serverDUID))
	ianaOpt := &dhcpv6.OptIANA{}
	optAddr := &dhcpv6.OptIAAddress{
		IPv6Addr:          requestedIP,
		PreferredLifetime: 3600 * time.Second,
		ValidLifetime:     7200 * time.Second,
	}
	ianaOpt.Options.Add(optAddr)
	req.AddOption(ianaOpt)

	// Call the handler
	respBytes, _, err := server.HandleDHCPv6(req.ToBytes())
	require.NoError(t, err)

	// Assert the response is a REPLY
	resp, err := dhcpv6.FromBytes(respBytes)
	require.NoError(t, err)
	msg, ok := resp.(*dhcpv6.Message)
	require.True(t, ok)
	require.Equal(t, dhcpv6.MessageTypeReply, msg.MessageType)

	// Assert the lease was created
	_, leaseExists := server.leasesV6[clientDUID.String()]
	require.True(t, leaseExists, "Lease should have been created")
}