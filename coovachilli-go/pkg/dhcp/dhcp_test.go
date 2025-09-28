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
	require.NoError(t, err)

	ip1, err := pool.getFreeIP()
	require.NoError(t, err)
	require.True(t, ip1.Equal(start))

	ip2, err := pool.getFreeIP()
	require.NoError(t, err)
	require.True(t, ip2.Equal(net.ParseIP("10.1.0.101")))

	_, err = pool.getFreeIP()
	require.Error(t, err, "getFreeIP should have failed when pool is exhausted")
}

func TestHandleRequest_Renewal_AuthFailure(t *testing.T) {
	// Setup
	cfg := &config.Config{
		Lease:   1 * time.Hour,
		MACAuth: true, // Enable MAC Auth to trigger the re-authentication logic.
	}
	sm := core.NewSessionManager()
	radiusReqChan := make(chan *core.Session, 1)
	logger := zerolog.Nop()

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

	// 1. Create an initial lease and an AUTHENTICATED session for the client.
	server.leasesV4[clientMAC.String()] = &Lease{
		IP:      clientIP,
		MAC:     clientMAC,
		Expires: time.Now().Add(30 * time.Minute),
	}
	session := sm.CreateSession(clientIP, clientMAC, cfg)
	session.Authenticated = true // This is crucial for simulating a renewal.

	// 2. Create a DHCPREQUEST packet for renewal.
	reqPacket, err := dhcpv4.New(
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithClientIP(clientIP),
		dhcpv4.WithHwAddr(clientMAC),
	)
	require.NoError(t, err)
	reqBytes := reqPacket.ToBytes()

	// 3. Goroutine to simulate RADIUS failure.
	go func() {
		s := <-radiusReqChan
		require.Equal(t, session.SessionID, s.SessionID)
		s.AuthResult <- false // Signal failure.
	}()

	// 4. Call the handler.
	respBytes, _, err := server.HandleDHCPv4(reqBytes)
	require.NoError(t, err)

	// 5. Assert the response is a NAK.
	resp, err := dhcpv4.FromBytes(respBytes)
	require.NoError(t, err)
	require.Equal(t, dhcpv4.MessageTypeNak, resp.MessageType(), "Response should be a NAK on re-authentication failure")
}

func TestHandleSolicit(t *testing.T) {
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
	req, err := dhcpv6.NewSolicit(clientMAC)
	require.NoError(t, err)
	req.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionRapidCommit})
	reqBytes := req.ToBytes()
	respBytes, _, err := server.HandleDHCPv6(reqBytes)
	require.NoError(t, err)
	resp, err := dhcpv6.FromBytes(respBytes)
	require.NoError(t, err)
	msg, ok := resp.(*dhcpv6.Message)
	require.True(t, ok)
	require.Equal(t, dhcpv6.MessageTypeAdvertise, msg.MessageType)
	respIana := msg.GetOneOption(dhcpv6.OptionIANA).(*dhcpv6.OptIANA)
	respAddr := respIana.Options.GetOne(dhcpv6.OptionIAAddr).(*dhcpv6.OptIAAddress)
	require.True(t, respAddr.IPv6Addr.Equal(net.ParseIP("2001:db8::100")))
	dnsServers := msg.Options.DNS()
	require.NotNil(t, dnsServers)
	require.Len(t, dnsServers, 1)
	require.True(t, dnsServers[0].Equal(cfg.DNS1V6))
}

func TestRelayDHCPv4(t *testing.T) {
	// This test is more of an integration test and depends on network setup.
	// It's kept here for completeness but might be flaky in some environments.
	t.Skip("Skipping relay test as it requires specific network setup")
}

func TestHandleRequestV6(t *testing.T) {
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
	respBytes, _, err := server.HandleDHCPv6(req.ToBytes())
	require.NoError(t, err)
	resp, err := dhcpv6.FromBytes(respBytes)
	require.NoError(t, err)
	msg, ok := resp.(*dhcpv6.Message)
	require.True(t, ok)
	require.Equal(t, dhcpv6.MessageTypeReply, msg.MessageType)
	_, leaseExists := server.leasesV6[clientDUID.String()]
	require.True(t, leaseExists, "Lease should have been created")
}

type mockSessionManagerForVLANTest struct {
	core.SessionManager
	createdVLANID uint16
}

func (m *mockSessionManagerForVLANTest) CreateSession(ip net.IP, mac net.HardwareAddr, vlanID uint16, cfg *config.Config) *core.Session {
	m.createdVLANID = vlanID
	// Return a dummy session to avoid nil pointers
	return &core.Session{AuthResult: make(chan bool, 1)}
}

func TestDHCP_VLAN(t *testing.T) {
	cfg := &config.Config{}
	logger := zerolog.Nop()
	sm := &mockSessionManagerForVLANTest{}
	radiusReqChan := make(chan *core.Session, 1)

	server := &Server{
		cfg:            cfg,
		sessionManager: sm,
		radiusReqChan:  radiusReqChan,
		logger:         logger,
	}

	// 1. Create a DHCP request packet
	clientMAC, _ := net.ParseMAC("00:00:5e:88:99:aa")
	req, err := dhcpv4.New(
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithClientIP(net.ParseIP("10.1.1.1")),
		dhcpv4.WithHwAddr(clientMAC),
	)
	require.NoError(t, err)

	// 2. Create the full Ethernet frame with a VLAN tag
	ethLayer := &layers.Ethernet{
		SrcMAC:       clientMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeDot1Q,
	}
	dot1qLayer := &layers.Dot1Q{
		VLANIdentifier: 123,
		Type:           layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		Version:  4,
		SrcIP:    net.IPv4zero,
		DstIP:    net.IPv4bcast,
		Protocol: layers.IPProtocolUDP,
	}
	udpLayer := &layers.UDP{
		SrcPort: 68,
		DstPort: 67,
	}
	_ = udpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err = gopacket.SerializeLayers(buffer, opts, ethLayer, dot1qLayer, ipLayer, udpLayer, gopacket.Payload(req.ToBytes()))
	require.NoError(t, err)

	// 3. Create a gopacket.Packet from the raw bytes
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// 4. Call the handler
	server.handlePacket(packet)

	// 5. Assert that the session was created with the correct VLAN ID
	require.Equal(t, uint16(123), sm.createdVLANID, "Session should be created with the correct VLAN ID")
}