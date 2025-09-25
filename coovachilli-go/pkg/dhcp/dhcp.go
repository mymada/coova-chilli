package dhcp

import (
	"fmt"
	"net"
	"sync"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/rs/zerolog"
)

// Server holds the state for the DHCP server.
type Server struct {
	sync.RWMutex
	cfg            *config.Config
	sessionManager *core.SessionManager
	radiusReqChan  chan<- *core.Session
	leasesV4       map[string]*Lease
	poolV4         *Pool
	leasesV6       map[string]*Lease // Using the same Lease struct for v6 for now
	poolV6         *Pool
	handle         *pcap.Handle
	ifaceMAC       net.HardwareAddr
	ifaceIPv6      net.IP
	logger         zerolog.Logger
}

// Lease holds information about a DHCP lease.
type Lease struct {
	IP      net.IP
	MAC     net.HardwareAddr
	Expires time.Time
}

// Pool manages the IP address pool.
type Pool struct {
	sync.RWMutex
	start net.IP
	end   net.IP
	used  map[string]bool
}

// NewServer creates a new DHCP server and starts listening for packets.
func NewServer(cfg *config.Config, sm *core.SessionManager, radiusReqChan chan<- *core.Session, logger zerolog.Logger) (*Server, error) {
	var poolV4, poolV6 *Pool
	var err error
	if !cfg.DHCPRelay {
		poolV4, err = NewPool(cfg.DHCPStart, cfg.DHCPEnd)
		if err != nil {
			return nil, fmt.Errorf("failed to create IPv4 pool: %w", err)
		}
		poolV6, err = NewPool(cfg.DHCPStartV6, cfg.DHCPEndV6)
		if err != nil {
			return nil, fmt.Errorf("failed to create IPv6 pool: %w", err)
		}
	}

	iface, err := net.InterfaceByName(cfg.DHCPIf)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", cfg.DHCPIf, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface %s: %w", cfg.DHCPIf, err)
	}
	var ifaceIPv6 net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.IsLinkLocalUnicast() {
			ifaceIPv6 = ipnet.IP
			break
		}
	}
	if ifaceIPv6 == nil {
		return nil, fmt.Errorf("could not find link-local IPv6 address on interface %s", cfg.DHCPIf)
	}

	handle, err := pcap.OpenLive(cfg.DHCPIf, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// Set a BPF filter to capture both DHCPv4 and DHCPv6 packets
	filter := "udp and (port 67 or 68 or 546 or 547)"
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	server := &Server{
		cfg:            cfg,
		sessionManager: sm,
		radiusReqChan:  radiusReqChan,
		leasesV4:       make(map[string]*Lease),
		poolV4:         poolV4,
		leasesV6:       make(map[string]*Lease),
		poolV6:         poolV6,
		handle:         handle,
		ifaceMAC:       iface.HardwareAddr,
		ifaceIPv6:      ifaceIPv6,
		logger:         logger.With().Str("component", "dhcp").Logger(),
	}

	go server.listen()
	go server.reapLeases()

	return server, nil
}

func (s *Server) reapLeases() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.Lock()
		s.poolV4.Lock()
		for mac, lease := range s.leasesV4 {
			if time.Now().After(lease.Expires) {
				s.logger.Info().Str("mac", mac).Str("ip", lease.IP.String()).Msg("Lease expired, reclaiming")
				delete(s.leasesV4, mac)
				delete(s.poolV4.used, lease.IP.String())
			}
		}
		s.poolV4.Unlock()
		s.Unlock()
	}
}

func (s *Server) listen() {
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	for packet := range packetSource.Packets() {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}
		udp, _ := udpLayer.(*layers.UDP)

		appLayer := packet.ApplicationLayer()
		if appLayer == nil {
			continue
		}

		switch udp.DstPort {
		case 67, 68: // DHCPv4
			if s.cfg.DHCPRelay {
				if err := s.relayDHCPv4(packet); err != nil {
					s.logger.Error().Err(err).Msg("Error relaying DHCPv4 packet")
				}
			} else {
				respBytes, req, err := s.HandleDHCPv4(appLayer.Payload())
				if err != nil {
					s.logger.Error().Err(err).Msg("Error handling DHCPv4 packet")
					continue
				}
				if respBytes != nil {
					if err := s.sendDHCPResponse(respBytes, req); err != nil {
						s.logger.Error().Err(err).Msg("Error sending DHCPv4 response")
					}
				}
			}
		case 546, 547: // DHCPv6
			respBytes, _, err := s.HandleDHCPv6(appLayer.Payload())
			if err != nil {
				s.logger.Error().Err(err).Msg("Error handling DHCPv6 packet")
				continue
			}
			if respBytes != nil {
				// Need the original packet to get source MAC/IP for response
				if err := s.sendDHCPv6Response(respBytes, packet); err != nil {
					s.logger.Error().Err(err).Msg("Error sending DHCPv6 response")
				}
			}
		}
	}
}

func (s *Server) sendDHCPv6Response(respBytes []byte, reqPacket gopacket.Packet) error {
	reqEthLayer := reqPacket.Layer(layers.LayerTypeEthernet)
	reqEth, _ := reqEthLayer.(*layers.Ethernet)

	reqIPv6Layer := reqPacket.Layer(layers.LayerTypeIPv6)
	reqIPv6, _ := reqIPv6Layer.(*layers.IPv6)

	ethLayer := &layers.Ethernet{
		SrcMAC:       s.ifaceMAC,
		DstMAC:       reqEth.SrcMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}

	ipLayer := &layers.IPv6{
		Version:      6,
		TrafficClass: 0,
		FlowLabel:    0,
		HopLimit:     64,
		NextHeader:   layers.IPProtocolUDP,
		SrcIP:        s.ifaceIPv6,
		DstIP:        reqIPv6.SrcIP,
	}

	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(547),
		DstPort: layers.UDPPort(546),
	}
	if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return fmt.Errorf("failed to set network layer for checksum: %w", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buffer, opts,
		ethLayer,
		ipLayer,
		udpLayer,
		gopacket.Payload(respBytes),
	); err != nil {
		return fmt.Errorf("failed to serialize DHCPv6 response packet: %w", err)
	}

	if err := s.handle.WritePacketData(buffer.Bytes()); err != nil {
		return fmt.Errorf("failed to send packet on raw socket: %w", err)
	}

	s.logger.Debug().Str("dst_mac", reqEth.SrcMAC.String()).Str("dst_ip", reqIPv6.SrcIP.String()).Msg("DHCPv6 response sent")
	return nil
}

func (s *Server) relayDHCPv4(packet gopacket.Packet) error {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return fmt.Errorf("cannot relay packet without UDP layer")
	}
	udp, _ := udpLayer.(*layers.UDP)
	if len(udp.Payload) == 0 {
		return fmt.Errorf("cannot relay packet with empty UDP payload")
	}

	dhcpPacket, err := dhcpv4.FromBytes(udp.Payload)
	if err != nil {
		return fmt.Errorf("failed to parse dhcpv4 packet for relay: %w", err)
	}

	// Set the gateway IP address in the packet
	dhcpPacket.GatewayIPAddr = s.cfg.DHCPListen

	// Add Relay Agent Information (Option 82)
	// This is a basic implementation. A production relay would add more sub-options.
	opt82 := dhcpv4.OptRelayAgentInfo(dhcpv4.OptGeneric(dhcpv4.OptionRelayAgentInformation, []byte("coovachilli-go")))
	dhcpPacket.UpdateOption(opt82)

	// Send the packet to the upstream DHCP server
	upstreamAddr := &net.UDPAddr{
		IP:   net.ParseIP(s.cfg.DHCPUpstream),
		Port: 67,
	}
	conn, err := net.DialUDP("udp", nil, upstreamAddr)
	if err != nil {
		return fmt.Errorf("failed to dial upstream dhcp server: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Write(dhcpPacket.ToBytes()); err != nil {
		return fmt.Errorf("failed to send relayed dhcp packet: %w", err)
	}

	s.logger.Info().
		Str("client_mac", dhcpPacket.ClientHWAddr.String()).
		Str("upstream", upstreamAddr.String()).
		Msg("Relayed DHCPv4 packet to upstream server")

	// Listen for the response
	buf := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return fmt.Errorf("failed to read from upstream dhcp server: %w", err)
	}

	s.logger.Info().Msg("Received response from upstream DHCP server")

	// Parse the response
	respPacket, err := dhcpv4.FromBytes(buf[:n])
	if err != nil {
		return fmt.Errorf("failed to parse relayed dhcp response: %w", err)
	}

	// Forward the response back to the client
	return s.sendDHCPResponse(respPacket.ToBytes(), respPacket)
}

func (s *Server) sendDHCPResponse(respBytes []byte, req *dhcpv4.DHCPv4) error {
	resp, err := dhcpv4.FromBytes(respBytes)
	if err != nil {
		return fmt.Errorf("failed to parse response bytes for sending: %w", err)
	}

	ethLayer := &layers.Ethernet{
		SrcMAC:       s.ifaceMAC,
		DstMAC:       req.ClientHWAddr,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    s.cfg.DHCPListen,
		DstIP:    resp.YourIPAddr,
	}

	// For DHCP Offer and Ack to a client without an IP, we broadcast.
	if resp.YourIPAddr.IsUnspecified() || resp.MessageType() == dhcpv4.MessageTypeOffer {
		ipLayer.DstIP = net.IPv4bcast
		ethLayer.DstMAC = layers.EthernetBroadcast
	}

	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(67),
		DstPort: layers.UDPPort(68),
	}
	if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return fmt.Errorf("failed to set network layer for checksum: %w", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buffer, opts,
		ethLayer,
		ipLayer,
		udpLayer,
		gopacket.Payload(respBytes),
	); err != nil {
		return fmt.Errorf("failed to serialize DHCP response packet: %w", err)
	}

	if err := s.handle.WritePacketData(buffer.Bytes()); err != nil {
		return fmt.Errorf("failed to send packet on raw socket: %w", err)
	}

	s.logger.Debug().Str("type", resp.MessageType().String()).Str("mac", req.ClientHWAddr.String()).Msg("DHCP response sent")
	return nil
}

// HandleDHCPv6 handles a DHCPv6 packet.
func (s *Server) HandleDHCPv6(packet []byte) ([]byte, dhcpv6.DHCPv6, error) {
	req, err := dhcpv6.FromBytes(packet)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse DHCPv6 request: %w", err)
	}
	msg, ok := req.(*dhcpv6.Message)
	if !ok {
		return nil, nil, fmt.Errorf("not a regular DHCPv6 message, got %s", req.Type())
	}

	s.logger.Debug().Str("type", req.Type().String()).Msg("Received DHCPv6 request")

	// For now, we'll just handle solicit and request messages.
	var resp dhcpv6.DHCPv6
	switch req.Type() {
	case dhcpv6.MessageTypeSolicit:
		resp, err = s.handleSolicit(msg)
	case dhcpv6.MessageTypeRequest:
		resp, err = s.handleRequestV6(msg)
	default:
		s.logger.Warn().Str("type", req.Type().String()).Msg("Unhandled DHCPv6 message type")
		return nil, nil, nil
	}

	if err != nil {
		return nil, nil, err
	}
	if resp == nil {
		return nil, nil, nil
	}

	return resp.ToBytes(), req, nil
}

func (s *Server) handleSolicit(req *dhcpv6.Message) (dhcpv6.DHCPv6, error) {
	s.poolV6.Lock()
	defer s.poolV6.Unlock()

	ip, err := s.poolV6.getFreeIP()
	if err != nil {
		return nil, err
	}

	// Get client DUID
	clientDUID := req.Options.ClientID()
	if clientDUID == nil {
		return nil, fmt.Errorf("no client DUID in SOLICIT")
	}

	// Create ADVERTISE response
	resp, err := dhcpv6.NewReplyFromMessage(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create DHCPv6 reply: %w", err)
	}
	resp.MessageType = dhcpv6.MessageTypeAdvertise

	serverDUID := &dhcpv6.DUIDLLT{
		HWType:        iana.HWTypeEthernet,
		Time:          dhcpv6.GetTime(),
		LinkLayerAddr: s.ifaceMAC,
	}
	resp.AddOption(dhcpv6.OptServerID(serverDUID))
	resp.AddOption(dhcpv6.OptClientID(clientDUID))

	// Add the IP address
	ianaOpt := req.GetOneOption(dhcpv6.OptionIANA)
	if ianaOpt == nil {
		return nil, fmt.Errorf("no IANA in SOLICIT")
	}
	iaid := ianaOpt.(*dhcpv6.OptIANA).IaId

	ianaResp := dhcpv6.OptIANA{
		IaId: iaid,
		T1:   3600 * time.Second,
		T2:   7200 * time.Second,
		Options: dhcpv6.IdentityOptions{
			Options: dhcpv6.Options{
				&dhcpv6.OptIAAddress{
					IPv6Addr:          ip,
					PreferredLifetime: 3600 * time.Second,
					ValidLifetime:     7200 * time.Second,
				},
			},
		},
	}
	resp.AddOption(&ianaResp)

	// Add DNS servers
	if s.cfg.DNS1V6 != nil {
		resp.AddOption(dhcpv6.OptDNS(s.cfg.DNS1V6))
	}
	if s.cfg.DNS2V6 != nil {
		resp.AddOption(dhcpv6.OptDNS(s.cfg.DNS2V6))
	}

	s.logger.Info().Str("ip", ip.String()).Msg("Advertising IPv6 address")
	return resp, nil
}

func (s *Server) handleRequestV6(req *dhcpv6.Message) (dhcpv6.DHCPv6, error) {
	// Get client DUID
	clientDUID := req.Options.ClientID()
	if clientDUID == nil {
		return nil, fmt.Errorf("no client DUID in REQUEST")
	}

	// Get the address the client is requesting
	ianaOpt := req.GetOneOption(dhcpv6.OptionIANA)
	if ianaOpt == nil {
		return nil, fmt.Errorf("no IANA in REQUEST")
	}
	clientIANA := ianaOpt.(*dhcpv6.OptIANA)
	iaAddrOpt := clientIANA.Options.GetOne(dhcpv6.OptionIAAddr)
	if iaAddrOpt == nil {
		return nil, fmt.Errorf("no IAAddress in REQUEST")
	}
	reqIP := iaAddrOpt.(*dhcpv6.OptIAAddress).IPv6Addr

	// TODO: Validate that the requested IP is valid and was offered by us.
	// For now, we'll just accept it.

	// Create lease
	s.Lock()
	s.leasesV6[clientDUID.String()] = &Lease{
		IP:      reqIP,
		Expires: time.Now().Add(s.cfg.Lease),
	}
	s.Unlock()

	// Create REPLY response
	resp, err := dhcpv6.NewReplyFromMessage(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create DHCPv6 REPLY: %w", err)
	}

	serverDUID := &dhcpv6.DUIDLLT{
		HWType:        iana.HWTypeEthernet,
		Time:          dhcpv6.GetTime(),
		LinkLayerAddr: s.ifaceMAC,
	}
	resp.AddOption(dhcpv6.OptServerID(serverDUID))
	resp.AddOption(dhcpv6.OptClientID(clientDUID))

	// Add the IP address back
	replyIana := dhcpv6.OptIANA{
		IaId: clientIANA.IaId,
		T1:   3600 * time.Second,
		T2:   7200 * time.Second,
		Options: dhcpv6.IdentityOptions{
			Options: dhcpv6.Options{
				&dhcpv6.OptIAAddress{
					IPv6Addr:          reqIP,
					PreferredLifetime: 3600 * time.Second,
					ValidLifetime:     7200 * time.Second,
				},
			},
		},
	}
	resp.AddOption(&replyIana)

	// Add DNS servers
	if s.cfg.DNS1V6 != nil {
		resp.AddOption(dhcpv6.OptDNS(s.cfg.DNS1V6))
	}
	if s.cfg.DNS2V6 != nil {
		resp.AddOption(dhcpv6.OptDNS(s.cfg.DNS2V6))
	}

	s.logger.Info().Str("ip", reqIP.String()).Msg("Replying to DHCPv6 request")
	return resp, nil
}

// HandleDHCPv4 handles a DHCPv4 packet. It returns the response bytes and the original request.
func (s *Server) HandleDHCPv4(packet []byte) ([]byte, *dhcpv4.DHCPv4, error) {
	req, err := dhcpv4.FromBytes(packet)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse DHCPv4 request: %w", err)
	}

	s.logger.Debug().Str("type", req.MessageType().String()).Str("mac", req.ClientHWAddr.String()).Msg("Received DHCPv4 request")

	// For now, we'll just handle discover and request messages.
	var respBytes []byte
	switch req.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		respBytes, err = s.handleDiscover(req)
	case dhcpv4.MessageTypeRequest:
		respBytes, err = s.handleRequest(req)
	default:
		s.logger.Warn().Str("type", req.MessageType().String()).Msg("Unhandled DHCPv4 message type")
		return nil, nil, nil
	}

	if err != nil {
		return nil, nil, err
	}

	return respBytes, req, nil
}

func (s *Server) handleDiscover(req *dhcpv4.DHCPv4) ([]byte, error) {
	s.poolV4.Lock()
	defer s.poolV4.Unlock()

	ip, err := s.poolV4.getFreeIP()
	if err != nil {
		return nil, err
	}

	resp, err := dhcpv4.NewReplyFromRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create DHCPv4 reply: %w", err)
	}

	resp.YourIPAddr = ip
	resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
	resp.UpdateOption(dhcpv4.OptServerIdentifier(s.cfg.DHCPListen))
	resp.UpdateOption(dhcpv4.OptIPAddressLeaseTime(s.cfg.Lease))
	resp.UpdateOption(dhcpv4.OptRouter(s.cfg.DHCPListen))
	resp.UpdateOption(dhcpv4.OptDNS(s.cfg.DNS1, s.cfg.DNS2))

	s.logger.Info().Str("ip", ip.String()).Str("mac", req.ClientHWAddr.String()).Msg("Offering IP")
	return resp.ToBytes(), nil
}

func (s *Server) handleRequest(req *dhcpv4.DHCPv4) ([]byte, error) {
	s.Lock()
	defer s.Unlock()

	reqIP := req.RequestedIPAddress()
	if reqIP == nil || reqIP.IsUnspecified() {
		reqIP = req.ClientIPAddr
	}

	if reqIP == nil || reqIP.IsUnspecified() {
		return nil, fmt.Errorf("no requested IP address in DHCPREQUEST")
	}

	isRenewal := false
	if _, ok := s.leasesV4[req.ClientHWAddr.String()]; ok {
		isRenewal = true
	}

	// For new leases, we need to reserve the IP first.
	if !isRenewal {
		s.poolV4.Lock()
		if s.poolV4.used[reqIP.String()] {
			s.poolV4.Unlock()
			s.logger.Warn().Str("ip", reqIP.String()).Msg("Requested IP is already in use, sending NAK")
			return s.makeNak(req)
		}
		s.poolV4.used[reqIP.String()] = true
		s.poolV4.Unlock()
	}

	// All requests (new and renewal) must go through RADIUS.
	// A session should already exist for renewals from the first request.
	session, ok := s.sessionManager.GetSessionByMAC(req.ClientHWAddr)
	if !ok {
		// If there's no session for a renewal, something is wrong.
		// For a new lease, we create one.
		if isRenewal {
			s.logger.Error().Str("mac", req.ClientHWAddr.String()).Msg("No session found for renewing MAC. Denying.")
			return s.makeNak(req)
		}
		session = s.sessionManager.CreateSession(reqIP, req.ClientHWAddr, s.cfg)
	}

	s.radiusReqChan <- session

	// Wait for the authentication result, with a timeout
	select {
	case authOK := <-session.AuthResult:
		if !authOK {
			s.logger.Warn().Str("mac", req.ClientHWAddr.String()).Msg("Authentication failed, sending NAK")
			// If it was a renewal, remove the old lease.
			if isRenewal {
				delete(s.leasesV4, req.ClientHWAddr.String())
			}
			// Clean up the IP we might have reserved
			s.poolV4.Lock()
			delete(s.poolV4.used, reqIP.String())
			s.poolV4.Unlock()
			return s.makeNak(req)
		}
	case <-time.After(5 * time.Second):
		s.logger.Error().Str("mac", req.ClientHWAddr.String()).Msg("Authentication timed out, sending NAK")
		if isRenewal {
			delete(s.leasesV4, req.ClientHWAddr.String())
		}
		s.poolV4.Lock()
		delete(s.poolV4.used, reqIP.String())
		s.poolV4.Unlock()
		return s.makeNak(req)
	}

	// If we reach here, authentication was successful.
	s.logger.Info().Str("mac", req.ClientHWAddr.String()).Bool("renewal", isRenewal).Msg("Authentication successful")
	lease := &Lease{
		IP:      reqIP,
		MAC:     req.ClientHWAddr,
		Expires: time.Now().Add(s.cfg.Lease),
	}
	s.leasesV4[req.ClientHWAddr.String()] = lease

	resp, err := dhcpv4.NewReplyFromRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create DHCPv4 reply: %w", err)
	}

	resp.YourIPAddr = reqIP
	resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	resp.UpdateOption(dhcpv4.OptServerIdentifier(s.cfg.DHCPListen))
	resp.UpdateOption(dhcpv4.OptIPAddressLeaseTime(s.cfg.Lease))
	resp.UpdateOption(dhcpv4.OptRouter(s.cfg.DHCPListen))
	resp.UpdateOption(dhcpv4.OptDNS(s.cfg.DNS1, s.cfg.DNS2))

	s.logger.Info().Str("ip", reqIP.String()).Str("mac", req.ClientHWAddr.String()).Msg("ACKing IP")

	return resp.ToBytes(), nil
}

func (s *Server) makeNak(req *dhcpv4.DHCPv4) ([]byte, error) {
	resp, err := dhcpv4.NewReplyFromRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create NAK reply: %w", err)
	}
	resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
	resp.UpdateOption(dhcpv4.OptServerIdentifier(s.cfg.DHCPListen))
	return resp.ToBytes(), nil
}

// NewPool creates a new IP address pool.
func NewPool(start, end net.IP) (*Pool, error) {
	// Basic validation
	if start == nil || end == nil {
		return nil, fmt.Errorf("start and end IP addresses must be specified")
	}
	return &Pool{
		start: start,
		end:   end,
		used:  make(map[string]bool),
	}, nil
}

func (p *Pool) getFreeIP() (net.IP, error) {
	// This is a very basic IP pool implementation.
	// It iterates through the IP range to find an available address.
	// A more efficient implementation would be needed for production.
	for ip := p.start; !ip.Equal(p.end); ip = nextIP(ip) {
		if !p.used[ip.String()] {
			p.used[ip.String()] = true
			return ip, nil
		}
	}
	return nil, fmt.Errorf("no free IP addresses in the pool")
}

func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] > 0 {
			break
		}
	}
	return next
}
