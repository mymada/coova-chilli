package dhcp

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/eapol"
	"coovachilli-go/pkg/metrics"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
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
	eapolHandler   *eapol.Handler
	recorder       metrics.Recorder
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
func NewServer(cfg *config.Config, sm *core.SessionManager, radiusReqChan chan<- *core.Session, eapolHandler *eapol.Handler, logger zerolog.Logger, recorder metrics.Recorder) (*Server, error) {
	var poolV4 *Pool
	var poolV6 *Pool
	var err error
	if !cfg.DHCPRelay {
		poolV4, err = NewPool(cfg.DHCPStart, cfg.DHCPEnd)
		if err != nil {
			return nil, fmt.Errorf("failed to create IPv4 pool: %w", err)
		}
		if cfg.DHCPStartV6 != nil && cfg.DHCPEndV6 != nil {
			poolV6, err = NewPool(cfg.DHCPStartV6, cfg.DHCPEndV6)
			if err != nil {
				return nil, fmt.Errorf("failed to create IPv6 pool: %w", err)
			}
		} else {
			logger.Warn().Msg("DHCPv6 pool not configured, DHCPv6 will be disabled.")
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
		logger.Warn().Str("interface", cfg.DHCPIf).Msg("Could not find link-local IPv6 address, DHCPv6 will be disabled.")
	}

	handle, err := pcap.OpenLive(cfg.DHCPIf, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	filter := "udp and (port 67 or 68 or 546 or 547)"
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	if recorder == nil {
		recorder = metrics.NewNoopRecorder()
	}
	server := &Server{
		cfg:            cfg,
		sessionManager: sm,
		radiusReqChan:  radiusReqChan,
		eapolHandler:   eapolHandler,
		recorder:       recorder,
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
		if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			eth, _ := ethLayer.(*layers.Ethernet)
			if eth.EthernetType == layers.EthernetTypeEAPOL {
				if s.eapolHandler != nil {
					s.eapolHandler.HandlePacket(packet)
				}
				continue
			}
		}

		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}
		udp, _ := udpLayer.(*layers.UDP)

		switch udp.DstPort {
		case 67, 68: // DHCPv4
			dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
			if dhcpLayer == nil {
				s.logger.Debug().Msg("Packet on DHCP ports is not a valid DHCPv4 packet, skipping")
				continue
			}
			if s.cfg.DHCPRelay {
				if err := s.relayDHCPv4(packet); err != nil {
					s.logger.Error().Err(err).Msg("Error relaying DHCPv4 packet")
				}
			} else {
				respBytes, req, err := s.HandleDHCPv4(dhcpLayer.LayerContents(), packet)
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
			if s.poolV6 == nil || s.ifaceIPv6 == nil {
				s.logger.Debug().Msg("DHCPv6 is disabled, skipping packet")
				continue
			}
			dhcpLayer := packet.Layer(layers.LayerTypeDHCPv6)
			if dhcpLayer == nil {
				s.logger.Debug().Msg("Packet on DHCPv6 ports is not a valid DHCPv6 packet, skipping")
				continue
			}
			respBytes, _, err := s.HandleDHCPv6(dhcpLayer.LayerContents())
			if err != nil {
				s.logger.Error().Err(err).Msg("Error handling DHCPv6 packet")
				continue
			}
			if respBytes != nil {
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
	var dhcpPayload []byte
	if dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4); dhcpLayer != nil {
		dhcpPayload = dhcpLayer.LayerContents()
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		// Fallback for test packets where gopacket might not decode the DHCP layer
		udp, _ := udpLayer.(*layers.UDP)
		dhcpPayload = udp.Payload
	}

	if len(dhcpPayload) == 0 {
		return fmt.Errorf("cannot relay packet without DHCPv4 layer or payload")
	}

	dhcpPacket, err := dhcpv4.FromBytes(dhcpPayload)
	if err != nil {
		return fmt.Errorf("failed to parse dhcpv4 packet for relay: %w", err)
	}

	dhcpPacket.GatewayIPAddr = s.cfg.DHCPListen

	// Create a sub-option for the relay agent information.
	agentCircuitID := dhcpv4.OptGeneric(dhcpv4.AgentCircuitIDSubOption, []byte("coovachilli-go"))

	// Create the main Relay Agent Information option (Option 82) and add the sub-option to it.
	opt82 := dhcpv4.OptRelayAgentInfo(agentCircuitID)
	dhcpPacket.UpdateOption(opt82)

	host, portStr, err := net.SplitHostPort(s.cfg.DHCPUpstream)
	if err != nil {
		return fmt.Errorf("invalid upstream address format '%s': %w", s.cfg.DHCPUpstream, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid upstream port '%s': %w", portStr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("invalid upstream IP address '%s'", host)
	}

	upstreamAddr := &net.UDPAddr{
		IP:   ip,
		Port: port,
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

	buf := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return fmt.Errorf("failed to read from upstream dhcp server: %w", err)
	}

	s.logger.Info().Msg("Received response from upstream DHCP server")

	respPacket, err := dhcpv4.FromBytes(buf[:n])
	if err != nil {
		return fmt.Errorf("failed to parse relayed dhcp response: %w", err)
	}

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

func (s *Server) HandleDHCPv6(packet []byte) ([]byte, dhcpv6.DHCPv6, error) {
	req, err := dhcpv6.FromBytes(packet)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse DHCPv6 request: %w", err)
	}

	s.logger.Debug().Str("type", req.Type().String()).Msg("Received DHCPv6 request")

	message, ok := req.(*dhcpv6.Message)
	if !ok {
		return nil, nil, fmt.Errorf("failed to assert request as DHCPv6 message")
	}

	var resp dhcpv6.DHCPv6
	switch req.Type() {
	case dhcpv6.MessageTypeSolicit:
		resp, err = s.handleSolicit(message)
	case dhcpv6.MessageTypeRequest:
		resp, err = s.handleRequestV6(message)
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
	s.logger.Debug().Msg("Handling DHCPv6 SOLICIT")
	s.poolV6.Lock()
	defer s.poolV6.Unlock()

	ip, err := s.poolV6.getFreeIP()
	if err != nil {
		return nil, err
	}

	clientDUID := req.Options.ClientID()
	if clientDUID == nil {
		return nil, fmt.Errorf("no client DUID in SOLICIT")
	}

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

	ianaOpt := req.GetOneOption(dhcpv6.OptionIANA)
	if ianaOpt == nil {
		return nil, fmt.Errorf("no IANA in SOLICIT")
	}
	ianaData := &dhcpv6.OptIANA{
		IaId: ianaOpt.(*dhcpv6.OptIANA).IaId,
		T1:   3600 * time.Second,
		T2:   7200 * time.Second,
	}
	iaAddr := &dhcpv6.OptIAAddress{
		IPv6Addr:          ip,
		PreferredLifetime: 3600 * time.Second,
		ValidLifetime:     7200 * time.Second,
	}
	ianaData.Options.Add(iaAddr)
	resp.AddOption(ianaData)

	var dnsServers []net.IP
	if s.cfg.DNS1V6 != nil {
		dnsServers = append(dnsServers, s.cfg.DNS1V6)
	}
	if s.cfg.DNS2V6 != nil {
		dnsServers = append(dnsServers, s.cfg.DNS2V6)
	}
	if len(dnsServers) > 0 {
		dhcpv6.WithDNS(dnsServers...)(resp)
	}

	s.logger.Info().Str("ip", ip.String()).Msg("Advertising IPv6 address")
	return resp, nil
}

func (s *Server) handleRequestV6(req *dhcpv6.Message) (dhcpv6.DHCPv6, error) {
	s.logger.Debug().Msg("Handling DHCPv6 REQUEST")
	clientDUID := req.Options.ClientID()
	if clientDUID == nil {
		return nil, fmt.Errorf("no client DUID in REQUEST")
	}

	ianaOpt := req.GetOneOption(dhcpv6.OptionIANA)
	if ianaOpt == nil {
		return nil, fmt.Errorf("no IANA in REQUEST")
	}
	ianaOption := ianaOpt.(*dhcpv6.OptIANA)
	iaAddrOpt := ianaOption.Options.GetOne(dhcpv6.OptionIAAddr)
	if iaAddrOpt == nil {
		return nil, fmt.Errorf("no IAAddress in REQUEST")
	}
	reqIP := iaAddrOpt.(*dhcpv6.OptIAAddress).IPv6Addr

	s.Lock()
	s.leasesV6[clientDUID.String()] = &Lease{
		IP:      reqIP,
		Expires: time.Now().Add(s.cfg.Lease),
	}
	s.Unlock()

	resp, err := dhcpv6.NewReplyFromMessage(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create DHCPv6 reply: %w", err)
	}

	serverDUID := &dhcpv6.DUIDLLT{
		HWType:        iana.HWTypeEthernet,
		Time:          dhcpv6.GetTime(),
		LinkLayerAddr: s.ifaceMAC,
	}
	resp.AddOption(dhcpv6.OptServerID(serverDUID))
	resp.AddOption(dhcpv6.OptClientID(clientDUID))

	replyIana := &dhcpv6.OptIANA{
		IaId: ianaOption.IaId,
		T1:   3600 * time.Second,
		T2:   7200 * time.Second,
	}
	replyIana.Options.Add(iaAddrOpt)
	resp.AddOption(replyIana)

	var dnsServers []net.IP
	if s.cfg.DNS1V6 != nil {
		dnsServers = append(dnsServers, s.cfg.DNS1V6)
	}
	if s.cfg.DNS2V6 != nil {
		dnsServers = append(dnsServers, s.cfg.DNS2V6)
	}
	if len(dnsServers) > 0 {
		dhcpv6.WithDNS(dnsServers...)(resp)
	}

	s.logger.Info().Str("ip", reqIP.String()).Msg("Replying to DHCPv6 request")
	return resp, nil
}

func (s *Server) HandleDHCPv4(dhcpPayload []byte, packet gopacket.Packet) ([]byte, *dhcpv4.DHCPv4, error) {
	req, err := dhcpv4.FromBytes(dhcpPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse DHCPv4 request: %w", err)
	}

	s.logger.Debug().Str("type", req.MessageType().String()).Str("mac", req.ClientHWAddr.String()).Msg("Received DHCPv4 request")

	labels := metrics.Labels{"type": req.MessageType().String()}
	s.recorder.IncCounter("chilli_dhcp_requests_total", labels)

	var respBytes []byte
	switch req.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		respBytes, err = s.handleDiscover(req)
	case dhcpv4.MessageTypeRequest:
		respBytes, err = s.handleRequest(req, packet)
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
	s.logger.Debug().Msg("Handling DHCPDISCOVER")
	s.poolV4.Lock()
	defer s.poolV4.Unlock()

	ip, err := s.poolV4.getFreeIP()
	if err != nil {
		return nil, err
	}

	s.logger.Info().Str("ip", ip.String()).Str("mac", req.ClientHWAddr.String()).Msg("Offering IP")

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

	return resp.ToBytes(), nil
}

func (s *Server) handleRequest(req *dhcpv4.DHCPv4, packet gopacket.Packet) ([]byte, error) {
	s.logger.Debug().Msg("Handling DHCPREQUEST")
	s.Lock()
	defer s.Unlock()

	var reqIP net.IP
	if opt := req.GetOneOption(dhcpv4.OptionRequestedIPAddress); opt != nil {
		reqIP = net.IP(opt)
	} else {
		reqIP = req.ClientIPAddr
	}

	if reqIP == nil || reqIP.IsUnspecified() {
		return nil, fmt.Errorf("no requested IP address in DHCPREQUEST from client")
	}

	isRenewal := false
	if _, ok := s.leasesV4[req.ClientHWAddr.String()]; ok {
		isRenewal = true
	}

	if !isRenewal {
		// The IP was already marked as 'used' by getFreeIP during the DISCOVER phase.
		// The check for "already in use" was flawed because it would conflict
		// with our own reservation. We now proceed directly to RADIUS auth.
	}

	session, ok := s.sessionManager.GetSessionByMAC(req.ClientHWAddr)
	if !ok {
		if isRenewal {
			s.logger.Error().Str("mac", req.ClientHWAddr.String()).Msg("No session found for renewing MAC. Denying.")
			return s.makeNak(req)
		}
		s.logger.Debug().Str("mac", req.ClientHWAddr.String()).Msg("Creating new session for DHCPREQUEST")
		var vlanID uint16
		if dot1qLayer := packet.Layer(layers.LayerTypeDot1Q); dot1qLayer != nil {
			dot1q, _ := dot1qLayer.(*layers.Dot1Q)
			vlanID = dot1q.VLANIdentifier
		}
		session = s.sessionManager.CreateSession(reqIP, req.ClientHWAddr, vlanID, s.cfg)
	}

	s.logger.Debug().Str("mac", req.ClientHWAddr.String()).Msg("Sending session to RADIUS for authorization")
	s.radiusReqChan <- session

	select {
	case authOK := <-session.AuthResult:
		if !authOK {
			s.logger.Warn().Str("mac", req.ClientHWAddr.String()).Msg("Authentication failed, sending NAK")
			if isRenewal {
				delete(s.leasesV4, req.ClientHWAddr.String())
			}
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

	s.logger.Info().Str("mac", req.ClientHWAddr.String()).Bool("renewal", isRenewal).Msg("Authentication successful, creating lease")
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

func NewPool(start, end net.IP) (*Pool, error) {
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