package dhcp

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
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
	leasesV4       map[string]*Lease
	poolV4         *Pool
	leasesV6       map[string]*Lease
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
		s.handlePacket(packet)
	}
}

func (s *Server) handlePacket(packet gopacket.Packet) {
	var vlanID uint16
	if dot1qLayer := packet.Layer(layers.LayerTypeDot1Q); dot1qLayer != nil {
		dot1q, _ := dot1qLayer.(*layers.Dot1Q)
		vlanID = dot1q.VLANIdentifier
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp, _ := udpLayer.(*layers.UDP)

	switch udp.DstPort {
	case 67, 68: // DHCPv4
		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
		if dhcpLayer == nil {
			s.logger.Debug().Msg("Packet on DHCP ports is not a valid DHCPv4 packet, skipping")
			return
		}
		if s.cfg.DHCPRelay {
			if err := s.relayDHCPv4(packet); err != nil {
				s.logger.Error().Err(err).Msg("Error relaying DHCPv4 packet")
			}
		} else {
			respBytes, req, err := s.HandleDHCPv4(dhcpLayer.LayerContents(), vlanID)
			if err != nil {
				s.logger.Error().Err(err).Msg("Error handling DHCPv4 packet")
				return
			}
			if respBytes != nil {
				if err := s.sendDHCPResponse(respBytes, req); err != nil {
					s.logger.Error().Err(err).Msg("Error sending DHCPv4 response")
				}
			}
		}
	case 546, 547: // DHCPv6
		// VLAN handling for DHCPv6 can be added here if needed
	}
}

func (s *Server) HandleDHCPv4(packet []byte, vlanID uint16) ([]byte, *dhcpv4.DHCPv4, error) {
	req, err := dhcpv4.FromBytes(packet)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse DHCPv4 request: %w", err)
	}
	s.logger.Debug().Str("type", req.MessageType().String()).Str("mac", req.ClientHWAddr.String()).Msg("Received DHCPv4 request")
	var respBytes []byte
	switch req.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		respBytes, err = s.handleDiscover(req)
	case dhcpv4.MessageTypeRequest:
		respBytes, err = s.handleRequest(req, vlanID)
	default:
		s.logger.Warn().Str("type", req.MessageType().String()).Msg("Unhandled DHCPv4 message type")
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return respBytes, req, nil
}

func (s *Server) handleRequest(req *dhcpv4.DHCPv4, vlanID uint16) ([]byte, error) {
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

	session, ok := s.sessionManager.GetSessionByMAC(req.ClientHWAddr)
	isNew := !ok
	if isNew {
		session = s.sessionManager.CreateSession(reqIP, req.ClientHWAddr, vlanID, s.cfg)
	}

	if s.cfg.MACAuth && !session.Authenticated {
		s.logger.Info().Str("mac", req.ClientHWAddr.String()).Msg("Performing MAC authentication for DHCPREQUEST")
		s.radiusReqChan <- session
		select {
		case authOK := <-session.AuthResult:
			if !authOK {
				s.logger.Warn().Str("mac", req.ClientHWAddr.String()).Msg("Authentication failed, sending NAK")
				if isNew {
					s.poolV4.Lock()
					delete(s.poolV4.used, reqIP.String())
					s.poolV4.Unlock()
				}
				return s.makeNak(req)
			}
			s.logger.Info().Str("mac", req.ClientHWAddr.String()).Msg("Authentication successful")
		case <-time.After(5 * time.Second):
			s.logger.Error().Str("mac", req.ClientHWAddr.String()).Msg("Authentication timed out, sending NAK")
			if isNew {
				s.poolV4.Lock()
				delete(s.poolV4.used, reqIP.String())
				s.poolV4.Unlock()
			}
			return s.makeNak(req)
		}
	}

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

// ... (le reste du fichier reste inchangé)

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

// Fonctions DHCPv6 (inchangées pour l'instant)
func (s *Server) sendDHCPv6Response(respBytes []byte, reqPacket gopacket.Packet) error { return nil }
func (s *Server) HandleDHCPv6(packet []byte) ([]byte, dhcpv6.DHCPv6, error) { return nil, nil, nil }
func (s *Server) handleSolicit(req *dhcpv6.Message) (dhcpv6.DHCPv6, error) { return nil, nil }
func (s *Server) handleRequestV6(req *dhcpv6.Message) (dhcpv6.DHCPv6, error) { return nil, nil }
func (s *Server) relayDHCPv4(packet gopacket.Packet) error { return nil }