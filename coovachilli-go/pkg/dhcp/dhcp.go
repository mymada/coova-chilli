package dhcp

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

// Server holds the state for the DHCP server.
type Server struct {
	sync.RWMutex
	cfg           *config.Config
	sessionManager *core.SessionManager
	radiusReqChan chan<- *core.Session
	leasesV4      map[string]*Lease
	poolV4        *Pool
	handle        *pcap.Handle
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
func NewServer(cfg *config.Config, sm *core.SessionManager, radiusReqChan chan<- *core.Session) (*Server, error) {
	pool, err := NewPool(cfg.DHCPStart, cfg.DHCPEnd)
	if err != nil {
		return nil, fmt.Errorf("failed to create IPv4 pool: %w", err)
	}

	handle, err := pcap.OpenLive(cfg.DHCPIf, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// Set a BPF filter to capture only DHCP packets
	filter := "udp and (port 67 or 68)"
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	server := &Server{
		cfg:           cfg,
		sessionManager: sm,
		radiusReqChan: radiusReqChan,
		leasesV4:      make(map[string]*Lease),
		poolV4:        pool,
		handle:        handle,
	}

	go server.listen()

	return server, nil
}

func (s *Server) listen() {
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	for packet := range packetSource.Packets() {
		// We only care about UDP packets
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			if appLayer := packet.ApplicationLayer(); appLayer != nil {
				resp, err := s.HandleDHCPv4(appLayer.Payload())
				if err != nil {
					log.Printf("Error handling DHCP packet: %v", err)
					continue
				}
				if resp != nil {
					// We need to construct the full Ethernet/IP/UDP packet to send back.
					// This is a complex task and will be implemented later.
					log.Printf("DHCP response created, but not sent.")
				}
			}
		}
	}
}

// HandleDHCPv4 handles a DHCPv4 packet.
func (s *Server) HandleDHCPv4(packet []byte) ([]byte, error) {
	req, err := dhcpv4.FromBytes(packet)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DHCPv4 request: %w", err)
	}

	log.Printf("Received DHCPv4 request: %s", req.MessageType().String())

	// For now, we'll just handle discover and request messages.
	switch req.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		return s.handleDiscover(req)
	case dhcpv4.MessageTypeRequest:
		return s.handleRequest(req)
	default:
		log.Printf("Unhandled DHCPv4 message type: %s", req.MessageType().String())
		return nil, nil
	}
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

	log.Printf("Offering IP %s to %s", ip, req.ClientHWAddr.String())
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

	s.poolV4.Lock()
	s.poolV4.used[reqIP.String()] = true
	s.poolV4.Unlock()

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

	log.Printf("ACKing IP %s for %s", reqIP, req.ClientHWAddr.String())

	// Create a new session for the client
	session := s.sessionManager.CreateSession(reqIP, req.ClientHWAddr)

	// Send an authentication request to the RADIUS channel
	s.radiusReqChan <- session

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
