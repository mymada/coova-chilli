package radius

import (
	"fmt"
	"net"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"github.com/rs/zerolog"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

// ProxyServer listens for and handles proxied RADIUS requests.
type ProxyServer struct {
	cfg            *config.Config
	logger         zerolog.Logger
	sessionManager *core.SessionManager
	radiusClient   *Client
}

// NewProxyServer creates a new RADIUS proxy server.
func NewProxyServer(cfg *config.Config, sm *core.SessionManager, rc *Client, logger zerolog.Logger) *ProxyServer {
	return &ProxyServer{
		cfg:            cfg,
		logger:         logger.With().Str("component", "radius-proxy").Logger(),
		sessionManager: sm,
		radiusClient:   rc,
	}
}

// Start begins listening for incoming RADIUS proxy requests.
func (s *ProxyServer) Start() {
	addr := fmt.Sprintf("%s:%d", s.cfg.ProxyListen, s.cfg.ProxyPort)
	s.logger.Info().Str("addr", addr).Msg("Starting RADIUS proxy server")

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		s.logger.Fatal().Err(err).Msg("Failed to start RADIUS proxy listener")
		return
	}
	defer pc.Close()

	for {
		buf := make([]byte, 4096)
		n, peer, err := pc.ReadFrom(buf)
		if err != nil {
			s.logger.Error().Err(err).Msg("Error reading from proxy socket")
			continue
		}

		packet, err := radius.Parse(buf[:n], []byte(s.cfg.ProxySecret))
		if err != nil {
			s.logger.Error().Err(err).Msg("Failed to parse incoming proxy packet")
			continue
		}

		go s.handleProxyRequest(pc, peer, packet)
	}
}

func (s *ProxyServer) handleProxyRequest(pc net.PacketConn, peer net.Addr, request *radius.Packet) {
	callingStationID := rfc2865.CallingStationID_GetString(request)
	if callingStationID == "" {
		s.logger.Warn().Msg("Received proxy request without Calling-Station-ID; dropping")
		return
	}

	mac, err := net.ParseMAC(callingStationID)
	if err != nil {
		s.logger.Warn().Err(err).Str("calling-station-id", callingStationID).Msg("Failed to parse MAC address from Calling-Station-ID")
		return
	}

	s.logger.Info().Str("mac", mac.String()).Str("code", request.Code.String()).Msg("Received proxied RADIUS request")

	session, ok := s.sessionManager.GetSessionByMAC(mac)
	if !ok {
		s.logger.Warn().Str("mac", mac.String()).Msg("No session found for proxied request; creating a temporary one")
		ip := rfc2865.FramedIPAddress_Get(request)
		if ip == nil {
			ip = net.ParseIP("0.0.0.0")
		}
		session = s.sessionManager.CreateSession(ip, mac, 0)
		session.Redir.Username = rfc2865.UserName_GetString(request)
	}

	var upstreamResponse *radius.Packet
	switch request.Code {
	case radius.CodeAccessRequest:
		// For a proxy, we must forward the original packet's attributes,
		// especially the encrypted User-Password, which we cannot decrypt.
		// We create a new packet and copy all attributes.
		upstreamPacket := radius.New(request.Code, []byte(s.radiusClient.cfg.RadiusSecret))
		upstreamPacket.Attributes = request.Attributes
		upstreamPacket.Authenticator = request.Authenticator

		// Use the client's exchange mechanism to send the request upstream.
		upstreamResponse, err = s.radiusClient.exchangeWithFailover(upstreamPacket, true)

	case radius.CodeAccountingRequest:
		statusType := rfc2866.AcctStatusType_Get(request)
		upstreamResponse, err = s.radiusClient.SendAccountingRequest(session, statusType)
	default:
		s.logger.Warn().Str("code", request.Code.String()).Msg("Unsupported RADIUS code for proxying")
		return
	}

	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to forward proxied request to upstream RADIUS server")
		reject := request.Response(radius.CodeAccessReject)
		encoded, _ := reject.Encode()
		pc.WriteTo(encoded, peer)
		return
	}

	responseForNAS := request.Response(upstreamResponse.Code)
	responseForNAS.Attributes = upstreamResponse.Attributes

	encoded, err := responseForNAS.Encode()
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to encode proxy response")
		return
	}

	if _, err := pc.WriteTo(encoded, peer); err != nil {
		s.logger.Error().Err(err).Msg("Failed to write proxy response back to NAS")
	}
}