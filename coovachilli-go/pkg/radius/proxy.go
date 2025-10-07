package radius

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"github.com/rs/zerolog"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

// ProxyRealm represents a realm routing configuration
type ProxyRealm struct {
	Name           string
	Servers        []ProxyUpstreamServer
	LoadBalancing  string // "round-robin", "failover", "least-load"
	currentIndex   int
	mu             sync.Mutex
}

// ProxyUpstreamServer represents an upstream RADIUS server
type ProxyUpstreamServer struct {
	Address    string
	AuthPort   int
	AcctPort   int
	Secret     []byte
	Timeout    time.Duration
	MaxRetries int
	Priority   int
	Weight     int
	Active     bool
	failures   int
	mu         sync.Mutex
}

// ProxyServer listens for and handles proxied RADIUS requests.
type ProxyServer struct {
	cfg            *config.Config
	logger         zerolog.Logger
	sessionManager *core.SessionManager
	radiusClient   *Client
	realms         map[string]*ProxyRealm
	realmsMu       sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
}

// NewProxyServer creates a new RADIUS proxy server.
func NewProxyServer(cfg *config.Config, sm *core.SessionManager, rc *Client, logger zerolog.Logger) *ProxyServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &ProxyServer{
		cfg:            cfg,
		logger:         logger.With().Str("component", "radius-proxy").Logger(),
		sessionManager: sm,
		radiusClient:   rc,
		realms:         make(map[string]*ProxyRealm),
		ctx:            ctx,
		cancel:         cancel,
	}
}

// AddRealm adds a realm routing configuration
func (s *ProxyServer) AddRealm(realm *ProxyRealm) {
	s.realmsMu.Lock()
	defer s.realmsMu.Unlock()

	s.realms[realm.Name] = realm

	s.logger.Info().
		Str("realm", realm.Name).
		Int("servers", len(realm.Servers)).
		Str("load_balancing", realm.LoadBalancing).
		Msg("Added realm to proxy")
}

// Stop stops the proxy server
func (s *ProxyServer) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.logger.Info().Msg("RADIUS proxy server stopped")
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

		var packet *radius.Packet
		err = s.cfg.ProxySecret.Access(func(secret []byte) error {
			// Create a copy of the secret that will persist after this closure
			secretCopy := make([]byte, len(secret))
			copy(secretCopy, secret)
			var parseErr error
			packet, parseErr = radius.Parse(buf[:n], secretCopy)
			return parseErr
		})
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

	// Extract realm from username for advanced routing
	username := rfc2865.UserName_GetString(request)
	realm := s.extractRealm(username)

	s.logger.Info().
		Str("mac", mac.String()).
		Str("code", request.Code.String()).
		Str("realm", realm).
		Str("username", username).
		Msg("Received proxied RADIUS request")

	session, ok := s.sessionManager.GetSessionByMAC(mac)
	if !ok {
		s.logger.Warn().Str("mac", mac.String()).Msg("No session found for proxied request; creating a temporary one")
		ip := rfc2865.FramedIPAddress_Get(request)
		if ip == nil {
			ip = net.ParseIP("0.0.0.0")
		}
		session = s.sessionManager.CreateSession(ip, mac, 0)
		session.Redir.Username = username
	}

	var upstreamResponse *radius.Packet

	// Check if realm-based routing is configured
	s.realmsMu.RLock()
	realmCfg, hasRealm := s.realms[realm]
	s.realmsMu.RUnlock()

	if hasRealm && len(realmCfg.Servers) > 0 {
		// Use realm-based routing
		upstreamResponse, err = s.routeToRealm(request, realmCfg, session)
	} else {
		// Fallback to default routing
		switch request.Code {
		case radius.CodeAccessRequest:
			// For a proxy, we must forward the original packet's attributes,
			// especially the encrypted User-Password, which we cannot decrypt.
			// We create a new packet and copy all attributes.
			var upstreamPacket *radius.Packet
			err = s.radiusClient.cfg.RadiusSecret.Access(func(secret []byte) error {
				// Create a copy of the secret that will persist after this closure
				secretCopy := make([]byte, len(secret))
				copy(secretCopy, secret)
				upstreamPacket = radius.New(request.Code, secretCopy)
				upstreamPacket.Attributes = request.Attributes
				upstreamPacket.Authenticator = request.Authenticator
				return nil
			})
			if err != nil {
				s.logger.Error().Err(err).Msg("Failed to access RADIUS secret for upstream packet")
				return
			}

			// Use the client's exchange mechanism to send the request upstream.
			upstreamResponse, err = s.radiusClient.exchangeWithFailover(upstreamPacket, true)

		case radius.CodeAccountingRequest:
			statusType := rfc2866.AcctStatusType_Get(request)
			upstreamResponse, err = s.radiusClient.SendAccountingRequest(session, statusType)
		default:
			s.logger.Warn().Str("code", request.Code.String()).Msg("Unsupported RADIUS code for proxying")
			return
		}
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

// extractRealm extracts the realm from a username
func (s *ProxyServer) extractRealm(username string) string {
	// Look for @ separator
	if idx := strings.LastIndex(username, "@"); idx != -1 {
		return username[idx+1:]
	}
	// Look for \ separator (Windows domain style)
	if idx := strings.Index(username, "\\"); idx != -1 {
		return username[:idx]
	}
	return "default"
}

// routeToRealm routes a packet to a realm's upstream servers
func (s *ProxyServer) routeToRealm(request *radius.Packet, realm *ProxyRealm, session *core.Session) (*radius.Packet, error) {
	// Select upstream server based on load balancing strategy
	server, err := s.selectUpstreamServer(realm)
	if err != nil {
		return nil, err
	}

	// Forward packet to selected server
	return s.forwardToUpstream(request, server, session)
}

// selectUpstreamServer selects an upstream server based on load balancing strategy
func (s *ProxyServer) selectUpstreamServer(realm *ProxyRealm) (*ProxyUpstreamServer, error) {
	if len(realm.Servers) == 0 {
		return nil, fmt.Errorf("no upstream servers configured for realm: %s", realm.Name)
	}

	realm.mu.Lock()
	defer realm.mu.Unlock()

	switch realm.LoadBalancing {
	case "round-robin":
		return s.selectRoundRobin(realm)
	case "failover":
		return s.selectFailover(realm)
	case "least-load":
		return s.selectLeastLoad(realm)
	default:
		return s.selectRoundRobin(realm)
	}
}

// selectRoundRobin selects the next server in round-robin fashion
func (s *ProxyServer) selectRoundRobin(realm *ProxyRealm) (*ProxyUpstreamServer, error) {
	attempts := 0
	for attempts < len(realm.Servers) {
		server := &realm.Servers[realm.currentIndex]
		realm.currentIndex = (realm.currentIndex + 1) % len(realm.Servers)

		if server.Active {
			return server, nil
		}
		attempts++
	}

	return nil, fmt.Errorf("no active upstream servers available")
}

// selectFailover selects the highest priority active server
func (s *ProxyServer) selectFailover(realm *ProxyRealm) (*ProxyUpstreamServer, error) {
	var bestServer *ProxyUpstreamServer
	highestPriority := -1

	for i := range realm.Servers {
		server := &realm.Servers[i]
		if server.Active && server.Priority > highestPriority {
			bestServer = server
			highestPriority = server.Priority
		}
	}

	if bestServer == nil {
		return nil, fmt.Errorf("no active upstream servers available")
	}

	return bestServer, nil
}

// selectLeastLoad selects the server with the fewest failures
func (s *ProxyServer) selectLeastLoad(realm *ProxyRealm) (*ProxyUpstreamServer, error) {
	var bestServer *ProxyUpstreamServer
	minFailures := int(^uint(0) >> 1) // Max int

	for i := range realm.Servers {
		server := &realm.Servers[i]
		server.mu.Lock()
		failures := server.failures
		server.mu.Unlock()

		if server.Active && failures < minFailures {
			bestServer = server
			minFailures = failures
		}
	}

	if bestServer == nil {
		return nil, fmt.Errorf("no active upstream servers available")
	}

	return bestServer, nil
}

// forwardToUpstream forwards a packet to an upstream server
func (s *ProxyServer) forwardToUpstream(request *radius.Packet, server *ProxyUpstreamServer, session *core.Session) (*radius.Packet, error) {
	isAuth := request.Code == radius.CodeAccessRequest
	port := server.AcctPort
	if isAuth {
		port = server.AuthPort
	}

	target := fmt.Sprintf("%s:%d", server.Address, port)

	// Re-encode packet with upstream server's secret
	newPacket := radius.New(request.Code, server.Secret)
	for _, attr := range request.Attributes {
		newPacket.Add(attr.Type, attr.Attribute)
	}

	// Set timeout
	timeout := server.Timeout
	if timeout == 0 {
		timeout = s.cfg.RadiusTimeout
	}

	ctx, cancel := context.WithTimeout(s.ctx, timeout)
	defer cancel()

	// Send packet with retries
	maxRetries := server.MaxRetries
	if maxRetries == 0 {
		maxRetries = 3
	}

	var response *radius.Packet
	var err error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			s.logger.Debug().
				Int("attempt", attempt).
				Str("server", target).
				Msg("Retrying RADIUS request")
		}

		response, err = radius.Exchange(ctx, newPacket, target)
		if err == nil {
			// Success - reset failure counter
			server.mu.Lock()
			server.failures = 0
			server.Active = true
			server.mu.Unlock()
			return response, nil
		}

		if ctx.Err() != nil {
			break
		}
	}

	// Mark failure
	server.mu.Lock()
	server.failures++
	if server.failures >= 3 {
		server.Active = false
		s.logger.Warn().
			Str("server", target).
			Int("failures", server.failures).
			Msg("Marking upstream server as inactive")
	}
	server.mu.Unlock()

	return nil, fmt.Errorf("failed to forward packet to %s after %d attempts: %w", target, maxRetries, err)
}

// StartHealthCheck starts health checking of upstream servers
func (s *ProxyServer) StartHealthCheck(interval time.Duration) {
	go s.healthCheckLoop(interval)
}

// healthCheckLoop performs periodic health checks
func (s *ProxyServer) healthCheckLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.performHealthChecks()
		}
	}
}

// performHealthChecks checks all upstream servers
func (s *ProxyServer) performHealthChecks() {
	s.realmsMu.RLock()
	realms := make([]*ProxyRealm, 0, len(s.realms))
	for _, realm := range s.realms {
		realms = append(realms, realm)
	}
	s.realmsMu.RUnlock()

	for _, realm := range realms {
		for i := range realm.Servers {
			server := &realm.Servers[i]
			s.checkServer(server)
		}
	}
}

// checkServer performs a health check on a single server
func (s *ProxyServer) checkServer(server *ProxyUpstreamServer) {
	target := fmt.Sprintf("%s:%d", server.Address, server.AuthPort)

	// Create status server request
	packet := radius.New(radius.CodeStatusServer, server.Secret)
	rfc2865.NASIdentifier_SetString(packet, "proxy-health-check")

	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()

	_, err := radius.Exchange(ctx, packet, target)

	server.mu.Lock()
	if err == nil {
		// Server is healthy
		if !server.Active {
			s.logger.Info().Str("server", target).Msg("Upstream server is now active")
		}
		server.Active = true
		server.failures = 0
	} else {
		server.failures++
		if server.failures >= 3 && server.Active {
			s.logger.Warn().Str("server", target).Msg("Upstream server is now inactive")
			server.Active = false
		}
	}
	server.mu.Unlock()
}