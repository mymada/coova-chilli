package admin

import (
	"encoding/json"
	"net"
	"net/http"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"github.com/rs/zerolog"
)

// Server represents the admin API server
type Server struct {
	cfg          *config.Config
	sessionMgr   *core.SessionManager
	disconnecter core.Disconnector
	logger       zerolog.Logger
	httpServer   *http.Server
	rateLimiter  *RateLimiter // ✅ SECURITY FIX CVE-002: Rate limiting
}

// NewServer creates a new admin API server
func NewServer(
	cfg *config.Config,
	sm *core.SessionManager,
	disconnecter core.Disconnector,
	logger zerolog.Logger,
) *Server {
	rl := NewRateLimiter(logger)
	go rl.Cleanup() // Start background cleanup

	return &Server{
		cfg:          cfg,
		sessionMgr:   sm,
		disconnecter: disconnecter,
		logger:       logger.With().Str("component", "admin").Logger(),
		rateLimiter:  rl, // ✅ SECURITY FIX CVE-002
	}
}

// Start starts the admin API server
func (s *Server) Start() {
	if !s.cfg.AdminAPI.Enabled {
		s.logger.Info().Msg("Admin API is disabled")
		return
	}

	mux := http.NewServeMux()

	// Register API endpoints
	mux.HandleFunc("/api/sessions", s.handleSessions)
	mux.HandleFunc("/api/sessions/disconnect", s.handleDisconnect)
	mux.HandleFunc("/api/stats", s.handleStats)

	s.httpServer = &http.Server{
		Addr:    s.cfg.AdminAPI.Listen,
		Handler: s.authMiddleware(mux),
	}

	s.logger.Info().Str("addr", s.cfg.AdminAPI.Listen).Msg("Starting admin API server")
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		s.logger.Error().Err(err).Msg("Admin API server failed")
	}
}

// authMiddleware provides authentication for the admin API
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ✅ SECURITY FIX CVE-002: Extract client IP
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}

		// ✅ SECURITY FIX CVE-002: Check rate limiting before authentication
		if !s.rateLimiter.IsAllowed(clientIP) {
			s.logger.Warn().Str("ip", clientIP).Msg("Admin API rate limit exceeded")
			http.Error(w, "Too many requests. Try again later.", http.StatusTooManyRequests)
			return
		}

		if s.cfg.AdminAPI.AuthToken != nil && s.cfg.AdminAPI.AuthToken.IsSet() {
			token := r.Header.Get("Authorization")

			// Access the secret token securely
			authorized := false
			err := s.cfg.AdminAPI.AuthToken.Access(func(plaintext []byte) error {
				expectedToken := "Bearer " + string(plaintext)
				if token == expectedToken {
					authorized = true
				}
				return nil
			})

			// ✅ SECURITY FIX CVE-002: Record authentication attempt
			s.rateLimiter.RecordAttempt(clientIP, authorized && err == nil)

			if err != nil || !authorized {
				s.logger.Warn().Str("ip", clientIP).Msg("Failed admin authentication attempt")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			s.logger.Info().Str("ip", clientIP).Msg("Successful admin authentication")
		}
		next.ServeHTTP(w, r)
	})
}

// handleSessions returns all active sessions
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	sessions := s.sessionMgr.GetAllSessions()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

// handleDisconnect disconnects a session
func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "Missing IP parameter", http.StatusBadRequest)
		return
	}

	// Find session by IP and disconnect
	sessions := s.sessionMgr.GetAllSessions()
	for _, session := range sessions {
		if session.HisIP.String() == ip {
			s.disconnecter.Disconnect(session, "Admin-Disconnect")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "disconnected"})
			return
		}
	}

	http.Error(w, "Session not found", http.StatusNotFound)
}

// handleStats returns server statistics
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"total_sessions":  len(s.sessionMgr.GetAllSessions()),
		"active_sessions": s.countActiveSessions(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// countActiveSessions counts authenticated sessions
func (s *Server) countActiveSessions() int {
	count := 0
	for _, session := range s.sessionMgr.GetAllSessions() {
		if session != nil && session.IsAuthenticated() {
			count++
		}
	}
	return count
}
