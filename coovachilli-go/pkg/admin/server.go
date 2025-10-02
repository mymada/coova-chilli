package admin

import (
	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

// Server holds the dependencies for the admin API server.
type Server struct {
	cfg            *config.Config
	sessionManager *core.SessionManager
	disconnecter   core.Disconnector
	logger         zerolog.Logger
	router         *mux.Router
}

// NewServer creates a new admin API server.
func NewServer(cfg *config.Config, sm *core.SessionManager, dc core.Disconnector, logger zerolog.Logger) *Server {
	s := &Server{
		cfg:            cfg,
		sessionManager: sm,
		disconnecter:   dc,
		logger:         logger.With().Str("component", "admin-api").Logger(),
		router:         mux.NewRouter(),
	}
	s.setupRoutes()
	return s
}

// Start begins listening for admin API requests.
func (s *Server) Start() {
	if !s.cfg.AdminAPI.Enabled {
		s.logger.Info().Msg("Admin API is disabled.")
		return
	}

	listenAddr := s.cfg.AdminAPI.Listen
	s.logger.Info().Str("addr", listenAddr).Msg("Starting admin API server")

	if err := http.ListenAndServe(listenAddr, s.router); err != nil {
		s.logger.Error().Err(err).Msg("Admin API server failed to start")
	}
}

func (s *Server) setupRoutes() {
	api := s.router.PathPrefix("/api/v1").Subrouter()

	// Apply authentication middleware to all API routes
	api.Use(s.authMiddleware)

	api.HandleFunc("/status", s.handleStatus).Methods("GET")
	api.HandleFunc("/sessions", s.handleListSessions).Methods("GET")
	api.HandleFunc("/sessions/{id}", s.handleGetSession).Methods("GET")
	api.HandleFunc("/sessions/{id}/logout", s.handleLogoutSession).Methods("POST")
}

// --- Response Structs ---
type sessionResponse struct {
	ID            string    `json:"id"`
	Username      string    `json:"username"`
	IP            string    `json:"ip"`
	MAC           string    `json:"mac"`
	VLANID        uint16    `json:"vlan_id"`
	Authenticated bool      `json:"authenticated"`
	StartTime     time.Time `json:"start_time"`
	LastSeen      time.Time `json:"last_seen"`
	InputOctets   uint64    `json:"input_octets"`
	OutputOctets  uint64    `json:"output_octets"`
}

type statusResponse struct {
	Status         string `json:"status"`
	Uptime         string `json:"uptime"`
	ActiveSessions int    `json:"active_sessions"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// --- Handler Implementations ---

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	uptime := time.Since(core.StartTime).Round(time.Second).String()
	resp := statusResponse{
		Status:         "ok",
		Uptime:         uptime,
		ActiveSessions: len(s.sessionManager.GetAllSessions()),
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	allSessions := s.sessionManager.GetAllSessions()
	resp := make([]sessionResponse, 0, len(allSessions))

	for _, session := range allSessions {
		session.RLock()
		resp = append(resp, sessionResponse{
			ID:            session.HisMAC.String(), // Use MAC as the primary ID
			Username:      session.Redir.Username,
			IP:            session.HisIP.String(),
			MAC:           session.HisMAC.String(),
			VLANID:        session.VLANID,
			Authenticated: session.Authenticated,
			StartTime:     session.StartTime,
			LastSeen:      session.LastSeen,
			InputOctets:   session.InputOctets,
			OutputOctets:  session.OutputOctets,
		})
		session.RUnlock()
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	session := s.findSession(id)
	if session == nil {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("session not found for identifier: %s", id))
		return
	}

	session.RLock()
	resp := sessionResponse{
		ID:            session.HisMAC.String(),
		Username:      session.Redir.Username,
		IP:            session.HisIP.String(),
		MAC:           session.HisMAC.String(),
		VLANID:        session.VLANID,
		Authenticated: session.Authenticated,
		StartTime:     session.StartTime,
		LastSeen:      session.LastSeen,
		InputOctets:   session.InputOctets,
		OutputOctets:  session.OutputOctets,
	}
	session.RUnlock()

	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleLogoutSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	session := s.findSession(id)
	if session == nil {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("session not found for identifier: %s", id))
		return
	}

	s.logger.Info().Str("id", id).Msg("Admin API triggered logout")
	s.disconnecter.Disconnect(session, "Admin-Reset-API")

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "{\"status\":\"ok\", \"message\":\"session disconnected\"}")
}

// --- Helper methods ---

func (s *Server) findSession(identifier string) *core.Session {
	if ip := net.ParseIP(identifier); ip != nil {
		if session, ok := s.sessionManager.GetSessionByIP(ip); ok {
			return session
		}
	}
	if mac, err := net.ParseMAC(identifier); err == nil {
		if session, ok := s.sessionManager.GetSessionByMAC(mac); ok {
			return session
		}
	}
	return nil
}

func (s *Server) writeError(w http.ResponseWriter, code int, message string) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(errorResponse{Error: message})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Don't authenticate if no token is configured, for easier development
		if s.cfg.AdminAPI.AuthToken == "" {
			s.logger.Warn().Msg("Admin API authentication is disabled because no auth_token is configured.")
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.logger.Warn().Msg("Admin API request missing Authorization header")
			s.writeError(w, http.StatusUnauthorized, "Authorization header required")
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			s.logger.Warn().Msg("Admin API request with malformed Authorization header")
			s.writeError(w, http.StatusUnauthorized, "Malformed Authorization header, expected 'Bearer <token>'")
			return
		}

		token := parts[1]
		if token != s.cfg.AdminAPI.AuthToken {
			s.logger.Warn().Msg("Admin API request with invalid token")
			s.writeError(w, http.StatusUnauthorized, "Invalid authentication token")
			return
		}

		next.ServeHTTP(w, r)
	})
}