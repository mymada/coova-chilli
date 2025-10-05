package admin

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

// RateLimiter provides per-IP, per-endpoint rate limiting
type RateLimiter struct {
	mu       sync.RWMutex
	requests map[string]*endpointLimiter // key: IP:endpoint
	limits   map[string]rateLimitConfig  // key: endpoint
}

type endpointLimiter struct {
	tokens     float64
	lastUpdate time.Time
}

type rateLimitConfig struct {
	requestsPerSecond float64
	burst             int
}

// NewRateLimiter creates a rate limiter with default limits
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string]*endpointLimiter),
		limits:   make(map[string]rateLimitConfig),
	}

	// Default: 10 req/s for all endpoints
	rl.setDefaultLimit("*", 10.0, 20)

	// Stricter limits for sensitive operations
	rl.setDefaultLimit("POST:/api/v1/sessions/*/logout", 1.0, 2)
	rl.setDefaultLimit("POST:/api/v1/sessions/*/authorize", 1.0, 2)
	rl.setDefaultLimit("POST:/api/v1/snapshots", 0.1, 1)        // 1 per 10s
	rl.setDefaultLimit("POST:/api/v1/snapshots/*/restore", 0.05, 1) // 1 per 20s
	rl.setDefaultLimit("POST:/api/v1/security/ids/block", 0.5, 2)
	rl.setDefaultLimit("POST:/api/v1/config/reload", 0.05, 1)

	// Read operations: more permissive
	rl.setDefaultLimit("GET:/api/v1/dashboard", 5.0, 10)
	rl.setDefaultLimit("GET:/api/v1/sessions", 2.0, 5)

	return rl
}

func (rl *RateLimiter) setDefaultLimit(endpoint string, reqPerSec float64, burst int) {
	rl.limits[endpoint] = rateLimitConfig{
		requestsPerSecond: reqPerSec,
		burst:             burst,
	}
}

// Allow checks if a request should be allowed (token bucket algorithm)
func (rl *RateLimiter) Allow(ip, method, endpoint string) bool {
	key := fmt.Sprintf("%s:%s:%s", ip, method, endpoint)

	// Find matching limit
	limitKey := fmt.Sprintf("%s:%s", method, endpoint)
	config, exists := rl.limits[limitKey]
	if !exists {
		// Try wildcard match for dynamic routes (e.g., /sessions/*/logout)
		config = rl.findWildcardLimit(method, endpoint)
		if config.requestsPerSecond == 0 {
			config = rl.limits["*"] // Use default
		}
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	limiter, exists := rl.requests[key]

	if !exists {
		// First request: create with full burst
		rl.requests[key] = &endpointLimiter{
			tokens:     float64(config.burst) - 1,
			lastUpdate: now,
		}
		return true
	}

	// Refill tokens based on time elapsed (token bucket)
	elapsed := now.Sub(limiter.lastUpdate).Seconds()
	limiter.tokens += elapsed * config.requestsPerSecond

	// Cap at burst size
	if limiter.tokens > float64(config.burst) {
		limiter.tokens = float64(config.burst)
	}

	limiter.lastUpdate = now

	// Check if we have tokens
	if limiter.tokens >= 1.0 {
		limiter.tokens--
		return true
	}

	return false
}

// findWildcardLimit matches dynamic routes like /sessions/*/logout
func (rl *RateLimiter) findWildcardLimit(method, endpoint string) rateLimitConfig {
	for limitKey, config := range rl.limits {
		if strings.Contains(limitKey, "*") {
			pattern := strings.Replace(limitKey, "*", "[^/]+", -1)
			pattern = fmt.Sprintf("^%s$", pattern)
			// Simple wildcard match
			if matchWildcard(limitKey, fmt.Sprintf("%s:%s", method, endpoint)) {
				return config
			}
		}
	}
	return rateLimitConfig{}
}

// matchWildcard performs simple wildcard matching
func matchWildcard(pattern, str string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == str
	}

	// Must start with first part
	if !strings.HasPrefix(str, parts[0]) {
		return false
	}
	str = str[len(parts[0]):]

	// Must end with last part
	if !strings.HasSuffix(str, parts[len(parts)-1]) {
		return false
	}
	str = str[:len(str)-len(parts[len(parts)-1])]

	// Check middle parts
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(str, parts[i])
		if idx == -1 {
			return false
		}
		str = str[idx+len(parts[i]):]
	}

	return true
}

// CleanupOldEntries removes entries older than 1 hour
func (rl *RateLimiter) CleanupOldEntries() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for key, limiter := range rl.requests {
		if now.Sub(limiter.lastUpdate) > time.Hour {
			delete(rl.requests, key)
		}
	}
}

// extractClientIP extracts the real client IP from headers or connection
func extractClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take first IP in chain
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		ip := strings.TrimSpace(xri)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateLimitMiddleware applies per-endpoint rate limiting
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractClientIP(r)
		endpoint := r.URL.Path
		method := r.Method

		if !s.rateLimiter.Allow(ip, method, endpoint) {
			s.logger.Warn().
				Str("ip", ip).
				Str("method", method).
				Str("endpoint", endpoint).
				Msg("Rate limit exceeded")

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-RateLimit-Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Rate limit exceeded. Please try again later.",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// setupAPIRoutes configures all REST API routes
func (s *Server) setupAPIRoutes() {
	api := s.router.PathPrefix("/api/v1").Subrouter()

	// Apply middleware chain: security headers -> rate limiting -> authentication
	api.Use(s.securityHeadersMiddleware)
	api.Use(s.rateLimitMiddleware)
	api.Use(s.authMiddleware)

	// Status & Health
	api.HandleFunc("/status", s.handleStatus).Methods("GET")
	api.HandleFunc("/health", s.handleHealth).Methods("GET")

	// Dashboard
	api.HandleFunc("/dashboard", s.handleDashboard).Methods("GET")
	api.HandleFunc("/dashboard/stats", s.handleDashboardStats).Methods("GET")

	// Sessions Management
	api.HandleFunc("/sessions", s.handleListSessions).Methods("GET")
	api.HandleFunc("/sessions/{id}", s.handleGetSession).Methods("GET")
	api.HandleFunc("/sessions/{id}/logout", s.handleLogoutSession).Methods("POST")
	api.HandleFunc("/sessions/{id}/authorize", s.handleAuthorizeSession).Methods("POST")

	// User Management
	api.HandleFunc("/users", s.handleListUsers).Methods("GET")
	api.HandleFunc("/users/{username}", s.handleGetUser).Methods("GET")
	api.HandleFunc("/users/{username}/sessions", s.handleGetUserSessions).Methods("GET")

	// Configuration Management
	api.HandleFunc("/config", s.handleGetConfig).Methods("GET")
	api.HandleFunc("/config/reload", s.handleReloadConfig).Methods("POST")

	// Snapshots
	api.HandleFunc("/snapshots", s.handleListSnapshots).Methods("GET")
	api.HandleFunc("/snapshots", s.handleCreateSnapshot).Methods("POST")
	api.HandleFunc("/snapshots/{id}", s.handleGetSnapshot).Methods("GET")
	api.HandleFunc("/snapshots/{id}/restore", s.handleRestoreSnapshot).Methods("POST")
	api.HandleFunc("/snapshots/{id}", s.handleDeleteSnapshot).Methods("DELETE")

	// Security
	api.HandleFunc("/security/ids/events", s.handleIDSEvents).Methods("GET")
	api.HandleFunc("/security/ids/block", s.handleBlockIP).Methods("POST")
	api.HandleFunc("/security/ids/unblock", s.handleUnblockIP).Methods("POST")
	api.HandleFunc("/security/threats", s.handleThreats).Methods("GET")

	// Filtering
	api.HandleFunc("/filter/domains", s.handleListBlockedDomains).Methods("GET")
	api.HandleFunc("/filter/domains", s.handleBlockDomain).Methods("POST")
	api.HandleFunc("/filter/domains/{domain}", s.handleUnblockDomain).Methods("DELETE")

	// Multi-site (if enabled)
	api.HandleFunc("/sites", s.handleListSites).Methods("GET")
	api.HandleFunc("/sites/{id}", s.handleGetSite).Methods("GET")
	api.HandleFunc("/sites/{id}/stats", s.handleGetSiteStats).Methods("GET")
}

// Dashboard handlers

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
	}
	json.NewEncoder(w).Encode(health)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.dashboard == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Dashboard not initialized")
		return
	}

	stats := s.dashboard.GetStats()
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleDashboardStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.dashboard == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Dashboard not initialized")
		return
	}

	stats := s.dashboard.GetStats()

	// Return simplified stats
	simplified := map[string]interface{}{
		"uptime":              stats.Uptime.String(),
		"active_sessions":     stats.ActiveSessions,
		"authenticated":       stats.AuthenticatedSessions,
		"total_sessions":      stats.TotalSessions,
		"unique_users":        stats.UniqueUsers,
		"input_octets":        stats.TotalInputOctets,
		"output_octets":       stats.TotalOutputOctets,
		"input_rate":          stats.CurrentInputRate,
		"output_rate":         stats.CurrentOutputRate,
		"blocked_threats":     stats.BlockedThreats,
		"ids_events":          stats.IDSEvents,
		"filtered_domains":    stats.FilteredDomains,
		"successful_auths":    stats.SuccessfulAuths,
		"failed_auths":        stats.FailedAuths,
	}

	json.NewEncoder(w).Encode(simplified)
}

// User management handlers

type userResponse struct {
	Username       string    `json:"username"`
	ActiveSessions int       `json:"active_sessions"`
	TotalOctets    uint64    `json:"total_octets"`
	LastSeen       time.Time `json:"last_seen"`
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Collect users from active sessions
	sessions := s.sessionManager.GetAllSessions()
	userMap := make(map[string]*userResponse)

	for _, session := range sessions {
		session.RLock()
		username := session.Redir.Username
		if username != "" {
			if ur, exists := userMap[username]; exists {
				ur.ActiveSessions++
				ur.TotalOctets += session.InputOctets + session.OutputOctets
				if session.LastSeen.After(ur.LastSeen) {
					ur.LastSeen = session.LastSeen
				}
			} else {
				userMap[username] = &userResponse{
					Username:       username,
					ActiveSessions: 1,
					TotalOctets:    session.InputOctets + session.OutputOctets,
					LastSeen:       session.LastSeen,
				}
			}
		}
		session.RUnlock()
	}

	users := make([]userResponse, 0, len(userMap))
	for _, ur := range userMap {
		users = append(users, *ur)
	}

	json.NewEncoder(w).Encode(users)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	username := vars["username"]

	sessions := s.sessionManager.GetAllSessions()
	var userSessions []sessionResponse

	for _, session := range sessions {
		session.RLock()
		if session.Redir.Username == username {
			userSessions = append(userSessions, sessionResponse{
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
			})
		}
		session.RUnlock()
	}

	if len(userSessions) == 0 {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("user not found: %s", username))
		return
	}

	response := map[string]interface{}{
		"username": username,
		"sessions": userSessions,
	}

	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleGetUserSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	username := vars["username"]

	sessions := s.sessionManager.GetAllSessions()
	var userSessions []sessionResponse

	for _, session := range sessions {
		session.RLock()
		if session.Redir.Username == username {
			userSessions = append(userSessions, sessionResponse{
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
			})
		}
		session.RUnlock()
	}

	json.NewEncoder(w).Encode(userSessions)
}

// Configuration handlers

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Return sanitized config (without secrets)
	sanitized := map[string]interface{}{
		"net":            s.cfg.NetStr,
		"dhcpif":         s.cfg.DHCPIf,
		"uamport":        s.cfg.UAMPort,
		"radiusserver1":  s.cfg.RadiusServer1,
		"vlan_enabled":   s.cfg.VLAN.Enabled,
		"ids_enabled":    s.cfg.IDS.Enabled,
		"filter_enabled": s.cfg.URLFilter.Enabled,
		"gdpr_enabled":   s.cfg.GDPR.Enabled,
	}

	json.NewEncoder(w).Encode(sanitized)
}

func (s *Server) handleReloadConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// TODO: Implement config reload logic
	s.writeError(w, http.StatusNotImplemented, "Config reload not yet implemented")
}

// Session authorization handler

type authorizeRequest struct {
	Username string `json:"username"`
	Duration int    `json:"duration"` // in seconds
}

func (s *Server) handleAuthorizeSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	// Validate session ID
	if err := ValidateSessionID(id); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid session ID: %v", err))
		return
	}

	var req authorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate username
	if err := ValidateUsername(req.Username); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid username: %v", err))
		return
	}

	// Validate duration
	if req.Duration < 0 || req.Duration > 86400*7 {
		s.writeError(w, http.StatusBadRequest, "duration must be between 0 and 604800 seconds (7 days)")
		return
	}

	session := s.findSession(id)
	if session == nil {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("session not found: %s", id))
		return
	}

	session.Lock()
	session.Authenticated = true
	session.Redir.Username = req.Username
	session.Unlock()

	s.logger.Info().
		Str("session_id", id).
		Str("username", req.Username).
		Msg("Session authorized via API")

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, `{"status":"ok", "message":"session authorized"}`)
}

// Placeholder handlers for advanced features

func (s *Server) handleIDSEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// TODO: Integrate with IDS module
	json.NewEncoder(w).Encode([]interface{}{})
}

func (s *Server) handleBlockIP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// TODO: Integrate with IDS module
	s.writeError(w, http.StatusNotImplemented, "IDS integration pending")
}

func (s *Server) handleUnblockIP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// TODO: Integrate with IDS module
	s.writeError(w, http.StatusNotImplemented, "IDS integration pending")
}

func (s *Server) handleThreats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// TODO: Integrate with antimalware module
	json.NewEncoder(w).Encode([]interface{}{})
}

func (s *Server) handleListBlockedDomains(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// TODO: Integrate with filter module
	json.NewEncoder(w).Encode([]interface{}{})
}

func (s *Server) handleBlockDomain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// TODO: Integrate with filter module
	s.writeError(w, http.StatusNotImplemented, "Filter integration pending")
}

func (s *Server) handleUnblockDomain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// TODO: Integrate with filter module
	s.writeError(w, http.StatusNotImplemented, "Filter integration pending")
}

func (s *Server) handleListSites(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// TODO: Implement multi-site management
	json.NewEncoder(w).Encode([]interface{}{})
}

func (s *Server) handleGetSite(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// TODO: Implement multi-site management
	s.writeError(w, http.StatusNotImplemented, "Multi-site not yet implemented")
}

func (s *Server) handleGetSiteStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// TODO: Implement multi-site management
	s.writeError(w, http.StatusNotImplemented, "Multi-site not yet implemented")
}
