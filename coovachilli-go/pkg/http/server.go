package http

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/fas"
	"coovachilli-go/pkg/firewall"
	"coovachilli-go/pkg/metrics"
	"coovachilli-go/pkg/radius"
	"coovachilli-go/pkg/script"
	"coovachilli-go/pkg/wispr"
	"github.com/rs/zerolog"
	"layeh.com/radius/rfc2866"
)

// SSOHandlers interface for SSO integration
type SSOHandlers interface {
	RegisterRoutes(mux *http.ServeMux)
}

// Server holds the state for the HTTP server.
type Server struct {
	cfg            *config.Config
	sessionManager *core.SessionManager
	radiusReqChan  chan<- *core.Session
	disconnecter   core.Disconnector
	logger         zerolog.Logger
	recorder       metrics.Recorder
	firewall       firewall.FirewallManager
	scriptRunner   *script.Runner
	radiusClient   *radius.Client
	templates      *template.Template
	ssoHandlers    SSOHandlers
}

// NewServer creates a new HTTP server.
func NewServer(
	cfg *config.Config,
	sm *core.SessionManager,
	radiusReqChan chan<- *core.Session,
	disconnecter core.Disconnector,
	logger zerolog.Logger,
	recorder metrics.Recorder,
	fw firewall.FirewallManager,
	sr *script.Runner,
	rc *radius.Client,
	ssoHandlers SSOHandlers,
) (*Server, error) {
	if recorder == nil {
		recorder = metrics.NewNoopRecorder()
	}

	templateDir := cfg.TemplateDir
	if templateDir == "" {
		templateDir = "www/templates" // Default directory
	}
	templates, err := template.ParseGlob(filepath.Join(templateDir, "*.html"))
	if err != nil {
		// If templates fail to load, we can't serve the portal.
		// However, we can proceed if FAS is enabled, as the local portal won't be used.
		if !cfg.FAS.Enabled {
			return nil, fmt.Errorf("failed to parse templates and FAS is not enabled: %w", err)
		}
		logger.Warn().Err(err).Msg("Failed to parse local templates, but proceeding because FAS is enabled")
	} else {
		logger.Info().Str("path", templateDir).Msg("HTML templates loaded")
	}

	return &Server{
		cfg:            cfg,
		sessionManager: sm,
		radiusReqChan:  radiusReqChan,
		disconnecter:   disconnecter,
		logger:         logger.With().Str("component", "http").Logger(),
		recorder:       recorder,
		firewall:       fw,
		scriptRunner:   sr,
		radiusClient:   rc,
		templates:      templates,
		ssoHandlers:    ssoHandlers,
	}, nil
}

// Start starts the HTTP server.
func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handlePortal)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/logout", s.handleLogout)

	// API endpoints
	mux.HandleFunc("/api/v1/fas/auth", s.handleFASAuth)
	mux.HandleFunc("/api/v1/status", s.handleApiStatus)
	mux.HandleFunc("/api/v1/login", s.handleApiLogin)
	mux.HandleFunc("/api/v1/logout", s.handleApiLogout)
	mux.HandleFunc("/json/status", s.handleJsonpStatus)

	// WISPr endpoints
	http.HandleFunc("/wispr", s.handleWISPr)
	http.HandleFunc("/wispr/login", s.handleWISPrLogin)

	// ✅ CORRECTION CRITIQUE: Enregistrer les routes SSO
	if s.ssoHandlers != nil {
		s.logger.Info().Msg("Registering SSO routes")
		s.ssoHandlers.RegisterRoutes(mux)
	}

	addr := fmt.Sprintf(":%d", s.cfg.UAMPort)

	rateLimiter := NewRateLimiter(s.logger, s.cfg.UAMRateLimitEnabled, s.cfg.UAMRateLimit, s.cfg.UAMRateLimitBurst)

	server := &http.Server{
		Addr:         addr,
		Handler:      rateLimiter.Middleware(mux),
		ReadTimeout:  s.cfg.UAMReadTimeout,
		WriteTimeout: s.cfg.UAMWriteTimeout,
		IdleTimeout:  s.cfg.UAMIdleTimeout,
	}

	s.logger.Info().
		Str("addr", addr).
		Dur("read_timeout", server.ReadTimeout).
		Dur("write_timeout", server.WriteTimeout).
		Dur("idle_timeout", server.IdleTimeout).
		Msg("Starting UAM server")

	var err error
	if s.cfg.CertFile != "" && s.cfg.KeyFile != "" {
		s.logger.Info().Msg("UAM server will use HTTPS")
		err = server.ListenAndServeTLS(s.cfg.CertFile, s.cfg.KeyFile)
	} else {
		s.logger.Info().Msg("UAM server will use HTTP")
		err = server.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		s.logger.Fatal().Err(err).Msg("UAM server failed")
	}
}

const sessionCookieName = "coova_session"

func (s *Server) handlePortal(w http.ResponseWriter, r *http.Request) {
	// First, check for an existing valid session cookie to bypass login/FAS
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		session, ok := s.sessionManager.GetSessionByToken(cookie.Value)
		if ok && session.Authenticated {
			s.logger.Info().Str("user", session.Redir.Username).Msg("Automatic login via cookie successful")
			http.Redirect(w, r, "/status", http.StatusFound)
			return
		}
	}

	// If FAS is enabled, redirect to the external authentication service.
	if s.cfg.FAS.Enabled {
		ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			s.logger.Error().Err(err).Msg("Failed to get client IP for FAS redirect")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		ip := net.ParseIP(ipStr)
		session, ok := s.sessionManager.GetSessionByIP(ip)
		if !ok {
			s.logger.Warn().Str("ip", ipStr).Msg("No session found for incoming client for FAS redirect")
			http.Error(w, "Session not found", http.StatusNotFound)
			return
		}

		// Generate the FAS token
		tokenString, err := fas.GenerateToken(session, &s.cfg.FAS)
		if err != nil {
			s.logger.Error().Err(err).Msg("Failed to generate FAS token")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Construct the redirection URL
		fasURL, err := url.Parse(s.cfg.FAS.URL)
		if err != nil {
			s.logger.Error().Err(err).Str("url", s.cfg.FAS.URL).Msg("Failed to parse FAS URL")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		q := fasURL.Query()
		q.Set("token", tokenString)
		q.Set("client_mac", session.HisMAC.String())
		q.Set("client_ip", session.HisIP.String())
		q.Set("nas_id", s.cfg.RadiusNASID)
		q.Set("original_url", r.URL.String()) // Pass the originally requested URL
		fasURL.RawQuery = q.Encode()

		s.logger.Info().Str("user_ip", ipStr).Str("redirect_url", fasURL.String()).Msg("Redirecting user to FAS")
		http.Redirect(w, r, fasURL.String(), http.StatusFound)
		return
	}

	// Fallback to local login page if FAS is not enabled
	err = s.templates.ExecuteTemplate(w, "login.html", nil)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to execute login template")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// ✅ SECURITY: Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, 1048576) // 1MB max
	defer r.Body.Close()

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	s.logger.Info().Str("user", username).Str("remote_addr", r.RemoteAddr).Msg("Login attempt")

	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "Failed to get client IP address", http.StatusInternalServerError)
		return
	}
	ip := net.ParseIP(ipStr)

	session, ok := s.sessionManager.GetSessionByIP(ip)
	if !ok {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	session.Lock()
	session.Redir.Username = username
	session.Redir.Password = password
	session.Unlock()

	s.radiusReqChan <- session

	now := time.Now()
	labels := map[string]string{"type": "uam"} // UAM login
	s.recorder.IncCounter("chilli_http_logins_total", labels)

	select {
	case authOK := <-session.AuthResult:
		duration := time.Since(now).Seconds()
		s.recorder.ObserveHistogram("chilli_http_login_duration_seconds", labels, duration)
		if authOK {
			labels["status"] = "success"
			s.recorder.IncCounter("chilli_http_login_outcomes_total", labels)

			token, err := generateSecureToken(32)
			if err != nil {
				s.logger.Error().Err(err).Msg("Failed to generate session token")
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			session.Lock()
			session.Token = token
			session.Unlock()
			s.sessionManager.AssociateToken(session)

			// ✅ CORRECTION: Secure cookie settings
			cookie := &http.Cookie{
				Name:     sessionCookieName,
				Value:    token,
				Expires:  time.Now().Add(24 * time.Hour),
				HttpOnly: true,
				Path:     "/",
				SameSite: http.SameSiteStrictMode, // ✅ CSRF protection
			}

			// Set Secure flag if using HTTPS
			if s.cfg.CertFile != "" && s.cfg.KeyFile != "" {
				cookie.Secure = true // ✅ HTTPS only
			}

			http.SetCookie(w, cookie)

			http.Redirect(w, r, "/status", http.StatusFound)
		} else {
			labels["status"] = "failure"
			s.recorder.IncCounter("chilli_http_login_outcomes_total", labels)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "<h1>Login Failed</h1><p>Invalid username or password.</p>")
		}
	case <-time.After(10 * time.Second):
		duration := time.Since(now).Seconds()
		s.recorder.ObserveHistogram("chilli_http_login_duration_seconds", labels, duration)
		labels["status"] = "timeout"
		s.recorder.IncCounter("chilli_http_login_outcomes_total", labels)
		http.Error(w, "Login request timed out.", http.StatusGatewayTimeout)
	}
}

func generateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type statusPageData struct {
	Username        string
	IPAddress       string
	MACAddress      string
	StartTime       string
	SessionDuration string
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "Failed to get client IP address", http.StatusInternalServerError)
		return
	}
	ip := net.ParseIP(ipStr)

	session, ok := s.sessionManager.GetSessionByIP(ip)
	if !ok {
		http.Error(w, "Session not found. Please log in again.", http.StatusNotFound)
		return
	}

	session.RLock()
	defer session.RUnlock()

	duration := time.Since(session.StartTime).Round(time.Second)
	data := statusPageData{
		Username:        session.Redir.Username,
		IPAddress:       session.HisIP.String(),
		MACAddress:      session.HisMAC.String(),
		StartTime:       session.StartTime.Format(time.RFC1123),
		SessionDuration: duration.String(),
	}

	// If templates are not loaded (e.g., FAS mode), return JSON response
	if s.templates == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
		return
	}

	err = s.templates.ExecuteTemplate(w, "status.html", data)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to execute status template")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "Failed to get client IP address", http.StatusInternalServerError)
		return
	}
	ip := net.ParseIP(ipStr)

	session, ok := s.sessionManager.GetSessionByIP(ip)
	if !ok {
		http.Error(w, "Session not found.", http.StatusNotFound)
		return
	}

	s.disconnecter.Disconnect(session, "User-Request")

	fmt.Fprint(w, "<h1>You have been logged out.</h1>")
}

// --- API Handlers ---

type apiStatusResponse struct {
	Username      string `json:"username"`
	IP            string `json:"ip"`
	MAC           string `json:"mac"`
	SessionStart  time.Time `json:"session_start"`
	SessionUptime int64  `json:"session_uptime_seconds"`
	InputOctets   uint64 `json:"input_octets"`
	OutputOctets  uint64 `json:"output_octets"`
}

func (s *Server) handleApiStatus(w http.ResponseWriter, r *http.Request) {
	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "{\"error\":\"Failed to get client IP address\"}", http.StatusInternalServerError)
		return
	}
	ip := net.ParseIP(ipStr)

	session, ok := s.sessionManager.GetSessionByIP(ip)
	if !ok {
		http.Error(w, "{\"error\":\"Session not found\"}", http.StatusNotFound)
		return
	}

	session.RLock()
	defer session.RUnlock()

	resp := apiStatusResponse{
		Username:      session.Redir.Username,
		IP:            session.HisIP.String(),
		MAC:           session.HisMAC.String(),
		SessionStart:  session.StartTime,
		SessionUptime: int64(time.Since(session.StartTime).Seconds()),
		InputOctets:   session.InputOctets,
		OutputOctets:  session.OutputOctets,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

type apiLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleApiLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "{\"error\":\"Method not allowed\"}", http.StatusMethodNotAllowed)
		return
	}

	// ✅ SECURITY: Limit request body size to prevent DoS
	r.Body = http.MaxBytesReader(w, r.Body, 1048576) // 1MB max
	defer r.Body.Close()

	var req apiLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "{\"error\":\"Invalid request body\"}", http.StatusBadRequest)
		return
	}

	s.logger.Info().Str("user", req.Username).Str("remote_addr", r.RemoteAddr).Msg("API login attempt")

	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "{\"error\":\"Failed to get client IP address\"}", http.StatusInternalServerError)
		return
	}
	ip := net.ParseIP(ipStr)

	session, ok := s.sessionManager.GetSessionByIP(ip)
	if !ok {
		http.Error(w, "{\"error\":\"Session not found\"}", http.StatusNotFound)
		return
	}

	session.Lock()
	session.Redir.Username = req.Username
	session.Redir.Password = req.Password
	session.Unlock()

	s.radiusReqChan <- session

	now := time.Now()
	labels := map[string]string{"type": "api"}
	s.recorder.IncCounter("chilli_http_logins_total", labels)

	w.Header().Set("Content-Type", "application/json")
	select {
	case authOK := <-session.AuthResult:
		duration := time.Since(now).Seconds()
		s.recorder.ObserveHistogram("chilli_http_login_duration_seconds", labels, duration)

		if authOK {
			labels["status"] = "success"
			s.recorder.IncCounter("chilli_http_login_outcomes_total", labels)

			token, err := generateSecureToken(32)
			if err != nil {
				s.logger.Error().Err(err).Msg("Failed to generate session token")
				http.Error(w, "{\"error\":\"Internal server error\"}", http.StatusInternalServerError)
				return
			}

			session.Lock()
			session.Token = token
			session.Unlock()
			s.sessionManager.AssociateToken(session)

			// ✅ SECURITY: Secure cookie with CSRF protection
			cookie := &http.Cookie{
				Name:     sessionCookieName,
				Value:    token,
				Expires:  time.Now().Add(24 * time.Hour),
				HttpOnly: true,
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
			}
			if s.cfg.CertFile != "" && s.cfg.KeyFile != "" {
				cookie.Secure = true
			}
			http.SetCookie(w, cookie)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "{\"status\":\"success\"}")
		} else {
			labels["status"] = "failure"
			s.recorder.IncCounter("chilli_http_login_outcomes_total", labels)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "{\"error\":\"Invalid username or password\"}")
		}
	case <-time.After(10 * time.Second):
		duration := time.Since(now).Seconds()
		s.recorder.ObserveHistogram("chilli_http_login_duration_seconds", labels, duration)
		labels["status"] = "timeout"
		s.recorder.IncCounter("chilli_http_login_outcomes_total", labels)
		w.WriteHeader(http.StatusGatewayTimeout)
		fmt.Fprint(w, "{\"error\":\"Login request timed out\"}")
	}
}

func (s *Server) handleApiLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "{\"error\":\"Method not allowed\"}", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		http.Error(w, "{\"error\":\"Not authenticated\"}", http.StatusUnauthorized)
		return
	}

	session, ok := s.sessionManager.GetSessionByToken(cookie.Value)
	if !ok {
		http.Error(w, "{\"error\":\"Invalid session\"}", http.StatusUnauthorized)
		return
	}

	s.logger.Info().Str("user", session.Redir.Username).Msg("API logout")

	// Clear the cookie
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Path:     "/",
	})

	s.disconnecter.Disconnect(session, "User-Request")

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, "{\"status\":\"logged_out\"}")
}

// --- JSONP Handler ---

type jsonpStatusResponse struct {
	ClientState int    `json:"clientState"`
	Message     string `json:"message,omitempty"`
	core.SessionParams
	Accounting jsonpAccounting `json:"accounting"`
}

type jsonpAccounting struct {
	SessionTime  uint32 `json:"sessionTime"`
	IdleTime     uint32 `json:"idleTime"`
	InputOctets  uint64 `json:"inputOctets"`
	OutputOctets uint64 `json:"outputOctets"`
}

// isValidJSONPCallback validates that a JSONP callback is safe.
// It only allows alphanumeric characters, underscores, dots, and dollar signs.
// This prevents XSS attacks via callback injection.
func isValidJSONPCallback(callback string) bool {
	if len(callback) == 0 || len(callback) > 100 {
		return false
	}
	// First character must be letter, underscore, or dollar sign
	if !((callback[0] >= 'a' && callback[0] <= 'z') ||
		(callback[0] >= 'A' && callback[0] <= 'Z') ||
		callback[0] == '_' || callback[0] == '$') {
		return false
	}
	// Subsequent characters can include digits and dots
	for _, ch := range callback[1:] {
		if !((ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '_' || ch == '.' || ch == '$') {
			return false
		}
	}
	return true
}

func (s *Server) handleJsonpStatus(w http.ResponseWriter, r *http.Request) {
	callback := r.URL.Query().Get("callback")
	if callback == "" {
		http.Error(w, "Callback function name is required", http.StatusBadRequest)
		return
	}

	// SECURITY: Validate callback to prevent XSS injection
	if !isValidJSONPCallback(callback) {
		s.logger.Warn().Str("callback", callback).Msg("Invalid JSONP callback rejected")
		http.Error(w, "Invalid callback function name", http.StatusBadRequest)
		return
	}

	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ipStr = r.RemoteAddr
	}
	ip := net.ParseIP(ipStr)

	session, ok := s.sessionManager.GetSessionByIP(ip)

	var resp jsonpStatusResponse
	if !ok || !session.Authenticated {
		resp = jsonpStatusResponse{
			ClientState: 0, // Not authenticated
		}
	} else {
		session.RLock()
		resp = jsonpStatusResponse{
			ClientState:   1, // Authenticated
			SessionParams: session.SessionParams,
			Accounting: jsonpAccounting{
				SessionTime:  uint32(time.Since(session.StartTime).Seconds()),
				IdleTime:     uint32(time.Since(session.LastSeen).Seconds()),
				InputOctets:  session.InputOctets,
				OutputOctets: session.OutputOctets,
			},
		}
		session.RUnlock()
	}

	jsonBytes, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/javascript")
	fmt.Fprintf(w, "%s(%s);", callback, string(jsonBytes))
}

// --- WISPr Handlers ---

func (s *Server) handleWISPr(w http.ResponseWriter, r *http.Request) {
	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ipStr = r.RemoteAddr
	}
	ip := net.ParseIP(ipStr)

	session, ok := s.sessionManager.GetSessionByIP(ip)

	// Check if client supports WISPr
	userAgent := r.Header.Get("User-Agent")
	accept := r.Header.Get("Accept")
	isWISPrClient := wispr.DetectWISPrClient(userAgent, accept)

	if !isWISPrClient {
		// Not a WISPr client, redirect to regular portal
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Generate WISPr XML
	includeSessionParams := ok && session.Authenticated
	wsprXML, err := wispr.GenerateWISPrXML(s.cfg, session, includeSessionParams)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to generate WISPr XML")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	fmt.Fprint(w, wsprXML)
}

func (s *Server) handleWISPrLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	username := r.FormValue("UserName")
	password := r.FormValue("Password")

	if username == "" || password == "" {
		wsprXML, _ := wispr.GenerateWISPrLoginResponse(s.cfg, nil, false, "Username and password required")
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, wsprXML)
		return
	}

	s.logger.Info().Str("user", username).Str("remote_addr", r.RemoteAddr).Msg("WISPr login attempt")

	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ipStr = r.RemoteAddr
	}
	ip := net.ParseIP(ipStr)

	session, ok := s.sessionManager.GetSessionByIP(ip)
	if !ok {
		wsprXML, _ := wispr.GenerateWISPrLoginResponse(s.cfg, nil, false, "Session not found")
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, wsprXML)
		return
	}

	session.Lock()
	session.Redir.Username = username
	session.Redir.Password = password
	session.Unlock()

	s.radiusReqChan <- session

	now := time.Now()
	labels := map[string]string{"type": "wispr"}
	s.recorder.IncCounter("chilli_http_logins_total", labels)

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	select {
	case authOK := <-session.AuthResult:
		duration := time.Since(now).Seconds()
		s.recorder.ObserveHistogram("chilli_http_login_duration_seconds", labels, duration)

		if authOK {
			labels["status"] = "success"
			s.recorder.IncCounter("chilli_http_login_outcomes_total", labels)

			wsprXML, err := wispr.GenerateWISPrLoginResponse(s.cfg, session, true, "")
			if err != nil {
				s.logger.Error().Err(err).Msg("Failed to generate WISPr login response")
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, wsprXML)
		} else {
			labels["status"] = "failure"
			s.recorder.IncCounter("chilli_http_login_outcomes_total", labels)

			wsprXML, _ := wispr.GenerateWISPrLoginResponse(s.cfg, nil, false, "Invalid username or password")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, wsprXML)
		}
	case <-time.After(10 * time.Second):
		duration := time.Since(now).Seconds()
		s.recorder.ObserveHistogram("chilli_http_login_duration_seconds", labels, duration)
		labels["status"] = "timeout"
		s.recorder.IncCounter("chilli_http_login_outcomes_total", labels)

		wsprXML, _ := wispr.GenerateWISPrLoginResponse(s.cfg, nil, false, "Login request timed out")
		w.WriteHeader(http.StatusGatewayTimeout)
		fmt.Fprint(w, wsprXML)
	}
}

func (s *Server) handleFASAuth(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug().Msg("Received a FAS callback request")

	// 1. Get the token from the query parameters
	tokenString := r.URL.Query().Get("token")
	if tokenString == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	// 2. Validate the token
	claims, err := fas.ValidateToken(tokenString, &s.cfg.FAS)
	if err != nil {
		s.logger.Warn().Err(err).Msg("FAS token validation failed")
		http.Error(w, "Invalid or expired token", http.StatusForbidden)
		return
	}

	// 3. Find the session using the MAC address from the token
	clientMAC, err := net.ParseMAC(claims.ClientMAC)
	if err != nil {
		s.logger.Error().Err(err).Str("mac", claims.ClientMAC).Msg("Failed to parse MAC address from FAS token")
		http.Error(w, "Invalid token claims", http.StatusBadRequest)
		return
	}

	session, ok := s.sessionManager.GetSessionByMAC(clientMAC)
	if !ok {
		s.logger.Warn().Str("mac", clientMAC.String()).Msg("No session found for MAC address in FAS token")
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// ✅ CORRECTION CRITIQUE: Valider l'état de la session
	session.RLock()
	alreadyAuth := session.Authenticated
	sessionIP := session.HisIP.String()
	sessionLastSeen := session.LastSeen
	expectedNonce := session.FASNonce
	session.RUnlock()

	// ✅ SECURITY FIX CVE-001: Validate nonce to prevent replay attacks
	if expectedNonce == "" {
		s.logger.Warn().
			Str("mac", clientMAC.String()).
			Msg("FAS token already consumed (nonce empty) - replay attack blocked")
		http.Error(w, "Token already used", http.StatusConflict)
		return
	}

	if claims.SessionNonce != expectedNonce {
		s.logger.Warn().
			Str("expected_nonce", expectedNonce[:16]+"...").
			Str("received_nonce", claims.SessionNonce[:16]+"...").
			Str("mac", clientMAC.String()).
			Msg("FAS token nonce mismatch - replay attack blocked")
		http.Error(w, "Invalid token nonce", http.StatusForbidden)
		return
	}

	// Vérifier que la session n'est pas déjà authentifiée
	if alreadyAuth {
		s.logger.Warn().
			Str("mac", clientMAC.String()).
			Str("ip", sessionIP).
			Msg("FAS callback received for already authenticated session - rejecting")
		http.Error(w, "Session already authenticated", http.StatusConflict)
		return
	}

	// Vérifier que l'IP correspond (protection anti-hijacking)
	if sessionIP != claims.ClientIP {
		s.logger.Warn().
			Str("token_ip", claims.ClientIP).
			Str("session_ip", sessionIP).
			Str("mac", clientMAC.String()).
			Msg("FAS token IP mismatch - possible session hijacking")
		http.Error(w, "Session validation failed", http.StatusForbidden)
		return
	}

	// Vérifier que la session est récente (< 10 minutes depuis dernier paquet)
	if time.Since(sessionLastSeen) > 10*time.Minute {
		s.logger.Warn().
			Str("mac", clientMAC.String()).
			Dur("idle_time", time.Since(sessionLastSeen)).
			Msg("FAS callback for stale session - rejecting")
		http.Error(w, "Session expired", http.StatusGone)
		return
	}

	// 4. Update session with parameters from FAS
	session.Lock()
	session.Authenticated = true
	session.FASNonce = "" // ✅ SECURITY: Consume nonce to prevent replay
	// The username is not provided by FAS, but we can set it to the MAC address for accounting purposes
	if session.Redir.Username == "" {
		session.Redir.Username = claims.ClientMAC
	}

	if timeoutStr := r.URL.Query().Get("session_timeout"); timeoutStr != "" {
		if timeout, err := strconv.ParseUint(timeoutStr, 10, 32); err == nil {
			session.SessionParams.SessionTimeout = uint32(timeout)
		}
	}
	if idleTimeoutStr := r.URL.Query().Get("idle_timeout"); idleTimeoutStr != "" {
		if idleTimeout, err := strconv.ParseUint(idleTimeoutStr, 10, 32); err == nil {
			session.SessionParams.IdleTimeout = uint32(idleTimeout)
		}
	}
	if downSpeedStr := r.URL.Query().Get("download_speed"); downSpeedStr != "" {
		if downSpeed, err := strconv.ParseUint(downSpeedStr, 10, 64); err == nil {
			session.SessionParams.BandwidthMaxDown = downSpeed * 1000 // Convert kbps to bps
		}
	}
	if upSpeedStr := r.URL.Query().Get("upload_speed"); upSpeedStr != "" {
		if upSpeed, err := strconv.ParseUint(upSpeedStr, 10, 64); err == nil {
			session.SessionParams.BandwidthMaxUp = upSpeed * 1000 // Convert kbps to bps
		}
	}
	session.Unlock()

	// 5. Finalize the session (firewall, accounting, scripts)
	s.logger.Info().Str("user", session.Redir.Username).Str("ip", session.HisIP.String()).Msg("User authenticated successfully via FAS")
	if err := s.firewall.AddAuthenticatedUser(session.HisIP); err != nil {
		s.logger.Error().Err(err).Msg("Failed to add firewall rules for FAS user")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	go s.radiusClient.SendAccountingRequest(session, rfc2866.AcctStatusType(1)) // 1 = Start
	s.scriptRunner.RunScript(s.cfg.ConUp, session, 0)

	// 6. Redirect the user to their final destination
	continueURL := r.URL.Query().Get("continue_url")
	if continueURL == "" {
		continueURL = claims.OriginalURL
	}
	if continueURL == "" {
		continueURL = s.cfg.FAS.RedirectURL // Fallback to a default redirect URL
	}
	if continueURL == "" {
		continueURL = "/" // Ultimate fallback
	}

	http.Redirect(w, r, continueURL, http.StatusFound)
}