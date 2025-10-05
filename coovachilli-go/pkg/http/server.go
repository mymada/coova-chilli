package http

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/metrics"
	"coovachilli-go/pkg/wispr"
	"github.com/rs/zerolog"
)

const loginPage = `
<!DOCTYPE html>
<html>
<head>
    <title>Captive Portal</title>
</head>
<body>
    <h1>Welcome to the Captive Portal</h1>
    <form action="/login" method="post">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username"><br><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password"><br><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
`

const statusPageTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Session Status</title>
</head>
<body>
    <h1>Session Active</h1>
    <p>Welcome, %s!</p>
    <p>IP Address: %s</p>
    <p>MAC Address: %s</p>
    <p>Session Started: %s</p>
    <p>Session Duration: %s</p>
    <br>
    <form action="/logout" method="post">
        <input type="submit" value="Logout">
    </form>
</body>
</html>
`

// Server holds the state for the HTTP server.
type Server struct {
	cfg            *config.Config
	sessionManager *core.SessionManager
	radiusReqChan  chan<- *core.Session
	disconnecter   core.Disconnector
	logger         zerolog.Logger
	recorder       metrics.Recorder
}

// NewServer creates a new HTTP server.
func NewServer(cfg *config.Config, sm *core.SessionManager, radiusReqChan chan<- *core.Session, disconnecter core.Disconnector, logger zerolog.Logger, recorder metrics.Recorder) *Server {
	if recorder == nil {
		recorder = metrics.NewNoopRecorder()
	}
	return &Server{
		cfg:            cfg,
		sessionManager: sm,
		radiusReqChan:  radiusReqChan,
		disconnecter:   disconnecter,
		logger:         logger.With().Str("component", "http").Logger(),
		recorder:       recorder,
	}
}

// Start starts the HTTP server.
func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handlePortal)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/logout", s.handleLogout)

	// API endpoints
	mux.HandleFunc("/api/v1/status", s.handleApiStatus)
	mux.HandleFunc("/api/v1/login", s.handleApiLogin)
	mux.HandleFunc("/api/v1/logout", s.handleApiLogout)
	mux.HandleFunc("/json/status", s.handleJsonpStatus)

	// WISPr endpoints
	http.HandleFunc("/wispr", s.handleWISPr)
	http.HandleFunc("/wispr/login", s.handleWISPrLogin)

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
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		session, ok := s.sessionManager.GetSessionByToken(cookie.Value)
		if ok && session.Authenticated {
			s.logger.Info().Str("user", session.Redir.Username).Msg("Automatic login via cookie successful")
			http.Redirect(w, r, "/status", http.StatusFound)
			return
		}
	}

	fmt.Fprint(w, loginPage)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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
	labels := metrics.Labels{"type": "uam"} // UAM login
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

			http.SetCookie(w, &http.Cookie{
				Name:     sessionCookieName,
				Value:    token,
				Expires:  time.Now().Add(24 * time.Hour),
				HttpOnly: true,
				Path:     "/",
			})

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
	statusHTML := fmt.Sprintf(statusPageTemplate,
		session.Redir.Username,
		session.HisIP,
		session.HisMAC,
		session.StartTime.Format(time.RFC1123),
		duration,
	)
	fmt.Fprint(w, statusHTML)
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
	labels := metrics.Labels{"type": "api"}
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

			http.SetCookie(w, &http.Cookie{
				Name:     sessionCookieName,
				Value:    token,
				Expires:  time.Now().Add(24 * time.Hour),
				HttpOnly: true,
				Path:     "/",
			})
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
	labels := metrics.Labels{"type": "wispr"}
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
