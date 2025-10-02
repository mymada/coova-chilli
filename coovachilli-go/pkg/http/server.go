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
	http.HandleFunc("/", s.handlePortal)
	http.HandleFunc("/login", s.handleLogin)
	http.HandleFunc("/status", s.handleStatus)
	http.HandleFunc("/logout", s.handleLogout)

	// API endpoints
	http.HandleFunc("/api/v1/status", s.handleApiStatus)
	http.HandleFunc("/api/v1/login", s.handleApiLogin)
	http.HandleFunc("/api/v1/logout", s.handleApiLogout)
	http.HandleFunc("/json/status", s.handleJsonpStatus)

	addr := fmt.Sprintf(":%d", s.cfg.UAMPort)

	if s.cfg.CertFile != "" && s.cfg.KeyFile != "" {
		s.logger.Info().Str("addr", addr).Msg("Starting HTTPS server")
		if err := http.ListenAndServeTLS(addr, s.cfg.CertFile, s.cfg.KeyFile, nil); err != nil {
			s.logger.Fatal().Err(err).Msg("Failed to start HTTPS server")
		}
	} else {
		s.logger.Info().Str("addr", addr).Msg("Starting HTTP server")
		if err := http.ListenAndServe(addr, nil); err != nil {
			s.logger.Fatal().Err(err).Msg("Failed to start HTTP server")
		}
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

func (s *Server) handleJsonpStatus(w http.ResponseWriter, r *http.Request) {
	callback := r.URL.Query().Get("callback")
	if callback == "" {
		http.Error(w, "Callback function name is required", http.StatusBadRequest)
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
