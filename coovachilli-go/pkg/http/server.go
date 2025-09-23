package http

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
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

// Server holds the state for the HTTP server.
type Server struct {
	cfg            *config.Config
	sessionManager *core.SessionManager
	radiusReqChan  chan<- *core.Session
	logger         zerolog.Logger
}

// NewServer creates a new HTTP server.
func NewServer(cfg *config.Config, sm *core.SessionManager, radiusReqChan chan<- *core.Session, logger zerolog.Logger) *Server {
	return &Server{
		cfg:            cfg,
		sessionManager: sm,
		radiusReqChan:  radiusReqChan,
		logger:         logger.With().Str("component", "http").Logger(),
	}
}

// Start starts the HTTP server.
func (s *Server) Start() {
	http.HandleFunc("/", s.handlePortal)
	http.HandleFunc("/login", s.handleLogin)

	addr := fmt.Sprintf(":%d", s.cfg.UAMPort)
	s.logger.Info().Str("addr", addr).Msg("Starting HTTP server")
	if err := http.ListenAndServe(addr, nil); err != nil {
		s.logger.Fatal().Err(err).Msg("Failed to start HTTP server")
	}
}

func (s *Server) handlePortal(w http.ResponseWriter, r *http.Request) {
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

	// Get the client's IP address
	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "Failed to get client IP address", http.StatusInternalServerError)
		return
	}
	ip := net.ParseIP(ipStr)

	// Get the session from the session manager
	session, ok := s.sessionManager.GetSessionByIP(ip)
	if !ok {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// Update the session with the login credentials
	session.Lock()
	session.Redir.Username = username
	session.Redir.Password = password
	session.Unlock()

	s.radiusReqChan <- session

	// Wait for the authentication result, with a timeout
	select {
	case authOK := <-session.AuthResult:
		if authOK {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<h1>Login Successful</h1><p>You can now access the internet.</p>")
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "<h1>Login Failed</h1><p>Invalid username or password.</p>")
		}
	case <-time.After(10 * time.Second):
		http.Error(w, "Login request timed out.", http.StatusGatewayTimeout)
	}
}
