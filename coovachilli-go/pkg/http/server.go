package http

import (
	"fmt"
	"log"
	"net"
	"net/http"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
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
}

// NewServer creates a new HTTP server.
func NewServer(cfg *config.Config, sm *core.SessionManager, radiusReqChan chan<- *core.Session) *Server {
	return &Server{
		cfg:            cfg,
		sessionManager: sm,
		radiusReqChan:  radiusReqChan,
	}
}

// Start starts the HTTP server.
func (s *Server) Start() {
	http.HandleFunc("/", s.handlePortal)
	http.HandleFunc("/login", s.handleLogin)

	addr := fmt.Sprintf(":%d", s.cfg.UAMPort)
	log.Printf("Starting HTTP server on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
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

	log.Printf("Login attempt from username: %s", username)

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

	// In a real implementation, we would wait for the RADIUS response
	// and then show a success or failure page. For now, we'll just
	// show a simple success message.
	fmt.Fprint(w, "Login request sent. Please wait.")
}
