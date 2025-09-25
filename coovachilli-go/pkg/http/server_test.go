package http

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// Mock components for testing
type mockDisconnector struct {
	Called  bool
	Session *core.Session
}

func (m *mockDisconnector) Disconnect(session *core.Session, reason string) {
	m.Called = true
	m.Session = session
}

func TestHandleStatus(t *testing.T) {
	// Setup
	sm := core.NewSessionManager()
	server := NewServer(&config.Config{}, sm, nil, nil, zerolog.Nop())

	// Create a mock session
	clientIP := net.ParseIP("10.0.0.15")
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:02")
	session := sm.CreateSession(clientIP, clientMAC, &config.Config{})
	session.Authenticated = true
	session.Redir.Username = "testuser"

	req := httptest.NewRequest("GET", "/status", nil)
	rr := httptest.NewRecorder()
	req.RemoteAddr = clientIP.String() + ":12345"

	server.handleStatus(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	require.Contains(t, body, "<h1>Session Active</h1>")
	require.Contains(t, body, "Welcome, testuser!")
	require.Contains(t, body, "IP Address: 10.0.0.15")
}

func TestHandleLogout(t *testing.T) {
	// Setup
	sm := core.NewSessionManager()
	mockDc := &mockDisconnector{}
	server := NewServer(&config.Config{}, sm, nil, mockDc, zerolog.Nop())

	// Create a mock session
	clientIP := net.ParseIP("10.0.0.15")
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:02")
	session := sm.CreateSession(clientIP, clientMAC, &config.Config{})

	req := httptest.NewRequest("POST", "/logout", nil)
	rr := httptest.NewRecorder()
	req.RemoteAddr = clientIP.String() + ":12345"

	server.handleLogout(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	require.Contains(t, rr.Body.String(), "You have been logged out")

	// Assert that the disconnector was called
	require.True(t, mockDc.Called, "Disconnect should have been called")
	require.Equal(t, session, mockDc.Session, "Disconnect called with wrong session")
}

func TestHandleApiStatus(t *testing.T) {
	// Setup
	sm := core.NewSessionManager()
	server := NewServer(&config.Config{}, sm, nil, nil, zerolog.Nop())

	// Create a mock session
	clientIP := net.ParseIP("10.0.0.15")
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:02")
	session := sm.CreateSession(clientIP, clientMAC, &config.Config{})
	session.Authenticated = true
	session.Redir.Username = "testuser"

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	rr := httptest.NewRecorder()
	req.RemoteAddr = clientIP.String() + ":12345"

	server.handleApiStatus(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	body := rr.Body.String()
	require.Contains(t, body, `"username":"testuser"`)
	require.Contains(t, body, `"ip":"10.0.0.15"`)
}

func TestHandleApiLogout(t *testing.T) {
	// Setup
	sm := core.NewSessionManager()
	mockDc := &mockDisconnector{}
	server := NewServer(&config.Config{}, sm, nil, mockDc, zerolog.Nop())

	// Create a mock session with a token
	clientIP := net.ParseIP("10.0.0.15")
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:02")
	session := sm.CreateSession(clientIP, clientMAC, &config.Config{})
	session.Token = "testtoken"
	sm.AssociateToken(session)

	req := httptest.NewRequest("POST", "/api/v1/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "testtoken"})
	rr := httptest.NewRecorder()

	server.handleApiLogout(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	require.Contains(t, rr.Body.String(), "logged_out")

	// Assert that the disconnector was called
	require.True(t, mockDc.Called, "Disconnect should have been called")
	require.Equal(t, session, mockDc.Session, "Disconnect called with wrong session")
}
