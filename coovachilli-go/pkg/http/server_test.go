package http

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/firewall"
	"coovachilli-go/pkg/radius"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"layeh.com/radius/rfc2866"
)

// Mock components for testing
type mockRadius struct {
	Called bool
}

func (m *mockRadius) SendAccountingRequest(session *core.Session, statusType rfc2866.AcctStatusType) (*radius.Packet, error) {
	m.Called = true
	return nil, nil
}

type mockFirewall struct {
	Called bool
	IP     net.IP
}

func (m *mockFirewall) RemoveAuthenticatedUser(ip net.IP) error {
	m.Called = true
	m.IP = ip
	return nil
}

func TestHandleStatus(t *testing.T) {
	// Setup
	sm := core.NewSessionManager()
	server := NewServer(&config.Config{}, sm, nil, nil, nil, zerolog.Nop())

	// Create a mock session
	clientIP := net.ParseIP("10.0.0.15")
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:02")
	session := sm.CreateSession(clientIP, clientMAC)
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
	mockFw := &mockFirewall{}
	mockRadius := &mockRadius{}
	server := NewServer(&config.Config{}, sm, nil, mockRadius, mockFw, zerolog.Nop())

	// Create a mock session
	clientIP := net.ParseIP("10.0.0.15")
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:02")
	sm.CreateSession(clientIP, clientMAC)

	req := httptest.NewRequest("POST", "/logout", nil)
	rr := httptest.NewRecorder()
	req.RemoteAddr = clientIP.String() + ":12345"

	server.handleLogout(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	require.Contains(t, rr.Body.String(), "You have been logged out")

	// Assert that the mocks were called
	require.True(t, mockFw.Called, "firewall.RemoveAuthenticatedUser should have been called")
	require.True(t, mockFw.IP.Equal(clientIP), "firewall.RemoveAuthenticatedUser called with wrong IP")
	require.True(t, mockRadius.Called, "radius.SendAccountingRequest should have been called")

	// Assert that the session was deleted
	_, ok := sm.GetSessionByIP(clientIP)
	require.False(t, ok, "Session should have been deleted")
}

func TestHandleApiStatus(t *testing.T) {
	// Setup
	sm := core.NewSessionManager()
	server := NewServer(&config.Config{}, sm, nil, nil, nil, zerolog.Nop())

	// Create a mock session
	clientIP := net.ParseIP("10.0.0.15")
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:02")
	session := sm.CreateSession(clientIP, clientMAC)
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
	mockFw := &mockFirewall{}
	mockRadius := &mockRadius{}
	server := NewServer(&config.Config{}, sm, nil, mockRadius, mockFw, zerolog.Nop())

	// Create a mock session with a token
	clientIP := net.ParseIP("10.0.0.15")
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:02")
	session := sm.CreateSession(clientIP, clientMAC)
	session.Token = "testtoken"
	sm.AssociateToken(session)

	req := httptest.NewRequest("POST", "/api/v1/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "testtoken"})
	rr := httptest.NewRecorder()

	server.handleApiLogout(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	require.Contains(t, rr.Body.String(), "logged_out")

	// Assert that the mocks were called
	require.True(t, mockFw.Called, "firewall.RemoveAuthenticatedUser should have been called")
	require.True(t, mockRadius.Called, "radius.SendAccountingRequest should have been called")

	// Assert that the session was deleted
	_, ok := sm.GetSessionByToken("testtoken")
	require.False(t, ok, "Session should have been deleted")
}
