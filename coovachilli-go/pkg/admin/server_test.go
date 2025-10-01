package admin

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// mockDisconnector is a mock implementation of the Disconnector interface for testing.
type mockDisconnector struct {
	Called  bool
	Session *core.Session
}

func (m *mockDisconnector) Disconnect(session *core.Session, reason string) {
	m.Called = true
	m.Session = session
}

// setupTestServer creates a new admin server with mock dependencies for testing.
func setupTestServer(t *testing.T, cfg *config.Config) (*Server, *core.SessionManager, *mockDisconnector) {
	sm := core.NewSessionManager(cfg, nil)
	dc := &mockDisconnector{}
	server := NewServer(cfg, sm, dc, zerolog.Nop())
	return server, sm, dc
}

func TestHandleStatus(t *testing.T) {
	cfg := &config.Config{}
	server, sm, _ := setupTestServer(t, cfg)

	// Add a session to test the count
	sm.CreateSession(net.ParseIP("10.0.0.1"), net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, 0)

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var resp statusResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, "ok", resp.Status)
	require.Equal(t, 1, resp.ActiveSessions)
}

func TestHandleListSessions(t *testing.T) {
	cfg := &config.Config{}
	server, sm, _ := setupTestServer(t, cfg)

	// Add two sessions
	sm.CreateSession(net.ParseIP("10.0.0.1"), net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x01}, 101)
	sm.CreateSession(net.ParseIP("10.0.0.2"), net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x02}, 102)

	req := httptest.NewRequest("GET", "/api/v1/sessions", nil)
	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var resp []sessionResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Len(t, resp, 2)

	// Sort by IP to ensure deterministic order for testing
	sort.Slice(resp, func(i, j int) bool {
		return resp[i].IP < resp[j].IP
	})

	require.Equal(t, "10.0.0.1", resp[0].IP)
	require.Equal(t, "10.0.0.2", resp[1].IP)
}

func TestHandleGetSession(t *testing.T) {
	cfg := &config.Config{}
	server, sm, _ := setupTestServer(t, cfg)
	mac, _ := net.ParseMAC("01:02:03:04:05:03")
	ip := net.ParseIP("10.0.0.3")
	session := sm.CreateSession(ip, mac, 103)
	session.Redir.Username = "testuser"

	// Test find by MAC
	req := httptest.NewRequest("GET", "/api/v1/sessions/01:02:03:04:05:03", nil)
	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var resp sessionResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, "testuser", resp.Username)

	// Test find by IP
	req = httptest.NewRequest("GET", "/api/v1/sessions/10.0.0.3", nil)
	rr = httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, "testuser", resp.Username)

	// Test not found
	req = httptest.NewRequest("GET", "/api/v1/sessions/1.2.3.4", nil)
	rr = httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleLogoutSession(t *testing.T) {
	cfg := &config.Config{}
	server, sm, dc := setupTestServer(t, cfg)
	mac, _ := net.ParseMAC("01:02:03:04:05:04")
	ip := net.ParseIP("10.0.0.4")
	sm.CreateSession(ip, mac, 104)

	req := httptest.NewRequest("POST", "/api/v1/sessions/10.0.0.4/logout", nil)
	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	require.True(t, dc.Called, "Disconnect should have been called")
	require.Equal(t, "10.0.0.4", dc.Session.HisIP.String())
}

func TestAuthMiddleware(t *testing.T) {
	cfg := &config.Config{
		AdminAPI: config.AdminAPIConfig{
			AuthToken: "secret-token",
		},
	}
	server, _, _ := setupTestServer(t, cfg)

	// Case 1: No token
	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusUnauthorized, rr.Code)
	require.Contains(t, rr.Body.String(), "Authorization header required")

	// Case 2: Malformed token
	req.Header.Set("Authorization", "Bearer")
	rr = httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusUnauthorized, rr.Code)
	require.Contains(t, rr.Body.String(), "Malformed Authorization header")

	// Case 3: Invalid token
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr = httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusUnauthorized, rr.Code)
	require.Contains(t, rr.Body.String(), "Invalid authentication token")

	// Case 4: Valid token
	req.Header.Set("Authorization", "Bearer secret-token")
	rr = httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	require.Contains(t, rr.Body.String(), `"status":"ok"`)
}