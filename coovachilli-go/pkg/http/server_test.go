package http

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/fas"
	"coovachilli-go/pkg/metrics"
	"coovachilli-go/pkg/radius"
	"coovachilli-go/pkg/script"
	"coovachilli-go/pkg/securestore"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// --- Mock Implementations ---

type mockDisconnector struct {
	Called  bool
	Session *core.Session
}

func (m *mockDisconnector) Disconnect(session *core.Session, reason string) {
	m.Called = true
	m.Session = session
}

type mockFirewallManager struct{}

func (m *mockFirewallManager) Initialize() error                               { return nil }
func (m *mockFirewallManager) Cleanup()                                        {}
func (m *mockFirewallManager) Reconfigure(newConfig *config.Config) error      { return nil }
func (m *mockFirewallManager) AddWalledGardenNetwork(network string) error     { return nil }
func (m *mockFirewallManager) AddWalledGardenIP(ip string) error               { return nil }
func (m *mockFirewallManager) AddAuthenticatedUser(ip net.IP) error            { return nil }
func (m *mockFirewallManager) RemoveAuthenticatedUser(ip net.IP) error         { return nil }

// --- Test Setup Helper ---

func setupTestServer(t *testing.T) (*Server, *config.Config, *core.SessionManager, *mockDisconnector) {
	cfg := &config.Config{
		TemplateDir: "/nonexistent/templates", // Use nonexistent path to force JSON fallback
		FAS: config.FASConfig{
			Enabled: true, // Enable FAS to bypass template requirement
			Secret: securestore.NewSecret("test-secret-for-fas"),
		},
	}
	sm := core.NewSessionManager(cfg, nil)
	mockDc := &mockDisconnector{}
	mockFw := &mockFirewallManager{}
	mockSr := script.NewRunner(zerolog.Nop(), cfg)
	mockRc := radius.NewClient(cfg, zerolog.Nop(), nil)

	radiusReqChan := make(chan *core.Session, 1)

	server, err := NewServer(cfg, sm, radiusReqChan, mockDc, zerolog.Nop(), metrics.NewNoopRecorder(), mockFw, mockSr, mockRc)
	require.NoError(t, err, "NewServer should not return an error during test setup")

	return server, cfg, sm, mockDc
}

// --- Test Cases ---

func TestHandleStatus(t *testing.T) {
	server, _, sm, _ := setupTestServer(t)

	clientIP := net.ParseIP("10.0.0.15")
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:02")
	session := sm.CreateSession(clientIP, clientMAC, 0)
	session.Authenticated = true
	session.Redir.Username = "testuser"
	session.StartTime = time.Now()

	req := httptest.NewRequest("GET", "/status", nil)
	rr := httptest.NewRecorder()
	req.RemoteAddr = clientIP.String() + ":12345"

	server.handleStatus(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	// When FAS is enabled and templates are nil, expect JSON response
	var data map[string]interface{}
	err := json.NewDecoder(rr.Body).Decode(&data)
	require.NoError(t, err)
	require.Equal(t, "testuser", data["Username"])
	require.Equal(t, clientIP.String(), data["IPAddress"])
}

func TestHandleFASAuth(t *testing.T) {
	server, cfg, sm, _ := setupTestServer(t)

	clientIP := net.ParseIP("10.1.0.100")
	clientMAC, _ := net.ParseMAC("00:00:5E:00:53:AA")
	session := sm.CreateSession(clientIP, clientMAC, 0)
	require.NotNil(t, session)

	token, err := fas.GenerateToken(session, &cfg.FAS)
	require.NoError(t, err)

	reqURL := "/api/v1/fas/auth?token=" + token + "&session_timeout=3600"
	req := httptest.NewRequest("GET", reqURL, nil)
	rr := httptest.NewRecorder()

	server.handleFASAuth(rr, req)

	require.Equal(t, http.StatusFound, rr.Code)
	session.RLock()
	require.True(t, session.Authenticated)
	require.Equal(t, uint32(3600), session.SessionParams.SessionTimeout)
	session.RUnlock()
}

func TestHandleLogout(t *testing.T) {
	server, _, sm, mockDc := setupTestServer(t)

	clientIP := net.ParseIP("10.0.0.15")
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:02")
	_ = sm.CreateSession(clientIP, clientMAC, 0)

	req := httptest.NewRequest("POST", "/logout", nil)
	rr := httptest.NewRecorder()
	req.RemoteAddr = clientIP.String() + ":12345"

	server.handleLogout(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	require.True(t, mockDc.Called)
}

func TestHandleApiStatus(t *testing.T) {
	server, _, sm, _ := setupTestServer(t)

	clientIP := net.ParseIP("10.0.0.15")
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:02")
	session := sm.CreateSession(clientIP, clientMAC, 0)
	session.Authenticated = true
	session.Redir.Username = "testuser"

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	rr := httptest.NewRecorder()
	req.RemoteAddr = clientIP.String() + ":12345"

	server.handleApiStatus(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp apiStatusResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, "testuser", resp.Username)
}

func TestHandleJsonpStatus(t *testing.T) {
	server, _, sm, _ := setupTestServer(t)

	clientIP := net.ParseIP("10.0.0.15")
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:02")
	session := sm.CreateSession(clientIP, clientMAC, 0)
	session.Authenticated = true
	session.SessionParams.SessionTimeout = 3600

	req := httptest.NewRequest("GET", "/json/status?callback=myCallback", nil)
	rr := httptest.NewRecorder()
	req.RemoteAddr = clientIP.String() + ":12345"

	server.handleJsonpStatus(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	require.True(t, strings.HasPrefix(body, "myCallback("))
}