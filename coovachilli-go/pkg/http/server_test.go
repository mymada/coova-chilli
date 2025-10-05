package http

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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

// setupTestServer is a helper to create a server instance for testing.
func setupTestServer(t *testing.T) (*Server, *config.Config, *core.SessionManager, *mockDisconnector) {
	cfg := &config.Config{
		TemplateDir: "../../www/templates",
	}
	sm := core.NewSessionManager(cfg, nil)
	mockDc := &mockDisconnector{}
	server, err := NewServer(cfg, sm, nil, mockDc, zerolog.Nop(), nil)
	require.NoError(t, err, "NewServer should not return an error during test setup")
	return server, cfg, sm, mockDc
}

func TestHandleStatus(t *testing.T) {
	// Setup
	server, _, sm, _ := setupTestServer(t)

	// Create a mock session
	clientIP := net.ParseIP("10.0.0.15")
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:02")
	session := sm.CreateSession(clientIP, clientMAC, 0)
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
	server, _, sm, mockDc := setupTestServer(t)

	// Create a mock session
	clientIP := net.ParseIP("10.0.0.15")
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:02")
	session := sm.CreateSession(clientIP, clientMAC, 0)

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
	server, _, sm, _ := setupTestServer(t)

	// Create a mock session
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
	require.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	body := rr.Body.String()
	require.Contains(t, body, `"username":"testuser"`)
	require.Contains(t, body, `"ip":"10.0.0.15"`)
}

func TestHandleApiLogout(t *testing.T) {
	// Setup
	server, _, sm, mockDc := setupTestServer(t)

	// Create a mock session with a token
	clientIP := net.ParseIP("10.0.0.15")
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:02")
	session := sm.CreateSession(clientIP, clientMAC, 0)
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

func TestHandleJsonpStatus(t *testing.T) {
	// Setup
	server, _, sm, _ := setupTestServer(t)

	// Create a mock session
	clientIP := net.ParseIP("10.0.0.15")
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:02")
	session := sm.CreateSession(clientIP, clientMAC, 0)
	session.Authenticated = true
	session.SessionParams.SessionTimeout = 3600
	session.InputOctets = 1024
	session.OutputOctets = 2048

	req := httptest.NewRequest("GET", "/json/status?callback=myCallback", nil)
	rr := httptest.NewRecorder()
	req.RemoteAddr = clientIP.String() + ":12345"

	server.handleJsonpStatus(rr, req)

	// Assertions
	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "application/javascript", rr.Header().Get("Content-Type"))

	body := rr.Body.String()
	require.True(t, strings.HasPrefix(body, "myCallback("), "Response should be a JSONP callback")
	require.True(t, strings.HasSuffix(body, ");"), "Response should end correctly")

	// Verify JSON content
	jsonStr := body[len("myCallback(") : len(body)-2]
	var resp jsonpStatusResponse
	err := json.Unmarshal([]byte(jsonStr), &resp)
	require.NoError(t, err)

	require.Equal(t, 1, resp.ClientState)
	require.Equal(t, uint32(3600), resp.SessionTimeout)
	require.Equal(t, uint64(1024), resp.Accounting.InputOctets)
	require.Equal(t, uint64(2048), resp.Accounting.OutputOctets)
}

// SECURITY TESTS
func TestIsValidJSONPCallback(t *testing.T) {
	tests := []struct {
		name     string
		callback string
		valid    bool
	}{
		// Valid callbacks
		{"simple function", "myCallback", true},
		{"namespaced function", "jQuery.myCallback", true},
		{"deep namespace", "app.utils.callbacks.handleResponse", true},
		{"with underscore", "my_callback_function", true},
		{"with dollar sign", "$callback", true},
		{"mixed valid chars", "jQuery1_9$callback", true},

		// Invalid callbacks - Security tests
		{"XSS attempt - script tag", "<script>alert(1)</script>", false},
		{"XSS attempt - event handler", "alert(document.cookie)", false},
		{"XSS attempt - parentheses", "alert(1)", false},
		{"XSS attempt - semicolon", "func;alert(1)", false},
		{"XSS attempt - quotes", "func'alert(1)'", false},
		{"XSS attempt - backslash", "func\\alert", false},
		{"XSS attempt - newline", "func\nalert(1)", false},
		{"XSS attempt - null byte", "func\x00alert", false},
		{"path traversal attempt", "../../../etc/passwd", false},
		{"starts with digit", "1callback", false},
		{"starts with dot", ".callback", false},
		{"empty string", "", false},
		{"too long", strings.Repeat("a", 101), false},
		{"space in middle", "my callback", false},
		{"special chars", "my!callback", false},
		{"SQL injection attempt", "'; DROP TABLE users--", false},
		{"command injection", "`rm -rf /`", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidJSONPCallback(tt.callback)
			if result != tt.valid {
				t.Errorf("isValidJSONPCallback(%q) = %v, want %v", tt.callback, result, tt.valid)
			}
		})
	}
}

func TestHandleJsonpStatus_SecurityValidation(t *testing.T) {
	server, _, _, _ := setupTestServer(t)

	maliciousCallbacks := []struct {
		name     string
		callback string
	}{
		{"script tag", "<script>alert(1)</script>"},
		{"parentheses", "alert(document.cookie)"},
		{"quotes", "';alert(1)//"},
		{"path traversal", "../../etc/passwd"},
		{"backticks", "`rm -rf /`"},
		{"semicolon", "func;alert(1)"},
		{"exclamation", "func!alert"},
	}

	for _, tc := range maliciousCallbacks {
		t.Run("rejects_"+tc.name, func(t *testing.T) {
			// Create request with query parameter directly to avoid URL parsing issues
			req := httptest.NewRequest("GET", "/json/status", nil)
			q := req.URL.Query()
			q.Set("callback", tc.callback)
			req.URL.RawQuery = q.Encode()
			rr := httptest.NewRecorder()
			req.RemoteAddr = "10.0.0.1:12345"

			server.handleJsonpStatus(rr, req)

			// Should reject with 400 Bad Request
			require.Equal(t, http.StatusBadRequest, rr.Code)
			require.Contains(t, rr.Body.String(), "Invalid callback")
		})
	}
}

func TestHandleJsonpStatus_NoCallback(t *testing.T) {
	server, _, _, _ := setupTestServer(t)

	req := httptest.NewRequest("GET", "/json/status", nil)
	rr := httptest.NewRecorder()
	req.RemoteAddr = "10.0.0.1:12345"

	server.handleJsonpStatus(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "Callback function name is required")
}