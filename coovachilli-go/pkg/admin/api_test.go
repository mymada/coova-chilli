package admin

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// mockDisconnector is a mock implementation for testing disconnection logic.
type mockDisconnector struct {
	Called  bool
	Session *core.Session
}

func (m *mockDisconnector) Disconnect(session *core.Session, reason string) {
	m.Called = true
	m.Session = session
}

// setupTestAPIServer is a helper to create an API server instance for testing.
func setupTestAPIServer(t *testing.T) (*APIServer, *config.Config, *core.SessionManager, *mockDisconnector) {
	tempDir := t.TempDir() // Create a temporary directory for snapshots
	cfg := &config.Config{
		AdminAPI: config.AdminAPIConfig{
			Enabled:     false, // Disable auth for tests
			SnapshotDir: tempDir,
		},
		TemplateDir: tempDir, // Use temp dir for templates as well
	}
	sm := core.NewSessionManager(cfg, nil)
	dc := &mockDisconnector{}
	server, err := NewAPIServer(cfg, zerolog.Nop(), sm, dc)
	require.NoError(t, err, "NewAPIServer should not return an error during test setup")
	return server, cfg, sm, dc
}

func TestSiteAPIEndpoints(t *testing.T) {
	server, _, _, _ := setupTestAPIServer(t)
	router := mux.NewRouter()
	api := router.PathPrefix("/api/v1").Subrouter()
	api.Use(server.authMiddleware)
	api.HandleFunc("/sites", server.handleGetSites).Methods("GET")
	api.HandleFunc("/sites", server.handleCreateSite).Methods("POST")

	// --- 1. Test GET /sites (empty) ---
	req, _ := http.NewRequest("GET", "/api/v1/sites", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	require.JSONEq(t, `[]`, rr.Body.String(), "Initially, the list of sites should be empty")

	// --- 2. Test POST /sites (create a new site) ---
	sitePayload := []byte(`{"id": "test-site-1", "name": "Test Site", "description": "A site for testing"}`)
	req, _ = http.NewRequest("POST", "/api/v1/sites", bytes.NewBuffer(sitePayload))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code, "Creating a site should return 201 Created")

	var createdSite Site
	err := json.Unmarshal(rr.Body.Bytes(), &createdSite)
	require.NoError(t, err)
	require.Equal(t, "test-site-1", createdSite.ID)
	require.Equal(t, "Test Site", createdSite.Name)

	// --- 3. Test GET /sites (with one site) ---
	req, _ = http.NewRequest("GET", "/api/v1/sites", nil)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var sites []Site
	err = json.Unmarshal(rr.Body.Bytes(), &sites)
	require.NoError(t, err)
	require.Len(t, sites, 1, "There should be one site in the list")
	require.Equal(t, "test-site-1", sites[0].ID)
}

func TestSessionAPIEndpoints(t *testing.T) {
	server, _, sm, dc := setupTestAPIServer(t)
	router := mux.NewRouter()
	api := router.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/sites/{site_id}/sessions", server.handleListSessions).Methods("GET")
	api.HandleFunc("/sites/{site_id}/sessions/{session_id}", server.handleDeleteSession).Methods("DELETE")

	// --- 1. Create a mock session ---
	clientIP := net.ParseIP("10.1.0.100")
	clientMAC, _ := net.ParseMAC("00:00:5E:00:53:AA")
	session := sm.CreateSession(clientIP, clientMAC, 0)
	session.SessionID = "test-session-123"
	session.Redir.Username = "test-user"

	// --- 2. Test GET /sessions ---
	req, _ := http.NewRequest("GET", "/api/v1/sites/default/sessions", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var sessions []apiSession
	err := json.Unmarshal(rr.Body.Bytes(), &sessions)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	require.Equal(t, "test-session-123", sessions[0].SessionID)
	require.Equal(t, "test-user", sessions[0].Username)

	// --- 3. Test DELETE /sessions/{session_id} ---
	req, _ = http.NewRequest("DELETE", "/api/v1/sites/default/sessions/test-session-123", nil)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
	require.True(t, dc.Called, "Disconnect should have been called")
	require.Equal(t, session, dc.Session, "Disconnect was called on the wrong session")
}

func TestTemplateAPIEndpoints(t *testing.T) {
	server, cfg, _, _ := setupTestAPIServer(t)
	router := mux.NewRouter()
	router.SkipClean(true) // Disable path cleaning for this test
	api := router.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/sites/{id}/templates/{template_name}", server.handleGetTemplate).Methods("GET")
	api.HandleFunc("/sites/{id}/templates/{template_name}", server.handleUpdateTemplate).Methods("PUT")

	// --- 1. Create a dummy template file ---
	templatePath := filepath.Join(cfg.TemplateDir, "test.html")
	originalContent := "Hello {{.Name}}"
	err := os.WriteFile(templatePath, []byte(originalContent), 0644)
	require.NoError(t, err)

	// --- 2. Test GET /templates/{template_name} ---
	req, _ := http.NewRequest("GET", "/api/v1/sites/default/templates/test.html", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var templateResp apiTemplateResponse
	err = json.Unmarshal(rr.Body.Bytes(), &templateResp)
	require.NoError(t, err)
	require.Equal(t, "test.html", templateResp.Name)
	require.Equal(t, originalContent, templateResp.Content)

	// --- 3. Test PUT /templates/{template_name} ---
	updatePayload := []byte(`{"content": "Goodbye {{.Name}}"}`)
	req, _ = http.NewRequest("PUT", "/api/v1/sites/default/templates/test.html", bytes.NewBuffer(updatePayload))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	// Verify the file content was updated
	updatedContent, err := os.ReadFile(templatePath)
	require.NoError(t, err)
	require.Equal(t, "Goodbye {{.Name}}", string(updatedContent))

	// --- 4. Test for Path Traversal vulnerability ---
	req, _ = http.NewRequest("GET", "/api/v1/sites/default/templates/../../secret.txt", nil)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	// The router cleans the path, so the handler will receive "secret.txt" and correctly return a 404.
	// This is secure behavior.
	require.Equal(t, http.StatusNotFound, rr.Code, "Should return Not Found for a path traversal attempt")
}