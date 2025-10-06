package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

// APIServer is the main server for the administration API.
type APIServer struct {
	cfg              *config.Config
	logger           zerolog.Logger
	multiSiteManager *MultiSiteManager
	snapshotManager  *SnapshotManager
	sessionManager   *core.SessionManager
	disconnecter     core.Disconnector
}

// NewAPIServer creates a new API server.
func NewAPIServer(cfg *config.Config, logger zerolog.Logger, sm *core.SessionManager, dc core.Disconnector) (*APIServer, error) {
	snapshotDir := cfg.AdminAPI.SnapshotDir
	if snapshotDir == "" {
		snapshotDir = "/var/lib/coovachilli/snapshots" // Default directory
	}

	snapshotMgr, err := NewSnapshotManager(snapshotDir, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize snapshot manager: %w", err)
	}

	return &APIServer{
		cfg:              cfg,
		logger:           logger.With().Str("component", "admin_api").Logger(),
		multiSiteManager: NewMultiSiteManager(logger, true), // Initialize the multi-site manager
		snapshotManager:  snapshotMgr,
		sessionManager:   sm,
		disconnecter:     dc,
	}, nil
}

// Start registers the API routes and starts listening.
func (s *APIServer) Start() {
	r := mux.NewRouter()
	api := r.PathPrefix("/api/v1").Subrouter()

	// Add authentication middleware to all API routes
	api.Use(s.authMiddleware)

	// Site management endpoints
	api.HandleFunc("/sites", s.handleGetSites).Methods("GET")
	api.HandleFunc("/sites", s.handleCreateSite).Methods("POST")
	api.HandleFunc("/sites/{id}", s.handleGetSite).Methods("GET")
	api.HandleFunc("/sites/{id}", s.handleUpdateSite).Methods("PUT")
	api.HandleFunc("/sites/{id}", s.handleDeleteSite).Methods("DELETE")

	// For now, other endpoints will return a "not implemented" message
	api.HandleFunc("/sites/{id}/config", s.handleNotImplemented).Methods("GET", "PUT")
	api.HandleFunc("/sites/{id}/sessions", s.handleListSessions).Methods("GET")
	api.HandleFunc("/sites/{id}/sessions/{session_id}", s.handleDeleteSession).Methods("DELETE")

	// Snapshot management endpoints
	api.HandleFunc("/snapshots", s.handleListSnapshots).Methods("GET")
	api.HandleFunc("/snapshots", s.handleCreateSnapshot).Methods("POST")
	api.HandleFunc("/snapshots/{id}", s.handleGetSnapshot).Methods("GET")
	api.HandleFunc("/snapshots/{id}/restore", s.handleRestoreSnapshot).Methods("POST")
	api.HandleFunc("/snapshots/{id}", s.handleDeleteSnapshot).Methods("DELETE")
	api.HandleFunc("/sites/{id}/templates/{template_name}", s.handleGetTemplate).Methods("GET")
	api.HandleFunc("/sites/{id}/templates/{template_name}", s.handleUpdateTemplate).Methods("PUT")

	listenAddr := s.cfg.AdminAPI.Listen
	s.logger.Info().Str("address", listenAddr).Msg("Starting Admin API server")
	if err := http.ListenAndServe(listenAddr, r); err != nil && err != http.ErrServerClosed {
		s.logger.Fatal().Err(err).Msg("Admin API server failed")
	}
}

// authMiddleware checks for a valid Bearer token.
func (s *APIServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.AdminAPI.Enabled || !s.cfg.AdminAPI.AuthToken.IsSet() {
			// If API is not enabled or no token is set, allow access (or handle as an error)
			// For this implementation, we'll proceed, but in production, you might want to deny.
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error": "Authorization header required"}`, http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, `{"error": "Invalid Authorization header format"}`, http.StatusUnauthorized)
			return
		}

		token := parts[1]
		valid, err := s.cfg.AdminAPI.AuthToken.EqualToConstantTime([]byte(token))
		if err != nil {
			http.Error(w, `{"error": "Internal server error during auth"}`, http.StatusInternalServerError)
			return
		}
		if !valid {
			http.Error(w, `{"error": "Invalid authentication token"}`, http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// respondWithJSON is a helper to write JSON responses.
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

// Handler implementations
func (s *APIServer) handleGetSites(w http.ResponseWriter, r *http.Request) {
	sites := s.multiSiteManager.ListSites()
	respondWithJSON(w, http.StatusOK, sites)
}

func (s *APIServer) handleCreateSite(w http.ResponseWriter, r *http.Request) {
	var site Site
	if err := json.NewDecoder(r.Body).Decode(&site); err != nil {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if err := s.multiSiteManager.AddSite(&site); err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusConflict)
		return
	}
	respondWithJSON(w, http.StatusCreated, site)
}

func (s *APIServer) handleGetSite(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	site, err := s.multiSiteManager.GetSite(id)
	if err != nil {
		http.Error(w, `{"error": "Site not found"}`, http.StatusNotFound)
		return
	}
	respondWithJSON(w, http.StatusOK, site)
}

func (s *APIServer) handleUpdateSite(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	var siteData Site
	if err := json.NewDecoder(r.Body).Decode(&siteData); err != nil {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}
	updatedSite, err := s.multiSiteManager.UpdateSite(id, &siteData)
	if err != nil {
		http.Error(w, `{"error": "Site not found"}`, http.StatusNotFound)
		return
	}
	respondWithJSON(w, http.StatusOK, updatedSite)
}

func (s *APIServer) handleDeleteSite(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	if err := s.multiSiteManager.RemoveSite(id); err != nil {
		http.Error(w, `{"error": "Site not found"}`, http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *APIServer) handleNotImplemented(w http.ResponseWriter, r *http.Request) {
	respondWithJSON(w, http.StatusNotImplemented, map[string]string{"message": "This endpoint is not yet implemented."})
}

// Session API Handlers

// apiSession is a struct for a clean JSON representation of a session.
type apiSession struct {
	SessionID         string    `json:"session_id"`
	Username          string    `json:"username"`
	IPAddress         string    `json:"ip_address"`
	MACAddress        string    `json:"mac_address"`
	StartTime         time.Time `json:"start_time"`
	SessionDuration   uint32    `json:"session_duration_seconds"`
	InputOctets       uint64    `json:"input_octets"`
	OutputOctets      uint64    `json:"output_octets"`
}

func (s *APIServer) handleListSessions(w http.ResponseWriter, r *http.Request) {
	// In a true multi-site setup, we would filter by site_id.
	// For now, we list all sessions managed by this instance.
	allSessions := s.sessionManager.GetAllSessions()
	resp := make([]apiSession, 0, len(allSessions))

	for _, session := range allSessions {
		session.RLock()
		resp = append(resp, apiSession{
			SessionID:       session.SessionID,
			Username:        session.Redir.Username,
			IPAddress:       session.HisIP.String(),
			MACAddress:      session.HisMAC.String(),
			StartTime:       session.StartTime,
			SessionDuration: core.MonotonicTime() - session.StartTimeSec,
			InputOctets:     session.InputOctets,
			OutputOctets:    session.OutputOctets,
		})
		session.RUnlock()
	}
	respondWithJSON(w, http.StatusOK, resp)
}

func (s *APIServer) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["session_id"]

	session, ok := s.sessionManager.GetSessionByID(sessionID)
	if !ok {
		s.writeError(w, http.StatusNotFound, "Session not found")
		return
	}

	s.disconnecter.Disconnect(session, "Admin-Reset")
	s.logger.Info().Str("session_id", sessionID).Msg("Session disconnected by admin API")
	w.WriteHeader(http.StatusNoContent)
}


// writeError is a helper for sending uniform JSON error responses.
func (s *APIServer) writeError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

// Snapshot HTTP Handlers

func (s *APIServer) handleListSnapshots(w http.ResponseWriter, r *http.Request) {
	if s.snapshotManager == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Snapshot manager not initialized")
		return
	}
	snapshots := s.snapshotManager.ListSnapshots()
	respondWithJSON(w, http.StatusOK, snapshots)
}

type createSnapshotRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (s *APIServer) handleCreateSnapshot(w http.ResponseWriter, r *http.Request) {
	if s.snapshotManager == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Snapshot manager not initialized")
		return
	}
	var req createSnapshotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Name == "" {
		req.Name = "Snapshot " + time.Now().Format("2006-01-02 15:04:05")
	}
	snapshot, err := s.snapshotManager.CreateSnapshot(req.Name, req.Description)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to create snapshot")
		s.writeError(w, http.StatusInternalServerError, "Failed to create snapshot")
		return
	}
	s.logger.Info().Str("snapshot_id", snapshot.ID).Str("name", snapshot.Name).Msg("Snapshot created")
	respondWithJSON(w, http.StatusCreated, snapshot)
}

func (s *APIServer) handleGetSnapshot(w http.ResponseWriter, r *http.Request) {
	if s.snapshotManager == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Snapshot manager not initialized")
		return
	}
	vars := mux.Vars(r)
	id := vars["id"]
	snapshot, err := s.snapshotManager.GetSnapshot(id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, snapshot)
}

func (s *APIServer) handleRestoreSnapshot(w http.ResponseWriter, r *http.Request) {
	if s.snapshotManager == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Snapshot manager not initialized")
		return
	}
	vars := mux.Vars(r)
	id := vars["id"]
	configPath := os.Getenv("COOVACHILLI_CONFIG")
	if configPath == "" {
		configPath = "/etc/coovachilli/config.yaml"
	}
	if err := s.snapshotManager.RestoreSnapshot(id, configPath); err != nil {
		s.logger.Error().Err(err).Str("snapshot_id", id).Msg("Failed to restore snapshot")
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to restore snapshot: %v", err))
		return
	}
	s.logger.Info().Str("snapshot_id", id).Msg("Snapshot restored")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, `{"status":"ok", "message":"snapshot restored - restart required"}`)
}

func (s *APIServer) handleDeleteSnapshot(w http.ResponseWriter, r *http.Request) {
	if s.snapshotManager == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Snapshot manager not initialized")
		return
	}
	vars := mux.Vars(r)
	id := vars["id"]
	if err := s.snapshotManager.DeleteSnapshot(id); err != nil {
		s.logger.Error().Err(err).Str("snapshot_id", id).Msg("Failed to delete snapshot")
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to delete snapshot: %v", err))
		return
	}
	s.logger.Info().Str("snapshot_id", id).Msg("Snapshot deleted")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, `{"status":"ok", "message":"snapshot deleted"}`)
}

// Template API Handlers

type apiTemplateResponse struct {
	Name         string    `json:"name"`
	Content      string    `json:"content"`
	LastModified time.Time `json:"last_modified"`
}

type apiUpdateTemplateRequest struct {
	Content string `json:"content"`
}

// secureJoin securely joins a base directory and a requested filename, preventing path traversal.
func (s *APIServer) secureJoin(baseDir, requestedFile string) (string, error) {
	if requestedFile == "" {
		return "", fmt.Errorf("requested file is empty")
	}

	// Join the base directory and the requested file. filepath.Join cleans the path.
	destPath := filepath.Join(baseDir, requestedFile)

	// Get absolute paths to be certain.
	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("could not get absolute path for base directory")
	}
	absDestPath, err := filepath.Abs(destPath)
	if err != nil {
		return "", fmt.Errorf("could not get absolute path for destination")
	}

	// The key security check: is the final path still inside the base directory?
	if !strings.HasPrefix(absDestPath, absBaseDir) {
		s.logger.Warn().Str("requested_path", requestedFile).Str("resolved_path", absDestPath).Msg("Potential path traversal attack detected")
		return "", fmt.Errorf("invalid path: potential directory traversal attack")
	}

	return absDestPath, nil
}

func (s *APIServer) handleGetTemplate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	templateName := vars["template_name"]

	templateDir := s.cfg.TemplateDir
	if templateDir == "" {
		templateDir = "www/templates"
	}

	fullPath, err := s.secureJoin(templateDir, templateName)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid template name")
		return
	}

	content, err := os.ReadFile(fullPath)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Template not found")
		return
	}

	stat, _ := os.Stat(fullPath)

	resp := apiTemplateResponse{
		Name:         filepath.Base(fullPath),
		Content:      string(content),
		LastModified: stat.ModTime(),
	}
	respondWithJSON(w, http.StatusOK, resp)
}

func (s *APIServer) handleUpdateTemplate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	templateName := vars["template_name"]

	templateDir := s.cfg.TemplateDir
	if templateDir == "" {
		templateDir = "www/templates"
	}

	fullPath, err := s.secureJoin(templateDir, templateName)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid template name")
		return
	}

	var req apiUpdateTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Ensure the directory exists
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		s.logger.Error().Err(err).Msg("Failed to create template directory")
		s.writeError(w, http.StatusInternalServerError, "Failed to write template")
		return
	}

	if err := os.WriteFile(fullPath, []byte(req.Content), 0644); err != nil {
		s.logger.Error().Err(err).Msg("Failed to write template file")
		s.writeError(w, http.StatusInternalServerError, "Failed to write template")
		return
	}

	s.logger.Info().Str("template", fullPath).Msg("Template updated via API")
	respondWithJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "template updated"})
}