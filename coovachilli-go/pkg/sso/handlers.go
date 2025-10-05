package sso

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

// SSOHandlers provides HTTP handlers for SSO endpoints
type SSOHandlers struct {
	manager *SSOManager
}

// NewSSOHandlers creates new SSO handlers
func NewSSOHandlers(manager *SSOManager) *SSOHandlers {
	return &SSOHandlers{
		manager: manager,
	}
}

// RegisterRoutes registers SSO routes with the router
func (h *SSOHandlers) RegisterRoutes(router *mux.Router) {
	// SSO info endpoint
	router.HandleFunc("/sso/info", h.handleInfo).Methods("GET")

	// SAML endpoints
	router.HandleFunc("/sso/saml/login", h.handleSAMLLogin).Methods("GET")
	router.HandleFunc("/sso/saml/acs", h.handleSAMLCallback).Methods("POST")
	router.HandleFunc("/sso/saml/metadata", h.handleSAMLMetadata).Methods("GET")

	// OIDC endpoints
	router.HandleFunc("/sso/oidc/login", h.handleOIDCLogin).Methods("GET")
	router.HandleFunc("/sso/oidc/callback", h.handleOIDCCallback).Methods("GET")
}

// handleInfo returns information about available SSO providers
func (h *SSOHandlers) handleInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	info := map[string]interface{}{
		"enabled":   true,
		"providers": h.manager.GetAvailableProviders(),
		"saml": map[string]interface{}{
			"enabled":     h.manager.IsSAMLEnabled(),
			"login_url":   "/sso/saml/login",
			"acs_url":     "/sso/saml/acs",
			"metadata_url": "/sso/saml/metadata",
		},
		"oidc": map[string]interface{}{
			"enabled":      h.manager.IsOIDCEnabled(),
			"login_url":    "/sso/oidc/login",
			"callback_url": "/sso/oidc/callback",
		},
	}

	json.NewEncoder(w).Encode(info)
}

// handleSAMLLogin initiates SAML login flow
func (h *SSOHandlers) handleSAMLLogin(w http.ResponseWriter, r *http.Request) {
	if !h.manager.IsSAMLEnabled() {
		http.Error(w, "SAML is not enabled", http.StatusNotFound)
		return
	}

	// Get optional relay state
	relayState := r.URL.Query().Get("RelayState")

	// Initiate SAML login
	authURL, err := h.manager.InitiateSAMLLogin(relayState)
	if err != nil {
		h.manager.logger.Error().Err(err).Msg("Failed to initiate SAML login")
		http.Error(w, "Failed to initiate SAML login", http.StatusInternalServerError)
		return
	}

	// Redirect to IdP
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleSAMLCallback handles SAML ACS (Assertion Consumer Service) callback
func (h *SSOHandlers) handleSAMLCallback(w http.ResponseWriter, r *http.Request) {
	if !h.manager.IsSAMLEnabled() {
		http.Error(w, "SAML is not enabled", http.StatusNotFound)
		return
	}

	// Handle SAML callback
	user, err := h.manager.HandleSAMLCallback(r)
	if err != nil {
		h.manager.logger.Error().Err(err).Msg("SAML authentication failed")
		http.Error(w, fmt.Sprintf("SAML authentication failed: %v", err), http.StatusUnauthorized)
		return
	}

	// Return user info as JSON (in production, this should create a session)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"provider": user.Provider,
		"username": user.Username,
		"email":    user.Email,
		"groups":   user.Groups,
		"message":  "SAML authentication successful",
	})
}

// handleSAMLMetadata returns SAML SP metadata
func (h *SSOHandlers) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	if !h.manager.IsSAMLEnabled() {
		http.Error(w, "SAML is not enabled", http.StatusNotFound)
		return
	}

	// TODO: Generate SAML SP metadata XML
	// For now, return a placeholder
	w.Header().Set("Content-Type", "application/xml")
	w.Write([]byte(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <!-- SAML SP Metadata - TODO: Implement full metadata generation -->
</EntityDescriptor>`))
}

// handleOIDCLogin initiates OIDC login flow
func (h *SSOHandlers) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if !h.manager.IsOIDCEnabled() {
		http.Error(w, "OIDC is not enabled", http.StatusNotFound)
		return
	}

	// Initiate OIDC login
	authURL, state, nonce, err := h.manager.InitiateOIDCLogin()
	if err != nil {
		h.manager.logger.Error().Err(err).Msg("Failed to initiate OIDC login")
		http.Error(w, "Failed to initiate OIDC login", http.StatusInternalServerError)
		return
	}

	// Store state and nonce in cookie for validation (in production, use secure session)
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_nonce",
		Value:    nonce,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes
	})

	// Redirect to authorization endpoint
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOIDCCallback handles OIDC callback
func (h *SSOHandlers) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if !h.manager.IsOIDCEnabled() {
		http.Error(w, "OIDC is not enabled", http.StatusNotFound)
		return
	}

	// Get code and state from query
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		// Check for error
		errorCode := r.URL.Query().Get("error")
		errorDesc := r.URL.Query().Get("error_description")
		h.manager.logger.Error().
			Str("error", errorCode).
			Str("description", errorDesc).
			Msg("OIDC authentication error")
		http.Error(w, fmt.Sprintf("OIDC error: %s - %s", errorCode, errorDesc), http.StatusUnauthorized)
		return
	}

	// Verify state from cookie
	stateCookie, err := r.Cookie("oidc_state")
	if err != nil || stateCookie.Value != state {
		h.manager.logger.Error().Err(err).Msg("Invalid state parameter")
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Handle OIDC callback
	user, err := h.manager.HandleOIDCCallback(r.Context(), code, state)
	if err != nil {
		h.manager.logger.Error().Err(err).Msg("OIDC authentication failed")
		http.Error(w, fmt.Sprintf("OIDC authentication failed: %v", err), http.StatusUnauthorized)
		return
	}

	// Clear state and nonce cookies
	http.SetCookie(w, &http.Cookie{
		Name:   "oidc_state",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:   "oidc_nonce",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	// Return user info as JSON (in production, this should create a session)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"provider": user.Provider,
		"username": user.Username,
		"email":    user.Email,
		"name":     user.Name,
		"groups":   user.Groups,
		"message":  "OIDC authentication successful",
	})
}
