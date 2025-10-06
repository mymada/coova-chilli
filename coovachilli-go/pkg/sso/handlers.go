package sso

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/firewall"
	"coovachilli-go/pkg/script"

	"layeh.com/radius/rfc2866"
)

// CoreSession represents a minimal interface to core session
type CoreSession interface {
	Lock()
	Unlock()
	GetIP() net.IP
	GetMAC() net.HardwareAddr
	SetAuthenticated(bool)
	SetUsername(string)
	InitializeShaper(*config.Config)
}

// SessionManager interface for network session management
type SessionManager interface {
	GetSessionByIP(ip net.IP) (CoreSession, bool)
}

// RadiusClient interface for accounting
type RadiusClient interface {
	SendAccountingRequest(session interface{}, statusType interface{}) error
}

// SSOHandlers provides HTTP handlers for SSO endpoints
type SSOHandlers struct {
	manager        *SSOManager
	sessionManager SessionManager
	firewall       firewall.FirewallManager
	radiusClient   RadiusClient
	scriptRunner   *script.Runner
	cfg            *config.Config
}

// NewSSOHandlers creates new SSO handlers
func NewSSOHandlers(manager *SSOManager) *SSOHandlers {
	return &SSOHandlers{
		manager: manager,
	}
}

// SetSessionManager sets the core session manager
func (h *SSOHandlers) SetSessionManager(sm SessionManager) {
	h.sessionManager = sm
}

// SetFirewall sets the firewall manager
func (h *SSOHandlers) SetFirewall(fw firewall.FirewallManager) {
	h.firewall = fw
}

// SetRadiusClient sets the RADIUS client
func (h *SSOHandlers) SetRadiusClient(rc RadiusClient) {
	h.radiusClient = rc
}

// SetScriptRunner sets the script runner
func (h *SSOHandlers) SetScriptRunner(sr *script.Runner) {
	h.scriptRunner = sr
}

// SetConfig sets the configuration
func (h *SSOHandlers) SetConfig(cfg *config.Config) {
	h.cfg = cfg
}

// RegisterRoutes registers SSO routes with the standard mux
func (h *SSOHandlers) RegisterRoutes(mux *http.ServeMux) {
	// SSO info endpoint
	mux.HandleFunc("/sso/info", h.handleInfo)

	// SAML endpoints
	mux.HandleFunc("/sso/saml/login", h.handleSAMLLogin)
	mux.HandleFunc("/sso/saml/acs", h.handleSAMLCallback)
	mux.HandleFunc("/sso/saml/metadata", h.handleSAMLMetadata)

	// OIDC endpoints
	mux.HandleFunc("/sso/oidc/login", h.handleOIDCLogin)
	mux.HandleFunc("/sso/oidc/callback", h.handleOIDCCallback)
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

// getClientIP extracts the client IP from the request
func (h *SSOHandlers) getClientIP(r *http.Request) net.IP {
	// Try X-Forwarded-For first (if behind proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			if ip := net.ParseIP(strings.TrimSpace(ips[0])); ip != nil {
				return ip
			}
		}
	}

	// Try X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if ip := net.ParseIP(xri); ip != nil {
			return ip
		}
	}

	// Fall back to RemoteAddr
	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}
	return net.ParseIP(ipStr)
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

	// ✅ CORRECTION CRITIQUE: Intégrer avec session réseau
	if h.sessionManager != nil && h.firewall != nil {
		clientIP := h.getClientIP(r)
		if clientIP == nil {
			h.manager.logger.Error().Msg("Failed to get client IP for SSO")
			http.Error(w, "Failed to determine client IP", http.StatusInternalServerError)
			return
		}

		// Récupérer la session réseau existante
		session, ok := h.sessionManager.GetSessionByIP(clientIP)
		if !ok {
			h.manager.logger.Warn().
				Str("ip", clientIP.String()).
				Msg("No network session found for SSO authentication")
			http.Error(w, "Network session not found. Please reconnect to the network.", http.StatusNotFound)
			return
		}

		// Activer l'authentification réseau
		session.Lock()
		session.SetAuthenticated(true)
		session.SetUsername(user.Username)
		if h.cfg != nil {
			session.InitializeShaper(h.cfg)
		}
		session.Unlock()

		// Appliquer les règles firewall
		if err := h.firewall.AddAuthenticatedUser(clientIP); err != nil {
			h.manager.logger.Error().Err(err).
				Str("user", user.Username).
				Str("ip", clientIP.String()).
				Msg("Failed to add firewall rules for SSO user")
			http.Error(w, "Failed to apply network access", http.StatusInternalServerError)
			return
		}

		// Envoyer RADIUS Accounting-Start
		if h.radiusClient != nil {
			// Unwrap to get raw session for RADIUS
			if adapter, ok := session.(*CoreSessionAdapter); ok {
				go h.radiusClient.SendAccountingRequest(adapter.GetRawSession(), rfc2866.AcctStatusType_Value_Start)
			}
		}

		// Exécuter script conup
		if h.scriptRunner != nil && h.cfg != nil && h.cfg.ConUp != "" {
			if adapter, ok := session.(*CoreSessionAdapter); ok {
				h.scriptRunner.RunScript(h.cfg.ConUp, adapter.GetRawSession(), 0)
			}
		}

		h.manager.logger.Info().
			Str("username", user.Username).
			Str("email", user.Email).
			Str("method", "saml").
			Str("ip", clientIP.String()).
			Msg("SSO authentication successful - network access granted")

		// Set secure cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "coova_session",
			Value:    generateSessionToken(),
			Expires:  time.Now().Add(24 * time.Hour),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
		})

		// Redirect to status page
		http.Redirect(w, r, "/status", http.StatusFound)
		return
	}

	// Fallback: Return JSON (legacy behavior)
	h.manager.logger.Warn().Msg("SSO handlers not fully configured - returning JSON only")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"provider": user.Provider,
		"username": user.Username,
		"email":    user.Email,
		"groups":   user.Groups,
		"message":  "SAML authentication successful (network integration not configured)",
	})
}

// generateSessionToken generates a secure random session token
func generateSessionToken() string {
	// Simple implementation - in production use crypto/rand
	return fmt.Sprintf("sso_%d", time.Now().UnixNano())
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

	// ✅ CORRECTION CRITIQUE: Intégrer avec session réseau (comme SAML)
	if h.sessionManager != nil && h.firewall != nil {
		clientIP := h.getClientIP(r)
		if clientIP == nil {
			h.manager.logger.Error().Msg("Failed to get client IP for OIDC")
			http.Error(w, "Failed to determine client IP", http.StatusInternalServerError)
			return
		}

		// Récupérer la session réseau existante
		session, ok := h.sessionManager.GetSessionByIP(clientIP)
		if !ok {
			h.manager.logger.Warn().
				Str("ip", clientIP.String()).
				Msg("No network session found for OIDC authentication")
			http.Error(w, "Network session not found. Please reconnect to the network.", http.StatusNotFound)
			return
		}

		// Activer l'authentification réseau
		session.Lock()
		session.SetAuthenticated(true)
		session.SetUsername(user.Username)
		if h.cfg != nil {
			session.InitializeShaper(h.cfg)
		}
		session.Unlock()

		// Appliquer les règles firewall
		if err := h.firewall.AddAuthenticatedUser(clientIP); err != nil {
			h.manager.logger.Error().Err(err).
				Str("user", user.Username).
				Str("ip", clientIP.String()).
				Msg("Failed to add firewall rules for OIDC user")
			http.Error(w, "Failed to apply network access", http.StatusInternalServerError)
			return
		}

		// Envoyer RADIUS Accounting-Start
		if h.radiusClient != nil {
			// Unwrap to get raw session for RADIUS
			if adapter, ok := session.(*CoreSessionAdapter); ok {
				go h.radiusClient.SendAccountingRequest(adapter.GetRawSession(), rfc2866.AcctStatusType_Value_Start)
			}
		}

		// Exécuter script conup
		if h.scriptRunner != nil && h.cfg != nil && h.cfg.ConUp != "" {
			if adapter, ok := session.(*CoreSessionAdapter); ok {
				h.scriptRunner.RunScript(h.cfg.ConUp, adapter.GetRawSession(), 0)
			}
		}

		h.manager.logger.Info().
			Str("username", user.Username).
			Str("email", user.Email).
			Str("method", "oidc").
			Str("ip", clientIP.String()).
			Msg("OIDC authentication successful - network access granted")

		// Set secure cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "coova_session",
			Value:    generateSessionToken(),
			Expires:  time.Now().Add(24 * time.Hour),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
		})

		// Redirect to status page
		http.Redirect(w, r, "/status", http.StatusFound)
		return
	}

	// Fallback: Return JSON (legacy behavior)
	h.manager.logger.Warn().Msg("OIDC handlers not fully configured - returning JSON only")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"provider": user.Provider,
		"username": user.Username,
		"email":    user.Email,
		"name":     user.Name,
		"groups":   user.Groups,
		"message":  "OIDC authentication successful (network integration not configured)",
	})
}
