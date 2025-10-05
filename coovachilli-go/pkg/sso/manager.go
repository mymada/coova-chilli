package sso

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// SSOConfig holds SSO configuration
type SSOConfig struct {
	Enabled bool         `yaml:"enabled" envconfig:"SSO_ENABLED"`
	SAML    *SAMLConfig  `yaml:"saml"`
	OIDC    *OIDCConfig  `yaml:"oidc"`
}

// SSOManager manages multiple SSO providers
type SSOManager struct {
	config       *SSOConfig
	logger       zerolog.Logger
	samlProvider *SAMLProvider
	oidcProvider *OIDCProvider
	sessions     map[string]*SSOSession
	sessionsMu   sync.RWMutex
}

// SSOSession represents an SSO session
type SSOSession struct {
	ID           string
	Provider     string // "saml" or "oidc"
	Username     string
	Email        string
	Groups       []string
	Attributes   map[string]interface{}
	CreatedAt    time.Time
	ExpiresAt    time.Time
	State        string // For OIDC
	Nonce        string // For OIDC
	RelayState   string // For SAML
}

// SSOUser represents a unified SSO user
type SSOUser struct {
	Provider   string
	Subject    string
	Username   string
	Email      string
	Name       string
	Groups     []string
	Attributes map[string]interface{}
}

// NewSSOManager creates a new SSO manager
func NewSSOManager(config *SSOConfig, logger zerolog.Logger) (*SSOManager, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("SSO is not enabled")
	}

	mgr := &SSOManager{
		config:   config,
		logger:   logger.With().Str("component", "sso-manager").Logger(),
		sessions: make(map[string]*SSOSession),
	}

	// Initialize SAML provider if enabled
	if config.SAML != nil && config.SAML.Enabled {
		saml, err := NewSAMLProvider(config.SAML, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize SAML provider: %w", err)
		}
		mgr.samlProvider = saml
		mgr.logger.Info().Msg("SAML provider enabled")
	}

	// Initialize OIDC provider if enabled
	if config.OIDC != nil && config.OIDC.Enabled {
		oidc, err := NewOIDCProvider(config.OIDC, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize OIDC provider: %w", err)
		}
		mgr.oidcProvider = oidc
		mgr.logger.Info().Msg("OIDC provider enabled")
	}

	if mgr.samlProvider == nil && mgr.oidcProvider == nil {
		return nil, fmt.Errorf("no SSO providers enabled")
	}

	// Start session cleanup goroutine
	go mgr.cleanupExpiredSessions()

	return mgr, nil
}

// IsSAMLEnabled returns true if SAML is enabled
func (mgr *SSOManager) IsSAMLEnabled() bool {
	return mgr.samlProvider != nil
}

// IsOIDCEnabled returns true if OIDC is enabled
func (mgr *SSOManager) IsOIDCEnabled() bool {
	return mgr.oidcProvider != nil
}

// InitiateSAMLLogin initiates SAML login flow
func (mgr *SSOManager) InitiateSAMLLogin(relayState string) (string, error) {
	if !mgr.IsSAMLEnabled() {
		return "", fmt.Errorf("SAML is not enabled")
	}

	// Build SAML AuthnRequest URL
	authURL, err := mgr.samlProvider.BuildAuthURL(relayState)
	if err != nil {
		return "", fmt.Errorf("failed to build SAML auth URL: %w", err)
	}

	// Create session
	session := &SSOSession{
		ID:         generateRandomString(32),
		Provider:   "saml",
		RelayState: relayState,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}

	mgr.sessionsMu.Lock()
	mgr.sessions[session.ID] = session
	mgr.sessionsMu.Unlock()

	mgr.logger.Info().
		Str("session_id", session.ID).
		Str("relay_state", relayState).
		Msg("SAML login initiated")

	return authURL, nil
}

// InitiateOIDCLogin initiates OIDC login flow
func (mgr *SSOManager) InitiateOIDCLogin() (authURL, state, nonce string, err error) {
	if !mgr.IsOIDCEnabled() {
		return "", "", "", fmt.Errorf("OIDC is not enabled")
	}

	// Generate state and nonce
	state = generateRandomString(32)
	nonce = generateRandomString(32)

	// Build OIDC authorization URL
	authURL, err = mgr.oidcProvider.BuildAuthURL(state, nonce)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to build OIDC auth URL: %w", err)
	}

	// Create session
	session := &SSOSession{
		ID:        generateRandomString(32),
		Provider:  "oidc",
		State:     state,
		Nonce:     nonce,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	mgr.sessionsMu.Lock()
	mgr.sessions[session.ID] = session
	mgr.sessionsMu.Unlock()

	mgr.logger.Info().
		Str("session_id", session.ID).
		Str("state", state).
		Msg("OIDC login initiated")

	return authURL, state, nonce, nil
}

// HandleSAMLCallback handles SAML callback
func (mgr *SSOManager) HandleSAMLCallback(r *http.Request) (*SSOUser, error) {
	if !mgr.IsSAMLEnabled() {
		return nil, fmt.Errorf("SAML is not enabled")
	}

	// Process SAML response
	samlUser, err := mgr.samlProvider.HandleCallback(r)
	if err != nil {
		return nil, fmt.Errorf("SAML callback failed: %w", err)
	}

	// Convert to unified SSO user
	user := &SSOUser{
		Provider:   "saml",
		Subject:    samlUser.NameID,
		Username:   samlUser.Username,
		Email:      samlUser.Email,
		Groups:     samlUser.Groups,
		Attributes: make(map[string]interface{}),
	}

	// Copy SAML attributes
	for k, v := range samlUser.Attributes {
		user.Attributes[k] = v
	}

	mgr.logger.Info().
		Str("provider", "saml").
		Str("username", user.Username).
		Msg("SSO authentication successful")

	return user, nil
}

// HandleOIDCCallback handles OIDC callback
func (mgr *SSOManager) HandleOIDCCallback(ctx context.Context, code, state string) (*SSOUser, error) {
	if !mgr.IsOIDCEnabled() {
		return nil, fmt.Errorf("OIDC is not enabled")
	}

	// Verify state
	mgr.sessionsMu.RLock()
	var session *SSOSession
	for _, s := range mgr.sessions {
		if s.Provider == "oidc" && s.State == state {
			session = s
			break
		}
	}
	mgr.sessionsMu.RUnlock()

	if session == nil {
		return nil, fmt.Errorf("invalid state parameter")
	}

	// Check session expiration
	if time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("session expired")
	}

	// Process OIDC callback
	oidcUser, err := mgr.oidcProvider.HandleCallback(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("OIDC callback failed: %w", err)
	}

	// Convert to unified SSO user
	user := &SSOUser{
		Provider:   "oidc",
		Subject:    oidcUser.Subject,
		Username:   oidcUser.Username,
		Email:      oidcUser.Email,
		Name:       oidcUser.Name,
		Groups:     oidcUser.Groups,
		Attributes: oidcUser.Claims,
	}

	// Clean up session
	mgr.sessionsMu.Lock()
	delete(mgr.sessions, session.ID)
	mgr.sessionsMu.Unlock()

	mgr.logger.Info().
		Str("provider", "oidc").
		Str("username", user.Username).
		Msg("SSO authentication successful")

	return user, nil
}

// GetAvailableProviders returns list of enabled SSO providers
func (mgr *SSOManager) GetAvailableProviders() []string {
	providers := make([]string, 0, 2)

	if mgr.IsSAMLEnabled() {
		providers = append(providers, "saml")
	}

	if mgr.IsOIDCEnabled() {
		providers = append(providers, "oidc")
	}

	return providers
}

// cleanupExpiredSessions periodically removes expired sessions
func (mgr *SSOManager) cleanupExpiredSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		mgr.sessionsMu.Lock()

		expired := 0
		for id, session := range mgr.sessions {
			if now.After(session.ExpiresAt) {
				delete(mgr.sessions, id)
				expired++
			}
		}

		mgr.sessionsMu.Unlock()

		if expired > 0 {
			mgr.logger.Debug().
				Int("expired", expired).
				Msg("Cleaned up expired SSO sessions")
		}
	}
}

// GetSessionCount returns the number of active SSO sessions
func (mgr *SSOManager) GetSessionCount() int {
	mgr.sessionsMu.RLock()
	defer mgr.sessionsMu.RUnlock()
	return len(mgr.sessions)
}
