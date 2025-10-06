package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"coovachilli-go/pkg/auth/qrcode"
	"coovachilli-go/pkg/auth/sms"
	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/guest"
	"coovachilli-go/pkg/roles"
	"coovachilli-go/pkg/sso"
	"github.com/rs/zerolog"
)

// AuthMethod represents an authentication method
type AuthMethod string

const (
	AuthMethodRADIUS   AuthMethod = "radius"
	AuthMethodLocal    AuthMethod = "local"
	AuthMethodLDAP     AuthMethod = "ldap"
	AuthMethodSAML     AuthMethod = "saml"
	AuthMethodOIDC     AuthMethod = "oidc"
	AuthMethodQRCode   AuthMethod = "qrcode"
	AuthMethodSMS      AuthMethod = "sms"
	AuthMethodGuest    AuthMethod = "guest"
	AuthMethodMAC      AuthMethod = "mac"
)

// AuthRequest represents a unified authentication request
type AuthRequest struct {
	Method      AuthMethod
	Username    string
	Password    string
	MAC         net.HardwareAddr
	IP          net.IP
	Token       string // For QR code, SMS code, guest code, or JWT
	PhoneNumber string // For SMS
	Context     context.Context

	// SSO specific
	SSOProvider string
	SSOCode     string
	SSOState    string

	// Session context
	SessionID   string
	UserAgent   string
	OriginalURL string
}

// AuthResponse represents a unified authentication response
type AuthResponse struct {
	Success      bool
	Method       AuthMethod
	Username     string
	Email        string
	Groups       []string
	RoleID       string
	Attributes   map[string]interface{}
	SessionToken string
	ExpiresAt    time.Time
	Error        error

	// RADIUS attributes (if applicable)
	SessionTimeout     uint32
	IdleTimeout        uint32
	BandwidthMaxDown   uint64
	BandwidthMaxUp     uint64
	VLANID             uint16
}

// AuthenticationManager coordinates all authentication methods
type AuthenticationManager struct {
	cfg    *config.Config
	logger zerolog.Logger
	mu     sync.RWMutex

	// Authentication providers
	ssoManager *sso.SSOManager
	qrManager    *qrcode.QRAuthManager
	smsManager   *sms.SMSAuthManager
	guestManager *guest.GuestManager
	roleManager  *roles.RoleManager

	// Authentication statistics
	stats AuthStats

	// Session management
	sessions map[string]*AuthSession // sessionToken -> AuthSession
}

// AuthSession represents an authenticated session
type AuthSession struct {
	ID           string
	Username     string
	Email        string
	Method       AuthMethod
	RoleID       string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	LastActivity time.Time
	Attributes   map[string]interface{}
	IPAddress    net.IP
	MAC          net.HardwareAddr
}

// AuthStats tracks authentication statistics
type AuthStats struct {
	TotalAttempts     uint64
	SuccessfulAuths   uint64
	FailedAuths       uint64
	MethodStats       map[AuthMethod]uint64
	ActiveSessions    int
}

// NewAuthenticationManager creates a new unified authentication manager
func NewAuthenticationManager(cfg *config.Config, logger zerolog.Logger) (*AuthenticationManager, error) {
	am := &AuthenticationManager{
		cfg:      cfg,
		logger:   logger.With().Str("component", "auth-manager").Logger(),
		sessions: make(map[string]*AuthSession),
		stats: AuthStats{
			MethodStats: make(map[AuthMethod]uint64),
		},
	}

	// Initialize LDAP if enabled
	if cfg.LDAP.Enabled {
		// LDAP authenticator wrapper needed
		am.logger.Info().Msg("LDAP authentication enabled")
	}

	// Initialize SSO if enabled
	if cfg.SSO.Enabled {
		ssoConfig := convertToSSOConfig(&cfg.SSO)
		ssoMgr, err := sso.NewSSOManager(ssoConfig, logger)
		if err != nil {
			am.logger.Warn().Err(err).Msg("Failed to initialize SSO manager")
		} else {
			am.ssoManager = ssoMgr
			am.logger.Info().Msg("SSO authentication enabled")
		}
	}

	// Initialize QR code authentication
	if cfg.QRCode.Enabled {
		qrConfig := convertToQRCodeConfig(&cfg.QRCode)
		qrMgr, err := qrcode.NewQRAuthManager(qrConfig, logger)
		if err != nil {
			am.logger.Warn().Err(err).Msg("Failed to initialize QR code manager")
		} else {
			am.qrManager = qrMgr
			am.logger.Info().Msg("QR code authentication enabled")
		}
	}

	// Initialize SMS authentication
	if cfg.SMS.Enabled {
		smsConfig := convertToSMSConfig(&cfg.SMS)
		smsMgr, err := sms.NewSMSAuthManager(smsConfig, logger)
		if err != nil {
			am.logger.Warn().Err(err).Msg("Failed to initialize SMS manager")
		} else {
			am.smsManager = smsMgr
			am.logger.Info().Msg("SMS authentication enabled")
		}
	}

	// Initialize guest code management
	if cfg.Guest.Enabled {
		guestConfig := convertToGuestConfig(&cfg.Guest)
		guestMgr, err := guest.NewGuestManager(guestConfig, logger)
		if err != nil {
			am.logger.Warn().Err(err).Msg("Failed to initialize guest manager")
		} else {
			am.guestManager = guestMgr
			am.logger.Info().Msg("Guest code authentication enabled")
		}
	}

	// Initialize role management
	if cfg.Roles.Enabled {
		roleConfig := convertToRoleConfig(&cfg.Roles)
		roleMgr, err := roles.NewRoleManager(roleConfig, logger)
		if err != nil {
			am.logger.Warn().Err(err).Msg("Failed to initialize role manager")
		} else {
			am.roleManager = roleMgr
			am.logger.Info().Msg("Role management enabled")
		}
	}

	// Start session cleanup
	go am.cleanupExpiredSessions()

	am.logger.Info().Msg("Authentication manager initialized")
	return am, nil
}

// Authenticate performs authentication using the specified method
func (am *AuthenticationManager) Authenticate(req *AuthRequest) (*AuthResponse, error) {
	am.mu.Lock()
	am.stats.TotalAttempts++
	am.mu.Unlock()

	am.logger.Info().
		Str("method", string(req.Method)).
		Str("username", req.Username).
		Str("ip", req.IP.String()).
		Msg("Authentication attempt")

	var resp *AuthResponse
	var err error

	// Route to appropriate authentication method
	switch req.Method {
	case AuthMethodLocal:
		resp, err = am.authenticateLocal(req)

	case AuthMethodLDAP:
		resp, err = am.authenticateLDAP(req)

	case AuthMethodQRCode:
		resp, err = am.authenticateQRCode(req)

	case AuthMethodSMS:
		resp, err = am.authenticateSMS(req)

	case AuthMethodGuest:
		resp, err = am.authenticateGuest(req)

	case AuthMethodMAC:
		resp, err = am.authenticateMAC(req)

	case AuthMethodSAML, AuthMethodOIDC:
		resp, err = am.authenticateSSO(req)

	default:
		err = fmt.Errorf("unsupported authentication method: %s", req.Method)
	}

	// Update statistics
	am.mu.Lock()
	if err != nil || !resp.Success {
		am.stats.FailedAuths++
		am.logger.Warn().
			Err(err).
			Str("method", string(req.Method)).
			Str("username", req.Username).
			Msg("Authentication failed")
	} else {
		am.stats.SuccessfulAuths++
		am.stats.MethodStats[req.Method]++
		am.logger.Info().
			Str("method", string(req.Method)).
			Str("username", resp.Username).
			Msg("Authentication successful")
	}
	am.mu.Unlock()

	if err != nil {
		return nil, err
	}

	// If authentication succeeded, apply role-based settings
	if resp.Success && am.roleManager != nil {
		if err := am.applyRoleSettings(resp); err != nil {
			am.logger.Warn().Err(err).Msg("Failed to apply role settings")
		}
	}

	// Create session if successful
	if resp.Success {
		session := &AuthSession{
			ID:           generateSessionID(),
			Username:     resp.Username,
			Email:        resp.Email,
			Method:       req.Method,
			RoleID:       resp.RoleID,
			CreatedAt:    time.Now(),
			ExpiresAt:    resp.ExpiresAt,
			LastActivity: time.Now(),
			Attributes:   resp.Attributes,
			IPAddress:    req.IP,
			MAC:          req.MAC,
		}

		am.mu.Lock()
		am.sessions[resp.SessionToken] = session
		am.stats.ActiveSessions = len(am.sessions)
		am.mu.Unlock()

		resp.SessionToken = session.ID
	}

	return resp, nil
}

// authenticateLocal authenticates against local user database
func (am *AuthenticationManager) authenticateLocal(req *AuthRequest) (*AuthResponse, error) {
	// TODO: Implement local user authentication
	// For now, return not implemented
	return &AuthResponse{
		Success: false,
		Method:  AuthMethodLocal,
		Error:   fmt.Errorf("local authentication not yet implemented"),
	}, nil
}

// authenticateLDAP authenticates against LDAP/Active Directory
func (am *AuthenticationManager) authenticateLDAP(req *AuthRequest) (*AuthResponse, error) {
	// TODO: Implement LDAP authentication
	return &AuthResponse{
		Success: false,
		Method:  AuthMethodLDAP,
		Error:   fmt.Errorf("LDAP authentication not yet implemented"),
	}, nil
}

// authenticateQRCode authenticates using QR code token
func (am *AuthenticationManager) authenticateQRCode(req *AuthRequest) (*AuthResponse, error) {
	if am.qrManager == nil {
		return nil, fmt.Errorf("QR code authentication not configured")
	}

	token, err := am.qrManager.ValidateToken(req.Token, req.IP.String())
	if err != nil {
		return &AuthResponse{
			Success: false,
			Method:  AuthMethodQRCode,
			Error:   fmt.Errorf("invalid QR token: %w", err),
		}, nil
	}

	return &AuthResponse{
		Success:      true,
		Method:       AuthMethodQRCode,
		Username:     token.Username,
		SessionToken: generateSessionToken(),
		ExpiresAt:    time.Now().Add(8 * time.Hour),
		Attributes:   token.SessionData,
	}, nil
}

// authenticateSMS authenticates using SMS verification code
func (am *AuthenticationManager) authenticateSMS(req *AuthRequest) (*AuthResponse, error) {
	if am.smsManager == nil {
		return nil, fmt.Errorf("SMS authentication not configured")
	}

	success, err := am.smsManager.VerifyCode(req.PhoneNumber, req.Token)
	if err != nil {
		return &AuthResponse{
			Success: false,
			Method:  AuthMethodSMS,
			Error:   fmt.Errorf("SMS verification failed: %w", err),
		}, nil
	}

	if !success {
		return &AuthResponse{
			Success: false,
			Method:  AuthMethodSMS,
			Error:   fmt.Errorf("invalid SMS code"),
		}, nil
	}

	return &AuthResponse{
		Success:      true,
		Method:       AuthMethodSMS,
		Username:     req.PhoneNumber,
		SessionToken: generateSessionToken(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		Attributes:   make(map[string]interface{}),
	}, nil
}

// authenticateGuest authenticates using guest code
func (am *AuthenticationManager) authenticateGuest(req *AuthRequest) (*AuthResponse, error) {
	if am.guestManager == nil {
		return nil, fmt.Errorf("guest authentication not configured")
	}

	guestCode, err := am.guestManager.ValidateGuestCode(req.Token)
	if err != nil {
		return &AuthResponse{
			Success: false,
			Method:  AuthMethodGuest,
			Error:   fmt.Errorf("invalid guest code: %w", err),
		}, nil
	}

	// Activate the guest code
	if err := am.guestManager.ActivateGuestCode(req.Token, req.Username); err != nil {
		return &AuthResponse{
			Success: false,
			Method:  AuthMethodGuest,
			Error:   fmt.Errorf("failed to activate guest code: %w", err),
		}, nil
	}

	return &AuthResponse{
		Success:      true,
		Method:       AuthMethodGuest,
		Username:     guestCode.GuestName,
		Email:        guestCode.GuestEmail,
		SessionToken: generateSessionToken(),
		ExpiresAt:    guestCode.ExpiresAt,
		RoleID:       "guest",
		Attributes: map[string]interface{}{
			"guest_company":     guestCode.GuestCompany,
			"max_sessions":      guestCode.MaxSessions,
			"session_duration":  guestCode.SessionDuration,
			"bandwidth_down":    guestCode.BandwidthDown,
			"bandwidth_up":      guestCode.BandwidthUp,
		},
	}, nil
}

// authenticateMAC authenticates using MAC address
func (am *AuthenticationManager) authenticateMAC(req *AuthRequest) (*AuthResponse, error) {
	// MAC authentication logic
	// Typically checks against a whitelist or performs RADIUS MAC auth

	return &AuthResponse{
		Success:      true,
		Method:       AuthMethodMAC,
		Username:     req.MAC.String(),
		SessionToken: generateSessionToken(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		Attributes:   make(map[string]interface{}),
	}, nil
}

// authenticateSSO handles SSO authentication (SAML/OIDC)
func (am *AuthenticationManager) authenticateSSO(req *AuthRequest) (*AuthResponse, error) {
	if am.ssoManager == nil {
		return nil, fmt.Errorf("SSO not configured")
	}

	// SSO authentication is handled via HTTP callbacks
	// This method should not be called directly
	return nil, fmt.Errorf("SSO authentication must be initiated via HTTP")
}

// applyRoleSettings applies role-based settings to auth response
func (am *AuthenticationManager) applyRoleSettings(resp *AuthResponse) error {
	role, err := am.roleManager.GetUserRole(resp.Username)
	if err != nil {
		// Use default role or continue without role
		return err
	}

	resp.RoleID = role.ID
	resp.BandwidthMaxDown = role.MaxBandwidthDown
	resp.BandwidthMaxUp = role.MaxBandwidthUp
	resp.VLANID = role.VLANID

	if role.MaxSessionDuration > 0 {
		resp.SessionTimeout = uint32(role.MaxSessionDuration.Seconds())
	}

	// Add role permissions to attributes
	if resp.Attributes == nil {
		resp.Attributes = make(map[string]interface{})
	}
	resp.Attributes["role"] = role.Name
	resp.Attributes["permissions"] = role.Permissions
	resp.Attributes["qos_class"] = role.QoSClass

	am.logger.Info().
		Str("username", resp.Username).
		Str("role", role.Name).
		Msg("Applied role settings")

	return nil
}

// ValidateSession checks if a session token is valid
func (am *AuthenticationManager) ValidateSession(sessionToken string) (*AuthSession, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	session, exists := am.sessions[sessionToken]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("session expired")
	}

	return session, nil
}

// RevokeSession invalidates a session
func (am *AuthenticationManager) RevokeSession(sessionToken string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if _, exists := am.sessions[sessionToken]; !exists {
		return fmt.Errorf("session not found")
	}

	delete(am.sessions, sessionToken)
	am.stats.ActiveSessions = len(am.sessions)

	am.logger.Info().Str("token", sessionToken[:16]+"...").Msg("Session revoked")
	return nil
}

// GetStats returns authentication statistics
func (am *AuthenticationManager) GetStats() AuthStats {
	am.mu.RLock()
	defer am.mu.RUnlock()

	stats := am.stats
	stats.ActiveSessions = len(am.sessions)

	// Copy method stats
	methodStats := make(map[AuthMethod]uint64)
	for k, v := range am.stats.MethodStats {
		methodStats[k] = v
	}
	stats.MethodStats = methodStats

	return stats
}

// cleanupExpiredSessions periodically removes expired sessions
func (am *AuthenticationManager) cleanupExpiredSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		am.mu.Lock()
		now := time.Now()
		expired := 0

		for token, session := range am.sessions {
			if now.After(session.ExpiresAt) {
				delete(am.sessions, token)
				expired++
			}
		}

		am.stats.ActiveSessions = len(am.sessions)
		am.mu.Unlock()

		if expired > 0 {
			am.logger.Debug().
				Int("expired", expired).
				Msg("Cleaned up expired sessions")
		}
	}
}

// Helper functions

func generateSessionID() string {
	return fmt.Sprintf("sess_%d", time.Now().UnixNano())
}

func generateSessionToken() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		// Fallback to time-based if crypto fails
		return fmt.Sprintf("tok_%d", time.Now().UnixNano())
	}
	return base64.URLEncoding.EncodeToString(b)
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.URLEncoding.EncodeToString(b)[:length]
}

// Config conversion helpers
func convertToSSOConfig(cfg *config.SSOConfig) *sso.SSOConfig {
	var samlCfg *sso.SAMLConfig
	if cfg.SAML.Enabled {
		samlCfg = &sso.SAMLConfig{
			Enabled:                 cfg.SAML.Enabled,
			IDPEntityID:             cfg.SAML.IDPEntityID,
			IDPSSOURL:               cfg.SAML.IDPSSOURL,
			IDPCertificate:          cfg.SAML.IDPCertificate,
			IDPCertificateRaw:       cfg.SAML.IDPCertificateRaw,
			SPEntityID:              cfg.SAML.SPEntityID,
			SPAssertionConsumerURL:  cfg.SAML.SPAssertionConsumerURL,
			SPPrivateKey:            cfg.SAML.SPPrivateKey,
			SPCertificate:           cfg.SAML.SPCertificate,
			NameIDFormat:            cfg.SAML.NameIDFormat,
			SignRequests:            cfg.SAML.SignRequests,
			RequireSignedResponse:   cfg.SAML.RequireSignedResponse,
			MaxClockSkew:            cfg.SAML.MaxClockSkew,
			UsernameAttribute:       cfg.SAML.UsernameAttribute,
			EmailAttribute:          cfg.SAML.EmailAttribute,
			GroupsAttribute:         cfg.SAML.GroupsAttribute,
		}
	}

	var oidcCfg *sso.OIDCConfig
	if cfg.OIDC.Enabled {
		oidcCfg = &sso.OIDCConfig{
			Enabled:         cfg.OIDC.Enabled,
			ProviderURL:     cfg.OIDC.ProviderURL,
			ClientID:        cfg.OIDC.ClientID,
			ClientSecret:    cfg.OIDC.ClientSecret,
			RedirectURL:     cfg.OIDC.RedirectURL,
			Scopes:          cfg.OIDC.Scopes,
			UsernameClai:    cfg.OIDC.UsernameClai, // Note: field name has typo
			EmailClaim:      cfg.OIDC.EmailClaim,
			GroupsClaim:     cfg.OIDC.GroupsClaim,
			VerifyIssuer:    cfg.OIDC.VerifyIssuer,
			MaxClockSkew:    cfg.OIDC.MaxClockSkew,
			InsecureSkipTLS: cfg.OIDC.InsecureSkipTLS,
		}
	}

	return &sso.SSOConfig{
		Enabled: cfg.Enabled,
		SAML:    samlCfg,
		OIDC:    oidcCfg,
	}
}

func convertToQRCodeConfig(cfg *config.QRCodeAuthConfig) *qrcode.QRCodeConfig {
	return &qrcode.QRCodeConfig{
		Enabled:         cfg.Enabled,
		TokenExpiry:     cfg.TokenExpiry,
		CleanupInterval: cfg.CleanupInterval,
		QRSize:          cfg.QRSize,
		BaseURL:         cfg.BaseURL,
	}
}

func convertToSMSConfig(cfg *config.SMSAuthConfig) *sms.SMSConfig {
	return &sms.SMSConfig{
		Enabled:          cfg.Enabled,
		Provider:         cfg.Provider,
		CodeLength:       cfg.CodeLength,
		CodeExpiry:       cfg.CodeExpiry,
		MaxAttempts:      cfg.MaxAttempts,
		RateLimitWindow:  cfg.RateLimitWindow,
		MaxPerWindow:     cfg.MaxPerWindow,
		TwilioAccountSID: cfg.TwilioAccountSID,
		TwilioAuthToken:  cfg.TwilioAuthToken,
		TwilioFromNumber: cfg.TwilioFromNumber,
		NexmoAPIKey:      cfg.NexmoAPIKey,
		NexmoAPISecret:   cfg.NexmoAPISecret,
		NexmoFromName:    cfg.NexmoFromName,
	}
}

func convertToGuestConfig(cfg *config.GuestCodeConfig) *guest.GuestConfig {
	return &guest.GuestConfig{
		Enabled:          cfg.Enabled,
		CodeLength:       cfg.CodeLength,
		CodePrefix:       cfg.CodePrefix,
		DefaultDuration:  cfg.DefaultDuration,
		MaxConcurrent:    cfg.MaxConcurrent,
		CleanupInterval:  cfg.CleanupInterval,
		RequireApproval:  cfg.RequireApproval,
		AllowSelfService: cfg.AllowSelfService,
	}
}

func convertToRoleConfig(cfg *config.RoleManagementConfig) *roles.RoleConfig {
	return &roles.RoleConfig{
		Enabled:     cfg.Enabled,
		RolesDir:    cfg.RolesDir,
		DefaultRole: cfg.DefaultRole,
	}
}
