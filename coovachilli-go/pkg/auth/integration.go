package auth

import (
	"fmt"
	"net"
	"time"

	"coovachilli-go/pkg/config"
)

// CoreSession interface for network session integration
type CoreSession interface {
	Lock()
	Unlock()
	GetIP() net.IP
	GetMAC() net.HardwareAddr
	SetAuthenticated(bool)
	SetUsername(string)
	InitializeShaper(*config.Config)
	SetSessionParams(params SessionParams)
	GetSessionParams() SessionParams
}

// SessionParams represents network session parameters
type SessionParams struct {
	SessionTimeout   uint32
	IdleTimeout      uint32
	BandwidthMaxUp   uint64
	BandwidthMaxDown uint64
	MaxInputOctets   uint64
	MaxOutputOctets  uint64
	MaxTotalOctets   uint64
	InterimInterval  uint32
	FilterID         string
}

// ApplyRoleToNetworkSession applies role settings to a core network session
func (am *AuthenticationManager) ApplyRoleToNetworkSession(coreSession CoreSession, roleID string) error {
	if am.roleManager == nil {
		return fmt.Errorf("role manager not initialized")
	}

	role, err := am.roleManager.GetRole(roleID)
	if err != nil {
		return fmt.Errorf("failed to get role %s: %w", roleID, err)
	}

	// Build session params from role
	// Convert time.Duration to uint32 seconds for SessionTimeout
	var sessionTimeout uint32
	if role.MaxSessionDuration > 0 {
		sessionTimeout = uint32(role.MaxSessionDuration.Seconds())
	}

	params := SessionParams{
		SessionTimeout:   sessionTimeout,
		IdleTimeout:      0, // Not available in roles.Role
		BandwidthMaxDown: role.MaxBandwidthDown,
		BandwidthMaxUp:   role.MaxBandwidthUp,
		MaxInputOctets:   0, // Not available in roles.Role - use MaxDailyData if needed
		MaxOutputOctets:  0, // Not available in roles.Role
		MaxTotalOctets:   role.MaxDailyData, // Map daily data limit
		FilterID:         "", // Not available in roles.Role
	}

	// Apply to network session
	coreSession.Lock()
	coreSession.SetSessionParams(params)
	coreSession.Unlock()

	am.logger.Info().
		Str("role_id", roleID).
		Str("role_name", role.Name).
		Uint64("bandwidth_down", role.MaxBandwidthDown).
		Uint64("bandwidth_up", role.MaxBandwidthUp).
		Uint32("session_timeout", sessionTimeout).
		Msg("Role applied to network session")

	return nil
}

// NotifyNetworkSessionAuthenticated is called when a network session is authenticated
// This synchronizes the auth.AuthSession with the core.Session
func (am *AuthenticationManager) NotifyNetworkSessionAuthenticated(
	coreSession CoreSession,
	username string,
	method AuthMethod,
) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Find or create auth session
	var authSession *AuthSession
	for _, session := range am.sessions {
		if session.Username == username && session.IPAddress.Equal(coreSession.GetIP()) {
			authSession = session
			break
		}
	}

	if authSession == nil {
		// Create new auth session
		authSession = &AuthSession{
			ID:           generateSessionID(),
			Username:     username,
			Method:       method,
			CreatedAt:    time.Now(),
			ExpiresAt:    time.Now().Add(24 * time.Hour),
			LastActivity: time.Now(),
			IPAddress:    coreSession.GetIP(),
			MAC:          coreSession.GetMAC(),
			Attributes:   make(map[string]interface{}),
		}
		am.sessions[authSession.ID] = authSession
	}

	// Apply role if user has one
	if authSession.RoleID != "" {
		if err := am.ApplyRoleToNetworkSession(coreSession, authSession.RoleID); err != nil {
			am.logger.Warn().Err(err).
				Str("username", username).
				Str("role_id", authSession.RoleID).
				Msg("Failed to apply role to network session")
		}
	}

	return nil
}

// SyncSessionState synchronizes state between core and auth sessions
func (am *AuthenticationManager) SyncSessionState(coreSessionID string, authenticated bool) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Update all auth sessions for this core session
	for _, authSession := range am.sessions {
		// Match by core session ID (would need to store this)
		if authenticated {
			authSession.LastActivity = time.Now()
		}
	}
}
