package disconnect

import (
	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/firewall"
	"coovachilli-go/pkg/radius"
	"coovachilli-go/pkg/script"
	"github.com/rs/zerolog"
	"layeh.com/radius/rfc2866"
)

// Manager handles the logic for disconnecting a user session.
type Manager struct {
	cfg          *config.Config
	sm           *core.SessionManager
	fw           firewall.FirewallManager
	radiusClient radius.AccountingSender
	scriptRunner *script.Runner
	logger       zerolog.Logger
}

// NewManager creates a new disconnection manager.
func NewManager(cfg *config.Config, sm *core.SessionManager, fw firewall.FirewallManager, radiusClient radius.AccountingSender, scriptRunner *script.Runner, logger zerolog.Logger) *Manager {
	return &Manager{
		cfg:          cfg,
		sm:           sm,
		fw:           fw,
		radiusClient: radiusClient,
		scriptRunner: scriptRunner,
		logger:       logger.With().Str("component", "disconnect").Logger(),
	}
}

// Disconnect performs all the necessary steps to terminate a user's session.
func (m *Manager) Disconnect(session *core.Session, reason string) {
	session.Lock()
	if !session.Authenticated {
		session.Unlock()
		m.logger.Debug().Str("mac", session.HisMAC.String()).Msg("Session already unauthenticated, skipping disconnect")
		return
	}
	session.Authenticated = false
	session.Unlock()

	m.logger.Info().
		Str("mac", session.HisMAC.String()).
		Str("ip", session.HisIP.String()).
		Str("username", session.Redir.Username).
		Str("reason", reason).
		Msg("Disconnecting session")

	// 1. Send RADIUS Accounting-Stop packet
	if m.radiusClient != nil {
		_, err := m.radiusClient.SendAccountingRequest(session, rfc2866.AcctStatusType(2)) // 2 = Stop
		if err != nil {
			m.logger.Error().Err(err).Msg("Failed to send RADIUS accounting stop packet")
		}
	}

	// 2. Run connection-down script
	if m.scriptRunner != nil {
		// The original `RunConDown` was likely a wrapper. We call RunScript directly.
		// A more robust implementation would map the string reason to a cause code.
		m.scriptRunner.RunScript(m.cfg.ConDown, session, 2) // Cause 2 for User-Request
	}

	// 3. Remove firewall rules
	if m.fw != nil {
		if err := m.fw.RemoveAuthenticatedUser(session.HisIP); err != nil {
			m.logger.Error().Err(err).Msg("Failed to remove firewall rules")
		}
	}

	// 4. Delete the session from the manager
	m.sm.DeleteSession(session)

	m.logger.Info().Str("mac", session.HisMAC.String()).Msg("Session terminated successfully")
}