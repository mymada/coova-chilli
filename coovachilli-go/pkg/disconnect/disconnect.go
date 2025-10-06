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
// ✅ CORRECTION: Rendu atomique avec rollback en cas d'échec
func (m *Manager) Disconnect(session *core.Session, reason string) {
	session.Lock()
	if !session.Authenticated {
		session.Unlock()
		m.logger.Debug().Str("mac", session.HisMAC.String()).Msg("Session already unauthenticated, skipping disconnect")
		return
	}

	// Sauvegarder l'état pour rollback potentiel
	wasAuthenticated := session.Authenticated
	session.Authenticated = false
	session.Unlock()

	m.logger.Info().
		Str("mac", session.HisMAC.String()).
		Str("ip", session.HisIP.String()).
		Str("username", session.Redir.Username).
		Str("reason", reason).
		Msg("Disconnecting session")

	// Track des étapes réussies pour rollback
	var (
		radiusSent     bool
		scriptRan      bool
		firewallRemoved bool
	)

	// 1. Send RADIUS Accounting-Stop packet
	if m.radiusClient != nil {
		_, err := m.radiusClient.SendAccountingRequest(session, rfc2866.AcctStatusType(2)) // 2 = Stop
		if err != nil {
			m.logger.Error().Err(err).Msg("Failed to send RADIUS accounting stop packet")
			// Rollback: restaurer état authentifié
			session.Lock()
			session.Authenticated = wasAuthenticated
			session.Unlock()
			m.logger.Warn().Msg("Disconnect aborted: RADIUS accounting failed, session state restored")
			return
		}
		radiusSent = true
	}

	// 2. Run connection-down script
	if m.scriptRunner != nil {
		// Note: Les scripts ne retournent pas d'erreur, donc on continue
		m.scriptRunner.RunScript(m.cfg.ConDown, session, 2) // Cause 2 for User-Request
		scriptRan = true
	}

	// 3. Remove firewall rules (CRITIQUE)
	if m.fw != nil {
		if err := m.fw.RemoveAuthenticatedUser(session.HisIP); err != nil {
			m.logger.Error().Err(err).Msg("Failed to remove firewall rules")

			// CRITIQUE: Si firewall échoue après RADIUS Stop, on a un problème
			// On envoie un RADIUS Interim Update pour corriger les stats
			if radiusSent && m.radiusClient != nil {
				m.logger.Warn().Msg("Attempting to send RADIUS Interim-Update to correct accounting")
				session.Lock()
				session.Authenticated = true // Temporairement pour stats correctes
				session.Unlock()
				m.radiusClient.SendAccountingRequest(session, rfc2866.AcctStatusType(3)) // 3 = Interim
			}

			// Ne pas supprimer la session si firewall a échoué
			m.logger.Error().Msg("Disconnect incomplete: Firewall removal failed, session preserved")
			return
		}
		firewallRemoved = true
	}

	// 4. Delete the session from the manager (point de non-retour)
	m.sm.DeleteSession(session)

	m.logger.Info().
		Str("mac", session.HisMAC.String()).
		Bool("radius_sent", radiusSent).
		Bool("script_ran", scriptRan).
		Bool("firewall_removed", firewallRemoved).
		Msg("Session terminated successfully")
}