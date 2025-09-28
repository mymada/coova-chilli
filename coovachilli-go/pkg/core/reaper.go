package core

import (
	"time"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
	"layeh.com/radius/rfc2866"
)

// Disconnector defines the interface for disconnecting a session.
// This allows us to avoid circular dependencies.
type Disconnector interface {
	Disconnect(session *Session, reason string)
}

// AccountingSender defines an interface for sending accounting packets.
type AccountingSender interface {
	SendAccountingRequest(session *Session, statusType rfc2866.AcctStatusType, reason string)
}

// Reaper periodically checks for expired sessions and disconnects them.
type Reaper struct {
	cfg              *config.Config
	sm               *SessionManager
	disconnecter     Disconnector
	accountingSender AccountingSender
	logger           zerolog.Logger
	ticker           *time.Ticker
	quit             chan struct{}
}

// NewReaper creates a new session reaper.
func NewReaper(cfg *config.Config, sm *SessionManager, disconnecter Disconnector, accountingSender AccountingSender, logger zerolog.Logger) *Reaper {
	return &Reaper{
		cfg:              cfg,
		sm:               sm,
		disconnecter:     disconnecter,
		accountingSender: accountingSender,
		logger:           logger.With().Str("component", "reaper").Logger(),
		quit:             make(chan struct{}),
	}
}

// Start begins the reaping process in a background goroutine.
func (r *Reaper) Start() {
	// Use the main interval from config, or a default of 60s if not set
	interval := r.cfg.Interval
	if interval == 0 {
		interval = 60 * time.Second
	}
	r.ticker = time.NewTicker(interval)
	go r.run()
	r.logger.Info().Str("interval", interval.String()).Msg("Session reaper started")
}

// Stop terminates the reaping process.
func (r *Reaper) Stop() {
	if r.ticker != nil {
		r.ticker.Stop()
	}
	close(r.quit)
	r.logger.Info().Msg("Session reaper stopped")
}

func (r *Reaper) run() {
	for {
		select {
		case <-r.ticker.C:
			r.reapSessions()
		case <-r.quit:
			return
		}
	}
}

func (r *Reaper) reapSessions() {
	sessions := r.sm.GetAllSessions()
	now := MonotonicTime()
	r.logger.Debug().Int("count", len(sessions)).Msg("Reaping sessions")

	for _, session := range sessions {
		if !session.Authenticated {
			continue
		}

		session.RLock()
		// Copy all necessary params under read lock
		p := session.SessionParams
		inputOctets := session.InputOctets
		outputOctets := session.OutputOctets
		startTime := session.StartTimeSec
		lastActivityTime := session.LastActivityTimeSec
		lastInterimUpdateTime := session.LastInterimUpdateTime
		session.RUnlock()

		// Check session timeout
		if p.SessionTimeout > 0 {
			if (now - startTime) >= p.SessionTimeout {
				r.logger.Info().Str("user", session.Redir.Username).Str("ip", session.HisIP.String()).Msg("Session timeout reached")
				r.disconnecter.Disconnect(session, "Session-Timeout")
				continue // Disconnected, move to next session
			}
		}

		// Check idle timeout
		if p.IdleTimeout > 0 {
			if (now - lastActivityTime) >= p.IdleTimeout {
				r.logger.Info().Str("user", session.Redir.Username).Str("ip", session.HisIP.String()).Msg("Idle timeout reached")
				r.disconnecter.Disconnect(session, "Idle-Timeout")
				continue // Disconnected, move to next session
			}
		}

		// Check data quotas
		if p.MaxTotalOctets > 0 && (inputOctets+outputOctets) >= p.MaxTotalOctets {
			r.logger.Info().Str("user", session.Redir.Username).Str("ip", session.HisIP.String()).Msg("Total data quota reached")
			r.disconnecter.Disconnect(session, "Data-Limit-Reached")
			continue
		}
		if p.MaxInputOctets > 0 && inputOctets >= p.MaxInputOctets {
			r.logger.Info().Str("user", session.Redir.Username).Str("ip", session.HisIP.String()).Msg("Input data quota reached")
			r.disconnecter.Disconnect(session, "Data-Limit-Reached")
			continue
		}
		if p.MaxOutputOctets > 0 && outputOctets >= p.MaxOutputOctets {
			r.logger.Info().Str("user", session.Redir.Username).Str("ip", session.HisIP.String()).Msg("Output data quota reached")
			r.disconnecter.Disconnect(session, "Data-Limit-Reached")
			continue
		}

		// Check for interim accounting update
		if p.InterimInterval > 0 {
			if (now - lastInterimUpdateTime) >= p.InterimInterval {
				r.logger.Debug().Str("user", session.Redir.Username).Str("ip", session.HisIP.String()).Msg("Sending interim accounting update")
				// Use integer value 3 for Interim-Update as the named constant is not available in this library version.
				r.accountingSender.SendAccountingRequest(session, rfc2866.AcctStatusType(3), "Interim-Update")
				session.Lock()
				session.LastInterimUpdateTime = now
				session.Unlock()
			}
		}
	}
}