package core

import (
	"time"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
)

// Disconnector defines the interface for disconnecting a session.
// This allows us to avoid circular dependencies.
type Disconnector interface {
	Disconnect(session *Session, reason string)
}

// Reaper periodically checks for expired sessions and disconnects them.
type Reaper struct {
	cfg          *config.Config
	sm           *SessionManager
	disconnecter Disconnector
	logger       zerolog.Logger
	ticker       *time.Ticker
	quit         chan struct{}
}

// NewReaper creates a new session reaper.
func NewReaper(cfg *config.Config, sm *SessionManager, disconnecter Disconnector, logger zerolog.Logger) *Reaper {
	return &Reaper{
		cfg:          cfg,
		sm:           sm,
		disconnecter: disconnecter,
		logger:       logger.With().Str("component", "reaper").Logger(),
		quit:         make(chan struct{}),
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
		sessionTimeout := session.SessionParams.SessionTimeout
		idleTimeout := session.SessionParams.IdleTimeout
		startTime := session.StartTimeSec
		lastActivityTime := session.LastActivityTimeSec
		session.RUnlock()

		// Check session timeout
		if sessionTimeout > 0 {
			sessionDuration := now - startTime
			if sessionDuration >= sessionTimeout {
				r.logger.Info().Str("session_id", session.ChilliSessionID).Str("mac", session.HisMAC.String()).Msg("Session timeout reached")
				r.disconnecter.Disconnect(session, "Session-Timeout")
				continue // Move to the next session
			}
		}

		// Check idle timeout
		if idleTimeout > 0 {
			idleDuration := now - lastActivityTime
			if idleDuration >= idleTimeout {
				r.logger.Info().Str("session_id", session.ChilliSessionID).Str("mac", session.HisMAC.String()).Msg("Idle timeout reached")
				r.disconnecter.Disconnect(session, "Idle-Timeout")
				continue // Move to the next session
			}
		}
	}
}