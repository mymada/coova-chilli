package sso

import (
	"net"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
)

// CoreSessionAdapter wraps core.Session to implement CoreSession interface
type CoreSessionAdapter struct {
	session *core.Session
}

// NewCoreSessionAdapter creates a new adapter
func NewCoreSessionAdapter(session *core.Session) *CoreSessionAdapter {
	return &CoreSessionAdapter{session: session}
}

// Lock locks the session
func (a *CoreSessionAdapter) Lock() {
	a.session.Lock()
}

// Unlock unlocks the session
func (a *CoreSessionAdapter) Unlock() {
	a.session.Unlock()
}

// GetIP returns the client IP
func (a *CoreSessionAdapter) GetIP() net.IP {
	return a.session.HisIP
}

// GetMAC returns the client MAC
func (a *CoreSessionAdapter) GetMAC() net.HardwareAddr {
	return a.session.HisMAC
}

// SetAuthenticated sets authentication status
func (a *CoreSessionAdapter) SetAuthenticated(authenticated bool) {
	a.session.Authenticated = authenticated
}

// SetUsername sets the username
func (a *CoreSessionAdapter) SetUsername(username string) {
	a.session.Redir.Username = username
}

// InitializeShaper initializes bandwidth shaper
func (a *CoreSessionAdapter) InitializeShaper(cfg *config.Config) {
	a.session.InitializeShaper(cfg)
}

// GetRawSession returns the underlying core.Session for RADIUS accounting
func (a *CoreSessionAdapter) GetRawSession() *core.Session {
	return a.session
}

// SessionManagerAdapter wraps core.SessionManager
type SessionManagerAdapter struct {
	sm *core.SessionManager
}

// NewSessionManagerAdapter creates a new adapter
func NewSessionManagerAdapter(sm *core.SessionManager) *SessionManagerAdapter {
	return &SessionManagerAdapter{sm: sm}
}

// GetSessionByIP retrieves session by IP address
func (a *SessionManagerAdapter) GetSessionByIP(ip net.IP) (CoreSession, bool) {
	session, ok := a.sm.GetSessionByIP(ip)
	if !ok {
		return nil, false
	}
	return NewCoreSessionAdapter(session), true
}
