package core

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Session holds the state for a single client session.
type Session struct {
	sync.RWMutex

	// Client identifiers
	HisIP   net.IP
	HisIPv6 net.IP
	HisMAC  net.HardwareAddr

	// Session state
	Authenticated bool
	StartTime     time.Time
	LastSeen      time.Time
	LastUpTime    time.Time
	SessionID     string
	ChilliSessionID string

	// RADIUS parameters
	SessionParams SessionParams

	// Accounting data
	InputOctets   uint64
	OutputOctets  uint64
	InputPackets  uint64
	OutputPackets uint64

	// UAM/Redir state
	Redir RedirState

	// AuthResult is used to signal the result of an authentication attempt.
	AuthResult chan bool
}

// SessionParams holds RADIUS-provisioned session parameters.
type SessionParams struct {
	SessionTimeout   uint32
	IdleTimeout      uint32
	BandwidthMaxUp   uint64
	BandwidthMaxDown uint64
	MaxInputOctets   uint64
	MaxOutputOctets  uint64
	MaxTotalOctets   uint64
	InterimInterval  uint32
	URL              string
	FilterID         string
}

// RedirState holds state related to the UAM/redirection process.
type RedirState struct {
	Username string
	Password string
	Challenge []byte
	UserURL  string
	State    []byte
	Class    []byte
	CUI      []byte
}

// SessionManager manages all active sessions.
type SessionManager struct {
	sync.RWMutex
	sessionsByIPv4 map[string]*Session
	sessionsByIPv6 map[string]*Session
	sessionsByMAC  map[string]*Session
}

// NewSessionManager creates a new SessionManager.
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessionsByIPv4: make(map[string]*Session),
		sessionsByIPv6: make(map[string]*Session),
		sessionsByMAC:  make(map[string]*Session),
	}
}

// CreateSession creates a new session for a client.
func (sm *SessionManager) CreateSession(ip net.IP, mac net.HardwareAddr) *Session {
	sm.Lock()
	defer sm.Unlock()

	session := &Session{
		HisIP:      ip,
		HisMAC:     mac,
		StartTime:  time.Now(),
		LastSeen:   time.Now(),
		AuthResult: make(chan bool, 1),
	}

	if ip.To4() != nil {
		sm.sessionsByIPv4[ip.String()] = session
	} else {
		sm.sessionsByIPv6[ip.String()] = session
	}
	sm.sessionsByMAC[mac.String()] = session

	return session
}

// GetSessionByIP returns a session by IP address.
func (sm *SessionManager) GetSessionByIP(ip net.IP) (*Session, bool) {
	sm.RLock()
	defer sm.RUnlock()

	var session *Session
	var ok bool
	if ip.To4() != nil {
		session, ok = sm.sessionsByIPv4[ip.String()]
	} else {
		session, ok = sm.sessionsByIPv6[ip.String()]
	}
	return session, ok
}

// GetSessionByMAC returns a session by MAC address.
func (sm *SessionManager) GetSessionByMAC(mac net.HardwareAddr) (*Session, bool) {
	sm.RLock()
	defer sm.RUnlock()

	session, ok := sm.sessionsByMAC[mac.String()]
	return session, ok
}

// DeleteSession deletes a session.
func (sm *SessionManager) DeleteSession(session *Session) {
	sm.Lock()
	defer sm.Unlock()

	if session.HisIP != nil {
		if session.HisIP.To4() != nil {
			delete(sm.sessionsByIPv4, session.HisIP.String())
		} else {
			delete(sm.sessionsByIPv6, session.HisIP.String())
		}
	}
	if session.HisMAC != nil {
		delete(sm.sessionsByMAC, session.HisMAC.String())
	}
}

// GetAllSessions returns all active sessions.
func (sm *SessionManager) GetAllSessions() []*Session {
	sm.RLock()
	defer sm.RUnlock()
	sessions := make([]*Session, 0, len(sm.sessionsByIPv4)+len(sm.sessionsByIPv6))
	for _, s := range sm.sessionsByIPv4 {
		sessions = append(sessions, s)
	}
	for _, s := range sm.sessionsByIPv6 {
		sessions = append(sessions, s)
	}
	return sessions
}
