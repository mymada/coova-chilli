package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sync"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/metrics"
)

var StartTime = time.Now()

// MonotonicTime returns a uint32 representing the number of seconds since the process started.
func MonotonicTime() uint32 {
	return uint32(time.Since(StartTime).Seconds())
}

// EAPOLState holds state related to the 802.1X/EAPOL process.
type EAPOLState struct {
	HandshakeState string `json:"-"` // Not for persistence
	PMK            []byte `json:"-"` // Pairwise Master Key, not for persistence
	PTK            []byte `json:"-"` // Pairwise Transient Key, not for persistence
	ANonce         []byte `json:"-"` // Authenticator Nonce, not for persistence
	SNonce         []byte `json:"-"` // Supplicant Nonce, not for persistence
	EapID          uint8  `json:"-"` // Last EAP identifier used
	ReplayCounter  uint64 `json:"-"` // EAPOL-Key Replay Counter
}

// Session holds the state for a single client session.
type Session struct {
	sync.RWMutex

	// Client identifiers
	HisIP  net.IP
	HisMAC net.HardwareAddr
	VLANID uint16

	// Session state
	Authenticated       bool
	StartTime           time.Time
	LastSeen            time.Time
	LastUpTime          time.Time
	SessionID           string
	ChilliSessionID     string
	StartTimeSec        uint32 `json:"-"` // Monotonic time, not for persistence
	LastActivityTimeSec uint32 `json:"-"` // Monotonic time, not for persistence

	// RADIUS parameters
	SessionParams SessionParams

	// Accounting data
	InputOctets   uint64
	OutputOctets  uint64
	InputPackets  uint64
	OutputPackets uint64

	// Leaky Bucket for Bandwidth Shaping
	BucketUp       uint64
	BucketDown     uint64
	BucketUpSize   uint64
	BucketDownSize uint64
	LastBWTime     time.Time

	// UAM/Redir state
	Redir RedirState

	// AuthResult is used to signal the result of an authentication attempt.
	AuthResult chan bool

	// Token is a secure token for cookie-based auto-login.
	Token string

	// EAPOL state
	EAPOL EAPOLState
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
	State            []byte
	Class            []byte
	CUI              []byte
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
	sessionsByIPv4  map[string]*Session
	sessionsByIPv6  map[string]*Session
	sessionsByMAC   map[string]*Session
	sessionsByToken map[string]*Session
	recorder        metrics.Recorder
	cfg             *config.Config
}

// NewSessionManager creates a new SessionManager.
func NewSessionManager(cfg *config.Config, recorder metrics.Recorder) *SessionManager {
	if recorder == nil {
		recorder = metrics.NewNoopRecorder()
	}
	return &SessionManager{
		sessionsByIPv4:  make(map[string]*Session),
		sessionsByIPv6:  make(map[string]*Session),
		sessionsByMAC:   make(map[string]*Session),
		sessionsByToken: make(map[string]*Session),
		recorder:        recorder,
		cfg:             cfg,
	}
}

// StateData is the container for serializing persistent state.
type StateData struct {
	SaveTime uint32    `json:"save_time"`
	Sessions []*Session `json:"sessions"`
}

// CreateSession creates a new session for a client.
func (sm *SessionManager) CreateSession(ip net.IP, mac net.HardwareAddr, vlanID uint16) *Session {
	sm.Lock()
	defer sm.Unlock()

	now := MonotonicTime()
	session := &Session{
		HisIP:               ip,
		HisMAC:              mac,
		VLANID:              vlanID,
		StartTime:           time.Now(),
		LastSeen:            time.Now(),
		AuthResult:          make(chan bool, 1),
		StartTimeSec:        now,
		LastActivityTimeSec: now,
		SessionParams: SessionParams{
			SessionTimeout:   sm.cfg.DefSessionTimeout,
			IdleTimeout:      sm.cfg.DefIdleTimeout,
			BandwidthMaxDown: sm.cfg.DefBandwidthMaxDown,
			BandwidthMaxUp:   sm.cfg.DefBandwidthMaxUp,
		},
	}

	if ip.To4() != nil {
		sm.sessionsByIPv4[ip.String()] = session
	} else {
		sm.sessionsByIPv6[ip.String()] = session
	}
	sm.sessionsByMAC[mac.String()] = session

	sm.recorder.IncGauge("chilli_sessions_active_total", nil)

	return session
}

// GetSessionByIPs determines if an IP pair belongs to a session, returning the session and whether it's uplink.
func (sm *SessionManager) GetSessionByIPs(srcIP, dstIP net.IP) (*Session, bool) {
	sm.RLock()
	defer sm.RUnlock()

	if srcIP.To4() != nil {
		if session, ok := sm.sessionsByIPv4[srcIP.String()]; ok {
			return session, true // Uplink
		}
		if session, ok := sm.sessionsByIPv4[dstIP.String()]; ok {
			return session, false // Downlink
		}
	} else {
		if session, ok := sm.sessionsByIPv6[srcIP.String()]; ok {
			return session, true // Uplink
		}
		if session, ok := sm.sessionsByIPv6[dstIP.String()]; ok {
			return session, false // Downlink
		}
	}

	return nil, false
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

// GetSessionByToken returns a session by its auth token.
func (sm *SessionManager) GetSessionByToken(token string) (*Session, bool) {
	sm.RLock()
	defer sm.RUnlock()

	session, ok := sm.sessionsByToken[token]
	return session, ok
}

// AssociateToken adds the session to the token lookup map.
func (sm *SessionManager) AssociateToken(session *Session) {
	sm.Lock()
	defer sm.Unlock()
	if session.Token != "" {
		sm.sessionsByToken[session.Token] = session
	}
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
	if session.Token != "" {
		delete(sm.sessionsByToken, session.Token)
	}
	sm.recorder.DecGauge("chilli_sessions_active_total", nil)
}

// Reconfigure updates the configuration for the SessionManager.
func (sm *SessionManager) Reconfigure(newConfig *config.Config) error {
	sm.Lock()
	defer sm.Unlock()
	sm.cfg = newConfig
	return nil
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

// SaveSessions serializes all active, authenticated sessions to a file.
func (sm *SessionManager) SaveSessions(path string) error {
	sm.RLock()
	defer sm.RUnlock()

	if path == "" {
		return nil // Nothing to do if no path is configured
	}

	var sessionsToSave []*Session
	for _, s := range sm.sessionsByMAC {
		if s.Authenticated {
			sessionsToSave = append(sessionsToSave, s)
		}
	}

	if len(sessionsToSave) == 0 {
		return nil // Nothing to save
	}

	state := StateData{
		SaveTime: MonotonicTime(),
		Sessions: sessionsToSave,
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sessions: %w", err)
	}

	return ioutil.WriteFile(path, data, 0644)
}

// LoadSessions loads sessions from a file, adjusting for downtime.
func (sm *SessionManager) LoadSessions(path string) error {
	sm.Lock()
	defer sm.Unlock()

	if path == "" {
		return nil
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // State file doesn't exist, which is fine on first start
		}
		return fmt.Errorf("failed to read state file: %w", err)
	}

	var state StateData
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("failed to unmarshal state file: %w", err)
	}

	downtime := MonotonicTime() - state.SaveTime

	for _, s := range state.Sessions {
		// Adjust timeouts
		if s.SessionParams.SessionTimeout > 0 {
			if s.SessionParams.SessionTimeout > downtime {
				s.SessionParams.SessionTimeout -= downtime
			} else {
				continue // Session expired while daemon was down
			}
		}
		if s.SessionParams.IdleTimeout > 0 {
			if s.SessionParams.IdleTimeout > downtime {
				s.SessionParams.IdleTimeout -= downtime
			} else {
				continue // Session expired while daemon was down
			}
		}

		// Restore monotonic timestamps relative to the new process start
		s.StartTimeSec = MonotonicTime() - uint32(time.Since(s.StartTime).Seconds())
		s.LastActivityTimeSec = MonotonicTime() - uint32(time.Since(s.LastSeen).Seconds())

		// Re-populate the session manager's maps
		if s.HisIP != nil {
			if s.HisIP.To4() != nil {
				sm.sessionsByIPv4[s.HisIP.String()] = s
			} else {
				sm.sessionsByIPv6[s.HisIP.String()] = s
			}
		}
		if s.HisMAC != nil {
			sm.sessionsByMAC[s.HisMAC.String()] = s
		}
		if s.Token != "" {
			sm.sessionsByToken[s.Token] = s
		}
	}

	return nil
}