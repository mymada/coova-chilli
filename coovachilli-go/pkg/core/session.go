package core

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	StateMachine        *SessionStateMachine `json:"-"` // ✅ State machine for transitions
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

	// Advanced shaping and QoS
	ShaperStats     *ShaperStats
	TrafficClasses  map[QoSClass]TrafficClass
	RequestAuthenticator []byte `json:"-"` // For EAP key derivation

	// UAM/Redir state
	Redir RedirState

	// AuthResult is used to signal the result of an authentication attempt.
	AuthResult chan bool

	// Token is a secure token for cookie-based auto-login.
	Token string

	// FASNonce is a unique nonce to prevent FAS token replay attacks
	FASNonce string

	// EAPOL state
	EAPOL EAPOLState

	// EAP session state for advanced authentication
	EAPSession interface{} `json:"-"`
}

// GetIP returns the client IP address
func (s *Session) GetIP() net.IP {
	return s.HisIP
}

// GetMAC returns the client MAC address
func (s *Session) GetMAC() net.HardwareAddr {
	return s.HisMAC
}

// SetAuthenticated sets the authentication status
func (s *Session) SetAuthenticated(authenticated bool) {
	s.Authenticated = authenticated
}

// SetUsername sets the username in redir state
func (s *Session) SetUsername(username string) {
	s.Redir.Username = username
}

// SetSessionParams sets the session parameters (for role application)
func (s *Session) SetSessionParams(params interface{}) {
	// Type assertion to handle auth.SessionParams
	if authParams, ok := params.(struct {
		SessionTimeout   uint32
		IdleTimeout      uint32
		BandwidthMaxUp   uint64
		BandwidthMaxDown uint64
		MaxInputOctets   uint64
		MaxOutputOctets  uint64
		MaxTotalOctets   uint64
		InterimInterval  uint32
		FilterID         string
	}); ok {
		s.SessionParams.SessionTimeout = authParams.SessionTimeout
		s.SessionParams.IdleTimeout = authParams.IdleTimeout
		s.SessionParams.BandwidthMaxUp = authParams.BandwidthMaxUp
		s.SessionParams.BandwidthMaxDown = authParams.BandwidthMaxDown
		s.SessionParams.MaxInputOctets = authParams.MaxInputOctets
		s.SessionParams.MaxOutputOctets = authParams.MaxOutputOctets
		s.SessionParams.MaxTotalOctets = authParams.MaxTotalOctets
		s.SessionParams.InterimInterval = authParams.InterimInterval
		s.SessionParams.FilterID = authParams.FilterID
	}
}

// GetSessionParams returns current session parameters
func (s *Session) GetSessionParams() interface{} {
	return struct {
		SessionTimeout   uint32
		IdleTimeout      uint32
		BandwidthMaxUp   uint64
		BandwidthMaxDown uint64
		MaxInputOctets   uint64
		MaxOutputOctets  uint64
		MaxTotalOctets   uint64
		InterimInterval  uint32
		FilterID         string
	}{
		SessionTimeout:   s.SessionParams.SessionTimeout,
		IdleTimeout:      s.SessionParams.IdleTimeout,
		BandwidthMaxUp:   s.SessionParams.BandwidthMaxUp,
		BandwidthMaxDown: s.SessionParams.BandwidthMaxDown,
		MaxInputOctets:   s.SessionParams.MaxInputOctets,
		MaxOutputOctets:  s.SessionParams.MaxOutputOctets,
		MaxTotalOctets:   s.SessionParams.MaxTotalOctets,
		InterimInterval:  s.SessionParams.InterimInterval,
		FilterID:         s.SessionParams.FilterID,
	}
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

const (
	// MaxSessions is the maximum number of sessions allowed
	MaxSessions = 10000
)

// SessionHooks defines callbacks for session lifecycle events
type SessionHooks struct {
	OnIPUp   func(*Session)
	OnIPDown func(*Session)
}

// SessionManager manages all active sessions.
type SessionManager struct {
	// ✅ OPTIMIZATION: Use sync.Map for lock-free reads
	sessionsByIPv4  sync.Map // map[string]*Session
	sessionsByIPv6  sync.Map // map[string]*Session
	sessionsByMAC   sync.Map // map[string]*Session
	recorder        metrics.Recorder
	cfg             *config.Config
	sessionCountMu  sync.Mutex
	sessionCount    int // Track total sessions
	hooks           SessionHooks

	// ✅ Token manager is handled externally now
}

// NewSessionManager creates a new SessionManager.
func NewSessionManager(cfg *config.Config, recorder metrics.Recorder) *SessionManager {
	if recorder == nil {
		recorder = metrics.NewNoopRecorder()
	}
	// ✅ OPTIMIZATION: sync.Map is initialized empty
	return &SessionManager{
		recorder:        recorder,
		cfg:             cfg,
	}
}

// SetHooks sets the session lifecycle hooks
func (sm *SessionManager) SetHooks(hooks SessionHooks) {
	sm.sessionCountMu.Lock()
	defer sm.sessionCountMu.Unlock()
	sm.hooks = hooks
}


// StateData is the container for serializing persistent state.
type StateData struct {
	SaveTime uint32    `json:"save_time"`
	Sessions []*Session `json:"sessions"`
}

// CreateSession creates a new session for a client.
func (sm *SessionManager) CreateSession(ip net.IP, mac net.HardwareAddr, vlanID uint16) *Session {
	// ✅ OPTIMIZATION: Check session limit with minimal locking
	sm.sessionCountMu.Lock()
	if sm.sessionCount >= MaxSessions {
		sm.sessionCountMu.Unlock()
		return nil // Session limit reached
	}
	sm.sessionCount++
	sm.sessionCountMu.Unlock()

	now := MonotonicTime()

	// Generate unique FAS nonce for this session
	fasNonce := generateSecureNonce()

	session := &Session{
		HisIP:               ip,
		HisMAC:              mac,
		VLANID:              vlanID,
		StateMachine:        NewSessionStateMachine(), // ✅ Initialize state machine
		StartTime:           time.Now(),
		LastSeen:            time.Now(),
		AuthResult:          make(chan bool, 1),
		StartTimeSec:        now,
		LastActivityTimeSec: now,
		FASNonce:            fasNonce, // ✅ SECURITY: Unique nonce per session
		SessionParams: SessionParams{
			SessionTimeout:   sm.cfg.DefSessionTimeout,
			IdleTimeout:      sm.cfg.DefIdleTimeout,
			BandwidthMaxDown: sm.cfg.DefBandwidthMaxDown,
			BandwidthMaxUp:   sm.cfg.DefBandwidthMaxUp,
		},
	}

	// ✅ OPTIMIZATION: Lock-free writes with sync.Map
	if ip != nil {
		if ip.To4() != nil {
			sm.sessionsByIPv4.Store(ip.String(), session)
		} else {
			sm.sessionsByIPv6.Store(ip.String(), session)
		}
	}
	if mac != nil {
		sm.sessionsByMAC.Store(mac.String(), session)
	}

	sm.recorder.IncGauge("chilli_sessions_active_total", nil)

	// Call ipup hook if configured
	sm.sessionCountMu.Lock()
	onIPUp := sm.hooks.OnIPUp
	sm.sessionCountMu.Unlock()

	if onIPUp != nil {
		go onIPUp(session)
	}

	return session
}

// GetSessionByIPs determines if an IP pair belongs to a session, returning the session and whether it's uplink.
func (sm *SessionManager) GetSessionByIPs(srcIP, dstIP net.IP) (*Session, bool) {
	// ✅ OPTIMIZATION: Lock-free reads with sync.Map
	if srcIP.To4() != nil {
		if val, ok := sm.sessionsByIPv4.Load(srcIP.String()); ok {
			return val.(*Session), true // Uplink
		}
		if val, ok := sm.sessionsByIPv4.Load(dstIP.String()); ok {
			return val.(*Session), false // Downlink
		}
	} else {
		if val, ok := sm.sessionsByIPv6.Load(srcIP.String()); ok {
			return val.(*Session), true // Uplink
		}
		if val, ok := sm.sessionsByIPv6.Load(dstIP.String()); ok {
			return val.(*Session), false // Downlink
		}
	}

	return nil, false
}

// HasSessionByIP checks if a session exists for a given IP address.
func (sm *SessionManager) HasSessionByIP(ip net.IP) bool {
	// ✅ OPTIMIZATION: Lock-free reads
	var exists bool
	if ip.To4() != nil {
		_, exists = sm.sessionsByIPv4.Load(ip.String())
	} else {
		_, exists = sm.sessionsByIPv6.Load(ip.String())
	}
	return exists
}

// GetSessionByIP returns a session by IP address.
func (sm *SessionManager) GetSessionByIP(ip net.IP) (*Session, bool) {
	// ✅ OPTIMIZATION: Lock-free reads
	var val interface{}
	var ok bool
	if ip.To4() != nil {
		val, ok = sm.sessionsByIPv4.Load(ip.String())
	} else {
		val, ok = sm.sessionsByIPv6.Load(ip.String())
	}
	if !ok {
		return nil, false
	}
	return val.(*Session), true
}

// GetSessionByMAC returns a session by MAC address.
func (sm *SessionManager) GetSessionByMAC(mac net.HardwareAddr) (*Session, bool) {
	// ✅ OPTIMIZATION: Lock-free reads
	val, ok := sm.sessionsByMAC.Load(mac.String())
	if !ok {
		return nil, false
	}
	return val.(*Session), true
}

// GetSessionByToken is deprecated - use token.Manager instead
// Kept for backward compatibility, always returns false
func (sm *SessionManager) GetSessionByToken(token string) (*Session, bool) {
	return nil, false
}

// AssociateToken is deprecated - use token.Manager instead
// Kept for backward compatibility, does nothing
func (sm *SessionManager) AssociateToken(session *Session) {
	// No-op: Token management is external now
}

// DeleteSession deletes a session.
func (sm *SessionManager) DeleteSession(session *Session) {
	if session == nil {
		return
	}

	// Call ipdown hook before deleting session
	sm.sessionCountMu.Lock()
	ipdownHook := sm.hooks.OnIPDown
	sm.sessionCountMu.Unlock()

	if ipdownHook != nil {
		ipdownHook(session)
	}

	// ✅ OPTIMIZATION: Lock-free deletes with sync.Map
	if session.HisIP != nil {
		if session.HisIP.To4() != nil {
			sm.sessionsByIPv4.Delete(session.HisIP.String())
		} else {
			sm.sessionsByIPv6.Delete(session.HisIP.String())
		}
	}
	if session.HisMAC != nil {
		sm.sessionsByMAC.Delete(session.HisMAC.String())
	}

	sm.sessionCountMu.Lock()
	sm.sessionCount--
	sm.sessionCountMu.Unlock()

	sm.recorder.DecGauge("chilli_sessions_active_total", nil)

	// Close AuthResult channel to prevent goroutine leaks
	select {
	case <-session.AuthResult:
	default:
		close(session.AuthResult)
	}
}

// Reconfigure updates the configuration for the SessionManager.
func (sm *SessionManager) Reconfigure(newConfig *config.Config) error {
	sm.sessionCountMu.Lock()
	defer sm.sessionCountMu.Unlock()
	sm.cfg = newConfig
	return nil
}

// GetAllSessions returns all active sessions.
func (sm *SessionManager) GetAllSessions() []*Session {
	// ✅ OPTIMIZATION: Iterate sync.Map efficiently
	sessions := make([]*Session, 0, sm.sessionCount)
	sm.sessionsByIPv4.Range(func(key, value interface{}) bool {
		sessions = append(sessions, value.(*Session))
		return true
	})
	sm.sessionsByIPv6.Range(func(key, value interface{}) bool {
		sessions = append(sessions, value.(*Session))
		return true
	})
	return sessions
}

// SaveSessions serializes all active, authenticated sessions to a file.
func (sm *SessionManager) SaveSessions(path string) error {
	if path == "" {
		return nil // Nothing to do if no path is configured
	}

	var sessionsToSave []*Session
	sm.sessionsByMAC.Range(func(key, value interface{}) bool {
		s := value.(*Session)
		if s.Authenticated {
			sessionsToSave = append(sessionsToSave, s)
		}
		return true
	})

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

	return os.WriteFile(path, data, 0644)
}

// LoadSessions loads sessions from a file, adjusting for downtime.
func (sm *SessionManager) LoadSessions(path string) error {
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
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
				sm.sessionsByIPv4.Store(s.HisIP.String(), s)
			} else {
				sm.sessionsByIPv6.Store(s.HisIP.String(), s)
			}
		}
		if s.HisMAC != nil {
			sm.sessionsByMAC.Store(s.HisMAC.String(), s)
		}

		sm.sessionCountMu.Lock()
		sm.sessionCount++
		sm.sessionCountMu.Unlock()
	}

	return nil
}

// generateSecureNonce generates a cryptographically secure random nonce
func generateSecureNonce() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		// Fallback to timestamp-based if crypto fails (should never happen)
		return fmt.Sprintf("nonce_%d", time.Now().UnixNano())
	}
	return base64.URLEncoding.EncodeToString(b)
}