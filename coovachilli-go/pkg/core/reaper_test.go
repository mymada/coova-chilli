package core

import (
	"net"
	"testing"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"layeh.com/radius/rfc2866"
)

// mockDisconnector is a mock implementation of the Disconnector interface for testing.
type mockDisconnector struct {
	DisconnectedSessions map[string]string // Maps session MAC to disconnect reason
}

func (m *mockDisconnector) Disconnect(session *Session, reason string) {
	if m.DisconnectedSessions == nil {
		m.DisconnectedSessions = make(map[string]string)
	}
	m.DisconnectedSessions[session.HisMAC.String()] = reason
}

// mockAccountingSender is a mock implementation of the AccountingSender interface.
type mockAccountingSender struct {
	SentRequests []*Session
	LastStatus   rfc2866.AcctStatusType
}

func (m *mockAccountingSender) SendAccountingRequest(session *Session, statusType rfc2866.AcctStatusType, reason string) {
	if m.SentRequests == nil {
		m.SentRequests = make([]*Session, 0)
	}
	m.SentRequests = append(m.SentRequests, session)
	m.LastStatus = statusType
}

func TestReaper_Timeouts(t *testing.T) {
	// Setup
	sm := NewSessionManager()
	mockDc := &mockDisconnector{}
	mockAcct := &mockAccountingSender{}
	cfg := &config.Config{}
	logger := zerolog.Nop()

	reaper := NewReaper(cfg, sm, mockDc, mockAcct, logger)

	// --- Test Case 1: Session expired by Session-Timeout ---
	mac1, _ := net.ParseMAC("00:00:5e:00:53:01")
	session1 := sm.CreateSession(net.ParseIP("10.0.0.1"), mac1, 0, cfg)
	session1.Authenticated = true
	session1.SessionParams.SessionTimeout = 100 // seconds
	session1.StartTimeSec = MonotonicTime() - 101 // Started 101 seconds ago
	session1.LastActivityTimeSec = MonotonicTime() - 10 // Active recently

	// --- Test Case 2: Session expired by Idle-Timeout ---
	mac2, _ := net.ParseMAC("00:00:5e:00:53:02")
	session2 := sm.CreateSession(net.ParseIP("10.0.0.2"), mac2, 0, cfg)
	session2.Authenticated = true
	session2.SessionParams.IdleTimeout = 50 // seconds
	session2.StartTimeSec = MonotonicTime() - 1000 // Started long ago
	session2.LastActivityTimeSec = MonotonicTime() - 51 // Last seen 51 seconds ago

	// --- Test Case 3: Active session, should not be reaped ---
	mac3, _ := net.ParseMAC("00:00:5e:00:53:03")
	session3 := sm.CreateSession(net.ParseIP("10.0.0.3"), mac3, 0, cfg)
	session3.Authenticated = true
	session3.SessionParams.SessionTimeout = 1000
	session3.SessionParams.IdleTimeout = 500
	session3.StartTimeSec = MonotonicTime() - 100
	session3.LastActivityTimeSec = MonotonicTime() - 10

	// --- Test Case 4: Unauthenticated session, should not be reaped ---
	mac4, _ := net.ParseMAC("00:00:5e:00:53:04")
	_ = sm.CreateSession(net.ParseIP("10.0.0.4"), mac4, 0, cfg) // Not authenticated

	// Execute the reap function directly
	reaper.reapSessions()

	// Assertions
	require.Len(t, mockDc.DisconnectedSessions, 2, "Expected exactly 2 sessions to be disconnected")

	reason1, ok1 := mockDc.DisconnectedSessions[mac1.String()]
	require.True(t, ok1, "Session 1 should have been disconnected")
	require.Equal(t, "Session-Timeout", reason1, "Session 1 should be disconnected for Session-Timeout")

	reason2, ok2 := mockDc.DisconnectedSessions[mac2.String()]
	require.True(t, ok2, "Session 2 should have been disconnected")
	require.Equal(t, "Idle-Timeout", reason2, "Session 2 should be disconnected for Idle-Timeout")

	_, ok3 := mockDc.DisconnectedSessions[mac3.String()]
	require.False(t, ok3, "Active session 3 should not have been disconnected")
}

func TestReaper_QuotasAndAccounting(t *testing.T) {
	// Setup
	sm := NewSessionManager()
	mockDc := &mockDisconnector{}
	mockAcct := &mockAccountingSender{}
	cfg := &config.Config{}
	logger := zerolog.Nop()

	reaper := NewReaper(cfg, sm, mockDc, mockAcct, logger)

	// --- Test Case 1: Total data quota exceeded ---
	mac1, _ := net.ParseMAC("00:00:5e:00:53:11")
	session1 := sm.CreateSession(net.ParseIP("10.0.0.11"), mac1, 0, cfg)
	session1.Authenticated = true
	session1.SessionParams.MaxTotalOctets = 1000
	session1.InputOctets = 500
	session1.OutputOctets = 501 // Exceeded

	// --- Test Case 2: Interim accounting update needed ---
	mac2, _ := net.ParseMAC("00:00:5e:00:53:12")
	session2 := sm.CreateSession(net.ParseIP("10.0.0.12"), mac2, 0, cfg)
	session2.Authenticated = true
	session2.SessionParams.InterimInterval = 300
	session2.LastInterimUpdateTime = MonotonicTime() - 301 // Last update was 301 seconds ago

	// Execute the reap function
	reaper.reapSessions()

	// Assertions
	require.Len(t, mockDc.DisconnectedSessions, 1, "Expected exactly 1 session to be disconnected for data quota")
	reason1, ok1 := mockDc.DisconnectedSessions[mac1.String()]
	require.True(t, ok1, "Session 1 should have been disconnected")
	require.Equal(t, "Data-Limit-Reached", reason1)

	require.Len(t, mockAcct.SentRequests, 1, "Expected exactly 1 accounting request to be sent")
	require.Equal(t, session2, mockAcct.SentRequests[0])
	require.Equal(t, rfc2866.AcctStatusType(3), mockAcct.LastStatus)
}