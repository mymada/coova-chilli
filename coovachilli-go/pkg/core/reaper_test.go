package core

import (
	"net"
	"testing"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
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

func TestReaper(t *testing.T) {
	// Setup
	cfg := &config.Config{} // Empty config is fine for this test
	sm := NewSessionManager(cfg, nil)
	mockDc := &mockDisconnector{}
	logger := zerolog.Nop() // Disable logging output

	reaper := NewReaper(cfg, sm, mockDc, logger)

	// --- Test Case 1: Session expired by Session-Timeout ---
	mac1, _ := net.ParseMAC("00:00:5e:00:53:01")
	ip1 := net.ParseIP("10.0.0.1")
	session1 := sm.CreateSession(ip1, mac1, 0)
	session1.Authenticated = true
	session1.SessionParams.SessionTimeout = 100 // seconds
	session1.StartTimeSec = MonotonicTime() - 101 // Started 101 seconds ago
	session1.LastActivityTimeSec = MonotonicTime() - 10 // Active recently

	// --- Test Case 2: Session expired by Idle-Timeout ---
	mac2, _ := net.ParseMAC("00:00:5e:00:53:02")
	ip2 := net.ParseIP("10.0.0.2")
	session2 := sm.CreateSession(ip2, mac2, 0)
	session2.Authenticated = true
	session2.SessionParams.IdleTimeout = 50 // seconds
	session2.StartTimeSec = MonotonicTime() - 1000 // Started long ago
	session2.LastActivityTimeSec = MonotonicTime() - 51 // Last seen 51 seconds ago

	// --- Test Case 3: Active session, should not be reaped ---
	mac3, _ := net.ParseMAC("00:00:5e:00:53:03")
	ip3 := net.ParseIP("10.0.0.3")
	session3 := sm.CreateSession(ip3, mac3, 0)
	session3.Authenticated = true
	session3.SessionParams.SessionTimeout = 1000
	session3.SessionParams.IdleTimeout = 500
	session3.StartTimeSec = MonotonicTime() - 100
	session3.LastActivityTimeSec = MonotonicTime() - 10

	// --- Test Case 4: Unauthenticated session, should not be reaped ---
	mac4, _ := net.ParseMAC("00:00:5e:00:53:04")
	ip4 := net.ParseIP("10.0.0.4")
	_ = sm.CreateSession(ip4, mac4, 0) // Not authenticated

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