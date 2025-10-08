package core

import (
	"encoding/json"
	"net"
	"os"
	"testing"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionManager(t *testing.T) {
	cfg := &config.Config{}
	logger := zerolog.New(os.Stderr)
	sm := NewSessionManager(cfg, nil, logger)

	mac, _ := net.ParseMAC("00:00:5e:00:53:01")
	ip := net.ParseIP("10.1.0.100")

	// Test CreateSession
	session := sm.CreateSession(ip, mac, 0)
	require.NotNil(t, session, "CreateSession should not return nil")

	// Test GetSessionByIP
	s, ok := sm.GetSessionByIP(ip)
	require.True(t, ok, "GetSessionByIP should find the session")
	assert.Equal(t, session, s, "GetSessionByIP returned the wrong session")

	// Test GetSessionByMAC
	s, ok = sm.GetSessionByMAC(mac)
	require.True(t, ok, "GetSessionByMAC should find the session")
	assert.Equal(t, session, s, "GetSessionByMAC returned the wrong session")

	// Test DeleteSession
	sm.DeleteSession(session)
	_, ok = sm.GetSessionByIP(ip)
	assert.False(t, ok, "GetSessionByIP should not find the session after deletion")

	_, ok = sm.GetSessionByMAC(mac)
	assert.False(t, ok, "GetSessionByMAC should not find the session after deletion")
}

func TestCreateSession_Defaults(t *testing.T) {
	mac, _ := net.ParseMAC("00:00:5e:00:53:02")
	ip := net.ParseIP("10.1.0.101")

	cfg := &config.Config{
		DefSessionTimeout:   3600,
		DefIdleTimeout:      300,
		DefBandwidthMaxDown: 2000000,
		DefBandwidthMaxUp:   500000,
	}
	logger := zerolog.New(os.Stderr)
	sm := NewSessionManager(cfg, nil, logger)

	session := sm.CreateSession(ip, mac, 0)
	require.NotNil(t, session, "CreateSession should not return nil")

	assert.Equal(t, cfg.DefSessionTimeout, session.SessionParams.SessionTimeout, "Default SessionTimeout not set correctly")
	assert.Equal(t, cfg.DefIdleTimeout, session.SessionParams.IdleTimeout, "Default IdleTimeout not set correctly")
	assert.Equal(t, cfg.DefBandwidthMaxDown, session.SessionParams.BandwidthMaxDown, "Default BandwidthMaxDown not set correctly")
	assert.Equal(t, cfg.DefBandwidthMaxUp, session.SessionParams.BandwidthMaxUp, "Default BandwidthMaxUp not set correctly")
}

func TestSessionPersistence(t *testing.T) {
	// Setup: Create a temporary file for the session data
	tmpfile, err := os.CreateTemp("", "session_test_*.json")
	require.NoError(t, err, "Failed to create temp file")
	defer os.Remove(tmpfile.Name()) // Clean up after the test

	// Setup: Create a config that enables persistence and points to our temp file
	cfg := &config.Config{
		SessionPersistence: true,
		SessionFile:        tmpfile.Name(),
	}
	logger := zerolog.New(os.Stderr)

	// Setup: Create the initial session manager and add some sessions
	sm1 := NewSessionManager(cfg, nil, logger)

	mac1, _ := net.ParseMAC("00:00:5e:00:53:11")
	ip1 := net.ParseIP("10.1.0.111")
	session1 := sm1.CreateSession(ip1, mac1, 0)
	session1.Authenticated = true // This one should be saved
	session1.SessionParams.IdleTimeout = 1234
	session1.Redir.Username = "testuser1"

	mac2, _ := net.ParseMAC("00:00:5e:00:53:12")
	ip2 := net.ParseIP("10.1.0.112")
	sm1.CreateSession(ip2, mac2, 0) // Not authenticated, should NOT be saved

	// Action: Save the sessions
	err = sm1.SaveSessions()
	require.NoError(t, err, "SaveSessions() failed")
	tmpfile.Close() // Close the file descriptor to ensure data is flushed to disk.

	// Verification: Check that the file was written and is not empty by checking the path.
	info, err := os.Stat(tmpfile.Name())
	require.NoError(t, err, "Failed to stat temp file path after save")
	assert.Greater(t, info.Size(), int64(0), "Session file should not be empty after saving")

	// Setup: Create a new session manager to load the data into
	sm2 := NewSessionManager(cfg, nil, logger)

	// Action: Load the sessions
	err = sm2.LoadSessions()
	require.NoError(t, err, "LoadSessions() failed")

	// Verification: Check that the correct sessions were loaded
	assert.Equal(t, 1, len(sm2.GetAllSessions()), "Expected 1 session to be loaded")

	loadedSession, ok := sm2.GetSessionByIP(ip1)
	require.True(t, ok, "Authenticated session was not loaded")
	require.NotNil(t, loadedSession)

	assert.Equal(t, "testuser1", loadedSession.Redir.Username, "Loaded session has wrong username")
	assert.Equal(t, uint32(1234), loadedSession.SessionParams.IdleTimeout, "Loaded session has wrong idle timeout")
	assert.Equal(t, ip1.String(), loadedSession.HisIP.String())
	assert.Equal(t, mac1.String(), loadedSession.HisMAC.String())

	_, ok = sm2.GetSessionByIP(ip2)
	assert.False(t, ok, "Unauthenticated session should not have been loaded")
}

func TestLoadSessions_DowntimeAdjustment(t *testing.T) {
	// Setup
	tmpfile, err := os.CreateTemp("", "session_test_downtime_*.json")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	cfg := &config.Config{
		SessionPersistence: true,
		SessionFile:        tmpfile.Name(),
	}
	logger := zerolog.New(os.Stderr)
	// We don't use a session manager to save, we create the file manually
	// to control the save time.

	// Create sessions with different timeout conditions
	mac1, _ := net.ParseMAC("00:00:5e:00:53:21")
	ip1 := net.ParseIP("10.1.0.121")
	session1 := &Session{HisIP: ip1, HisMAC: mac1, Authenticated: true, SessionParams: SessionParams{SessionTimeout: 1000, IdleTimeout: 500}}

	mac2, _ := net.ParseMAC("00:00:5e:00:53:22")
	ip2 := net.ParseIP("10.1.0.122")
	session2 := &Session{HisIP: ip2, HisMAC: mac2, Authenticated: true, SessionParams: SessionParams{IdleTimeout: 30}} // Will expire

	// Manually create the state file with a timestamp in the past
	downtime := uint32(60) // 60 seconds
	state := StateData{
		SaveTime: MonotonicTime() - downtime,
		Sessions: []*Session{session1, session2},
	}
	data, err := json.MarshalIndent(state, "", "  ")
	require.NoError(t, err)
	err = os.WriteFile(tmpfile.Name(), data, 0644)
	require.NoError(t, err)

	// Action: Load into a new session manager
	sm2 := NewSessionManager(cfg, nil, logger)
	err = sm2.LoadSessions()
	require.NoError(t, err)

	// Verification
	assert.Equal(t, 1, len(sm2.GetAllSessions()), "Only one session should have survived the downtime")

	// Verify the surviving session
	loadedSession1, ok := sm2.GetSessionByIP(ip1)
	require.True(t, ok, "Surviving session not found")
	assert.Equal(t, uint32(1000-downtime), loadedSession1.SessionParams.SessionTimeout, "SessionTimeout not adjusted correctly")
	assert.Equal(t, uint32(500-downtime), loadedSession1.SessionParams.IdleTimeout, "IdleTimeout not adjusted correctly")

	// Verify the expired session was not loaded
	_, ok = sm2.GetSessionByIP(ip2)
	assert.False(t, ok, "Expired session should not have been loaded")
}