package main

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/firewall"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"layeh.com/radius/rfc2866"
)

// Mocks for dependencies that implement the new interfaces

type mockSessionManager struct {
	sessionsByMAC map[string]*core.Session
	sessionsByIP  map[string]*core.Session
}

func (m *mockSessionManager) GetSessionByMAC(mac net.HardwareAddr) (*core.Session, bool) {
	s, ok := m.sessionsByMAC[mac.String()]
	return s, ok
}
func (m *mockSessionManager) GetSessionByIP(ip net.IP) (*core.Session, bool) {
	s, ok := m.sessionsByIP[ip.String()]
	return s, ok
}
func (m *mockSessionManager) GetAllSessions() []*core.Session {
	var sessions []*core.Session
	for _, s := range m.sessionsByMAC {
		sessions = append(sessions, s)
	}
	return sessions
}

var _ sessionManagerInterface = &mockSessionManager{}

type mockDisconnectManager struct {
	disconnectedSession *core.Session
	disconnectedReason  string
}

func (m *mockDisconnectManager) Disconnect(session *core.Session, reason string) {
	m.disconnectedSession = session
	m.disconnectedReason = reason
}

var _ disconnectManagerInterface = &mockDisconnectManager{}

type mockFirewallManager struct {
	addedUserIP          net.IP
	addedUserBwUp        uint64
	addedUserBwDown      uint64
	addedToWalledGardenIP net.IP
	removedFromWalledGardenIP net.IP
}

func (m *mockFirewallManager) AddAuthenticatedUser(ip net.IP, bwUp, bwDown uint64) error {
	m.addedUserIP = ip
	m.addedUserBwUp = bwUp
	m.addedUserBwDown = bwDown
	return nil
}
func (m *mockFirewallManager) RemoveAuthenticatedUser(ip net.IP) error { return nil }
func (m *mockFirewallManager) UpdateUserBandwidth(ip net.IP, bwUp, bwDown uint64) error { return nil }
func (m *mockFirewallManager) AddToWalledGarden(ip net.IP, ttl uint32) error {
	m.addedToWalledGardenIP = ip
	return nil
}
func (m *mockFirewallManager) RemoveFromWalledGarden(ip net.IP) error {
	m.removedFromWalledGardenIP = ip
	return nil
}

var _ firewall.UserRuleManager = &mockFirewallManager{}

type mockAccountingSender struct {
	sentAcctRequest bool
	lastStatusType  rfc2866.AcctStatusType
}

func (m *mockAccountingSender) SendAccountingRequest(session *core.Session, statusType rfc2866.AcctStatusType, reason string) {
	m.sentAcctRequest = true
	m.lastStatusType = statusType
}

var _ accountingSenderInterface = &mockAccountingSender{}

func TestProcessCommand_Logout(t *testing.T) {
	logger := zerolog.Nop()
	cfg := &config.Config{}
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("10.0.0.1")
	session := &core.Session{HisMAC: mac, HisIP: ip}
	sm := &mockSessionManager{
		sessionsByMAC: map[string]*core.Session{mac.String(): session},
		sessionsByIP:  map[string]*core.Session{ip.String(): session},
	}
	dm := &mockDisconnectManager{}

	response := processCommand("logout 00:11:22:33:44:55", logger, cfg, sm, dm, nil, nil)
	require.Equal(t, session, dm.disconnectedSession)
	require.Equal(t, "Admin-Reset", dm.disconnectedReason)
	require.Contains(t, response, "OK")
}

func TestProcessCommand_Authorize(t *testing.T) {
	logger := zerolog.Nop()
	cfg := &config.Config{}
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("10.0.0.1")
	session := &core.Session{HisMAC: mac, HisIP: ip, Authenticated: false}
	sm := &mockSessionManager{sessionsByMAC: map[string]*core.Session{mac.String(): session}}
	fw := &mockFirewallManager{}
	rc := &mockAccountingSender{}

	response := processCommand("authorize 00:11:22:33:44:55", logger, cfg, sm, nil, fw, rc)
	require.True(t, session.Authenticated)
	require.Equal(t, ip, fw.addedUserIP)
	require.True(t, rc.sentAcctRequest)
	require.Contains(t, response, "OK")
}

func TestProcessCommand_Show(t *testing.T) {
	logger := zerolog.Nop()
	cfg := &config.Config{}
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("10.0.0.1")
	session := &core.Session{
		HisMAC:        mac,
		HisIP:         ip,
		Authenticated: true,
		Redir:         core.RedirState{Username: "testuser"},
	}
	sm := &mockSessionManager{sessionsByIP: map[string]*core.Session{ip.String(): session}}

	response := processCommand("show 10.0.0.1", logger, cfg, sm, nil, nil, nil)
	require.Contains(t, response, "Session Details for 10.0.0.1")
	require.Contains(t, response, "User-Name: testuser")
	require.Contains(t, response, "Authenticated: true")
}

func TestProcessCommand_Garden(t *testing.T) {
	logger := zerolog.Nop()
	cfg := &config.Config{}
	fw := &mockFirewallManager{}
	ipStr := "8.8.8.8"
	ip := net.ParseIP(ipStr)

	// Test add
	response := processCommand(fmt.Sprintf("garden add %s", ipStr), logger, cfg, nil, nil, fw, nil)
	require.Equal(t, ip, fw.addedToWalledGardenIP)
	require.Contains(t, response, "OK")

	// Test remove
	response = processCommand(fmt.Sprintf("garden remove %s", ipStr), logger, cfg, nil, nil, fw, nil)
	require.Equal(t, ip, fw.removedFromWalledGardenIP)
	require.Contains(t, response, "OK")
}