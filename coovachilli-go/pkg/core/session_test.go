package core

import (
	"net"
	"testing"

	"coovachilli-go/pkg/config"
)

func TestSessionManager(t *testing.T) {
	cfg := &config.Config{}
	sm := NewSessionManager(cfg, nil)

	mac, _ := net.ParseMAC("00:00:5e:00:53:01")
	ip := net.ParseIP("10.1.0.100")

	// Test CreateSession
	session := sm.CreateSession(ip, mac, 0)
	if session == nil {
		t.Fatal("CreateSession should not return nil")
	}

	// Test GetSessionByIP
	s, ok := sm.GetSessionByIP(ip)
	if !ok {
		t.Fatal("GetSessionByIP should find the session")
	}
	if s != session {
		t.Fatal("GetSessionByIP returned the wrong session")
	}

	// Test GetSessionByMAC
	s, ok = sm.GetSessionByMAC(mac)
	if !ok {
		t.Fatal("GetSessionByMAC should find the session")
	}
	if s != session {
		t.Fatal("GetSessionByMAC returned the wrong session")
	}

	// Test DeleteSession
	sm.DeleteSession(session)
	_, ok = sm.GetSessionByIP(ip)
	if ok {
		t.Fatal("GetSessionByIP should not find the session after deletion")
	}
	_, ok = sm.GetSessionByMAC(mac)
	if ok {
		t.Fatal("GetSessionByMAC should not find the session after deletion")
	}
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
	sm := NewSessionManager(cfg, nil)

	session := sm.CreateSession(ip, mac, 0)
	if session == nil {
		t.Fatal("CreateSession should not return nil")
	}

	if session.SessionParams.SessionTimeout != cfg.DefSessionTimeout {
		t.Errorf("Default SessionTimeout not set correctly: got %d, want %d", session.SessionParams.SessionTimeout, cfg.DefSessionTimeout)
	}
	if session.SessionParams.IdleTimeout != cfg.DefIdleTimeout {
		t.Errorf("Default IdleTimeout not set correctly: got %d, want %d", session.SessionParams.IdleTimeout, cfg.DefIdleTimeout)
	}
	if session.SessionParams.BandwidthMaxDown != cfg.DefBandwidthMaxDown {
		t.Errorf("Default BandwidthMaxDown not set correctly: got %d, want %d", session.SessionParams.BandwidthMaxDown, cfg.DefBandwidthMaxDown)
	}
	if session.SessionParams.BandwidthMaxUp != cfg.DefBandwidthMaxUp {
		t.Errorf("Default BandwidthMaxUp not set correctly: got %d, want %d", session.SessionParams.BandwidthMaxUp, cfg.DefBandwidthMaxUp)
	}
}
