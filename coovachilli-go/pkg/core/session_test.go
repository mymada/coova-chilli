package core

import (
	"net"
	"testing"
)

func TestSessionManager(t *testing.T) {
	sm := NewSessionManager()

	mac, _ := net.ParseMAC("00:00:5e:00:53:01")
	ip := net.ParseIP("10.1.0.100")

	// Test CreateSession
	session := sm.CreateSession(ip, mac)
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
