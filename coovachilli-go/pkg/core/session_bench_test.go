package core

import (
	"net"
	"testing"

	"coovachilli-go/pkg/config"
)

// Benchmark session creation
func BenchmarkCreateSession(b *testing.B) {
	cfg := &config.Config{}
	sm := NewSessionManager(cfg, nil)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("10.0.0.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm.CreateSession(ip, mac, 0)
	}
}

// Benchmark session lookup by IP
func BenchmarkGetSessionByIP(b *testing.B) {
	cfg := &config.Config{}
	sm := NewSessionManager(cfg, nil)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("10.0.0.1")
	sm.CreateSession(ip, mac, 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm.GetSessionByIP(ip)
	}
}

// Benchmark session lookup by MAC
func BenchmarkGetSessionByMAC(b *testing.B) {
	cfg := &config.Config{}
	sm := NewSessionManager(cfg, nil)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("10.0.0.1")
	sm.CreateSession(ip, mac, 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm.GetSessionByMAC(mac)
	}
}

// Benchmark concurrent session access
func BenchmarkConcurrentSessionAccess(b *testing.B) {
	cfg := &config.Config{}
	sm := NewSessionManager(cfg, nil)

	// Create multiple sessions
	for i := 0; i < 100; i++ {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		mac[5] = byte(i)
		ip := net.ParseIP("10.0.0.1")
		ip[3] = byte(i)
		sm.CreateSession(ip, mac, 0)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		ip := net.ParseIP("10.0.0.50")
		for pb.Next() {
			sm.GetSessionByIP(ip)
		}
	})
}

// Benchmark session with token lookup
func BenchmarkGetSessionByToken(b *testing.B) {
	cfg := &config.Config{}
	sm := NewSessionManager(cfg, nil)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("10.0.0.1")
	session := sm.CreateSession(ip, mac, 0)
	session.Token = "test-token-123"
	sm.AssociateToken(session)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm.GetSessionByToken("test-token-123")
	}
}

// Benchmark session removal
func BenchmarkRemoveSession(b *testing.B) {
	cfg := &config.Config{}
	sm := NewSessionManager(cfg, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		mac[5] = byte(i & 0xFF)
		ip := net.ParseIP("10.0.0.1")
		ip[3] = byte(i & 0xFF)
		session := sm.CreateSession(ip, mac, 0)
		b.StartTimer()

		sm.RemoveSession(session)
	}
}

// Benchmark GetAllSessions with many sessions
func BenchmarkGetAllSessions(b *testing.B) {
	cfg := &config.Config{}
	sm := NewSessionManager(cfg, nil)

	// Create 1000 sessions
	for i := 0; i < 1000; i++ {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		mac[4] = byte(i >> 8)
		mac[5] = byte(i & 0xFF)
		ip := net.ParseIP("10.0.0.1")
		ip[2] = byte(i >> 8)
		ip[3] = byte(i & 0xFF)
		sm.CreateSession(ip, mac, 0)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sm.GetAllSessions()
	}
}

// Benchmark memory allocation for session creation
func BenchmarkSessionMemoryAllocation(b *testing.B) {
	cfg := &config.Config{}
	sm := NewSessionManager(cfg, nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		mac[5] = byte(i & 0xFF)
		ip := net.ParseIP("10.0.0.1")
		ip[3] = byte(i & 0xFF)
		sm.CreateSession(ip, mac, 0)
	}
}
