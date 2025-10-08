package radius

import (
	"net"
	"testing"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyServerCreation(t *testing.T) {
	cfg := &config.Config{
		ProxyListen: "127.0.0.1",
		ProxyPort:   1645,
		RadiusTimeout: 5 * time.Second,
	}

	sm := core.NewSessionManager(cfg, nil, zerolog.Nop())
	rc := NewClient(cfg, zerolog.Nop(), nil)

	proxy := NewProxyServer(cfg, sm, rc, zerolog.Nop())

	assert.NotNil(t, proxy)
	assert.NotNil(t, proxy.realms)
	assert.NotNil(t, proxy.ctx)
	assert.NotNil(t, proxy.cancel)
}

func TestProxyAddRealm(t *testing.T) {
	cfg := &config.Config{
		ProxyListen: "127.0.0.1",
		ProxyPort:   1645,
	}

	sm := core.NewSessionManager(cfg, nil, zerolog.Nop())
	rc := NewClient(cfg, zerolog.Nop(), nil)
	proxy := NewProxyServer(cfg, sm, rc, zerolog.Nop())

	realm := &ProxyRealm{
		Name:          "example.com",
		LoadBalancing: "round-robin",
		Servers: []ProxyUpstreamServer{
			{
				Address:  "192.168.1.10",
				AuthPort: 1812,
				AcctPort: 1813,
				Secret:   []byte("secret"),
				Active:   true,
			},
		},
	}

	proxy.AddRealm(realm)

	proxy.realmsMu.RLock()
	storedRealm, exists := proxy.realms["example.com"]
	proxy.realmsMu.RUnlock()

	assert.True(t, exists)
	assert.Equal(t, "example.com", storedRealm.Name)
	assert.Len(t, storedRealm.Servers, 1)
}

func TestExtractRealm(t *testing.T) {
	cfg := &config.Config{}
	sm := core.NewSessionManager(cfg, nil, zerolog.Nop())
	rc := NewClient(cfg, zerolog.Nop(), nil)
	proxy := NewProxyServer(cfg, sm, rc, zerolog.Nop())

	tests := []struct {
		name     string
		username string
		want     string
	}{
		{
			name:     "standard @ separator",
			username: "user@example.com",
			want:     "example.com",
		},
		{
			name:     "windows domain style",
			username: "DOMAIN\\user",
			want:     "DOMAIN",
		},
		{
			name:     "no separator",
			username: "plainuser",
			want:     "default",
		},
		{
			name:     "multiple @ signs",
			username: "user@sub@example.com",
			want:     "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := proxy.extractRealm(tt.username)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSelectRoundRobin(t *testing.T) {
	realm := &ProxyRealm{
		Name:          "test",
		LoadBalancing: "round-robin",
		Servers: []ProxyUpstreamServer{
			{Address: "server1", Active: true},
			{Address: "server2", Active: true},
			{Address: "server3", Active: true},
		},
		currentIndex: 0,
	}

	cfg := &config.Config{}
	sm := core.NewSessionManager(cfg, nil, zerolog.Nop())
	rc := NewClient(cfg, zerolog.Nop(), nil)
	proxy := NewProxyServer(cfg, sm, rc, zerolog.Nop())

	// Test round-robin selection
	servers := make([]*ProxyUpstreamServer, 6)
	for i := 0; i < 6; i++ {
		server, err := proxy.selectRoundRobin(realm)
		require.NoError(t, err)
		servers[i] = server
	}

	// Should cycle through servers
	assert.Equal(t, "server1", servers[0].Address)
	assert.Equal(t, "server2", servers[1].Address)
	assert.Equal(t, "server3", servers[2].Address)
	assert.Equal(t, "server1", servers[3].Address) // Back to first
	assert.Equal(t, "server2", servers[4].Address)
	assert.Equal(t, "server3", servers[5].Address)
}

func TestSelectFailover(t *testing.T) {
	realm := &ProxyRealm{
		Name:          "test",
		LoadBalancing: "failover",
		Servers: []ProxyUpstreamServer{
			{Address: "server1", Active: true, Priority: 1},
			{Address: "server2", Active: true, Priority: 3},
			{Address: "server3", Active: true, Priority: 2},
		},
	}

	cfg := &config.Config{}
	sm := core.NewSessionManager(cfg, nil, zerolog.Nop())
	rc := NewClient(cfg, zerolog.Nop(), nil)
	proxy := NewProxyServer(cfg, sm, rc, zerolog.Nop())

	// Should always select highest priority
	for i := 0; i < 5; i++ {
		server, err := proxy.selectFailover(realm)
		require.NoError(t, err)
		assert.Equal(t, "server2", server.Address) // Priority 3 is highest
	}
}

func TestSelectFailoverWithInactiveServers(t *testing.T) {
	realm := &ProxyRealm{
		Name:          "test",
		LoadBalancing: "failover",
		Servers: []ProxyUpstreamServer{
			{Address: "server1", Active: false, Priority: 3}, // Highest but inactive
			{Address: "server2", Active: true, Priority: 2},
			{Address: "server3", Active: false, Priority: 1},
		},
	}

	cfg := &config.Config{}
	sm := core.NewSessionManager(cfg, nil, zerolog.Nop())
	rc := NewClient(cfg, zerolog.Nop(), nil)
	proxy := NewProxyServer(cfg, sm, rc, zerolog.Nop())

	server, err := proxy.selectFailover(realm)
	require.NoError(t, err)
	assert.Equal(t, "server2", server.Address) // Only active server
}

func TestSelectLeastLoad(t *testing.T) {
	realm := &ProxyRealm{
		Name:          "test",
		LoadBalancing: "least-load",
		Servers: []ProxyUpstreamServer{
			{Address: "server1", Active: true, failures: 5},
			{Address: "server2", Active: true, failures: 2},
			{Address: "server3", Active: true, failures: 8},
		},
	}

	cfg := &config.Config{}
	sm := core.NewSessionManager(cfg, nil, zerolog.Nop())
	rc := NewClient(cfg, zerolog.Nop(), nil)
	proxy := NewProxyServer(cfg, sm, rc, zerolog.Nop())

	server, err := proxy.selectLeastLoad(realm)
	require.NoError(t, err)
	assert.Equal(t, "server2", server.Address) // Fewest failures
}

func TestProxyServerStop(t *testing.T) {
	cfg := &config.Config{
		ProxyListen: "127.0.0.1",
		ProxyPort:   1645,
	}

	sm := core.NewSessionManager(cfg, nil, zerolog.Nop())
	rc := NewClient(cfg, zerolog.Nop(), nil)
	proxy := NewProxyServer(cfg, sm, rc, zerolog.Nop())

	// Verify context is active
	select {
	case <-proxy.ctx.Done():
		t.Fatal("Context should not be done before Stop")
	default:
	}

	// Stop the proxy
	proxy.Stop()

	// Verify context is cancelled
	select {
	case <-proxy.ctx.Done():
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Context should be done after Stop")
	}
}

func TestUpstreamServerFailureTracking(t *testing.T) {
	server := &ProxyUpstreamServer{
		Address:  "test-server",
		Active:   true,
		failures: 0,
	}

	// Simulate failures
	for i := 0; i < 2; i++ {
		server.mu.Lock()
		server.failures++
		server.mu.Unlock()
	}

	assert.Equal(t, 2, server.failures)
	assert.True(t, server.Active)

	// One more failure should mark it inactive
	server.mu.Lock()
	server.failures++
	if server.failures >= 3 {
		server.Active = false
	}
	server.mu.Unlock()

	assert.Equal(t, 3, server.failures)
	assert.False(t, server.Active)
}

func TestProxyRealmNoServers(t *testing.T) {
	realm := &ProxyRealm{
		Name:          "empty",
		LoadBalancing: "round-robin",
		Servers:       []ProxyUpstreamServer{},
	}

	cfg := &config.Config{}
	sm := core.NewSessionManager(cfg, nil, zerolog.Nop())
	rc := NewClient(cfg, zerolog.Nop(), nil)
	proxy := NewProxyServer(cfg, sm, rc, zerolog.Nop())

	_, err := proxy.selectRoundRobin(realm)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "upstream servers")
}

func TestProxyRealmAllInactive(t *testing.T) {
	realm := &ProxyRealm{
		Name:          "inactive",
		LoadBalancing: "round-robin",
		Servers: []ProxyUpstreamServer{
			{Address: "server1", Active: false},
			{Address: "server2", Active: false},
		},
	}

	cfg := &config.Config{}
	sm := core.NewSessionManager(cfg, nil, zerolog.Nop())
	rc := NewClient(cfg, zerolog.Nop(), nil)
	proxy := NewProxyServer(cfg, sm, rc, zerolog.Nop())

	_, err := proxy.selectRoundRobin(realm)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no active upstream servers")
}

func BenchmarkExtractRealm(b *testing.B) {
	cfg := &config.Config{}
	sm := core.NewSessionManager(cfg, nil, zerolog.Nop())
	rc := NewClient(cfg, zerolog.Nop(), nil)
	proxy := NewProxyServer(cfg, sm, rc, zerolog.Nop())

	username := "user@example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = proxy.extractRealm(username)
	}
}

func BenchmarkSelectRoundRobin(b *testing.B) {
	realm := &ProxyRealm{
		Name:          "test",
		LoadBalancing: "round-robin",
		Servers: []ProxyUpstreamServer{
			{Address: "server1", Active: true},
			{Address: "server2", Active: true},
			{Address: "server3", Active: true},
		},
	}

	cfg := &config.Config{}
	sm := core.NewSessionManager(cfg, nil, zerolog.Nop())
	rc := NewClient(cfg, zerolog.Nop(), nil)
	proxy := NewProxyServer(cfg, sm, rc, zerolog.Nop())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = proxy.selectRoundRobin(realm)
	}
}

func init() {
	// Ensure net package is initialized for tests
	_, _ = net.ParseMAC("00:11:22:33:44:55")
}