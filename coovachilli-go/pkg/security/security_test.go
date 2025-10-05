package security

import (
	"net"
	"testing"
	"time"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAntiMalware(t *testing.T) {
	cfg := &config.AntiMalwareConfig{
		Enabled:  true,
		Scanners: []string{"threatfox"},
		CacheTTL: 60,
	}

	am, err := NewAntiMalware(cfg, zerolog.Nop())
	require.NoError(t, err)
	require.NotNil(t, am)

	// Test hash scanning
	result, err := am.ScanHash("abc123def456")
	require.NoError(t, err)
	assert.Equal(t, ThreatLevelClean, result.ThreatLevel)

	// Test IP scanning
	ip := net.ParseIP("192.0.2.1")
	result, err = am.ScanIP(ip)
	require.NoError(t, err)
	assert.Equal(t, ThreatLevelClean, result.ThreatLevel)

	// Test stats
	stats := am.GetStats()
	assert.Greater(t, stats.TotalScans, uint64(0))
}

func TestIDS(t *testing.T) {
	cfg := &config.IDSConfig{
		Enabled:             true,
		DetectPortScan:      true,
		DetectBruteForce:    true,
		DetectDDoS:          true,
		PortScanThreshold:   5,
		BruteForceThreshold: 3,
		DDoSThreshold:       100,
		DDoSTimeWindow:      10,
	}

	ids, err := NewIDS(cfg, zerolog.Nop())
	require.NoError(t, err)
	require.NotNil(t, ids)

	srcIP := net.ParseIP("203.0.113.1")

	// Test brute force detection
	for i := 0; i < 2; i++ {
		event := ids.CheckAuthFailure(srcIP, "testuser")
		assert.Nil(t, event)
	}

	// This should trigger brute force detection
	event := ids.CheckAuthFailure(srcIP, "testuser")
	require.NotNil(t, event)
	assert.Equal(t, IntrusionBruteForce, event.Type)
	assert.Equal(t, "high", event.Severity)

	// Test blocking
	ids.BlockIP(srcIP, 5*time.Minute) // 5 minutes
	assert.True(t, ids.IsBlocked(srcIP))

	// Test stats
	stats := ids.GetStats()
	assert.Greater(t, stats.TotalEvents, uint64(0))
	assert.Greater(t, stats.BruteForceAttempts, uint64(0))
}

func TestIDS_SQLInjection(t *testing.T) {
	cfg := &config.IDSConfig{
		Enabled:            true,
		DetectSQLInjection: true,
	}

	ids, err := NewIDS(cfg, zerolog.Nop())
	require.NoError(t, err)

	srcIP := net.ParseIP("203.0.113.1")

	// Test SQL injection detection
	event := ids.CheckHTTPRequest(srcIP, "GET", "/page", "id=1' OR '1'='1")
	require.NotNil(t, event)
	assert.Equal(t, IntrusionSQLInjection, event.Type)

	// Clean request should pass
	event = ids.CheckHTTPRequest(srcIP, "GET", "/page", "id=123")
	assert.Nil(t, event)
}

func TestIDS_XSS(t *testing.T) {
	cfg := &config.IDSConfig{
		Enabled:   true,
		DetectXSS: true,
	}

	ids, err := NewIDS(cfg, zerolog.Nop())
	require.NoError(t, err)

	srcIP := net.ParseIP("203.0.113.1")

	// Test XSS detection
	event := ids.CheckHTTPRequest(srcIP, "POST", "/comment", "text=<script>alert('xss')</script>")
	require.NotNil(t, event)
	assert.Equal(t, IntrusionXSS, event.Type)
}
