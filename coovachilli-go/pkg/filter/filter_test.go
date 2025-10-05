package filter

import (
	"net"
	"os"
	"testing"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURLFilter_CheckDomain(t *testing.T) {
	// Create temporary test files
	domainBlocklist, err := os.CreateTemp("", "domain_blocklist_*.txt")
	require.NoError(t, err)
	defer os.Remove(domainBlocklist.Name())

	_, err = domainBlocklist.WriteString("example.com\n*.malicious.com\n# comment\n")
	require.NoError(t, err)
	domainBlocklist.Close()

	categoryRules, err := os.CreateTemp("", "category_rules_*.txt")
	require.NoError(t, err)
	defer os.Remove(categoryRules.Name())

	_, err = categoryRules.WriteString("adult:block:.*porn.*\nadvertising:log:.*ads.*\nsocial:allow:.*facebook.*\n")
	require.NoError(t, err)
	categoryRules.Close()

	cfg := &config.URLFilterConfig{
		Enabled:             true,
		DomainBlocklistPath: domainBlocklist.Name(),
		CategoryRulesPath:   categoryRules.Name(),
		DefaultAction:       "allow",
	}

	filter, err := NewURLFilter(cfg, zerolog.Nop())
	require.NoError(t, err)

	tests := []struct {
		name           string
		domain         string
		expectedAction FilterAction
		expectedReason string
	}{
		{
			name:           "exact match blocklist",
			domain:         "example.com",
			expectedAction: ActionBlock,
			expectedReason: "blocklist",
		},
		{
			name:           "wildcard match",
			domain:         "sub.malicious.com",
			expectedAction: ActionBlock,
			expectedReason: "wildcard",
		},
		{
			name:           "category block",
			domain:         "site.porn.com",
			expectedAction: ActionBlock,
			expectedReason: "adult",
		},
		{
			name:           "category log",
			domain:         "google-ads.com",
			expectedAction: ActionLog,
			expectedReason: "advertising",
		},
		{
			name:           "category allow",
			domain:         "www.facebook.com",
			expectedAction: ActionAllow,
			expectedReason: "social",
		},
		{
			name:           "default allow",
			domain:         "safe-site.com",
			expectedAction: ActionAllow,
			expectedReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, reason := filter.CheckDomain(tt.domain)
			assert.Equal(t, tt.expectedAction, action)
			assert.Equal(t, tt.expectedReason, reason)
		})
	}
}

func TestURLFilter_CheckIP(t *testing.T) {
	ipBlocklist, err := os.CreateTemp("", "ip_blocklist_*.txt")
	require.NoError(t, err)
	defer os.Remove(ipBlocklist.Name())

	_, err = ipBlocklist.WriteString("192.0.2.1\n198.51.100.5\n# comment\n")
	require.NoError(t, err)
	ipBlocklist.Close()

	cfg := &config.URLFilterConfig{
		Enabled:         true,
		IPBlocklistPath: ipBlocklist.Name(),
	}

	filter, err := NewURLFilter(cfg, zerolog.Nop())
	require.NoError(t, err)

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "blocked IP",
			ip:       "192.0.2.1",
			expected: true,
		},
		{
			name:     "allowed IP",
			ip:       "203.0.113.1",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			blocked := filter.CheckIP(ip)
			assert.Equal(t, tt.expected, blocked)
		})
	}
}

func TestURLFilter_DynamicAdd(t *testing.T) {
	cfg := &config.URLFilterConfig{
		Enabled:       true,
		DefaultAction: "allow",
	}

	filter, err := NewURLFilter(cfg, zerolog.Nop())
	require.NoError(t, err)

	// Initially not blocked
	action, _ := filter.CheckDomain("newbad.com")
	assert.Equal(t, ActionAllow, action)

	// Add to blocklist
	filter.AddBlockedDomain("newbad.com")

	// Now blocked
	action, reason := filter.CheckDomain("newbad.com")
	assert.Equal(t, ActionBlock, action)
	assert.Equal(t, "blocklist", reason)

	// Remove from blocklist
	filter.RemoveBlockedDomain("newbad.com")

	// Not blocked again
	action, _ = filter.CheckDomain("newbad.com")
	assert.Equal(t, ActionAllow, action)
}

func TestURLFilter_GetStats(t *testing.T) {
	cfg := &config.URLFilterConfig{
		Enabled:       true,
		DefaultAction: "allow",
	}

	filter, err := NewURLFilter(cfg, zerolog.Nop())
	require.NoError(t, err)

	filter.AddBlockedDomain("blocked.com")

	filter.CheckDomain("allowed.com")
	filter.CheckDomain("blocked.com")
	filter.CheckDomain("another.com")

	stats := filter.GetStats()
	assert.Equal(t, uint64(3), stats.TotalQueries)
	assert.Equal(t, uint64(1), stats.BlockedQueries)
	assert.Equal(t, uint64(2), stats.AllowedQueries)
}
