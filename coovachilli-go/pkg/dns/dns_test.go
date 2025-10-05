package dns

import (
	"net"
	"os"
	"testing"

	"coovachilli-go/pkg/config"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockGarden struct {
	lastDomain string
	lastIPs    []net.IP
	callCount  int
}

func (m *mockGarden) HandleDNSResponse(domain string, ips []net.IP) {
	m.lastDomain = domain
	m.lastIPs = ips
	m.callCount++
}

func TestNewProxy(t *testing.T) {
	cfg := &config.Config{
		DNS1: net.ParseIP("8.8.8.8"),
		DNS2: net.ParseIP("8.8.4.4"),
	}
	logger := zerolog.Nop()
	garden := &mockGarden{}

	proxy := NewProxy(cfg, logger, garden)

	assert.NotNil(t, proxy)
	assert.Equal(t, cfg, proxy.cfg)
	assert.Equal(t, garden, proxy.garden)
}

func TestHandleQuery_InvalidDNSPacket(t *testing.T) {
	cfg := &config.Config{DNS1: net.ParseIP("8.8.8.8")}
	proxy := NewProxy(cfg, zerolog.Nop(), nil)

	// Test with invalid DNS packet
	invalidPayload := []byte{0x00, 0x01, 0x02}
	resp, err := proxy.HandleQuery(invalidPayload)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to unpack dns query")
}

func TestHandleQuery_NoQuestions(t *testing.T) {
	cfg := &config.Config{DNS1: net.ParseIP("8.8.8.8")}
	proxy := NewProxy(cfg, zerolog.Nop(), nil)

	// Create a valid DNS message but with no questions
	msg := new(dns.Msg)
	msg.SetQuestion("", dns.TypeA)
	msg.Question = nil // Remove the question

	payload, err := msg.Pack()
	require.NoError(t, err)

	resp, err := proxy.HandleQuery(payload)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "no questions")
}

func TestHandleQuery_DomainTrimming(t *testing.T) {
	// This test verifies that trailing dots are removed from domain names
	garden := &mockGarden{}
	cfg := &config.Config{
		DNS1: net.ParseIP("8.8.8.8"),
		DNS2: net.ParseIP("8.8.4.4"),
	}

	_ = NewProxy(cfg, zerolog.Nop(), garden)

	tests := []struct {
		name           string
		queryDomain    string
		expectedDomain string
	}{
		{
			name:           "domain with trailing dot",
			queryDomain:    "example.com.",
			expectedDomain: "example.com",
		},
		{
			name:           "domain without trailing dot",
			queryDomain:    "example.org",
			expectedDomain: "example.org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: This test would require a mock DNS server to work properly
			// For now, it documents the expected behavior
			t.Skip("Requires mock DNS server - documents expected behavior")
		})
	}
}

func TestProxy_SecurityConsiderations(t *testing.T) {
	t.Run("should validate DNS response size", func(t *testing.T) {
		// DNS amplification attack prevention
		// Max UDP DNS response should be limited (typically 512 bytes, or 4096 with EDNS)
		t.Skip("TODO: Implement DNS response size validation")
	})

	t.Run("should prevent DNS cache poisoning", func(t *testing.T) {
		// Verify transaction IDs match
		// Verify query/response correlation
		t.Skip("TODO: Implement DNS cache poisoning prevention")
	})

	t.Run("should rate limit DNS queries per client", func(t *testing.T) {
		// Prevent DNS amplification attacks
		t.Skip("TODO: Implement per-client rate limiting")
	})

	t.Run("should validate DNS server responses", func(t *testing.T) {
		// Ensure responses come from configured upstream servers
		// Verify DNSSEC if enabled
		t.Skip("TODO: Implement DNS response validation")
	})
}

func TestProxy_ErrorHandling(t *testing.T) {
	t.Run("handles nil DNS1", func(t *testing.T) {
		cfg := &config.Config{} // No DNS servers configured
		proxy := NewProxy(cfg, zerolog.Nop(), nil)

		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		payload, _ := msg.Pack()

		// Should handle gracefully (will error when trying to dial)
		resp, err := proxy.HandleQuery(payload)
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("falls back to DNS2 on DNS1 failure", func(t *testing.T) {
		// This would require mocking network calls
		t.Skip("Requires network mocking")
	})
}

func TestProxy_GardenIntegration(t *testing.T) {
	t.Run("notifies garden of A record responses", func(t *testing.T) {
		// Would require mock DNS server
		t.Skip("Requires mock DNS server")
	})

	t.Run("notifies garden of AAAA record responses", func(t *testing.T) {
		// Would require mock DNS server
		t.Skip("Requires mock DNS server")
	})

	t.Run("does not notify garden for failed queries", func(t *testing.T) {
		garden := &mockGarden{}
		cfg := &config.Config{DNS1: net.ParseIP("192.0.2.1")} // TEST-NET-1, should fail
		proxy := NewProxy(cfg, zerolog.Nop(), garden)

		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		payload, _ := msg.Pack()

		proxy.HandleQuery(payload)

		// Garden should not be notified on error
		assert.Equal(t, 0, garden.callCount)
	})
}

func TestDNSProxyBlocklist(t *testing.T) {
	// Create a temporary blocklist file
	tmpfile, err := os.CreateTemp("", "blocklist_*.txt")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name()) // Clean up

	// Write a domain to the blocklist
	_, err = tmpfile.WriteString("blocked-domain.com\n")
	require.NoError(t, err)
	err = tmpfile.Close()
	require.NoError(t, err)

	// Configure the proxy to use the blocklist
	cfg := &config.Config{
		DNS1: net.ParseIP("8.8.8.8"), // A real upstream for the unblocked query
		DNS: config.DNSConfig{
			BlocklistEnabled: true,
			BlocklistPath:    tmpfile.Name(),
		},
	}
	logger := zerolog.Nop()
	proxy := NewProxy(cfg, logger, nil)

	// 1. Test a blocked domain
	t.Run("query for blocked domain", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("blocked-domain.com.", dns.TypeA)
		payload, err := msg.Pack()
		require.NoError(t, err)

		respPayload, err := proxy.HandleQuery(payload)
		require.NoError(t, err)

		respMsg := new(dns.Msg)
		err = respMsg.Unpack(respPayload)
		require.NoError(t, err)

		assert.Equal(t, dns.RcodeNameError, respMsg.Rcode, "Expected NXDOMAIN for a blocked domain")
	})

	// 2. Test an unblocked domain
	t.Run("query for unblocked domain", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		payload, err := msg.Pack()
		require.NoError(t, err)

		respPayload, err := proxy.HandleQuery(payload)
		require.NoError(t, err)

		respMsg := new(dns.Msg)
		err = respMsg.Unpack(respPayload)
		require.NoError(t, err)

		assert.Equal(t, dns.RcodeSuccess, respMsg.Rcode, "Expected RcodeSuccess for an unblocked domain")
	})
}
