package dns

import (
	"net"
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

	invalidPayload := []byte{0x00, 0x01, 0x02}
	resp, err := proxy.HandleQuery(invalidPayload)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to unpack dns query")
}

func TestHandleQuery_NoQuestions(t *testing.T) {
	cfg := &config.Config{DNS1: net.ParseIP("8.8.8.8")}
	proxy := NewProxy(cfg, zerolog.Nop(), nil)

	msg := new(dns.Msg)
	msg.SetQuestion("", dns.TypeA)
	msg.Question = nil
	payload, err := msg.Pack()
	require.NoError(t, err)

	resp, err := proxy.HandleQuery(payload)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "no questions")
}

func TestHandleQuery_DomainTrimming(t *testing.T) {
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
			t.Skip("Requires mock DNS server - documents expected behavior")
		})
	}
}

func TestHandleQuery_Cache(t *testing.T) {
	garden := &mockGarden{}
	cfg := &config.Config{
		DNS1: net.ParseIP("8.8.8.8"),
		DNS2: net.ParseIP("8.8.4.4"),
	}
	proxy := NewProxy(cfg, zerolog.Nop(), garden)

	domain := "example.com"
	ips := []net.IP{net.ParseIP("93.184.216.34")}
	proxy.cache.Set(domain+".", ips)

	msg := new(dns.Msg)
	msg.SetQuestion(domain+".", dns.TypeA)
	payload, err := msg.Pack()
	require.NoError(t, err)

	respBytes, err := proxy.HandleQuery(payload)
	require.NoError(t, err)

	resp := new(dns.Msg)
	err = resp.Unpack(respBytes)
	require.NoError(t, err)

	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	assert.Len(t, resp.Answer, 1)
	assert.Equal(t, domain+".", resp.Answer[0].Header().Name)
	assert.Equal(t, dns.TypeA, resp.Answer[0].Header().Rrtype)
	assert.Equal(t, ips[0], resp.Answer[0].(*dns.A).A)
}

func TestProxy_SecurityConsiderations(t *testing.T) {
	t.Run("should validate DNS response size", func(t *testing.T) {
		t.Skip("TODO: Implement DNS response size validation")
	})

	t.Run("should prevent DNS cache poisoning", func(t *testing.T) {
		t.Skip("TODO: Implement DNS cache poisoning prevention")
	})

	t.Run("should rate limit DNS queries per client", func(t *testing.T) {
		t.Skip("TODO: Implement per-client rate limiting")
	})

	t.Run("should validate DNS server responses", func(t *testing.T) {
		t.Skip("TODO: Implement DNS response validation")
	})
}

func TestProxy_ErrorHandling(t *testing.T) {
	t.Run("handles nil DNS1", func(t *testing.T) {
		cfg := &config.Config{}
		proxy := NewProxy(cfg, zerolog.Nop(), nil)

		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		payload, _ := msg.Pack()

		resp, err := proxy.HandleQuery(payload)
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("falls back to DNS2 on DNS1 failure", func(t *testing.T) {
		t.Skip("Requires network mocking")
	})
}

func TestProxy_GardenIntegration(t *testing.T) {
	t.Run("notifies garden of A record responses", func(t *testing.T) {
		t.Skip("Requires mock DNS server")
	})

	t.Run("notifies garden of AAAA record responses", func(t *testing.T) {
		t.Skip("Requires mock DNS server")
	})

	t.Run("does not notify garden for failed queries", func(t *testing.T) {
		garden := &mockGarden{}
		cfg := &config.Config{DNS1: net.ParseIP("192.0.2.1")}
		proxy := NewProxy(cfg, zerolog.Nop(), garden)

		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		payload, _ := msg.Pack()

		proxy.HandleQuery(payload)

		assert.Equal(t, 0, garden.callCount)
	})
}
