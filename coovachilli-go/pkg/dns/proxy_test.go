package dns

import (
	"net"
	"testing"
	"time"

	"coovachilli-go/pkg/config"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// startMockDNSServer starts a simple UDP server to act as an upstream DNS resolver.
func startMockDNSServer(t *testing.T, responsePacket []byte) (net.Addr, func()) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 1024)
		_ = pc.SetReadDeadline(time.Now().Add(1 * time.Second))
		_, addr, err := pc.ReadFrom(buffer)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(responsePacket, addr)
	}()

	closeFunc := func() {
		pc.Close()
		<-done
	}

	return pc.LocalAddr(), closeFunc
}

func buildMockResponse(t *testing.T) []byte {
	responseDNS := &layers.DNS{
		ID:           1234,
		QR:           true,
		OpCode:       layers.DNSOpCodeQuery,
		ResponseCode: layers.DNSResponseCodeNoErr,
		Questions: []layers.DNSQuestion{
			{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
		Answers: []layers.DNSResourceRecord{
			{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 300, IP: net.ParseIP("93.184.216.34")},
			{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 150, IP: net.ParseIP("1.2.3.4")},
		},
	}
	buf := gopacket.NewSerializeBuffer()
	// Using FixLengths ensures the packet is well-formed for the parser.
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := responseDNS.SerializeTo(buf, opts)
	require.NoError(t, err)
	return buf.Bytes()
}

func buildQuery(t *testing.T, id uint16, domain string) *layers.DNS {
	queryDNS := &layers.DNS{
		ID:        id,
		QR:        false,
		OpCode:    layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{{Name: []byte(domain), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
	}
	queryBuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := queryDNS.SerializeTo(queryBuf, opts)
	require.NoError(t, err)
	queryDNS.BaseLayer.Contents = queryBuf.Bytes()
	return queryDNS
}

func TestDNSProxy_HandleQuery(t *testing.T) {
	logger := zerolog.Nop()
	cfg := &config.Config{
		UAMDomains: []string{"example.com", "test.org"},
	}
	proxy := NewProxy(cfg, logger)

	t.Run("Allowed Domain", func(t *testing.T) {
		mockResponsePacket := buildMockResponse(t)
		mockServerAddr, stopMockServer := startMockDNSServer(t, mockResponsePacket)
		defer stopMockServer()

		queryDNS := buildQuery(t, 1234, "example.com")

		respBytes, resolvedIPs, err := proxy.HandleQuery(queryDNS, mockServerAddr.String())
		require.NoError(t, err)
		require.NotNil(t, respBytes)

		expectedIPs := map[string]uint32{
			"93.184.216.34": 300,
			"1.2.3.4":       150,
		}
		require.Equal(t, expectedIPs, resolvedIPs)
	})

	t.Run("Disallowed Domain", func(t *testing.T) {
		queryDNS := buildQuery(t, 5678, "google.com")
		respBytes, resolvedIPs, err := proxy.HandleQuery(queryDNS, "127.0.0.1:53")
		require.NoError(t, err)
		require.Nil(t, respBytes)
		require.Nil(t, resolvedIPs)
	})

	t.Run("Allowed Subdomain", func(t *testing.T) {
		mockResponsePacket := buildMockResponse(t)
		mockServerAddr, stopMockServer := startMockDNSServer(t, mockResponsePacket)
		defer stopMockServer()

		queryDNS := buildQuery(t, 4321, "www.example.com")

		respBytes, _, err := proxy.HandleQuery(queryDNS, mockServerAddr.String())
		require.NoError(t, err)
		require.NotNil(t, respBytes)
	})
}