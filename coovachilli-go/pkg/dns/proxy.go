package dns

import (
	"fmt"
	"net"
	"strings"

	"coovachilli-go/pkg/config"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/rs/zerolog"
)

// Proxy handles DNS proxying for the walled garden.
type Proxy struct {
	cfg    *config.Config
	logger zerolog.Logger
}

// NewProxy creates a new DNS proxy.
func NewProxy(cfg *config.Config, logger zerolog.Logger) *Proxy {
	return &Proxy{
		cfg:    cfg,
		logger: logger.With().Str("component", "dns_proxy").Logger(),
	}
}

// HandleQuery forwards a DNS query to an upstream server if the domain is allowed.
// It returns the response packet and a map of resolved IPs (as strings) to their TTLs.
func (p *Proxy) HandleQuery(query *layers.DNS) ([]byte, map[string]uint32, error) {
	if len(query.Questions) == 0 {
		return nil, nil, fmt.Errorf("DNS query has no questions")
	}
	question := query.Questions[0]
	domain := string(question.Name)

	allowed := false
	for _, allowedDomain := range p.cfg.UAMDomains {
		if strings.HasSuffix(domain, allowedDomain) {
			allowed = true
			break
		}
	}

	if !allowed {
		p.logger.Debug().Str("domain", domain).Msg("Domain not in walled garden, dropping DNS query")
		return nil, nil, nil // Not an error, just not handling it.
	}

	p.logger.Info().Str("domain", domain).Msg("Forwarding allowed DNS query to upstream")

	conn, err := net.Dial("udp", p.cfg.DNS1.String()+":53")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to upstream DNS server: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Write(query.BaseLayer.Contents); err != nil {
		return nil, nil, fmt.Errorf("failed to send DNS query upstream: %w", err)
	}

	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read DNS response from upstream: %w", err)
	}

	responseBytes := buffer[:n]
	p.logger.Info().Str("domain", domain).Int("bytes", n).Msg("Received DNS response from upstream")

	resolvedIPs := make(map[string]uint32)
	dnsResponse := &layers.DNS{}
	if err := dnsResponse.DecodeFromBytes(responseBytes, gopacket.NilDecodeFeedback); err == nil {
		for _, ans := range dnsResponse.Answers {
			if ans.Type == layers.DNSTypeA {
				resolvedIPs[ans.IP.String()] = ans.TTL
				p.logger.Debug().Str("domain", domain).Str("ip", ans.IP.String()).Uint32("ttl", ans.TTL).Msg("Resolved IPv4 address")
			}
		}
	} else {
		p.logger.Warn().Err(err).Msg("Failed to decode DNS response from upstream")
	}

	return responseBytes, resolvedIPs, nil
}