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

// Proxy handles DNS proxying for unauthenticated clients.
type Proxy struct {
	cfg    *config.Config
	logger zerolog.Logger
}

// NewProxy creates a new DNS proxy.
func NewProxy(cfg *config.Config, logger zerolog.Logger) *Proxy {
	return &Proxy{
		cfg:    cfg,
		logger: logger.With().Str("component", "dns").Logger(),
	}
}

// isAllowed checks if a domain is in the walled garden.
func (p *Proxy) isAllowed(domain string) bool {
	// Check exact domain matches and subdomains in uamdomains
	for _, allowedDomain := range p.cfg.UAMDomains {
		if strings.HasSuffix(domain, "."+allowedDomain) || domain == allowedDomain {
			return true
		}
	}

	// Check regex matches
	for _, re := range p.cfg.UAMRegexCompiled {
		if re.MatchString(domain) {
			return true
		}
	}

	return false
}

// HandleQuery processes a DNS query. It checks against the walled garden rules.
// If the domain is allowed, it proxies the request.
// Otherwise, it returns the captive portal's IP address.
func (p *Proxy) HandleQuery(query *layers.DNS, upstreamAddr string) ([]byte, map[string]uint32, error) {
	if len(query.Questions) == 0 {
		return nil, nil, fmt.Errorf("no questions in DNS query")
	}

	question := query.Questions[0]
	domain := string(question.Name)

	p.logger.Debug().Str("domain", domain).Msg("Processing DNS query for walled garden check")

	if p.isAllowed(domain) {
		p.logger.Debug().Str("domain", domain).Msg("Domain is in walled garden, proxying request")
		return p.proxyRequest(query, upstreamAddr)
	}

	p.logger.Debug().Str("domain", domain).Msg("Domain not in walled garden, redirecting to captive portal")
	return p.forgeResponse(query), nil, nil
}

// proxyRequest sends the query to a real DNS server and returns the response.
func (p *Proxy) proxyRequest(query *layers.DNS, upstreamAddr string) ([]byte, map[string]uint32, error) {
	conn, err := net.Dial("udp", upstreamAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to upstream DNS: %w", err)
	}
	defer conn.Close()

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err = gopacket.SerializeLayers(buf, opts, query)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize DNS query: %w", err)
	}

	if _, err := conn.Write(buf.Bytes()); err != nil {
		return nil, nil, fmt.Errorf("failed to write DNS query to upstream: %w", err)
	}

	respBuf := make([]byte, 512)
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read DNS response from upstream: %w", err)
	}

	return respBuf[:n], nil, nil // No caching implemented yet
}

// forgeResponse creates a fake DNS response pointing to the captive portal.
func (p *Proxy) forgeResponse(query *layers.DNS) []byte {
	response := *query
	response.QR = true
	response.ANCount = 1
	response.ResponseCode = layers.DNSResponseCodeNoErr

	answer := layers.DNSResourceRecord{
		Name:  query.Questions[0].Name,
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
		TTL:   60,
		IP:    p.cfg.UAMListen,
	}
	response.Answers = []layers.DNSResourceRecord{answer}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// We only need to serialize the DNS layer, the upper layers will be reconstructed by the caller.
	err := gopacket.SerializeLayers(buf, opts, &response)
	if err != nil {
		p.logger.Error().Err(err).Msg("Failed to serialize forged DNS response")
		return nil
	}

	return buf.Bytes()
}