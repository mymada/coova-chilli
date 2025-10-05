package dns

import (
	"fmt"
	"net"
	"strings"

	"coovachilli-go/pkg/config"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

// GardenInterface defines the methods the DNS proxy needs from the garden service.
// This is used to break the circular dependency between dns and garden packages.
type GardenInterface interface {
	HandleDNSResponse(domain string, ips []net.IP)
}

// Proxy handles DNS proxying for unauthenticated clients.
type Proxy struct {
	cfg    *config.Config
	logger zerolog.Logger
	garden GardenInterface // Interface to the walled garden service
}

// NewProxy creates a new DNS proxy.
func NewProxy(cfg *config.Config, logger zerolog.Logger, garden GardenInterface) *Proxy {
	return &Proxy{
		cfg:    cfg,
		logger: logger.With().Str("component", "dns").Logger(),
		garden: garden,
	}
}

// HandleQuery forwards a DNS query to an upstream server and notifies the
// walled garden of the response. It takes the raw DNS query payload and returns
// the raw DNS response payload.
func (p *Proxy) HandleQuery(queryPayload []byte) ([]byte, error) {
	req := new(dns.Msg)
	if err := req.Unpack(queryPayload); err != nil {
		return nil, fmt.Errorf("failed to unpack dns query: %w", err)
	}

	if len(req.Question) == 0 {
		return nil, fmt.Errorf("received dns query with no questions")
	}

	qname := req.Question[0].Name
	p.logger.Debug().Str("qname", qname).Msg("Handling DNS query")

	// Create a new DNS client
	c := new(dns.Client)
	// Use the configured DNS servers
	upstreamAddr := net.JoinHostPort(p.cfg.DNS1.String(), "53")

	// Forward the request to the upstream server
	resp, _, err := c.Exchange(req, upstreamAddr)
	if err != nil {
		p.logger.Error().Err(err).Str("qname", qname).Msg("Failed to forward DNS query to upstream")
		// Try the secondary DNS server if the first one fails
		if p.cfg.DNS2 != nil {
			p.logger.Debug().Str("dns_server", p.cfg.DNS2.String()).Msg("Trying secondary DNS server")
			upstreamAddr = net.JoinHostPort(p.cfg.DNS2.String(), "53")
			resp, _, err = c.Exchange(req, upstreamAddr)
			if err != nil {
				p.logger.Error().Err(err).Str("qname", qname).Msg("Failed to forward DNS query to secondary upstream")
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	// If the response is successful, extract IPs and notify the garden
	if resp != nil && resp.Rcode == dns.RcodeSuccess {
		var ips []net.IP
		for _, ans := range resp.Answer {
			switch rec := ans.(type) {
			case *dns.A:
				ips = append(ips, rec.A)
			case *dns.AAAA:
				ips = append(ips, rec.AAAA)
			}
		}

		if len(ips) > 0 && p.garden != nil {
			// Trim the trailing dot from the domain name before sending to garden
			trimmedDomain := qname
			if strings.HasSuffix(qname, ".") {
				trimmedDomain = qname[:len(qname)-1]
			}
			p.garden.HandleDNSResponse(trimmedDomain, ips)
		}
	}

	// Pack the response message back into bytes
	respBytes, err := resp.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack dns response: %w", err)
	}

	return respBytes, nil
}