package dns

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"coovachilli-go/pkg/config"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

type GardenInterface interface {
	HandleDNSResponse(domain string, ips []net.IP)
}

type Proxy struct {
	cfg    *config.Config
	logger zerolog.Logger
	garden GardenInterface
	cache  *DNSCache
}

func NewProxy(cfg *config.Config, logger zerolog.Logger, garden GardenInterface) *Proxy {
	return &Proxy{
		cfg:    cfg,
		logger: logger.With().Str("component", "dns").Logger(),
		garden: garden,
		cache:  NewDNSCache(),
	}
}

func (p *Proxy) HandleQuery(queryPayload []byte) ([]byte, error) {
	req := new(dns.Msg)
	if err := req.Unpack(queryPayload); err != nil {
		p.logger.Error().Err(err).Msg("Failed to unpack DNS query")
		return nil, fmt.Errorf("failed to unpack DNS query: %w", err)
	}

	if len(req.Question) == 0 {
		p.logger.Error().Msg("Received DNS query with no questions")
		return nil, fmt.Errorf("received DNS query with no questions")
	}

	qname := req.Question[0].Name
	p.logger.Debug().Str("qname", qname).Msg("Handling DNS query")

	if !isValidDomain(qname) {
		p.logger.Error().Str("qname", qname).Msg("Invalid domain name in DNS query")
		return nil, fmt.Errorf("invalid domain name in DNS query")
	}

	if ips, ok := p.cache.Get(qname); ok {
		resp := new(dns.Msg)
		resp.SetReply(req)
		for _, ip := range ips {
			if ip.To4() != nil {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   ip,
				})
			} else {
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
					AAAA: ip,
				})
			}
		}
		respBytes, err := resp.Pack()
		if err != nil {
			return nil, fmt.Errorf("failed to pack cached dns response: %w", err)
		}
		return respBytes, nil
	}

	encryptedPayload, err := encryptPayload(queryPayload)
	if err != nil {
		p.logger.Error().Err(err).Msg("Failed to encrypt DNS query payload")
		return nil, fmt.Errorf("failed to encrypt DNS query payload: %w", err)
	}

	upstreamAddrs := []string{net.JoinHostPort(p.cfg.DNS1.String(), "53")}
	if p.cfg.DNS2 != nil {
		upstreamAddrs = append(upstreamAddrs, net.JoinHostPort(p.cfg.DNS2.String(), "53"))
	}

	var resp *dns.Msg
	var lastErr error

	for _, addr := range upstreamAddrs {
		p.logger.Debug().Str("dns_server", addr).Msg("Trying DNS server")

		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
		}
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			p.logger.Error().Err(err).Str("dns_server", addr).Msg("Failed to connect to DNS server")
			lastErr = err
			continue
		}
		defer conn.Close()

		_, err = conn.Write(encryptedPayload)
		if err != nil {
			p.logger.Error().Err(err).Msg("Failed to send DNS query payload")
			lastErr = err
			continue
		}

		respBytes, err := io.ReadAll(conn)
		if err != nil {
			p.logger.Error().Err(err).Msg("Failed to read DNS response payload")
			lastErr = err
			continue
		}

		decryptedPayload, err := decryptPayload(respBytes)
		if err != nil {
			p.logger.Error().Err(err).Msg("Failed to decrypt DNS response payload")
			lastErr = err
			continue
		}

		resp = new(dns.Msg)
		if err := resp.Unpack(decryptedPayload); err != nil {
			p.logger.Error().Err(err).Msg("Failed to unpack DNS response")
			lastErr = err
			continue
		}
		if !isValidDNSResponse(resp) {
			p.logger.Error().Msg("Invalid DNS response")
			lastErr = fmt.Errorf("invalid DNS response")
			continue
		}

		break
	}

	if lastErr != nil && resp == nil {
		p.logger.Error().Err(lastErr).Str("qname", qname).Msg("Failed to forward DNS query to all upstream servers")
		return nil, fmt.Errorf("failed to forward DNS query: %w", lastErr)
	}

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
		if len(ips) > 0 {
			domain := strings.TrimSuffix(qname, ".")
			p.cache.Set(qname, ips)
			if p.garden != nil {
				p.garden.HandleDNSResponse(domain, ips)
			}
		}
	}

	respBytes, err := resp.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack dns response: %w", err)
	}
	return respBytes, nil
}

func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	for _, c := range domain {
		if !isValidDomainChar(c) {
			return false
		}
	}
	return true
}

func isValidDomainChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
	       (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') ||
	       c == '.' || c == '-' || c == '_'
}

type DNSCache struct {
	cache map[string][]net.IP
	mu    sync.Mutex
}

func NewDNSCache() *DNSCache {
	return &DNSCache{
		cache: make(map[string][]net.IP),
	}
}

func (c *DNSCache) Get(domain string) ([]net.IP, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ips, ok := c.cache[domain]
	return ips, ok
}

func (c *DNSCache) Set(domain string, ips []net.IP) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[domain] = ips
}

func encryptPayload(payload []byte) ([]byte, error) {
	// TODO: Implement proper encryption
	return payload, nil
}

func decryptPayload(payload []byte) ([]byte, error) {
	// TODO: Implement proper decryption
	return payload, nil
}

func isValidDNSResponse(resp *dns.Msg) bool {
	if resp == nil {
		return false
	}
	// Basic validation
	return resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError
}
