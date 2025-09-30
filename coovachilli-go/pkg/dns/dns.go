package dns

import (
	"coovachilli-go/pkg/config"
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

// HandleQuery processes a DNS query. This is a placeholder.
func (p *Proxy) HandleQuery(query *layers.DNS, upstreamAddr string) ([]byte, map[string]uint32, error) {
	p.logger.Debug().Str("qname", string(query.Questions[0].Name)).Msg("Handling DNS query (placeholder)")
	return nil, nil, nil
}