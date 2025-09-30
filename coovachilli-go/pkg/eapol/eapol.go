package eapol

import (
	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"github.com/gopacket/gopacket"
	"github.com/rs/zerolog"
)

// Handler handles EAPOL (802.1X) traffic.
type Handler struct {
	cfg    *config.Config
	sm     *core.SessionManager
	logger zerolog.Logger
}

// NewHandler creates a new EAPOL handler.
func NewHandler(cfg *config.Config, sm *core.SessionManager, logger zerolog.Logger) *Handler {
	return &Handler{
		cfg:    cfg,
		sm:     sm,
		logger: logger.With().Str("component", "eapol").Logger(),
	}
}

// HandlePacket processes an EAPOL packet. This is a placeholder.
func (h *Handler) HandlePacket(packet gopacket.Packet) {
	h.logger.Debug().Msg("Handling EAPOL packet (placeholder)")
}