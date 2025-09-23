package tun

import (
	"fmt"
	"os/exec"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
	"github.com/songgao/water"
)

// New creates and configures a new TUN interface.
func New(cfg *config.Config, logger zerolog.Logger) (*water.Interface, error) {
	log := logger.With().Str("component", "tun").Logger()

	waterCfg := water.Config{
		DeviceType: water.TUN,
	}
	waterCfg.Name = cfg.TUNDev

	ifce, err := water.New(waterCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface: %w", err)
	}

	log.Info().Str("device", ifce.Name()).Msg("TUN interface created")

	// Configure the IP address and bring the interface up.
	// This uses the `ip` command, which is Linux-specific.
	// A more portable solution would be needed for other OSes.
	cmd := exec.Command("ip", "addr", "add", cfg.Net.String(), "dev", ifce.Name())
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to set IP address for TUN interface: %w", err)
	}

	cmd = exec.Command("ip", "link", "set", "dev", ifce.Name(), "up")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to bring up TUN interface: %w", err)
	}

	log.Info().Str("device", ifce.Name()).Msg("TUN interface configured and up")

	return ifce, nil
}

// ReadPackets reads packets from the TUN interface and sends them to the dispatcher.
func ReadPackets(ifce *water.Interface, dispatch chan<- []byte, logger zerolog.Logger) {
	log := logger.With().Str("component", "tun").Logger()
	packet := make([]byte, 1500)
	for {
		n, err := ifce.Read(packet)
		if err != nil {
			log.Error().Err(err).Msg("Error reading from TUN interface")
			continue
		}
		dispatch <- packet[:n]
	}
}

// WritePacket writes a packet to the TUN interface.
func WritePacket(ifce *water.Interface, packet []byte) error {
	_, err := ifce.Write(packet)
	if err != nil {
		return fmt.Errorf("failed to write to TUN interface: %w", err)
	}
	return nil
}
