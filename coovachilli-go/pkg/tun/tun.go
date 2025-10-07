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

	ifce, err := water.New(waterCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface: %w", err)
	}

	log.Info().Str("device", ifce.Name()).Msg("TUN interface created")

	// Rename the interface if a specific name is configured
	if cfg.TUNDev != "" && ifce.Name() != cfg.TUNDev {
		cmd := exec.Command("ip", "link", "set", "dev", ifce.Name(), "name", cfg.TUNDev)
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("failed to rename TUN interface: %w", err)
		}
		log.Info().Str("old", ifce.Name()).Str("new", cfg.TUNDev).Msg("TUN interface renamed")
	}

	devName := ifce.Name()
	if cfg.TUNDev != "" {
		devName = cfg.TUNDev
	}

	// Configure the IPv4 address and bring the interface up.
	// This uses the `ip` command, which is Linux-specific.
	// A more portable solution would be needed for other OSes.
	cmd := exec.Command("ip", "addr", "add", cfg.Net.String(), "dev", devName)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to set IPv4 address for TUN interface: %w", err)
	}

	// Configure IPv6 address if enabled
	if cfg.IPv6Enable && cfg.NetV6.IP != nil {
		cmd = exec.Command("ip", "-6", "addr", "add", cfg.NetV6.String(), "dev", devName)
		if err := cmd.Run(); err != nil {
			log.Error().Err(err).Msg("Failed to set IPv6 address for TUN interface, continuing with IPv4 only")
		} else {
			log.Info().Str("device", devName).Str("ipv6", cfg.NetV6.String()).Msg("IPv6 configured on TUN interface")

			// Enable IPv6 forwarding for this interface
			cmd = exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.forwarding=1", devName))
			if err := cmd.Run(); err != nil {
				log.Warn().Err(err).Msg("Failed to enable IPv6 forwarding on TUN interface")
			}

			// Disable IPv6 autoconf to prevent conflicts with DHCPv6
			cmd = exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.autoconf=0", devName))
			if err := cmd.Run(); err != nil {
				log.Warn().Err(err).Msg("Failed to disable IPv6 autoconf on TUN interface")
			}

			// Accept Router Advertisements (needed for some setups)
			cmd = exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.accept_ra=2", devName))
			if err := cmd.Run(); err != nil {
				log.Warn().Err(err).Msg("Failed to configure IPv6 RA acceptance on TUN interface")
			}
		}
	}

	cmd = exec.Command("ip", "link", "set", "dev", devName, "up")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to bring up TUN interface: %w", err)
	}

	log.Info().Str("device", devName).Msg("TUN interface configured and up")

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
