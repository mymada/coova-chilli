package main

import (
	"net"
	"strings"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/firewall"
	"github.com/rs/zerolog"
	"layeh.com/radius/rfc2866"
)

func processCommand(rawCmd string, logger zerolog.Logger, cfg *config.Config, sm sessionManagerInterface, dm disconnectManagerInterface, fw firewall.UserRuleManager, rc accountingSenderInterface) {
	parts := strings.Fields(rawCmd)
	if len(parts) == 0 {
		return
	}
	cmd := parts[0]
	args := parts[1:]

	switch cmd {
	case "list":
		logger.Info().Msg("--- Active Sessions ---")
		for _, s := range sm.GetAllSessions() {
			logger.Info().
				Str("user", s.Redir.Username).
				Str("ip", s.HisIP.String()).
				Str("mac", s.HisMAC.String()).
				Time("started", s.StartTime).
				Msg("Session")
		}
		logger.Info().Msg("-----------------------")
	case "logout":
		if len(args) != 1 {
			logger.Warn().Msg("Usage: logout <mac_or_ip>")
			return
		}
		target := args[0]
		var sessionToDisconnect *core.Session
		if mac, err := net.ParseMAC(target); err == nil {
			sessionToDisconnect, _ = sm.GetSessionByMAC(mac)
		} else if ip := net.ParseIP(target); ip != nil {
			sessionToDisconnect, _ = sm.GetSessionByIP(ip)
		}
		if sessionToDisconnect != nil {
			logger.Info().Str("target", target).Msg("Disconnecting user by admin command")
			dm.Disconnect(sessionToDisconnect, "Admin-Reset")
		} else {
			logger.Warn().Str("target", target).Msg("Could not find session to disconnect")
		}
	case "authorize":
		if len(args) != 1 {
			logger.Warn().Msg("Usage: authorize <mac>")
			return
		}
		targetMAC, err := net.ParseMAC(args[0])
		if err != nil {
			logger.Warn().Err(err).Msg("Invalid MAC address provided for authorize command")
			return
		}
		sessionToAuthorize, ok := sm.GetSessionByMAC(targetMAC)
		if !ok {
			logger.Warn().Str("mac", args[0]).Msg("Could not find session to authorize")
			return
		}
		sessionToAuthorize.Lock()
		if sessionToAuthorize.Authenticated {
			logger.Warn().Str("mac", args[0]).Msg("Session is already authenticated")
			sessionToAuthorize.Unlock()
			return
		}
		logger.Info().Str("mac", args[0]).Msg("Authorizing user by admin command")
		sessionToAuthorize.Authenticated = true
		sessionToAuthorize.SessionParams.SessionTimeout = cfg.DefSessionTimeout
		sessionToAuthorize.SessionParams.IdleTimeout = cfg.DefIdleTimeout
		sessionToAuthorize.SessionParams.BandwidthMaxDown = cfg.DefBandwidthMaxDown
		sessionToAuthorize.SessionParams.BandwidthMaxUp = cfg.DefBandwidthMaxUp
		bwUp := sessionToAuthorize.SessionParams.BandwidthMaxUp
		bwDown := sessionToAuthorize.SessionParams.BandwidthMaxDown
		sessionIP := sessionToAuthorize.HisIP
		sessionToAuthorize.Unlock()
		if err := fw.AddAuthenticatedUser(sessionIP, bwUp, bwDown); err != nil {
			logger.Error().Err(err).Str("mac", args[0]).Msg("Failed to apply firewall rules for authorized user")
		}
		rc.SendAccountingRequest(sessionToAuthorize, rfc2866.AcctStatusType(1), "Admin-Authorize")
	default:
		logger.Warn().Str("cmd", cmd).Msg("Unknown command")
	}
}