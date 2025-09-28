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

import (
	"fmt"
)

func processCommand(rawCmd string, logger zerolog.Logger, cfg *config.Config, sm sessionManagerInterface, dm disconnectManagerInterface, fw firewall.UserRuleManager, rc accountingSenderInterface) string {
	parts := strings.Fields(rawCmd)
	if len(parts) == 0 {
		return ""
	}
	cmd := parts[0]
	args := parts[1:]

	switch cmd {
	case "list":
		var b strings.Builder
		sessions := sm.GetAllSessions()
		fmt.Fprintf(&b, "Total sessions: %d\n", len(sessions))
		for _, s := range sessions {
			fmt.Fprintf(&b, "MAC: %s, IP: %s, User: %s, Authenticated: %t\n", s.HisMAC, s.HisIP, s.Redir.Username, s.Authenticated)
		}
		return b.String()
	case "logout":
		if len(args) != 1 {
			return "ERROR: Usage: logout <mac_or_ip>"
		}
		target := args[0]
		var sessionToDisconnect *core.Session
		if mac, err := net.ParseMAC(target); err == nil {
			sessionToDisconnect, _ = sm.GetSessionByMAC(mac)
		} else if ip := net.ParseIP(target); ip != nil {
			sessionToDisconnect, _ = sm.GetSessionByIP(ip)
		}

		if sessionToDisconnect != nil {
			dm.Disconnect(sessionToDisconnect, "Admin-Reset")
			return fmt.Sprintf("OK: Disconnecting user %s", target)
		}
		return fmt.Sprintf("ERROR: Could not find session to disconnect for %s", target)
	case "authorize":
		if len(args) != 1 {
			return "ERROR: Usage: authorize <mac>"
		}
		targetMAC, err := net.ParseMAC(args[0])
		if err != nil {
			return fmt.Sprintf("ERROR: Invalid MAC address provided: %s", args[0])
		}
		sessionToAuthorize, ok := sm.GetSessionByMAC(targetMAC)
		if !ok {
			return fmt.Sprintf("ERROR: Could not find session to authorize for %s", args[0])
		}

		sessionToAuthorize.Lock()
		if sessionToAuthorize.Authenticated {
			sessionToAuthorize.Unlock()
			return fmt.Sprintf("WARN: Session is already authenticated for %s", args[0])
		}

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
			return fmt.Sprintf("ERROR: Failed to apply firewall rules for authorized user %s: %v", args[0], err)
		}
		rc.SendAccountingRequest(sessionToAuthorize, rfc2866.AcctStatusType(1), "Admin-Authorize")
		return fmt.Sprintf("OK: Authorized user %s", args[0])
	case "show":
		if len(args) != 1 {
			return "ERROR: Usage: show <mac_or_ip>"
		}
		target := args[0]
		var session *core.Session
		if mac, err := net.ParseMAC(target); err == nil {
			session, _ = sm.GetSessionByMAC(mac)
		} else if ip := net.ParseIP(target); ip != nil {
			session, _ = sm.GetSessionByIP(ip)
		}

		if session != nil {
			session.RLock()
			defer session.RUnlock()
			var b strings.Builder
			fmt.Fprintf(&b, "Session Details for %s:\n", target)
			fmt.Fprintf(&b, "  User-Name: %s\n", session.Redir.Username)
			fmt.Fprintf(&b, "  IP-Address: %s\n", session.HisIP)
			fmt.Fprintf(&b, "  MAC-Address: %s\n", session.HisMAC)
			fmt.Fprintf(&b, "  Authenticated: %t\n", session.Authenticated)
			fmt.Fprintf(&b, "  Session-Time: %ds / %ds\n", core.MonotonicTime()-session.StartTimeSec, session.SessionParams.SessionTimeout)
			fmt.Fprintf(&b, "  Idle-Time: %ds / %ds\n", core.MonotonicTime()-session.LastActivityTimeSec, session.SessionParams.IdleTimeout)
			fmt.Fprintf(&b, "  Data-In: %d bytes\n", session.InputOctets)
			fmt.Fprintf(&b, "  Data-Out: %d bytes\n", session.OutputOctets)
			fmt.Fprintf(&b, "  BW-Up: %d kbit/s\n", session.SessionParams.BandwidthMaxUp/1000)
			fmt.Fprintf(&b, "  BW-Down: %d kbit/s\n", session.SessionParams.BandwidthMaxDown/1000)
			return b.String()
		}
		return fmt.Sprintf("ERROR: Could not find session for %s", target)
	case "garden":
		if len(args) < 2 {
			return "ERROR: Usage: garden <add|remove> <ip>"
		}
		subCmd := args[0]
		targetIPStr := args[1]
		targetIP := net.ParseIP(targetIPStr)
		if targetIP == nil {
			return fmt.Sprintf("ERROR: Invalid IP address: %s", targetIPStr)
		}

		switch subCmd {
		case "add":
			// Add with a TTL of 0 to make it permanent
			if err := fw.AddToWalledGarden(targetIP, 0); err != nil {
				return fmt.Sprintf("ERROR: Failed to add IP to walled garden: %v", err)
			}
			return fmt.Sprintf("OK: Added %s to walled garden", targetIPStr)
		case "remove":
			if err := fw.RemoveFromWalledGarden(targetIP); err != nil {
				return fmt.Sprintf("ERROR: Failed to remove IP from walled garden: %v", err)
			}
			return fmt.Sprintf("OK: Removed %s from walled garden", targetIPStr)
		default:
			return fmt.Sprintf("ERROR: Unknown garden command '%s'", subCmd)
		}
	default:
		return fmt.Sprintf("ERROR: Unknown command '%s'", cmd)
	}
}