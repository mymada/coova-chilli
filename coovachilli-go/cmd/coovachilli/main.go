package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/dhcp"
	"coovachilli-go/pkg/firewall"
	"coovachilli-go/pkg/cmdsock"
	"coovachilli-go/pkg/http"
	"coovachilli-go/pkg/radius"
	"coovachilli-go/pkg/tun"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"encoding/binary"

	"github.com/rs/zerolog/log"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

const (
	WISPrVendorID = 14122
	WISPrBandwidthMaxDown = 7
	WISPrBandwidthMaxUp = 8
)

func main() {
	// Setup structured logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	log.Info().Msg("Starting CoovaChilli-Go...")

	cfg, err := config.Load("coovachilli-go/config.yaml")
	if err != nil {
		log.Fatal().Err(err).Msg("Error loading configuration")
	}

	fw, err := firewall.NewFirewall(cfg, log.Logger)
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating firewall manager")
	}
	if err := fw.Initialize(); err != nil {
		log.Fatal().Err(err).Msg("Error initializing firewall")
	}
	defer fw.Cleanup()

	sessionManager := core.NewSessionManager()
	radiusReqChan := make(chan *core.Session)
	radiusClient := radius.NewClient(cfg, log.Logger)

	_, err = dhcp.NewServer(cfg, sessionManager, radiusReqChan, log.Logger)
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating DHCP server")
	}

	httpServer := http.NewServer(cfg, sessionManager, radiusReqChan, radiusClient, fw, log.Logger)
	go httpServer.Start()

	ifce, err := tun.New(cfg, log.Logger)
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating TUN interface")
	}

	packetChan := make(chan []byte)
	go tun.ReadPackets(ifce, packetChan, log.Logger)

	cmdChan := make(chan string)
	cmdSockListener := cmdsock.NewListener(cfg.CmdSockPath, cmdChan, log.Logger)
	go cmdSockListener.Start()

	coaReqChan := make(chan radius.CoAIncomingRequest)
	go radiusClient.StartCoAListener(coaReqChan)

	// Command socket processing loop
	go func() {
		for cmd := range cmdChan {
			if cmd == "list" {
				log.Info().Msg("--- Active Sessions ---")
				for _, s := range sessionManager.GetAllSessions() {
					log.Info().
						Str("user", s.Redir.Username).
						Str("ip", s.HisIP.String()).
						Str("mac", s.HisMAC.String()).
						Time("started", s.StartTime).
						Msg("Session")
				}
				log.Info().Msg("-----------------------")
			} else {
				log.Warn().Str("cmd", cmd).Msg("Unknown command")
			}
		}
	}()

	// CoA processing loop
	go func() {
		for req := range coaReqChan {
			// For now, we only handle Disconnect-Request
			if req.Packet.Code != radius.CodeDisconnectRequest {
				log.Warn().Str("code", req.Packet.Code.String()).Msg("Received unhandled CoA/DM code")
				// Send NAK
				response := req.Packet.Response(radius.CodeDisconnectNAK)
				radiusClient.SendCoAResponse(response, req.Peer)
				continue
			}

			// Find session to disconnect
			userName, _ := rfc2865.UserName_GetString(req.Packet)
			// TODO: Also support finding by NAS-Port-Id, Acct-Session-Id, etc.
			var sessionToDisconnect *core.Session
			for _, s := range sessionManager.GetAllSessions() {
				if s.Redir.Username == userName {
					sessionToDisconnect = s
					break
				}
			}

			if sessionToDisconnect == nil {
				log.Warn().Str("user", userName).Msg("Received Disconnect-Request for unknown user")
				// Per RFC, if user is unknown, send ACK
				response := req.Packet.Response(radius.CodeDisconnectACK)
				radiusClient.SendCoAResponse(response, req.Peer)
				continue
			}

			log.Info().Str("user", userName).Msg("Disconnecting user per RADIUS request")
			// Terminate the session
			go radiusClient.SendAccountingRequest(sessionToDisconnect, rfc2866.AcctStatusType_Stop)
			if err := fw.RemoveAuthenticatedUser(sessionToDisconnect.HisIP); err != nil {
				log.Error().Err(err).Str("user", userName).Msg("Failed to remove firewall rules for disconnected user")
			}
			sessionManager.DeleteSession(sessionToDisconnect)

			// Send ACK
			response := req.Packet.Response(radius.CodeDisconnectACK)
			radiusClient.SendCoAResponse(response, req.Peer)
		}
	}()

	// RADIUS processing loop
	go func() {
		for session := range radiusReqChan {
			log.Info().Str("session", session.SessionID).Msg("Processing RADIUS request")
			resp, err := radiusClient.SendAccessRequest(session, session.Redir.Username, session.Redir.Password)
			if err != nil {
				log.Error().Err(err).Str("session", session.SessionID).Msg("Error sending RADIUS Access-Request")
				session.AuthResult <- false
				continue
			}

			if resp.Code == "Access-Accept" {
				log.Info().Str("user", session.Redir.Username).Msg("RADIUS Access-Accept")

				// Parse attributes from the response
				session.Lock()
				session.Authenticated = true
				if sessionTimeout, err := rfc2865.SessionTimeout_Get(resp.Packet); err == nil {
					session.SessionParams.SessionTimeout = uint32(sessionTimeout)
					log.Info().Uint32("timeout", session.SessionParams.SessionTimeout).Msg("Parsed Session-Timeout")
				}
				if idleTimeout, err := rfc2865.IdleTimeout_Get(resp.Packet); err == nil {
					session.SessionParams.IdleTimeout = uint32(idleTimeout)
					log.Info().Uint32("timeout", session.SessionParams.IdleTimeout).Msg("Parsed Idle-Timeout")
				}

				// Parse WISPr bandwidth attributes
				if vsa, err := radius.GetVendor(resp.Packet, WISPrVendorID, WISPrBandwidthMaxDown); err == nil && len(vsa) == 4 {
					session.SessionParams.BandwidthMaxDown = uint64(binary.BigEndian.Uint32(vsa))
					log.Info().Uint64("kbits", session.SessionParams.BandwidthMaxDown).Msg("Parsed WISPr-Bandwidth-Max-Down")
				}
				if vsa, err := radius.GetVendor(resp.Packet, WISPrVendorID, WISPrBandwidthMaxUp); err == nil && len(vsa) == 4 {
					session.SessionParams.BandwidthMaxUp = uint64(binary.BigEndian.Uint32(vsa))
					log.Info().Uint64("kbits", session.SessionParams.BandwidthMaxUp).Msg("Parsed WISPr-Bandwidth-Max-Up")
				}

				session.Unlock()

				if err := fw.AddAuthenticatedUser(session.HisIP); err != nil {
					log.Error().Err(err).Str("user", session.Redir.Username).Msg("Error adding firewall rule")
					session.AuthResult <- false // Signal failure if firewall rule fails
					continue
				}

				// Send accounting start
				go radiusClient.SendAccountingRequest(session, rfc2866.AcctStatusType_Start)
				session.AuthResult <- true
			} else {
				log.Warn().Str("user", session.Redir.Username).Str("code", string(resp.Code)).Msg("RADIUS Access-Reject")
				session.AuthResult <- false
			}
		}
	}()

	// Packet dispatcher
	go func() {
		for rawPacket := range packetChan {
			packet := gopacket.NewPacket(rawPacket, layers.LayerTypeIPv4, gopacket.Default)
			if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
				ipv4, _ := ipv4Layer.(*layers.IPv4)
				log.Debug().
					Str("src", ipv4.SrcIP.String()).
					Str("dst", ipv4.DstIP.String()).
					Str("proto", ipv4.Protocol.String()).
					Msg("TUN In: IPv4 packet")

			} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
				ipv6, _ := ipv6Layer.(*layers.IPv6)
				log.Debug().
					Str("src", ipv6.SrcIP.String()).
					Str("dst", ipv6.DstIP.String()).
					Str("proto", ipv6.NextHeader.String()).
					Msg("TUN In: IPv6 packet")
			} else {
				log.Warn().Int("size", len(rawPacket)).Msg("Received non-IP packet from TUN")
			}
		}
	}()

	log.Info().Msg("CoovaChilli-Go is running. Press Ctrl-C to stop.")

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Info().Msg("Shutting down CoovaChilli-Go...")

	// Perform cleanup tasks here
	// For example, send accounting stop for all active sessions
	for _, session := range sessionManager.GetAllSessions() {
		if session.Authenticated {
			radiusClient.SendAccountingRequest(session, rfc2866.AcctStatusType_Stop)
		}
	}

	// The deferred fw.Cleanup() will run now
}
