package main

import (
	"flag"
	"net"
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
	"coovachilli-go/pkg/disconnect"
	"coovachilli-go/pkg/icmpv6"
	"coovachilli-go/pkg/radius"
	"coovachilli-go/pkg/script"
	"coovachilli-go/pkg/tun"

	"github.com/songgao/water"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/rs/zerolog"

	"github.com/rs/zerolog/log"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/vendors/wispr"

	"coovachilli-go/pkg/auth"
)

func main() {
	// Setup structured logging
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	// Command-line flags
	configPath := flag.String("config", "config.yaml", "Path to the configuration file")
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	log.Info().Msg("Starting CoovaChilli-Go...")

	cfg, err := config.Load(*configPath)
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

	scriptRunner := script.NewRunner(log.Logger, cfg)
	sessionManager := core.NewSessionManager()

	// Load previous sessions
	if err := sessionManager.LoadSessions(cfg.StateFile); err != nil {
		log.Error().Err(err).Msg("Failed to load sessions from state file")
	} else {
		log.Info().Int("count", len(sessionManager.GetAllSessions())).Msg("Reloaded sessions from state file")
		// Re-apply firewall rules for reloaded sessions
		for _, s := range sessionManager.GetAllSessions() {
			if s.Authenticated {
				if err := fw.AddAuthenticatedUser(s.HisIP); err != nil {
					log.Error().Err(err).Str("user", s.Redir.Username).Msg("Failed to re-apply firewall rule for loaded session")
				}
			}
		}
	}

	radiusReqChan := make(chan *core.Session)
	radiusClient := radius.NewClient(cfg, log.Logger)
	disconnectManager := disconnect.NewManager(cfg, sessionManager, fw, radiusClient, scriptRunner, log.Logger)

	reaper := core.NewReaper(cfg, sessionManager, disconnectManager, log.Logger)
	reaper.Start()
	defer reaper.Stop()

	_, err = dhcp.NewServer(cfg, sessionManager, radiusReqChan, log.Logger)
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating DHCP server")
	}

	httpServer := http.NewServer(cfg, sessionManager, radiusReqChan, disconnectManager, log.Logger)
	go httpServer.Start()

	ifce, err := tun.New(cfg, log.Logger)
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating TUN interface")
	}

	packetChan := make(chan []byte)
	go tun.ReadPackets(ifce, packetChan, log.Logger)

	// Pass the TUN interface to the dispatcher so it can write packets back (for RAs)
	go processPackets(ifce, packetChan, cfg, sessionManager, log.Logger)

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
			if req.Packet.Code != layehradius.CodeDisconnectRequest {
				log.Warn().Str("code", req.Packet.Code.String()).Msg("Received unhandled CoA/DM code")
				// Send NAK
				response := req.Packet.Response(layehradius.CodeDisconnectNAK)
				radiusClient.SendCoAResponse(response, req.Peer)
				continue
			}

			// Find session to disconnect
			userName := rfc2865.UserName_GetString(req.Packet)
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
				response := req.Packet.Response(layehradius.CodeDisconnectACK)
				radiusClient.SendCoAResponse(response, req.Peer)
				continue
			}

			disconnectManager.Disconnect(sessionToDisconnect, "Admin-Reset")

			// Send ACK
			response := req.Packet.Response(layehradius.CodeDisconnectACK)
			radiusClient.SendCoAResponse(response, req.Peer)
		}
	}()

	// RADIUS processing loop
	go func() {
		for session := range radiusReqChan {
			go func(s *core.Session) {
				// Try local authentication first if enabled
				if cfg.UseLocalUsers {
					authenticated, err := auth.AuthenticateLocalUser(cfg.LocalUsersFile, s.Redir.Username, s.Redir.Password)
					if err != nil {
						log.Error().Err(err).Str("user", s.Redir.Username).Msg("Error during local authentication")
						// Fall through to RADIUS
					} else if authenticated {
						log.Info().Str("user", s.Redir.Username).Msg("Local authentication successful")
						s.Lock()
						s.Authenticated = true
						// Apply default session parameters for local users
						s.SessionParams.SessionTimeout = cfg.DefSessionTimeout
						s.SessionParams.IdleTimeout = cfg.DefIdleTimeout
						s.SessionParams.BandwidthMaxDown = cfg.DefBandwidthMaxDown
						s.SessionParams.BandwidthMaxUp = cfg.DefBandwidthMaxUp
						fw.AddAuthenticatedUser(s.HisIP)
						s.Unlock()
						s.AuthResult <- true
						return
					}
				}

				// Proceed with RADIUS authentication
				log.Info().Str("session", s.SessionID).Msg("Processing RADIUS request")
				resp, err := radiusClient.SendAccessRequest(s, s.Redir.Username, s.Redir.Password)
				if err != nil {
					log.Error().Err(err).Str("session", s.SessionID).Msg("Error sending RADIUS Access-Request")
					s.AuthResult <- false
					return
				}

				s.Lock()
				defer s.Unlock()

				if resp.Code == layehradius.CodeAccessAccept {
					log.Info().Str("user", s.Redir.Username).Msg("RADIUS Access-Accept")
					s.Authenticated = true

					// Apply RADIUS attributes, overriding defaults only if present
					if sessionTimeout, err := rfc2865.SessionTimeout_Lookup(resp); err == nil {
						s.SessionParams.SessionTimeout = uint32(sessionTimeout)
					}
					if idleTimeout, err := rfc2865.IdleTimeout_Lookup(resp); err == nil {
						s.SessionParams.IdleTimeout = uint32(idleTimeout)
					}
					if bwMaxDown, err := wispr.WISPrBandwidthMaxDown_Lookup(resp); err == nil {
						s.SessionParams.BandwidthMaxDown = uint64(bwMaxDown)
					}
					if bwMaxUp, err := wispr.WISPrBandwidthMaxUp_Lookup(resp); err == nil {
						s.SessionParams.BandwidthMaxUp = uint64(bwMaxUp)
					}

					if err := fw.AddAuthenticatedUser(s.HisIP); err != nil {
						log.Error().Err(err).Str("user", s.Redir.Username).Msg("Error adding firewall rule")
						s.AuthResult <- false // Signal failure if firewall rule fails
						return
					}

					// Send accounting start
					go radiusClient.SendAccountingRequest(s, rfc2866.AcctStatusType(1)) // 1 = Start
					// Run conup script
					scriptRunner.RunScript(cfg.ConUp, s, 0)
					s.AuthResult <- true

				} else {
					log.Warn().Str("user", s.Redir.Username).Str("code", resp.Code.String()).Msg("RADIUS Access-Reject")
					s.AuthResult <- false
				}
			}(session)
		}
	}()

func processPackets(ifce *water.Interface, packetChan <-chan []byte, cfg *config.Config, sessionManager *core.SessionManager, logger zerolog.Logger) {
	log := logger.With().Str("component", "dispatcher").Logger()
	for rawPacket := range packetChan {
		if len(rawPacket) == 0 {
			continue
		}

		var srcIP, dstIP net.IP
		var payloadLength uint64

		// Read the IP version from the first 4 bits of the packet
		ipVersion := rawPacket[0] >> 4
		packet := gopacket.NewPacket(rawPacket, layers.LayerTypeIPv4, gopacket.Lazy)

		switch ipVersion {
		case 4:
			packet = gopacket.NewPacket(rawPacket, layers.LayerTypeIPv4, gopacket.Default)
			if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
				ipv4, _ := ipv4Layer.(*layers.IPv4)
				srcIP, dstIP = ipv4.SrcIP, ipv4.DstIP
				payloadLength = uint64(len(ipv4.Payload))
				log.Debug().Str("src", srcIP.String()).Str("dst", dstIP.String()).Str("proto", ipv4.Protocol.String()).Msg("TUN In: IPv4")
			}
		case 6:
			packet = gopacket.NewPacket(rawPacket, layers.LayerTypeIPv6, gopacket.Default)
			if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
				ipv6, _ := ipv6Layer.(*layers.IPv6)
				srcIP, dstIP = ipv6.SrcIP, ipv6.DstIP
				payloadLength = uint64(len(ipv6.Payload))
				log.Debug().Str("src", srcIP.String()).Str("dst", dstIP.String()).Str("proto", ipv6.NextHeader.String()).Msg("TUN In: IPv6")

				// Check for ICMPv6 Router Solicitation
				if icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6); icmpv6Layer != nil {
					icmpv6Packet, _ := icmpv6Layer.(*layers.ICMPv6)
					if icmpv6Packet.TypeCode.Type() == layers.ICMPv6TypeRouterSolicitation {
						log.Info().Str("src", srcIP.String()).Msg("Received Router Solicitation")
						if cfg.IPv6Enable && cfg.NetV6.IP != nil {
							raPacket, err := icmpv6.BuildRouterAdvertisement(cfg, srcIP)
							if err != nil {
								log.Error().Err(err).Msg("Failed to build Router Advertisement")
							} else {
								if err := tun.WritePacket(ifce, raPacket); err != nil {
									log.Error().Err(err).Msg("Failed to send Router Advertisement")
								} else {
									log.Info().Str("dst", srcIP.String()).Msg("Sent Router Advertisement")
								}
							}
						}
						continue // Don't process RS as a session packet
					}
				}
			}
		default:
			log.Warn().Int("size", len(rawPacket)).Uint8("ipVersion", ipVersion).Msg("Received non-IP packet from TUN")
			continue
		}

		if srcIP == nil {
			continue // Couldn't parse packet
		}

		// For now, we only care about traffic originating from the client
		session, ok := sessionManager.GetSessionByIP(srcIP)
		if !ok {
			log.Debug().Str("ip", srcIP.String()).Msg("Packet from unknown source IP")
			continue
		}

		// Update session activity and stats
		session.Lock()
		session.LastSeen = time.Now()
		session.LastActivityTimeSec = core.MonotonicTime()
		session.OutputOctets += payloadLength
		session.OutputPackets++
		session.Unlock()
	}
}

	log.Info().Msg("CoovaChilli-Go is running. Press Ctrl-C to stop.")

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Info().Msg("Shutting down CoovaChilli-Go...")

	// Save active sessions to state file
	if err := sessionManager.SaveSessions(cfg.StateFile); err != nil {
		log.Error().Err(err).Msg("Failed to save sessions to state file")
	} else {
		log.Info().Msg("Successfully saved sessions to state file.")
	}

	// Perform cleanup tasks here
	// For example, send accounting stop for all active sessions
	for _, session := range sessionManager.GetAllSessions() {
		if session.Authenticated {
			disconnectManager.Disconnect(session, "NAS-Reboot")
		}
	}

	// The deferred fw.Cleanup() will run now
}