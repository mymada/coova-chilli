package main

import (
	"flag"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/dhcp"
	"coovachilli-go/pkg/dns"
	"coovachilli-go/pkg/firewall"
	"fmt"
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
	dnsProxy := dns.NewProxy(cfg, log.Logger)

	// Load previous sessions
	if err := sessionManager.LoadSessions(cfg.StateFile); err != nil {
		log.Error().Err(err).Msg("Failed to load sessions from state file")
	} else {
		log.Info().Int("count", len(sessionManager.GetAllSessions())).Msg("Reloaded sessions from state file")
		// Re-apply firewall rules for reloaded sessions
		for _, s := range sessionManager.GetAllSessions() {
			if s.Authenticated {
				if err := fw.AddAuthenticatedUser(s.HisIP, s.SessionParams.BandwidthMaxUp, s.SessionParams.BandwidthMaxDown); err != nil {
					log.Error().Err(err).Str("user", s.Redir.Username).Msg("Failed to re-apply firewall rule for loaded session")
				}
			}
		}
	}

	radiusReqChan := make(chan *core.Session)
	radiusClient := radius.NewClient(cfg, log.Logger)
	disconnectManager := disconnect.NewManager(cfg, sessionManager, fw, radiusClient, scriptRunner, log.Logger)

	reaper := core.NewReaper(cfg, sessionManager, disconnectManager, radiusClient, log.Logger)
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
	go processPackets(ifce, packetChan, cfg, sessionManager, dnsProxy, fw, log.Logger)

	cmdChan := make(chan string)
	cmdSockListener := cmdsock.NewListener(cfg.CmdSockPath, cmdChan, log.Logger)
	go cmdSockListener.Start()

	coaReqChan := make(chan radius.CoAIncomingRequest)
	go radiusClient.StartCoAListener(coaReqChan)

	// Command socket processing loop
	go func() {
		for rawCmd := range cmdChan {
			parts := strings.Fields(rawCmd)
			if len(parts) == 0 {
				continue
			}
			cmd := parts[0]
			args := parts[1:]

			switch cmd {
			case "list":
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
			// Placeholder for future commands
			case "logout":
				if len(args) != 1 {
					log.Warn().Msg("Usage: logout <mac_or_ip>")
					continue
				}
				target := args[0]
				var sessionToDisconnect *core.Session

				// Try parsing as MAC address first
				if mac, err := net.ParseMAC(target); err == nil {
					sessionToDisconnect, _ = sessionManager.GetSessionByMAC(mac)
				} else if ip := net.ParseIP(target); ip != nil {
					// Try parsing as IP address
					sessionToDisconnect, _ = sessionManager.GetSessionByIP(ip)
				}

				if sessionToDisconnect != nil {
					log.Info().Str("target", target).Msg("Disconnecting user by admin command")
					disconnectManager.Disconnect(sessionToDisconnect, "Admin-Reset")
				} else {
					log.Warn().Str("target", target).Msg("Could not find session to disconnect")
				}

			case "authorize":
				if len(args) != 1 {
					log.Warn().Msg("Usage: authorize <mac>")
					continue
				}
				targetMAC, err := net.ParseMAC(args[0])
				if err != nil {
					log.Warn().Err(err).Msg("Invalid MAC address provided for authorize command")
					continue
				}

				sessionToAuthorize, ok := sessionManager.GetSessionByMAC(targetMAC)
				if !ok {
					log.Warn().Str("mac", args[0]).Msg("Could not find session to authorize")
					continue
				}

				sessionToAuthorize.Lock()
				if sessionToAuthorize.Authenticated {
					log.Warn().Str("mac", args[0]).Msg("Session is already authenticated")
					sessionToAuthorize.Unlock()
					continue
				}

				log.Info().Str("mac", args[0]).Msg("Authorizing user by admin command")
				sessionToAuthorize.Authenticated = true
				// Apply default session parameters
				sessionToAuthorize.SessionParams.SessionTimeout = cfg.DefSessionTimeout
				sessionToAuthorize.SessionParams.IdleTimeout = cfg.DefIdleTimeout
				sessionToAuthorize.SessionParams.BandwidthMaxDown = cfg.DefBandwidthMaxDown
				sessionToAuthorize.SessionParams.BandwidthMaxUp = cfg.DefBandwidthMaxUp

				bwUp := sessionToAuthorize.SessionParams.BandwidthMaxUp
				bwDown := sessionToAuthorize.SessionParams.BandwidthMaxDown
				sessionIP := sessionToAuthorize.HisIP

				sessionToAuthorize.Unlock()

				// Grant network access
				if err := fw.AddAuthenticatedUser(sessionIP, bwUp, bwDown); err != nil {
					log.Error().Err(err).Str("mac", args[0]).Msg("Failed to apply firewall rules for authorized user")
					// Revert auth status on failure? For now, just log.
				}

				// Send accounting start
				go radiusClient.SendAccountingRequest(sessionToAuthorize, rfc2866.AcctStatusType(1), "Admin-Authorize")

			default:
				log.Warn().Str("cmd", cmd).Msg("Unknown command")
			}
		}
	}()

	// CoA processing loop
	go func() {
		for req := range coaReqChan {
			userName := rfc2865.UserName_GetString(req.Packet)
			// TODO: Also support finding by NAS-Port-Id, Acct-Session-Id, etc.
			var sessionToUpdate *core.Session
			for _, s := range sessionManager.GetAllSessions() {
				if s.Redir.Username == userName {
					sessionToUpdate = s
					break
				}
			}

			if sessionToUpdate == nil {
				log.Warn().Str("user", userName).Msg("Received CoA/Disconnect request for unknown user")
				// Per RFC, if user is unknown, send ACK for Disconnect and NAK for CoA
				var response *layehradius.Packet
				if req.Packet.Code == layehradius.CodeDisconnectRequest {
					response = req.Packet.Response(layehradius.CodeDisconnectACK)
				} else {
					response = req.Packet.Response(layehradius.CodeCoANAK)
				}
				radiusClient.SendCoAResponse(response, req.Peer)
				continue
			}

			switch req.Packet.Code {
			case layehradius.CodeDisconnectRequest:
				log.Info().Str("user", userName).Msg("Received Disconnect-Request")
				disconnectManager.Disconnect(sessionToUpdate, "Admin-Reset")
				response := req.Packet.Response(layehradius.CodeDisconnectACK)
				radiusClient.SendCoAResponse(response, req.Peer)

			case layehradius.CodeCoARequest:
				log.Info().Str("user", userName).Msg("Received CoA-Request, updating session parameters")

				sessionToUpdate.Lock()
				// Apply RADIUS attributes from CoA packet
				if sessionTimeout, err := rfc2865.SessionTimeout_Lookup(req.Packet); err == nil {
					log.Debug().Str("user", userName).Uint32("timeout", uint32(sessionTimeout)).Msg("Updating Session-Timeout")
					sessionToUpdate.SessionParams.SessionTimeout = uint32(sessionTimeout)
				}
				if idleTimeout, err := rfc2865.IdleTimeout_Lookup(req.Packet); err == nil {
					log.Debug().Str("user", userName).Uint32("timeout", uint32(idleTimeout)).Msg("Updating Idle-Timeout")
					sessionToUpdate.SessionParams.IdleTimeout = uint32(idleTimeout)
				}
				if bwMaxDown, err := wispr.WISPrBandwidthMaxDown_Lookup(req.Packet); err == nil {
					log.Debug().Str("user", userName).Uint64("bw", uint64(bwMaxDown)).Msg("Updating Bandwidth-Max-Down")
					sessionToUpdate.SessionParams.BandwidthMaxDown = uint64(bwMaxDown)
				}
				if bwMaxUp, err := wispr.WISPrBandwidthMaxUp_Lookup(req.Packet); err == nil {
					log.Debug().Str("user", userName).Uint64("bw", uint64(bwMaxUp)).Msg("Updating Bandwidth-Max-Up")
					sessionToUpdate.SessionParams.BandwidthMaxUp = uint64(bwMaxUp)
				}
				// Get the newly set bandwidth values
				bwUp := sessionToUpdate.SessionParams.BandwidthMaxUp
				bwDown := sessionToUpdate.SessionParams.BandwidthMaxDown
				sessionToUpdate.Unlock()

				// Apply the bandwidth changes to the firewall/TC
				if err := fw.UpdateUserBandwidth(sessionToUpdate.HisIP, bwUp, bwDown); err != nil {
					log.Error().Err(err).Str("user", userName).Msg("Failed to apply CoA bandwidth changes")
					// Send NAK because we couldn't apply the changes
					response := req.Packet.Response(layehradius.CodeCoANAK)
					radiusClient.SendCoAResponse(response, req.Peer)
					continue // Go to next request
				}

				response := req.Packet.Response(layehradius.CodeCoAACK)
				radiusClient.SendCoAResponse(response, req.Peer)

			default:
				log.Warn().Str("code", req.Packet.Code.String()).Msg("Received unhandled CoA/DM code")
				response := req.Packet.Response(layehradius.CodeCoANAK) // Generic NAK for unhandled
				radiusClient.SendCoAResponse(response, req.Peer)
			}
		}
	}()

	// RADIUS processing loop
	go func() {
		for session := range radiusReqChan {
			go func(s *core.Session) {
				var username, password string

				// If username is empty, it's a MAC auth attempt from the DHCP handler
				if s.Redir.Username == "" {
					username = strings.ToUpper(strings.Replace(s.HisMAC.String(), ":", "-", -1))
					if cfg.MACSuffix != "" {
						username += cfg.MACSuffix
					}

					if cfg.MACPasswd != "" {
						password = cfg.MACPasswd
					} else {
						password = username // Default password is the username
					}
					s.Redir.Username = username // Store generated username in session
					log.Info().Str("mac", s.HisMAC.String()).Str("user", username).Msg("Attempting MAC authentication")
				} else {
					// It's a UAM login, use credentials from the session
					username = s.Redir.Username
					password = s.Redir.Password
				}

				// Try local authentication first if enabled
				if cfg.UseLocalUsers {
					authenticated, err := auth.AuthenticateLocalUser(cfg.LocalUsersFile, username, password)
					if err != nil {
						log.Error().Err(err).Str("user", username).Msg("Error during local authentication")
						// Fall through to RADIUS
					} else if authenticated {
						log.Info().Str("user", username).Msg("Local authentication successful")
						s.Lock()
						s.Authenticated = true
						// Apply default session parameters for local users
						s.SessionParams.SessionTimeout = cfg.DefSessionTimeout
						s.SessionParams.IdleTimeout = cfg.DefIdleTimeout
						s.SessionParams.BandwidthMaxDown = cfg.DefBandwidthMaxDown
						s.SessionParams.BandwidthMaxUp = cfg.DefBandwidthMaxUp
						if err := fw.AddAuthenticatedUser(s.HisIP, s.SessionParams.BandwidthMaxUp, s.SessionParams.BandwidthMaxDown); err != nil {
							log.Error().Err(err).Str("user", s.Redir.Username).Msg("Error adding firewall/TC rules for local user")
							// We can still proceed, but log the error
						}
						s.Unlock()
						s.AuthResult <- true
						return
					}
				}

				// Proceed with RADIUS authentication
				log.Info().Str("user", username).Msg("Processing RADIUS request")
				resp, err := radiusClient.SendAccessRequest(s, username, password)
				if err != nil {
					log.Error().Err(err).Str("user", username).Msg("Error sending RADIUS Access-Request")
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

					if err := fw.AddAuthenticatedUser(s.HisIP, s.SessionParams.BandwidthMaxUp, s.SessionParams.BandwidthMaxDown); err != nil {
						log.Error().Err(err).Str("user", s.Redir.Username).Msg("Error adding firewall/TC rules")
						s.AuthResult <- false // Signal failure if firewall rule fails
						return
					}

					now := core.MonotonicTime()
					s.LastInterimUpdateTime = now // Set initial time for interim updates

					// Send accounting start
					// Use integer value 1 for Start as the named constant is not available in this library version.
					go radiusClient.SendAccountingRequest(s, rfc2866.AcctStatusType(1), "Start")
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

func processPackets(ifce *water.Interface, packetChan <-chan []byte, cfg *config.Config, sessionManager *core.SessionManager, dnsProxy *dns.Proxy, fw *firewall.Firewall, logger zerolog.Logger) {
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

		// DNS Interception for Walled Garden by Domain
		session.RLock()
		isAuthenticated := session.Authenticated
		session.RUnlock()

		if !isAuthenticated {
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				dnsQuery, _ := dnsLayer.(*layers.DNS)
				if dnsQuery.QR == false && dnsQuery.OpCode == layers.DNSOpCodeQuery {
					responseBytes, resolvedIPs, err := dnsProxy.HandleQuery(dnsQuery)
					if err != nil {
						log.Error().Err(err).Msg("DNS proxy failed to handle query")
					} else if responseBytes != nil {
						// Add resolved IPs to the walled garden
						for ipStr, ttl := range resolvedIPs {
							ip := net.ParseIP(ipStr)
							if ip == nil {
								log.Warn().Str("ip", ipStr).Msg("DNS proxy returned an invalid IP address")
								continue
							}
							if err := fw.AddToWalledGarden(ip, ttl); err != nil {
								log.Error().Err(err).Str("ip", ip.String()).Msg("Failed to add IP to walled garden")
							}
						}
						// Send the DNS response back to the client
						if err := sendDNSResponse(ifce, packet, responseBytes); err != nil {
							log.Error().Err(err).Msg("Failed to send DNS response to client")
						}
					}
					// We always stop processing DNS packets from unauthenticated users here.
					continue
				}
			}
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

func sendDNSResponse(ifce *water.Interface, reqPacket gopacket.Packet, respPayload []byte) error {
	// Extract layers from the original request to build the response
	reqIPv4, okIPv4 := reqPacket.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	reqUDP, okUDP := reqPacket.Layer(layers.LayerTypeUDP).(*layers.UDP)

	if !okIPv4 || !okUDP {
		return fmt.Errorf("could not parse original DNS request layers (not IPv4/UDP)")
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    reqIPv4.DstIP, // Our IP is the source
		DstIP:    reqIPv4.SrcIP, // Client's IP is the destination
	}

	udpLayer := &layers.UDP{
		SrcPort: reqUDP.DstPort, // DNS port 53
		DstPort: reqUDP.SrcPort, // Client's ephemeral port
	}
	if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return fmt.Errorf("failed to set network layer for DNS response checksum: %w", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buffer, opts, ipLayer, udpLayer, gopacket.Payload(respPayload)); err != nil {
		return fmt.Errorf("failed to serialize DNS response: %w", err)
	}

	if _, err := ifce.Write(buffer.Bytes()); err != nil {
		return fmt.Errorf("failed to write DNS response to TUN interface: %w", err)
	}
	return nil
}