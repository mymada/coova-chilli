package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"coovachilli-go/pkg/auth"
	"coovachilli-go/pkg/cmdsock"
	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/dhcp"
	"coovachilli-go/pkg/disconnect"
	"coovachilli-go/pkg/dns"
	"coovachilli-go/pkg/eapol"
	"coovachilli-go/pkg/firewall"
	"coovachilli-go/pkg/http"
	"coovachilli-go/pkg/radius"
	"coovachilli-go/pkg/script"
	"coovachilli-go/pkg/tun"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/songgao/water"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

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

	fw, err := firewall.New(cfg, log.Logger)
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
	eapolHandler := eapol.NewHandler(cfg, sessionManager, log.Logger)

	if err := sessionManager.LoadSessions(cfg.StateFile); err != nil {
		log.Error().Err(err).Msg("Failed to load sessions from state file")
	} else if len(sessionManager.GetAllSessions()) > 0 {
		log.Info().Int("count", len(sessionManager.GetAllSessions())).Msg("Reloaded sessions from state file")
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

	_, err = dhcp.NewServer(cfg, sessionManager, radiusReqChan, eapolHandler, log.Logger)
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
	go processPackets(ifce, packetChan, cfg, sessionManager, dnsProxy, fw, log.Logger)

	cmdChan := make(chan string)
	cmdSockListener := cmdsock.NewListener(cfg.CmdSockPath, cmdChan, log.Logger)
	go cmdSockListener.Start()

	go func() {
		for cmd := range cmdChan {
			response := processCommand(cmd, log.Logger, sessionManager, disconnectManager)
			log.Info().Str("command", cmd).Str("response", response).Msg("Processed command")
		}
	}()

	coaReqChan := make(chan radius.CoAIncomingRequest)
	go radiusClient.StartCoAListener(coaReqChan)

	go func() {
		for req := range coaReqChan {
			userName := rfc2865.UserName_GetString(req.Packet)
			var sessionToUpdate *core.Session
			for _, s := range sessionManager.GetAllSessions() {
				if s.Redir.Username == userName {
					sessionToUpdate = s
					break
				}
			}
			if sessionToUpdate == nil {
				log.Warn().Str("user", userName).Msg("Received CoA/Disconnect request for unknown user")
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
			default:
				log.Warn().Str("code", req.Packet.Code.String()).Msg("Received unhandled CoA/DM code")
				response := req.Packet.Response(layehradius.CodeCoANAK)
				radiusClient.SendCoAResponse(response, req.Peer)
			}
		}
	}()

	go func() {
		for session := range radiusReqChan {
			go func(s *core.Session) {
				var username, password string
				if s.Redir.Username == "" {
					username = strings.ToUpper(strings.Replace(s.HisMAC.String(), ":", "-", -1))
					if cfg.MACSuffix != "" {
						username += cfg.MACSuffix
					}
					if cfg.MACPasswd != "" {
						password = cfg.MACPasswd
					} else {
						password = username
					}
					s.Redir.Username = username
				} else {
					username = s.Redir.Username
					password = s.Redir.Password
				}
				if cfg.UseLocalUsers {
					authenticated, err := auth.AuthenticateLocalUser(cfg.LocalUsersFile, username, password)
					if err != nil {
						log.Error().Err(err).Str("user", username).Msg("Error during local authentication")
					} else if authenticated {
						s.Lock()
						s.Authenticated = true
						s.SessionParams.SessionTimeout = cfg.DefSessionTimeout
						s.SessionParams.IdleTimeout = cfg.DefIdleTimeout
						s.InitializeShaper(cfg)
						if err := fw.AddAuthenticatedUser(s.HisIP); err != nil {
							log.Error().Err(err).Str("user", s.Redir.Username).Msg("Error adding firewall/TC rules for local user")
						}
						s.Unlock()
						s.AuthResult <- true
						return
					}
				}
				resp, err := radiusClient.SendAccessRequest(s, username, password)
				if err != nil {
					log.Error().Err(err).Str("user", username).Msg("Error sending RADIUS Access-Request")
					s.AuthResult <- false
					return
				}
				s.Lock()
				defer s.Unlock()
				if resp.Code == layehradius.CodeAccessAccept {
					s.Authenticated = true
					s.InitializeShaper(cfg)
					if err := fw.AddAuthenticatedUser(s.HisIP); err != nil {
						log.Error().Err(err).Str("user", s.Redir.Username).Msg("Error adding firewall/TC rules")
						s.AuthResult <- false
						return
					}
					go radiusClient.SendAccountingRequest(s, 1, "Start")
					scriptRunner.RunScript(cfg.ConUp, s, 0)
					s.AuthResult <- true
				} else {
					s.AuthResult <- false
				}
			}(session)
		}
	}()

	log.Info().Msg("CoovaChilli-Go is running. Press Ctrl-C to stop.")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Info().Msg("Shutting down CoovaChilli-Go...")
	if err := sessionManager.SaveSessions(cfg.StateFile); err != nil {
		log.Error().Err(err).Msg("Failed to save sessions to state file")
	}
	for _, session := range sessionManager.GetAllSessions() {
		if session.Authenticated {
			disconnectManager.Disconnect(session, "NAS-Reboot")
		}
	}
}

func processPackets(ifce *water.Interface, packetChan <-chan []byte, cfg *config.Config, sessionManager *core.SessionManager, dnsProxy *dns.Proxy, fw firewall.FirewallManager, logger zerolog.Logger) {
	for rawPacket := range packetChan {
		if len(rawPacket) == 0 {
			continue
		}
		packet := gopacket.NewPacket(rawPacket, layers.LayerTypeEthernet, gopacket.Default)
		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			ipv4, _ := ipv4Layer.(*layers.IPv4)
			packetSize := uint64(len(ipv4.Payload))

			// Uplink traffic
			if session, ok := sessionManager.GetSessionByIP(ipv4.SrcIP); ok {
				isAuthenticated := session.Authenticated
				if isAuthenticated {
					if session.ShouldDropPacket(packetSize, true) {
						logger.Debug().Str("user", session.Redir.Username).Msg("Dropping upload packet due to bandwidth limit")
						continue
					}
					session.Lock()
					session.OutputOctets += packetSize
					session.OutputPackets++
					session.Unlock()
				}
				continue // Packet handled
			}

			// Downlink traffic
			if session, ok := sessionManager.GetSessionByIP(ipv4.DstIP); ok {
				isAuthenticated := session.Authenticated
				if isAuthenticated {
					if session.ShouldDropPacket(packetSize, false) {
						logger.Debug().Str("user", session.Redir.Username).Msg("Dropping download packet due to bandwidth limit")
						continue
					}
					session.Lock()
					session.InputOctets += packetSize
					session.InputPackets++
					session.Unlock()
				}
				continue // Packet handled
			}

			// Unauthenticated traffic (DNS special handling)
			session, ok := sessionManager.GetSessionByIP(ipv4.SrcIP)
			if !ok {
				continue
			}
			session.RLock()
			isAuthenticated := session.Authenticated
			session.RUnlock()
			if !isAuthenticated {
				if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
					dnsQuery, _ := dnsLayer.(*layers.DNS)
					if !dnsQuery.QR {
						upstreamAddr := fmt.Sprintf("%s:%d", cfg.DNS1.String(), 53)
						responseBytes, _, err := dnsProxy.HandleQuery(dnsQuery, upstreamAddr)
						if err == nil && responseBytes != nil {
							sendDNSResponse(ifce, packet, responseBytes)
						}
						continue
					}
				}
			}
		}
	}
}

func sendDNSResponse(ifce *water.Interface, reqPacket gopacket.Packet, respPayload []byte) error {
	reqIPv4, _ := reqPacket.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	reqUDP, _ := reqPacket.Layer(layers.LayerTypeUDP).(*layers.UDP)
	ipLayer := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: reqIPv4.DstIP, DstIP: reqIPv4.SrcIP}
	udpLayer := &layers.UDP{SrcPort: reqUDP.DstPort, DstPort: reqUDP.SrcPort}
	_ = udpLayer.SetNetworkLayerForChecksum(ipLayer)
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	_ = gopacket.SerializeLayers(buffer, opts, ipLayer, udpLayer, gopacket.Payload(respPayload))
	_, err := ifce.Write(buffer.Bytes())
	return err
}

func processCommand(command string, logger zerolog.Logger, sm *core.SessionManager, dm *disconnect.Manager) string {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "ERROR: Empty command"
	}
	switch parts[0] {
	case "list":
		var b strings.Builder
		for _, s := range sm.GetAllSessions() {
			b.WriteString(fmt.Sprintf("ip=%s mac=%s user=%s\n", s.HisIP, s.HisMAC, s.Redir.Username))
		}
		return b.String()
	}
	return "ERROR: Unknown command"
}