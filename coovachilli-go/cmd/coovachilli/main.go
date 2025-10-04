package main

import (
	"flag"
	"fmt"
	"io"
	"log/syslog"
	"net"
	stdhttp "net/http"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"coovachilli-go/pkg/admin"
	"coovachilli-go/pkg/auth"
	"coovachilli-go/pkg/cluster"
	"coovachilli-go/pkg/cmdsock"
	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/dhcp"
	"coovachilli-go/pkg/disconnect"
	"coovachilli-go/pkg/dns"
	"coovachilli-go/pkg/eapol"
	"coovachilli-go/pkg/firewall"
	"coovachilli-go/pkg/garden"
	"coovachilli-go/pkg/http"
	"coovachilli-go/pkg/metrics"
	"coovachilli-go/pkg/radius"
	"coovachilli-go/pkg/script"
	"coovachilli-go/pkg/tun"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sevlyar/go-daemon"
	"github.com/songgao/water"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

var (
	stop     = flag.Bool("stop", false, "send stop signal to the daemon")
	reloader *config.Reloader
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to the configuration file")
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	// The daemon library takes over signal handling, so we need to register our commands.
	daemon.AddCommand(daemon.BoolFlag(stop), syscall.SIGTERM, termHandler)
	daemon.AddCommand(daemon.BoolFlag(nil), syscall.SIGHUP, reloadHandler)

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Error loading configuration")
	}

	// Setup logger
	var logWriter io.Writer = os.Stderr
	var logFile *os.File
	if !cfg.Foreground {
		switch cfg.Logging.Destination {
		case "syslog":
			writer, err := syslog.New(syslog.LOG_NOTICE, cfg.Logging.SyslogTag)
			if err != nil {
				log.Fatal().Err(err).Msg("Unable to set up syslog")
			}
			logWriter = writer
		case "stdout":
			logWriter = os.Stdout
		default: // File
			logFile, err = os.OpenFile(cfg.Logging.Destination, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to open log file")
			}
			logWriter = logFile
			// Close log file on exit
			defer func() {
				if logFile != nil {
					logFile.Close()
				}
			}()
		}
		log.Logger = log.Output(logWriter)
	} else {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	if *debug || cfg.Logging.Level == "debug" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Initialize the reloader
	reloader = config.NewReloader(*configPath, log.Logger)

	// Daemonize if not in foreground
	if !cfg.Foreground {
		cntxt := &daemon.Context{
			PidFileName: cfg.PIDFile,
			PidFilePerm: 0644,
		}

		if len(daemon.ActiveFlags()) > 0 {
			d, err := cntxt.Search()
			if err != nil {
				log.Fatal().Err(err).Msg("Unable to find daemon process")
			}
			if err := daemon.SendCommands(d); err != nil {
				log.Error().Err(err).Msg("Failed to send command to daemon")
			}
			return
		}

		d, err := cntxt.Reborn()
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to daemonize")
		}
		if d != nil { // This is the parent process, exit
			return
		}
		defer cntxt.Release() // This is the daemon process
	}

	log.Info().Msg("Starting CoovaChilli-Go...")
	runApp(cfg, reloader)
	log.Info().Msg("CoovaChilli-Go has shut down.")
}

// termHandler is the signal handler for the daemon.
func termHandler(sig os.Signal) error {
	log.Info().Msg("Termination signal received. Shutting down.")
	return daemon.ErrStop
}

// reloadHandler is the signal handler for SIGHUP.
func reloadHandler(sig os.Signal) error {
	log.Info().Msg("SIGHUP signal received. Triggering configuration reload.")
	if reloader != nil {
		reloader.PerformReload()
	} else {
		log.Error().Msg("Reloader not initialized, cannot reload configuration.")
	}
	return nil
}

func runApp(cfg *config.Config, reloader *config.Reloader) {
	// Initialize metrics recorder
	var metricsRecorder metrics.Recorder
	if cfg.Metrics.Enabled {
		switch cfg.Metrics.Backend {
		case "prometheus":
			log.Info().Msg("Prometheus metrics enabled")
			metricsRecorder = metrics.NewPrometheusRecorder()
		default:
			log.Warn().Str("backend", cfg.Metrics.Backend).Msg("Unknown metrics backend, defaulting to no-op")
			metricsRecorder = metrics.NewNoopRecorder()
		}
	} else {
		log.Info().Msg("Metrics are disabled")
		metricsRecorder = metrics.NewNoopRecorder()
	}

	// Start metrics server if applicable
	if handler := metricsRecorder.Handler(); handler != nil {
		go func() {
			log.Info().Str("addr", cfg.Metrics.Listen).Msg("Starting metrics server")
			mux := stdhttp.NewServeMux()
			mux.Handle("/metrics", handler)
			if err := stdhttp.ListenAndServe(cfg.Metrics.Listen, mux); err != nil {
				log.Error().Err(err).Msg("Metrics server failed")
			}
		}()
	}

	var peerManager *cluster.PeerManager
	var err error
	if cfg.Cluster.Enabled {
		log.Info().Msg("Cluster mode enabled.")
		peerManager, err = cluster.NewManager(cfg.Cluster, cfg.DHCPIf, cfg.UAMListen)
		if err != nil {
			log.Fatal().Err(err).Msg("Error creating cluster manager")
		}
		go peerManager.Start()
	}

	fw, err := firewall.New(cfg, log.Logger)
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating firewall manager")
	}
	if err := fw.Initialize(); err != nil {
		log.Fatal().Err(err).Msg("Error initializing firewall")
	}
	defer fw.Cleanup()

	ifce, err := tun.New(cfg, log.Logger)
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating TUN interface")
	}

	// Drop privileges if configured
	if cfg.User != "" {
		u, err := user.Lookup(cfg.User)
		if err != nil {
			log.Fatal().Err(err).Str("user", cfg.User).Msg("Failed to look up user")
		}
		uid, err := strconv.Atoi(u.Uid)
		if err != nil {
			log.Fatal().Err(err).Str("uid", u.Uid).Msg("Failed to parse UID")
		}
		gid, err := strconv.Atoi(u.Gid)
		if err != nil {
			log.Fatal().Err(err).Str("gid", u.Gid).Msg("Failed to parse GID")
		}

		if cfg.Group != "" {
			g, err := user.LookupGroup(cfg.Group)
			if err != nil {
				log.Fatal().Err(err).Str("group", cfg.Group).Msg("Failed to look up group")
			}
			gid, err = strconv.Atoi(g.Gid)
			if err != nil {
				log.Fatal().Err(err).Str("gid", g.Gid).Msg("Failed to parse group GID")
			}
		}

		log.Info().Int("uid", uid).Int("gid", gid).Msg("Dropping privileges")
		if err := syscall.Setgid(gid); err != nil {
			log.Fatal().Err(err).Msg("Failed to set GID")
		}
		if err := syscall.Setuid(uid); err != nil {
			log.Fatal().Err(err).Msg("Failed to set UID")
		}
	}

	scriptRunner := script.NewRunner(log.Logger, cfg)
	sessionManager := core.NewSessionManager(cfg, metricsRecorder)

	// Initialize and start the Walled Garden service
	gardenService := garden.NewGarden(&cfg.WalledGarden, fw, log.Logger)
	gardenService.Start()
	defer gardenService.Stop()

	dnsProxy := dns.NewProxy(cfg, log.Logger, gardenService)

	// Set up session lifecycle hooks
	sessionManager.SetHooks(core.SessionHooks{
		OnIPUp: func(s *core.Session) {
			scriptRunner.RunScript(cfg.IPUp, s, 0)
		},
		OnIPDown: func(s *core.Session) {
			scriptRunner.RunScript(cfg.IPDown, s, 0)
		},
	})

	// Register reconfigurable components
	reloader.Register(fw)
	reloader.Register(sessionManager)

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
	radiusClient := radius.NewClient(cfg, log.Logger, metricsRecorder)
	disconnectManager := disconnect.NewManager(cfg, sessionManager, fw, radiusClient, scriptRunner, log.Logger)
	reaper := core.NewReaper(cfg, sessionManager, disconnectManager, log.Logger)

	// --- Network Handle and Interface Setup ---
	dhcpIface, err := net.InterfaceByName(cfg.DHCPIf)
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to get interface %s", cfg.DHCPIf)
	}

	handle, err := pcap.OpenLive(cfg.DHCPIf, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to open pcap handle")
	}
	defer handle.Close()

	// Combined filter for DHCP and EAPOL.
	filter := fmt.Sprintf("(udp and (port 67 or 68 or 546 or 547)) or (ether proto 0x%X)", layers.EthernetTypeEAPOL)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal().Err(err).Msg("Failed to set BPF filter")
	}

	eapolHandler := eapol.NewHandler(cfg, sessionManager, radiusClient, handle, *dhcpIface, log.Logger)

	reaper.Start()
	defer reaper.Stop()

	_, err = dhcp.NewServer(cfg, sessionManager, radiusReqChan, eapolHandler, log.Logger, metricsRecorder, handle, dhcpIface)
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating DHCP server")
	}

	// Start DHCP servers on additional interfaces if configured
	if len(cfg.MoreIF) > 0 {
		for _, ifName := range cfg.MoreIF {
			iface, err := net.InterfaceByName(ifName)
			if err != nil {
				log.Error().Err(err).Str("interface", ifName).Msg("Failed to get additional interface, skipping")
				continue
			}

			ifHandle, err := pcap.OpenLive(ifName, 65536, true, pcap.BlockForever)
			if err != nil {
				log.Error().Err(err).Str("interface", ifName).Msg("Failed to open pcap handle for additional interface, skipping")
				continue
			}

			if err := ifHandle.SetBPFFilter(filter); err != nil {
				log.Error().Err(err).Str("interface", ifName).Msg("Failed to set BPF filter for additional interface, skipping")
				ifHandle.Close()
				continue
			}

			_, err = dhcp.NewServer(cfg, sessionManager, radiusReqChan, eapolHandler, log.Logger, metricsRecorder, ifHandle, iface)
			if err != nil {
				log.Error().Err(err).Str("interface", ifName).Msg("Error creating DHCP server on additional interface, skipping")
				ifHandle.Close()
				continue
			}

			log.Info().Str("interface", ifName).Msg("Started DHCP server on additional interface")
		}
	}

	httpServer := http.NewServer(cfg, sessionManager, radiusReqChan, disconnectManager, log.Logger, metricsRecorder)
	go httpServer.Start()

	packetChan := make(chan []byte)
	go tun.ReadPackets(ifce, packetChan, log.Logger)
	go processPackets(ifce, packetChan, cfg, sessionManager, dnsProxy, fw, peerManager, log.Logger)

	// Start the admin API server
	adminServer := admin.NewServer(cfg, sessionManager, disconnectManager, log.Logger)
	go adminServer.Start()

	// Start the command socket listener
	cmdChan := make(chan cmdsock.Command, 10)
	cmdSocketListener := cmdsock.NewListener(cfg.CmdSocket, cmdChan, sessionManager, log.Logger)
	go cmdSocketListener.Start()

	// Handle command socket commands
	go func() {
		for cmd := range cmdChan {
			parts := strings.Fields(cmd.Cmd)
			if len(parts) == 0 {
				cmd.ResponseCh <- "ERROR: Empty command"
				continue
			}

			switch strings.ToLower(parts[0]) {
			case "disconnect", "kick":
				if len(parts) < 2 {
					cmd.ResponseCh <- "ERROR: disconnect requires a session identifier"
					continue
				}
				identifier := parts[1]
				ip := net.ParseIP(identifier)
				var session *core.Session
				var ok bool

				if ip != nil {
					session, ok = sessionManager.GetSessionByIP(ip)
				} else {
					mac, err := net.ParseMAC(identifier)
					if err == nil {
						session, ok = sessionManager.GetSessionByMAC(mac)
					}
				}

				if !ok || session == nil {
					cmd.ResponseCh <- fmt.Sprintf("ERROR: Session not found for identifier: %s", identifier)
				} else {
					disconnectManager.Disconnect(session, "Admin-Reset")
					cmd.ResponseCh <- fmt.Sprintf("OK: Session %s disconnected", identifier)
				}

			case "reload":
				// PerformReload loads the config itself and applies it.
				reloader.PerformReload()
				cmd.ResponseCh <- "OK: Configuration reload triggered"

			default:
				cmd.ResponseCh <- fmt.Sprintf("ERROR: Unknown command: %s", parts[0])
			}
		}
	}()

	coaReqChan := make(chan radius.CoAIncomingRequest)
	go radiusClient.StartCoAListener(coaReqChan)

	if cfg.ProxyEnable {
		proxyServer := radius.NewProxyServer(cfg, sessionManager, radiusClient, log.Logger)
		go proxyServer.Start()
	}

	go func() {
		for req := range coaReqChan {
			userName := rfc2865.UserName_GetString(req.Packet)

			// Find session by username with proper locking
			var sessionToUpdate *core.Session
			sessions := sessionManager.GetAllSessions()
			for _, s := range sessions {
				s.RLock()
				match := s.Redir.Username == userName
				s.RUnlock()
				if match {
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
					go radiusClient.SendAccountingRequest(s, rfc2866.AcctStatusType(1)) // 1 = Start
					scriptRunner.RunScript(cfg.ConUp, s, 0)
					s.AuthResult <- true
				} else {
					s.AuthResult <- false
				}
			}(session)
		}
	}()

	log.Info().Msg("CoovaChilli-Go is running. Press Ctrl-C to stop.")

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	<-sigChan
	log.Info().Msg("Shutting down CoovaChilli-Go...")

	// Close channels to stop goroutines
	close(radiusReqChan)
	close(coaReqChan)

	// Save sessions before shutdown
	if err := sessionManager.SaveSessions(cfg.StateFile); err != nil {
		log.Error().Err(err).Msg("Failed to save sessions to state file")
	}

	// Disconnect all authenticated sessions
	for _, session := range sessionManager.GetAllSessions() {
		if session != nil && session.Authenticated {
			disconnectManager.Disconnect(session, "NAS-Reboot")
		}
	}

	log.Info().Msg("Graceful shutdown completed")
}

func processPackets(ifce *water.Interface, packetChan <-chan []byte, cfg *config.Config, sessionManager *core.SessionManager, dnsProxy *dns.Proxy, fw firewall.FirewallManager, peerManager *cluster.PeerManager, logger zerolog.Logger) {
	for rawPacket := range packetChan {
		if peerManager != nil && peerManager.GetCurrentState() == cluster.PeerStateStandby {
			logger.Debug().Msg("Node is in standby, dropping packet.")
			continue
		}

		if len(rawPacket) == 0 {
			continue
		}
		packet := gopacket.NewPacket(rawPacket, layers.LayerTypeEthernet, gopacket.Default)
		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			ipv4, ok := ipv4Layer.(*layers.IPv4)
			if !ok || ipv4 == nil {
				continue
			}
			packetSize := uint64(len(ipv4.Payload))

			// Determine if the packet is uplink or downlink and find the session
			session, isUplink := sessionManager.GetSessionByIPs(ipv4.SrcIP, ipv4.DstIP)
			if session == nil {
				continue // No session found for either IP, drop packet
			}

			session.RLock()
			isAuthenticated := session.Authenticated
			session.RUnlock()

			if isAuthenticated {
				// Apply bandwidth shaping for authenticated users
				if session.ShouldDropPacket(packetSize, isUplink) {
					logger.Debug().Str("user", session.Redir.Username).Bool("isUplink", isUplink).Msg("Dropping packet due to bandwidth limit")
					continue
				}

				// Update accounting stats
				session.Lock()
				if isUplink {
					session.OutputOctets += packetSize
					session.OutputPackets++
				} else {
					session.InputOctets += packetSize
					session.InputPackets++
				}
				session.Unlock()
			} else {
				// Handle unauthenticated traffic.
				if isUplink {
					// For unauthenticated users, only allow DNS traffic to be proxied through our server.
					// The firewall should be configured to redirect DNS packets to the chilli instance,
					// but we still need to process them here. The firewall also handles allowing
					// traffic to the walled garden destinations.
					if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
						udp, _ := udpLayer.(*layers.UDP)
						// Check if it's a standard DNS query port
						if udp.DstPort == 53 {
							dnsQueryPayload := udp.Payload
							if responsePayload, err := dnsProxy.HandleQuery(dnsQueryPayload); err != nil {
								logger.Warn().Err(err).Msg("DNS proxy failed to handle query")
							} else if responsePayload != nil {
								// The proxy returned a response, send it back to the client.
								if err := sendDNSResponse(ifce, packet, responsePayload); err != nil {
									logger.Error().Err(err).Msg("Failed to send DNS response")
								}
							}
						}
					}
					// Other unauthenticated traffic is implicitly dropped as it won't be forwarded.
				}
			}
		}
	}
}

func sendDNSResponse(ifce *water.Interface, reqPacket gopacket.Packet, respPayload []byte) error {
	reqIPv4Layer := reqPacket.Layer(layers.LayerTypeIPv4)
	if reqIPv4Layer == nil {
		return fmt.Errorf("no IPv4 layer in request packet")
	}
	reqIPv4, ok := reqIPv4Layer.(*layers.IPv4)
	if !ok || reqIPv4 == nil {
		return fmt.Errorf("invalid IPv4 layer")
	}

	reqUDPLayer := reqPacket.Layer(layers.LayerTypeUDP)
	if reqUDPLayer == nil {
		return fmt.Errorf("no UDP layer in request packet")
	}
	reqUDP, ok := reqUDPLayer.(*layers.UDP)
	if !ok || reqUDP == nil {
		return fmt.Errorf("invalid UDP layer")
	}

	ipLayer := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: reqIPv4.DstIP, DstIP: reqIPv4.SrcIP}
	udpLayer := &layers.UDP{SrcPort: reqUDP.DstPort, DstPort: reqUDP.SrcPort}

	if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return fmt.Errorf("failed to set network layer for checksum: %w", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	if err := gopacket.SerializeLayers(buffer, opts, ipLayer, udpLayer, gopacket.Payload(respPayload)); err != nil {
		return fmt.Errorf("failed to serialize DNS response: %w", err)
	}

	if _, err := ifce.Write(buffer.Bytes()); err != nil {
		return fmt.Errorf("failed to write DNS response: %w", err)
	}

	return nil
}