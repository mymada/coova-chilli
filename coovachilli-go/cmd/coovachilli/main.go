package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"coovachilli-go/pkg/auth"
	"coovachilli-go/pkg/admin"
	"coovachilli-go/pkg/cluster"
	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/dhcp"
	"coovachilli-go/pkg/disconnect"
	"coovachilli-go/pkg/dns"
	"coovachilli-go/pkg/eapol"
	"coovachilli-go/pkg/firewall"
	"coovachilli-go/pkg/http"
	"coovachilli-go/pkg/metrics"
	"coovachilli-go/pkg/radius"
	"coovachilli-go/pkg/script"
	"coovachilli-go/pkg/tun"
	"io"
	stdhttp "net/http"
	"log/syslog"
	"os/user"
	"strconv"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
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
			logWriter, err = os.OpenFile(cfg.Logging.Destination, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to open log file")
			}
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
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)

		if cfg.Group != "" {
			g, err := user.LookupGroup(cfg.Group)
			if err != nil {
				log.Fatal().Err(err).Str("group", cfg.Group).Msg("Failed to look up group")
			}
			gid, _ = strconv.Atoi(g.Gid)
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
	dnsProxy := dns.NewProxy(cfg, log.Logger)
	eapolHandler := eapol.NewHandler(cfg, sessionManager, log.Logger)

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

	reaper.Start()
	defer reaper.Stop()

	_, err = dhcp.NewServer(cfg, sessionManager, radiusReqChan, eapolHandler, log.Logger, metricsRecorder)
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating DHCP server")
	}

	httpServer := http.NewServer(cfg, sessionManager, radiusReqChan, disconnectManager, log.Logger, metricsRecorder)
	go httpServer.Start()

	packetChan := make(chan []byte)
	go tun.ReadPackets(ifce, packetChan, log.Logger)
	go processPackets(ifce, packetChan, cfg, sessionManager, dnsProxy, fw, peerManager, log.Logger)

	// Start the admin API server
	adminServer := admin.NewServer(cfg, sessionManager, disconnectManager, log.Logger)
	go adminServer.Start()

	coaReqChan := make(chan radius.CoAIncomingRequest)
	go radiusClient.StartCoAListener(coaReqChan)

	if cfg.ProxyEnable {
		proxyServer := radius.NewProxyServer(cfg, sessionManager, radiusClient, log.Logger)
		go proxyServer.Start()
	}

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
			ipv4, _ := ipv4Layer.(*layers.IPv4)
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
				// Handle unauthenticated traffic (DNS only)
				if isUplink {
					if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
						dnsQuery, _ := dnsLayer.(*layers.DNS)
						if !dnsQuery.QR {
							upstreamAddr := fmt.Sprintf("%s:%d", cfg.DNS1.String(), 53)
							responseBytes, _, err := dnsProxy.HandleQuery(dnsQuery, upstreamAddr)
							if err == nil && responseBytes != nil {
								sendDNSResponse(ifce, packet, responseBytes)
							}
						}
					}
				}
				// Other unauthenticated traffic is dropped implicitly
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