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
	app, err := buildApplication(cfg, reloader)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to build application")
	}
	runApp(app)
	log.Info().Msg("CoovaChilli-Go has shut down.")
}

// application holds all the dependencies for the coovachilli application.
type application struct {
	cfg               *config.Config
	logger            zerolog.Logger
	reloader          *config.Reloader
	metricsRecorder   core.MetricsRecorder
	peerManager       core.PeerManager
	firewall          core.FirewallManager
	sessionManager    *core.SessionManager
	scriptRunner      core.ScriptRunner
	radiusClient      core.RadiusClient
	disconnectManager core.Disconnector
	reaper            core.Reaper
	httpServer        core.HttpServer
	adminServer       core.AdminServer
	dnsProxy          *dns.Proxy
	tunDevice         *water.Interface
	pcapHandle        *pcap.Handle
	parser            *gopacket.DecodingLayerParser
	ethLayer          layers.Ethernet
	ip4Layer          layers.IPv4
	udpLayer          layers.UDP
	dnsLayer          layers.DNS

	// Channels
	radiusReqChan chan *core.Session
	coaReqChan    chan core.CoAContext
	packetChan    chan []byte
	shutdownChan  chan os.Signal
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

func buildApplication(cfg *config.Config, reloader *config.Reloader) (*application, error) {
	app := &application{
		cfg:           cfg,
		logger:        log.Logger,
		reloader:      reloader,
		radiusReqChan: make(chan *core.Session),
		coaReqChan:    make(chan core.CoAContext),
		packetChan:    make(chan []byte),
		shutdownChan:  make(chan os.Signal, 1),
	}
	app.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &app.ethLayer, &app.ip4Layer, &app.udpLayer, &app.dnsLayer)

	// Initialize metrics recorder
	if cfg.Metrics.Enabled {
		switch cfg.Metrics.Backend {
		case "prometheus":
			app.logger.Info().Msg("Prometheus metrics enabled")
			app.metricsRecorder = metrics.NewPrometheusRecorder()
		default:
			app.logger.Warn().Str("backend", cfg.Metrics.Backend).Msg("Unknown metrics backend, defaulting to no-op")
			app.metricsRecorder = metrics.NewNoopRecorder()
		}
	} else {
		app.logger.Info().Msg("Metrics are disabled")
		app.metricsRecorder = metrics.NewNoopRecorder()
	}

	// Initialize cluster manager
	if cfg.Cluster.Enabled {
		app.logger.Info().Msg("Cluster mode enabled.")
		peerManager, err := cluster.NewManager(cfg.Cluster, cfg.DHCPIf, cfg.UAMListen)
		if err != nil {
			return nil, fmt.Errorf("error creating cluster manager: %w", err)
		}
		app.peerManager = peerManager
	}

	// Initialize firewall
	fw, err := firewall.New(cfg, app.logger)
	if err != nil {
		return nil, fmt.Errorf("error creating firewall manager: %w", err)
	}
	app.firewall = fw

	// Initialize TUN device
	ifce, err := tun.New(cfg, app.logger)
	if err != nil {
		return nil, fmt.Errorf("error creating TUN interface: %w", err)
	}
	app.tunDevice = ifce

	// Initialize other components
	app.scriptRunner = script.NewRunner(app.logger, cfg)
	app.sessionManager = core.NewSessionManager(cfg, app.metricsRecorder)
	app.dnsProxy = dns.NewProxy(cfg, app.logger)
	app.radiusClient = radius.NewClient(cfg, app.logger, app.metricsRecorder)
	app.disconnectManager = disconnect.NewManager(cfg, app.sessionManager, app.firewall, app.radiusClient, app.scriptRunner, app.logger)
	app.reaper = core.NewReaper(cfg, app.sessionManager, app.disconnectManager, app.logger)
	app.httpServer = http.NewServer(cfg, app.sessionManager, app.radiusReqChan, app.disconnectManager, app.logger, app.metricsRecorder)
	app.adminServer = admin.NewServer(cfg, app.sessionManager, app.disconnectManager, app.logger)

	// Register reconfigurable components
	reloader.Register(app.firewall)
	reloader.Register(app.sessionManager)

	return app, nil
}

func runApp(app *application) {
	// Initialize firewall and defer cleanup
	if err := app.firewall.Initialize(); err != nil {
		app.logger.Fatal().Err(err).Msg("Error initializing firewall")
	}
	defer app.firewall.Cleanup()

	// Drop privileges after network setup, but before starting listeners
	if app.cfg.User != "" {
		dropPrivileges(app.cfg, app.logger)
	}

	// Load existing sessions
	app.loadSessions()

	// Start background services
	app.startServices()

	// Setup signal handling
	signal.Notify(app.shutdownChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	<-app.shutdownChan
	app.logger.Info().Msg("Shutting down CoovaChilli-Go...")

	// Perform graceful shutdown
	app.shutdown()

	app.logger.Info().Msg("Graceful shutdown completed")
}

func (app *application) startServices() {
	// Start metrics server
	if handler := app.metricsRecorder.Handler(); handler != nil {
		go func() {
			app.logger.Info().Str("addr", app.cfg.Metrics.Listen).Msg("Starting metrics server")
			mux := stdhttp.NewServeMux()
			mux.Handle("/metrics", handler)
			if err := stdhttp.ListenAndServe(app.cfg.Metrics.Listen, mux); err != nil {
				app.logger.Error().Err(err).Msg("Metrics server failed")
			}
		}()
	}

	// Start cluster manager
	if app.peerManager != nil {
		go app.peerManager.Start()
	}

	// Start DHCP and EAPOL listeners
	app.startPcapListener()

	// Start session reaper
	app.reaper.Start()

	// Start UAM/HTTP server
	go app.httpServer.Start()

	// Start packet processing from TUN device
	go tun.ReadPackets(app.tunDevice, app.packetChan, app.logger)
	go app.processPackets()

	// Start admin API server
	go app.adminServer.Start()

	// Start RADIUS listeners (CoA, Proxy)
	go app.radiusClient.StartCoAListener(app.coaReqChan)
	if app.cfg.ProxyEnable {
		proxyServer := radius.NewProxyServer(app.cfg, app.sessionManager, app.radiusClient, app.logger)
		go proxyServer.Start()
	}

	// Start main application logic goroutines
	go app.handleCoARequests()
	go app.handleRadiusRequests()

	app.logger.Info().Msg("CoovaChilli-Go is running. Press Ctrl-C to stop.")
}

func (app *application) shutdown() {
	// Close channels to signal goroutines to stop
	close(app.radiusReqChan)
	close(app.coaReqChan)
	close(app.packetChan)

	// Stop the session reaper
	app.reaper.Stop()

	// Close network handles
	if app.pcapHandle != nil {
		app.pcapHandle.Close()
	}
	if app.tunDevice != nil {
		app.tunDevice.Close()
	}

	// Save sessions before shutdown
	if err := app.sessionManager.SaveSessions(app.cfg.StateFile); err != nil {
		app.logger.Error().Err(err).Msg("Failed to save sessions to state file")
	}

	// Disconnect all authenticated sessions
	for _, session := range app.sessionManager.GetAllSessions() {
		if session != nil && session.Authenticated {
			app.disconnectManager.Disconnect(session, "NAS-Reboot")
		}
	}
}

func (app *application) loadSessions() {
	if err := app.sessionManager.LoadSessions(app.cfg.StateFile); err != nil {
		app.logger.Error().Err(err).Msg("Failed to load sessions from state file")
		return
	}
	if len(app.sessionManager.GetAllSessions()) > 0 {
		app.logger.Info().Int("count", len(app.sessionManager.GetAllSessions())).Msg("Reloaded sessions from state file")
		for _, s := range app.sessionManager.GetAllSessions() {
			if s.Authenticated {
				if err := app.firewall.AddAuthenticatedUser(s.HisIP); err != nil {
					app.logger.Error().Err(err).Str("user", s.Redir.Username).Msg("Failed to re-apply firewall rule for loaded session")
				}
			}
		}
	}
}

func (app *application) startPcapListener() {
	dhcpIface, err := net.InterfaceByName(app.cfg.DHCPIf)
	if err != nil {
		app.logger.Fatal().Err(err).Msgf("Failed to get interface %s", app.cfg.DHCPIf)
	}

	handle, err := pcap.OpenLive(app.cfg.DHCPIf, 65536, true, pcap.BlockForever)
	if err != nil {
		app.logger.Fatal().Err(err).Msg("Failed to open pcap handle")
	}
	app.pcapHandle = handle

	filter := fmt.Sprintf("(udp and (port 67 or 68 or 546 or 547)) or (ether proto 0x%X)", layers.EthernetTypeEAPOL)
	if err := app.pcapHandle.SetBPFFilter(filter); err != nil {
		app.logger.Fatal().Err(err).Msg("Failed to set BPF filter")
	}

	eapolHandler := eapol.NewHandler(app.cfg, app.sessionManager, app.radiusClient, app.pcapHandle, *dhcpIface, app.logger)

	_, err = dhcp.NewServer(app.cfg, app.sessionManager, app.radiusReqChan, eapolHandler, app.logger, app.metricsRecorder, app.pcapHandle, dhcpIface)
	if err != nil {
		app.logger.Fatal().Err(err).Msg("Error creating DHCP server")
	}
}

func (app *application) handleCoARequests() {
	for req := range app.coaReqChan {
		userName := rfc2865.UserName_GetString(req.Packet())

		var sessionToUpdate *core.Session
		sessions := app.sessionManager.GetAllSessions()
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
			app.logger.Warn().Str("user", userName).Msg("Received CoA/Disconnect request for unknown user")
			var response *layehradius.Packet
			if req.Packet().Code == layehradius.CodeDisconnectRequest {
				response = req.Packet().Response(layehradius.CodeDisconnectACK)
			} else {
				response = req.Packet().Response(layehradius.CodeCoANAK)
			}
			app.radiusClient.SendCoAResponse(response, req.Peer())
			continue
		}

		switch req.Packet().Code {
		case layehradius.CodeDisconnectRequest:
			app.logger.Info().Str("user", userName).Msg("Received Disconnect-Request")
			app.disconnectManager.Disconnect(sessionToUpdate, "Admin-Reset")
			response := req.Packet().Response(layehradius.CodeDisconnectACK)
			app.radiusClient.SendCoAResponse(response, req.Peer())
		default:
			app.logger.Warn().Str("code", req.Packet().Code.String()).Msg("Received unhandled CoA/DM code")
			response := req.Packet().Response(layehradius.CodeCoANAK)
			app.radiusClient.SendCoAResponse(response, req.Peer())
		}
	}
}

func (app *application) handleRadiusRequests() {
	for session := range app.radiusReqChan {
		go func(s *core.Session) {
			var username, password string
			if s.Redir.Username == "" {
				username = strings.ToUpper(strings.Replace(s.HisMAC.String(), ":", "-", -1))
				if app.cfg.MACSuffix != "" {
					username += app.cfg.MACSuffix
				}
				if app.cfg.MACPasswd != "" {
					password = app.cfg.MACPasswd
				} else {
					password = username
				}
				s.Redir.Username = username
			} else {
				username = s.Redir.Username
				password = s.Redir.Password
			}

			if app.cfg.UseLocalUsers {
				authenticated, err := auth.AuthenticateLocalUser(app.cfg.LocalUsersFile, username, password)
				if err != nil {
					app.logger.Error().Err(err).Str("user", username).Msg("Error during local authentication")
				} else if authenticated {
					s.Lock()
					s.Authenticated = true
					s.SessionParams.SessionTimeout = app.cfg.DefSessionTimeout
					s.SessionParams.IdleTimeout = app.cfg.DefIdleTimeout
					s.InitializeShaper(app.cfg)
					if err := app.firewall.AddAuthenticatedUser(s.HisIP); err != nil {
						app.logger.Error().Err(err).Str("user", s.Redir.Username).Msg("Error adding firewall/TC rules for local user")
					}
					s.Unlock()
					s.AuthResult <- true
					return
				}
			}

			resp, err := app.radiusClient.SendAccessRequest(s, username, password)
			if err != nil {
				app.logger.Error().Err(err).Str("user", username).Msg("Error sending RADIUS Access-Request")
				s.AuthResult <- false
				return
			}

			s.Lock()
			defer s.Unlock()
			if resp.Code == layehradius.CodeAccessAccept {
				s.Authenticated = true
				s.InitializeShaper(app.cfg)
				if err := app.firewall.AddAuthenticatedUser(s.HisIP); err != nil {
					app.logger.Error().Err(err).Str("user", s.Redir.Username).Msg("Error adding firewall/TC rules")
					s.AuthResult <- false
					return
				}
				go app.radiusClient.SendAccountingRequest(s, rfc2866.AcctStatusType(1)) // 1 = Start
				app.scriptRunner.RunScript(app.cfg.ConUp, s, 0)
				s.AuthResult <- true
			} else {
				s.AuthResult <- false
			}
		}(session)
	}
}

func dropPrivileges(cfg *config.Config, logger zerolog.Logger) {
	u, err := user.Lookup(cfg.User)
	if err != nil {
		logger.Fatal().Err(err).Str("user", cfg.User).Msg("Failed to look up user")
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		logger.Fatal().Err(err).Str("uid", u.Uid).Msg("Failed to parse UID")
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		logger.Fatal().Err(err).Str("gid", u.Gid).Msg("Failed to parse GID")
	}

	if cfg.Group != "" {
		g, err := user.LookupGroup(cfg.Group)
		if err != nil {
			logger.Fatal().Err(err).Str("group", cfg.Group).Msg("Failed to look up group")
		}
		gid, err = strconv.Atoi(g.Gid)
		if err != nil {
			logger.Fatal().Err(err).Str("gid", g.Gid).Msg("Failed to parse group GID")
		}
	}

	logger.Info().Int("uid", uid).Int("gid", gid).Msg("Dropping privileges")
	if err := syscall.Setgid(gid); err != nil {
		logger.Fatal().Err(err).Msg("Failed to set GID")
	}
	if err := syscall.Setuid(uid); err != nil {
		logger.Fatal().Err(err).Msg("Failed to set UID")
	}
}

func (app *application) processPackets() {
	decodedLayers := make([]gopacket.LayerType, 0, 4)
	for rawPacket := range app.packetChan {
		// In cluster mode, standby nodes do not process packets
		if app.peerManager != nil && app.peerManager.GetCurrentState() == cluster.PeerStateStandby {
			app.logger.Debug().Msg("Node is in standby, dropping packet.")
			continue
		}
		if len(rawPacket) == 0 {
			continue
		}

		// Use the decoding layer parser to avoid memory allocations.
		err := app.parser.DecodeLayers(rawPacket, &decodedLayers)
		if err != nil {
			app.logger.Debug().Err(err).Msg("Error decoding packet")
			continue
		}

		isIPv4 := false
		isDNS := false
		for _, layerType := range decodedLayers {
			switch layerType {
			case layers.LayerTypeIPv4:
				isIPv4 = true
			case layers.LayerTypeDNS:
				isDNS = true
			}
		}

		if !isIPv4 {
			continue
		}

		ipv4 := &app.ip4Layer
		packetSize := uint64(len(ipv4.Payload))

		session, isUplink := app.sessionManager.GetSessionByIPs(ipv4.SrcIP, ipv4.DstIP)
		if session == nil {
			continue // No session found for this packet, drop it
		}

		session.RLock()
		isAuthenticated := session.Authenticated
		session.RUnlock()

		if isAuthenticated {
			if session.ShouldDropPacket(packetSize, isUplink) {
				app.logger.Debug().Str("user", session.Redir.Username).Bool("isUplink", isUplink).Msg("Dropping packet due to bandwidth limit")
				continue
			}
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
			// For unauthenticated users, only allow DNS traffic
			if isUplink && isDNS {
				dnsQuery := &app.dnsLayer
				if !dnsQuery.QR { // It's a query
					upstreamAddr := fmt.Sprintf("%s:%d", app.cfg.DNS1.String(), 53)
					responseBytes, _, err := app.dnsProxy.HandleQuery(dnsQuery, upstreamAddr)
					if err == nil && responseBytes != nil {
						sendDNSResponse(app.tunDevice, &app.ip4Layer, &app.udpLayer, responseBytes)
					}
				}
			}
			// All other unauthenticated traffic is implicitly dropped
		}
	}
}

func sendDNSResponse(ifce *water.Interface, reqIPv4 *layers.IPv4, reqUDP *layers.UDP, respPayload []byte) error {
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