package main

import (
	"bufio"
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
	"time"

	"coovachilli-go/pkg/admin"
	"coovachilli-go/pkg/auth"
	ldapauth "coovachilli-go/pkg/auth/ldap"
	"coovachilli-go/pkg/cluster"
	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/dhcp"
	"coovachilli-go/pkg/disconnect"
	"coovachilli-go/pkg/dns"
	"coovachilli-go/pkg/eapol"
	"coovachilli-go/pkg/firewall"
	"coovachilli-go/pkg/garden"
	"coovachilli-go/pkg/gdpr"
	"coovachilli-go/pkg/http"
	"coovachilli-go/pkg/metrics"
	"coovachilli-go/pkg/radius"
	"coovachilli-go/pkg/script"
	"coovachilli-go/pkg/security"
	"coovachilli-go/pkg/sso"
	"coovachilli-go/pkg/tun"
	"coovachilli-go/pkg/vlan"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sevlyar/go-daemon"
	"github.com/songgao/water"
	layehradius "layeh.com/radius"
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
	peerManager       *cluster.PeerManager
	firewall          firewall.FirewallManager
	sessionManager    *core.SessionManager
	scriptRunner      *script.Runner
	radiusClient      *radius.Client
	disconnectManager core.Disconnector
	reaper            core.Reaper
	httpServer        core.HttpServer
	adminServer       core.AdminServer
	gardenService     *garden.Garden
	dnsProxy          *dns.Proxy
	tunDevice         *water.Interface
	tunMAC            net.HardwareAddr
	pcapHandle        *pcap.Handle
	parser            *gopacket.DecodingLayerParser
	ethLayer          layers.Ethernet
	arpLayer          layers.ARP
	ip4Layer          layers.IPv4
	ip6Layer          layers.IPv6
	icmpv6Layer       layers.ICMPv6
	udpLayer          layers.UDP
	tcpLayer          layers.TCP
	dnsLayer          layers.DNS

	// Security modules
	antiMalware       *security.AntiMalware
	ids               *security.IDS
	vlanManager       *vlan.VLANManager
	gdprManager       *gdpr.GDPRManager
	ssoManager        *sso.SSOManager
	ssoHandlers       *sso.SSOHandlers // ✅ Added for SSO HTTP handlers

	// Admin modules
	dashboard         *admin.Dashboard
	multiSiteManager  *admin.MultiSiteManager
	policyManager     *admin.PolicyManager

	// Channels
	radiusReqChan chan *core.Session
	coaReqChan    chan core.CoAContext
	packetChan    chan []byte
	shutdownChan  chan os.Signal

	// L7 Filtering
	sniBlocklist map[string]struct{}
}

func loadSNIBlocklist(cfg *config.Config, logger zerolog.Logger) (map[string]struct{}, error) {
	blocklist := make(map[string]struct{})
	if !cfg.L7Filtering.SNIFilteringEnabled {
		return blocklist, nil
	}

	if cfg.L7Filtering.SNIBlocklistPath == "" {
		return nil, fmt.Errorf("SNI filtering is enabled but no blocklist path is configured")
	}

	file, err := os.Open(cfg.L7Filtering.SNIBlocklistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SNI blocklist file '%s': %w", cfg.L7Filtering.SNIBlocklistPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lines := 0
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" && !strings.HasPrefix(domain, "#") {
			blocklist[domain] = struct{}{}
			lines++
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading SNI blocklist file: %w", err)
	}

	logger.Info().Int("count", lines).Msg("Loaded domains into SNI blocklist")
	return blocklist, nil
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
	app.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &app.ethLayer, &app.arpLayer, &app.ip4Layer, &app.ip6Layer, &app.icmpv6Layer, &app.tcpLayer, &app.udpLayer, &app.dnsLayer)

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

	// Get the TUN interface's hardware address and store it
	netIface, err := net.InterfaceByName(ifce.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to get TUN network interface by name '%s': %w", ifce.Name(), err)
	}
	app.tunMAC = netIface.HardwareAddr

	// Initialize other components
	app.scriptRunner = script.NewRunner(app.logger, cfg)
	app.sessionManager = core.NewSessionManager(cfg, app.metricsRecorder)
	app.gardenService = garden.NewGarden(&cfg.WalledGarden, app.firewall, app.logger)
	app.dnsProxy = dns.NewProxy(cfg, app.logger, app.gardenService)
	app.radiusClient = radius.NewClient(cfg, app.logger, app.metricsRecorder)
	app.disconnectManager = disconnect.NewManager(cfg, app.sessionManager, app.firewall, app.radiusClient, app.scriptRunner, app.logger)
	app.reaper = core.NewReaper(cfg, app.sessionManager, app.disconnectManager, app.logger)

	app.httpServer, err = http.NewServer(cfg, app.sessionManager, app.radiusReqChan, app.disconnectManager, app.logger, app.metricsRecorder, app.firewall, app.scriptRunner, app.radiusClient, app.ssoHandlers)
	if err != nil {
		return nil, fmt.Errorf("error creating HTTP server: %w", err)
	}
	app.adminServer = admin.NewServer(cfg, app.sessionManager, app.disconnectManager, app.logger)

	// Initialize security modules
	if cfg.AntiMalware.Enabled {
		app.antiMalware, err = security.NewAntiMalware(&cfg.AntiMalware, app.logger)
		if err != nil {
			app.logger.Warn().Err(err).Msg("Failed to initialize AntiMalware, continuing without it")
		} else {
			app.logger.Info().Msg("AntiMalware initialized")
		}
	}

	if cfg.IDS.Enabled {
		app.ids, err = security.NewIDS(&cfg.IDS, app.logger)
		if err != nil {
			app.logger.Warn().Err(err).Msg("Failed to initialize IDS, continuing without it")
		} else {
			app.logger.Info().Msg("IDS initialized")
		}
	}

	// Initialize VLAN manager
	if cfg.VLAN.Enabled {
		app.vlanManager, err = vlan.NewVLANManager(&cfg.VLAN, app.logger)
		if err != nil {
			app.logger.Warn().Err(err).Msg("Failed to initialize VLAN manager, continuing without it")
		} else {
			app.logger.Info().Msg("VLAN manager initialized")
		}
	}

	// Initialize GDPR compliance
	if cfg.GDPR.Enabled {
		app.gdprManager, err = gdpr.NewGDPRManager(&cfg.GDPR, app.logger)
		if err != nil {
			app.logger.Warn().Err(err).Msg("Failed to initialize GDPR manager, continuing without it")
		} else {
			app.logger.Info().Msg("GDPR manager initialized")
		}
	}

	// Initialize SSO manager
	if cfg.SSO.Enabled {
		ssoConfig := sso.SSOConfig{
			Enabled: cfg.SSO.Enabled,
			SAML:    convertToSSOSAMLConfig(&cfg.SSO.SAML),
			OIDC:    convertToSSOOIDCConfig(&cfg.SSO.OIDC),
		}
		app.ssoManager, err = sso.NewSSOManager(&ssoConfig, app.logger)
		if err != nil {
			app.logger.Warn().Err(err).Msg("Failed to initialize SSO manager, continuing without it")
		} else {
			// ✅ CORRECTION: Connect SSO with network components
			ssoHandlers := sso.NewSSOHandlers(app.ssoManager)
			ssoHandlers.SetSessionManager(sso.NewSessionManagerAdapter(app.sessionManager))
			ssoHandlers.SetFirewall(app.firewall)
			// ssoHandlers.SetRadiusClient(app.radiusClient) // Commented: needs interface refactoring
			ssoHandlers.SetScriptRunner(app.scriptRunner)
			ssoHandlers.SetConfig(cfg)

			// Store handlers for HTTP server integration
			app.ssoHandlers = ssoHandlers

			app.logger.Info().Msg("SSO manager initialized and connected to network components")
		}
	}

	// Initialize admin modules
	app.dashboard = admin.NewDashboard(app.sessionManager)
	app.logger.Info().Msg("Dashboard initialized")

	if cfg.AdminAPI.Enabled {
		app.multiSiteManager = admin.NewMultiSiteManager(app.logger, true)
		app.logger.Info().Msg("Multi-site manager initialized")

		app.policyManager, err = admin.NewPolicyManager("./policies", app.logger)
		if err != nil {
			app.logger.Warn().Err(err).Msg("Failed to initialize Policy manager, continuing without it")
		} else {
			app.logger.Info().Msg("Policy manager initialized")
		}
	}

	// Register reconfigurable components
	reloader.Register(app.firewall)
	reloader.Register(app.sessionManager)

	// Load SNI blocklist for L7 filtering
	sniBlocklist, err := loadSNIBlocklist(cfg, app.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to load SNI blocklist: %w", err)
	}
	app.sniBlocklist = sniBlocklist

	return app, nil
}

func runApp(app *application) {
	// Initialize firewall and defer cleanup
	if err := app.firewall.Initialize(); err != nil {
		app.logger.Fatal().Err(err).Msg("Error initializing firewall")
	}
	defer app.firewall.Cleanup()

	// Start walled garden service
	app.gardenService.Start()
	defer app.gardenService.Stop()

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

	// Start dashboard collection
	if app.dashboard != nil {
		app.dashboard.Start(30 * time.Second)
		app.logger.Info().Msg("Dashboard collection started")
	}

	// Multi-site manager is available but sync is manual
	if app.multiSiteManager != nil {
		app.logger.Info().Msg("Multi-site manager ready")
	}

	// IDS monitoring is passive (no active Start method)
	if app.ids != nil {
		app.logger.Info().Msg("IDS monitoring ready")
	}

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
	// Stop admin services
	if app.dashboard != nil {
		app.dashboard.Stop()
		app.logger.Info().Msg("Dashboard stopped")
	}

	// Multi-site manager cleanup (no explicit Stop method needed)
	if app.multiSiteManager != nil {
		app.logger.Info().Msg("Multi-site manager cleanup")
	}

	// IDS cleanup (no explicit Stop method needed)
	if app.ids != nil {
		app.logger.Info().Msg("IDS cleanup")
	}

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
	for coaReq := range app.coaReqChan {
		go func(req core.CoAContext) {
			app.logger.Info().Msg("Received CoA/Disconnect request")
			// CoA request handling is delegated to the disconnect manager
			// For now, we just log and acknowledge
			// TODO: Implement proper CoA handling based on request type
			response := req.Packet().Response(layehradius.CodeCoANAK)
			if err := app.radiusClient.SendCoAResponse(response, req.Peer()); err != nil {
				app.logger.Error().Err(err).Msg("Failed to send CoA response")
			}
		}(coaReq)
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
					// Also send accounting start and run conup script for local users
					go app.radiusClient.SendAccountingRequest(s, rfc2866.AcctStatusType(1)) // 1 = Start
					app.scriptRunner.RunScript(app.cfg.ConUp, s, 0)
					s.AuthResult <- true
					return
				}
			}

			// Try LDAP authentication if enabled
			if app.cfg.LDAP.Enabled {
				ldapAuthenticated, err := ldapauth.Authenticate(&app.cfg.LDAP, username, password, app.logger)
				if err != nil {
					// Log the error but fall through to RADIUS as a fallback
					app.logger.Error().Err(err).Str("user", username).Msg("Error during LDAP authentication")
				} else if ldapAuthenticated {
					app.logger.Info().Str("user", username).Msg("User authenticated successfully via LDAP")
					s.Lock()
					s.Authenticated = true
					s.InitializeShaper(app.cfg)
					if err := app.firewall.AddAuthenticatedUser(s.HisIP); err != nil {
						app.logger.Error().Err(err).Str("user", s.Redir.Username).Msg("Error adding firewall/TC rules for LDAP user")
					}
					s.Unlock()
					go app.radiusClient.SendAccountingRequest(s, rfc2866.AcctStatusType(1)) // 1 = Start
					app.scriptRunner.RunScript(app.cfg.ConUp, s, 0)
					s.AuthResult <- true
					return
				}
			}

			// Fallback to RADIUS
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

func (app *application) dropPrivileges() {
	u, err := user.Lookup(app.cfg.User)
	if err != nil {
		app.logger.Fatal().Err(err).Str("user", app.cfg.User).Msg("Failed to look up user")
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		app.logger.Fatal().Err(err).Str("uid", u.Uid).Msg("Failed to parse UID")
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		app.logger.Fatal().Err(err).Str("gid", u.Gid).Msg("Failed to parse GID")
	}

	if app.cfg.Group != "" {
		g, err := user.LookupGroup(app.cfg.Group)
		if err != nil {
			app.logger.Fatal().Err(err).Str("group", app.cfg.Group).Msg("Failed to look up group")
		}
		gid, err = strconv.Atoi(g.Gid)
		if err != nil {
			app.logger.Fatal().Err(err).Str("gid", g.Gid).Msg("Failed to parse group GID")
		}
	}

	app.logger.Info().Int("uid", uid).Int("gid", gid).Msg("Dropping privileges")
	if err := syscall.Setgid(gid); err != nil {
		app.logger.Fatal().Err(err).Msg("Failed to set GID")
	}
	if err := syscall.Setuid(uid); err != nil {
		app.logger.Fatal().Err(err).Msg("Failed to set UID")
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

		if len(rawPacket) < 1 {
			continue
		}

		// Use the decoding layer parser to avoid memory allocations.
		err := app.parser.DecodeLayers(rawPacket, &decodedLayers)
		if err != nil {
			app.logger.Debug().Err(err).Msg("Error decoding packet")
			continue
		}

		for _, layerType := range decodedLayers {
			switch layerType {
			case layers.LayerTypeARP:
				app.handleARPRequest(&app.ethLayer, &app.arpLayer, app.tunDevice)
			case layers.LayerTypeIPv4:
				app.handleIPv4Packet(&app.ip4Layer, decodedLayers)
			case layers.LayerTypeIPv6:
				app.handleIPv6Packet(&app.ip6Layer, decodedLayers)
			}
		}
	}
}

func (app *application) handleARPRequest(eth *layers.Ethernet, arp *layers.ARP, writer io.Writer) {
	// We only care about ARP requests
	if arp.Operation != layers.ARPRequest {
		return
	}

	// Check if the requested IP is one that we manage
	targetIP := net.IP(arp.DstProtAddress)
	if !app.sessionManager.HasSessionByIP(targetIP) && targetIP.String() != app.cfg.DHCPListen.String() {
		return
	}

	app.logger.Debug().
		Str("targetIP", targetIP.String()).
		Str("senderIP", net.IP(arp.SourceProtAddress).String()).
		Str("senderMAC", net.HardwareAddr(arp.SourceHwAddress).String()).
		Msg("ARP Request for managed IP, sending reply")

	// Construct the ARP reply
	replyEth := &layers.Ethernet{
		SrcMAC:       app.tunMAC,
		DstMAC:       eth.SrcMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	replyArp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   app.tunMAC,
		SourceProtAddress: arp.DstProtAddress, // The IP we are replying for
		DstHwAddress:      arp.SourceHwAddress,
		DstProtAddress:    arp.SourceProtAddress,
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts, replyEth, replyArp)
	if err != nil {
		app.logger.Error().Err(err).Msg("Failed to serialize ARP reply")
		return
	}

	if _, err := writer.Write(buffer.Bytes()); err != nil {
		app.logger.Error().Err(err).Msg("Failed to write ARP reply")
	}
}

func (app *application) handleIPv4Packet(ipv4 *layers.IPv4, decodedLayers []gopacket.LayerType) {
	isDNS := false
	for _, layerType := range decodedLayers {
		if layerType == layers.LayerTypeDNS {
			isDNS = true
			break
		}
	}

	packetSize := uint64(len(ipv4.Payload))

	session, isUplink := app.sessionManager.GetSessionByIPs(ipv4.SrcIP, ipv4.DstIP)
	if session == nil {
		return // No session found for this packet, drop it
	}

	session.RLock()
	isAuthenticated := session.Authenticated
	session.RUnlock()

	if isAuthenticated {
		if session.ShouldDropPacket(packetSize, isUplink) {
			app.logger.Debug().Str("user", session.Redir.Username).Bool("isUplink", isUplink).Msg("Dropping packet due to bandwidth limit")
			return
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
		// Authenticated traffic is forwarded by the firewall
	} else {
		// Handle unauthenticated traffic.
		if isUplink {
			// For unauthenticated users, only allow DNS traffic to be proxied through our server.
			// The firewall should be configured to redirect DNS packets to the chilli instance,
			// but we still need to process them here. The firewall also handles allowing
			// traffic to the walled garden destinations.
			if isDNS {
				dnsQueryPayload := app.udpLayer.Payload
				if responsePayload, err := app.dnsProxy.HandleQuery(dnsQueryPayload); err != nil {
					app.logger.Warn().Err(err).Msg("DNS proxy failed to handle query")
				} else if responsePayload != nil {
					// The proxy returned a response, send it back to the client.
					if err := app.sendDNSResponse(ipv4, &app.udpLayer, responsePayload); err != nil {
						app.logger.Error().Err(err).Msg("Failed to send DNS response")
					}
				}
			}
			// Other unauthenticated traffic is implicitly dropped as it won't be forwarded.
		}
		// All other unauthenticated traffic is implicitly dropped
	}
}

func (app *application) handleIPv6Packet(ipv6 *layers.IPv6, decodedLayers []gopacket.LayerType) {
	// ✅ SECURITY: Validate IPv6 packet
	if err := security.ValidateIPv6Packet(ipv6.SrcIP, ipv6.DstIP); err != nil {
		app.logger.Debug().Err(err).
			Str("src_ip", ipv6.SrcIP.String()).
			Str("dst_ip", ipv6.DstIP.String()).
			Msg("Dropping invalid IPv6 packet")
		return
	}

	// Check if this is ICMPv6 (for NDP handling)
	isICMPv6 := false
	isDNS := false
	for _, layerType := range decodedLayers {
		if layerType == layers.LayerTypeICMPv6 {
			isICMPv6 = true
		}
		if layerType == layers.LayerTypeDNS {
			isDNS = true
		}
	}

	// Handle ICMPv6 Neighbor Discovery separately
	if isICMPv6 {
		app.handleICMPv6Packet(ipv6, &app.icmpv6Layer)
		return
	}

	packetSize := uint64(len(ipv6.Payload))

	session, isUplink := app.sessionManager.GetSessionByIPs(ipv6.SrcIP, ipv6.DstIP)
	if session == nil {
		return // No session found for this packet, drop it
	}

	session.RLock()
	isAuthenticated := session.Authenticated
	session.RUnlock()

	if isAuthenticated {
		if session.ShouldDropPacket(packetSize, isUplink) {
			app.logger.Debug().Str("user", session.Redir.Username).Bool("isUplink", isUplink).Msg("Dropping IPv6 packet due to bandwidth limit")
			return
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
		// Authenticated traffic is forwarded by the firewall
	} else {
		// Handle unauthenticated IPv6 traffic
		if isUplink {
			// For unauthenticated users, only allow DNS traffic
			if isDNS {
				dnsQueryPayload := app.udpLayer.Payload
				if responsePayload, err := app.dnsProxy.HandleQuery(dnsQueryPayload); err != nil {
					app.logger.Warn().Err(err).Msg("DNS proxy failed to handle IPv6 query")
				} else if responsePayload != nil {
					// Send DNS response back to the client
					if err := app.sendDNSResponseV6(ipv6, &app.udpLayer, responsePayload); err != nil {
						app.logger.Error().Err(err).Msg("Failed to send IPv6 DNS response")
					}
				}
			}
			// Other unauthenticated traffic is implicitly dropped
		}
	}
}

func (app *application) handleICMPv6Packet(ipv6 *layers.IPv6, icmpv6 *layers.ICMPv6) {
	// ✅ SECURITY: Validate ICMPv6 source address
	if err := security.ValidateICMPv6Source(ipv6.SrcIP, uint8(icmpv6.TypeCode.Type())); err != nil {
		app.logger.Debug().Err(err).
			Str("src_ip", ipv6.SrcIP.String()).
			Uint8("icmp_type", uint8(icmpv6.TypeCode.Type())).
			Msg("Dropping ICMPv6 packet with invalid source")
		return
	}

	// Handle Neighbor Solicitation (NDP - equivalent to ARP for IPv6)
	if icmpv6.TypeCode.Type() == layers.ICMPv6TypeNeighborSolicitation {
		app.handleNeighborSolicitation(ipv6, icmpv6)
		return
	}

	// Handle Router Solicitation
	if icmpv6.TypeCode.Type() == layers.ICMPv6TypeRouterSolicitation {
		app.handleRouterSolicitation(ipv6, icmpv6)
		return
	}

	// Other ICMPv6 types are allowed through for authenticated sessions
	session, _ := app.sessionManager.GetSessionByIPs(ipv6.SrcIP, ipv6.DstIP)
	if session != nil {
		session.RLock()
		isAuthenticated := session.Authenticated
		session.RUnlock()
		if isAuthenticated {
			// Let authenticated ICMPv6 through (ping, etc.)
			return
		}
	}
}

func (app *application) handleNeighborSolicitation(reqIPv6 *layers.IPv6, reqICMP *layers.ICMPv6) {
	// Parse the target address from the ICMPv6 payload
	if len(reqICMP.Payload) < 16 {
		return // Invalid NS packet
	}
	targetIP := net.IP(reqICMP.Payload[4:20]) // Target address starts at byte 4

	// Check if the target IP is one we manage
	if !app.sessionManager.HasSessionByIP(targetIP) &&
	   (app.cfg.DHCPListenV6 == nil || targetIP.String() != app.cfg.DHCPListenV6.String()) {
		return
	}

	app.logger.Debug().
		Str("targetIP", targetIP.String()).
		Str("srcIP", reqIPv6.SrcIP.String()).
		Msg("Neighbor Solicitation for managed IPv6, sending Neighbor Advertisement")

	// Get interface MAC address
	iface, err := net.InterfaceByName(app.tunDevice.Name())
	if err != nil {
		app.logger.Error().Err(err).Msg("Failed to get interface for NA reply")
		return
	}

	// Build Neighbor Advertisement
	ipLayer := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255,
		SrcIP:      targetIP,
		DstIP:      reqIPv6.SrcIP,
	}

	icmpLayer := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
	}

	// Neighbor Advertisement payload: Flags (4 bytes) + Target Address (16 bytes) + Options
	naPayload := make([]byte, 24)
	naPayload[0] = 0x60 // Flags: Router=0, Solicited=1, Override=1
	copy(naPayload[4:20], targetIP.To16())
	// Option: Target Link-Layer Address (type=2, length=1)
	naPayload[20] = 2  // Type
	naPayload[21] = 1  // Length (in units of 8 bytes)
	copy(naPayload[22:], iface.HardwareAddr)

	icmpLayer.Payload = naPayload
	if err := icmpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		app.logger.Error().Err(err).Msg("Failed to set checksum for NA")
		return
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buffer, opts, ipLayer, icmpLayer); err != nil {
		app.logger.Error().Err(err).Msg("Failed to serialize Neighbor Advertisement")
		return
	}

	if _, err := app.tunDevice.Write(buffer.Bytes()); err != nil {
		app.logger.Error().Err(err).Msg("Failed to write Neighbor Advertisement")
	}
}

func (app *application) handleRouterSolicitation(reqIPv6 *layers.IPv6, reqICMP *layers.ICMPv6) {
	// Only send RA if IPv6 is enabled
	if !app.cfg.IPv6Enable || app.cfg.NetV6.IP == nil {
		return
	}

	app.logger.Debug().Str("srcIP", reqIPv6.SrcIP.String()).Msg("Router Solicitation received, sending Router Advertisement")

	// Use the existing RA builder from pkg/icmpv6
	raBytes, err := app.buildRouterAdvertisement(reqIPv6.SrcIP)
	if err != nil {
		app.logger.Error().Err(err).Msg("Failed to build Router Advertisement")
		return
	}

	if _, err := app.tunDevice.Write(raBytes); err != nil {
		app.logger.Error().Err(err).Msg("Failed to write Router Advertisement")
	}
}

func (app *application) buildRouterAdvertisement(soliciterIP net.IP) ([]byte, error) {
	// Get interface MAC address
	iface, err := net.InterfaceByName(app.tunDevice.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to get interface: %w", err)
	}

	// Generate link-local address from MAC
	linkLocalIP := make(net.IP, 16)
	linkLocalIP[0] = 0xfe
	linkLocalIP[1] = 0x80
	// EUI-64 from MAC
	linkLocalIP[8] = iface.HardwareAddr[0] ^ 0x02
	linkLocalIP[9] = iface.HardwareAddr[1]
	linkLocalIP[10] = iface.HardwareAddr[2]
	linkLocalIP[11] = 0xff
	linkLocalIP[12] = 0xfe
	linkLocalIP[13] = iface.HardwareAddr[3]
	linkLocalIP[14] = iface.HardwareAddr[4]
	linkLocalIP[15] = iface.HardwareAddr[5]

	// Determine destination: soliciter or all-nodes multicast
	dstIP := soliciterIP
	if dstIP == nil || dstIP.IsUnspecified() {
		dstIP = net.ParseIP("ff02::1") // All-nodes multicast
	}

	ipv6 := &layers.IPv6{
		Version:    6,
		SrcIP:      linkLocalIP,
		DstIP:      dstIP,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255,
	}

	icmpv6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterAdvertisement, 0),
	}

	// RA payload: Cur Hop Limit (1) + Flags (1) + Router Lifetime (2) + Reachable Time (4) + Retrans Timer (4)
	raPayload := make([]byte, 12)
	raPayload[0] = 64  // Hop limit
	raPayload[1] = 0x00 // Flags: Managed=0, Other=0
	raPayload[2] = 0x07 // Router lifetime (1800s = 0x0708)
	raPayload[3] = 0x08

	// Add Source Link-Layer Address option
	sllaOpt := make([]byte, 8)
	sllaOpt[0] = 1 // Type: Source Link-Layer Address
	sllaOpt[1] = 1 // Length (in units of 8 bytes)
	copy(sllaOpt[2:], iface.HardwareAddr)
	raPayload = append(raPayload, sllaOpt...)

	// Add Prefix Information option
	prefixLen, _ := app.cfg.NetV6.Mask.Size()
	prefixOpt := make([]byte, 32)
	prefixOpt[0] = 3  // Type: Prefix Information
	prefixOpt[1] = 4  // Length (in units of 8 bytes)
	prefixOpt[2] = byte(prefixLen)
	prefixOpt[3] = 0xc0 // Flags: On-link=1, Autonomous=1
	// Valid lifetime: 2592000 seconds (30 days)
	prefixOpt[4] = 0x00
	prefixOpt[5] = 0x27
	prefixOpt[6] = 0x8d
	prefixOpt[7] = 0x00
	// Preferred lifetime: 604800 seconds (7 days)
	prefixOpt[8] = 0x00
	prefixOpt[9] = 0x09
	prefixOpt[10] = 0x3a
	prefixOpt[11] = 0x80
	// Reserved
	prefixOpt[12] = 0x00
	prefixOpt[13] = 0x00
	prefixOpt[14] = 0x00
	prefixOpt[15] = 0x00
	// Prefix
	copy(prefixOpt[16:], app.cfg.NetV6.IP.To16())
	raPayload = append(raPayload, prefixOpt...)

	icmpv6.Payload = raPayload
	if err := icmpv6.SetNetworkLayerForChecksum(ipv6); err != nil {
		return nil, fmt.Errorf("failed to set checksum: %w", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buffer, opts, ipv6, icmpv6); err != nil {
		return nil, fmt.Errorf("failed to serialize RA packet: %w", err)
	}

	return buffer.Bytes(), nil
}

func (app *application) sendDNSResponseV6(reqIPv6 *layers.IPv6, reqUDP *layers.UDP, respPayload []byte) error {
	ipLayer := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolUDP,
		HopLimit:   64,
		SrcIP:      reqIPv6.DstIP,
		DstIP:      reqIPv6.SrcIP,
	}
	udpLayer := &layers.UDP{SrcPort: reqUDP.DstPort, DstPort: reqUDP.SrcPort}

	if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return fmt.Errorf("failed to set network layer for checksum: %w", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	dnsLayer := &layers.DNS{}
	if err := dnsLayer.DecodeFromBytes(respPayload, gopacket.NilDecodeFeedback); err != nil {
		return fmt.Errorf("failed to decode dns response payload for serialization: %w", err)
	}
	dnsLayer.QR = true // Set the QR bit to indicate a response

	if err := gopacket.SerializeLayers(buffer, opts, ipLayer, udpLayer, dnsLayer); err != nil {
		return fmt.Errorf("failed to serialize IPv6 DNS response: %w", err)
	}

	if _, err := app.tunDevice.Write(buffer.Bytes()); err != nil {
		return fmt.Errorf("failed to write IPv6 DNS response: %w", err)
	}

	return nil
}

func (app *application) sendDNSResponse(reqIPv4 *layers.IPv4, reqUDP *layers.UDP, respPayload []byte) error {
	ipLayer := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: reqIPv4.DstIP, DstIP: reqIPv4.SrcIP}
	udpLayer := &layers.UDP{SrcPort: reqUDP.DstPort, DstPort: reqUDP.SrcPort}

	if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return fmt.Errorf("failed to set network layer for checksum: %w", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	dnsLayer := &layers.DNS{}
	if err := dnsLayer.DecodeFromBytes(respPayload, gopacket.NilDecodeFeedback); err != nil {
		return fmt.Errorf("failed to decode dns response payload for serialization: %w", err)
	}
	dnsLayer.QR = true // Set the QR bit to indicate a response

	if err := gopacket.SerializeLayers(buffer, opts, ipLayer, udpLayer, dnsLayer); err != nil {
		return fmt.Errorf("failed to serialize DNS response: %w", err)
	}

	if _, err := app.tunDevice.Write(buffer.Bytes()); err != nil {
		return fmt.Errorf("failed to write DNS response: %w", err)
	}

	return nil
}

// convertToSSOSAMLConfig converts config.SAMLConfig to sso.SAMLConfig
func convertToSSOSAMLConfig(cfg *config.SAMLConfig) *sso.SAMLConfig {
	if cfg == nil {
		return nil
	}
	return &sso.SAMLConfig{
		Enabled:                 cfg.Enabled,
		IDPEntityID:             cfg.IDPEntityID,
		IDPSSOURL:               cfg.IDPSSOURL,
		IDPCertificate:          cfg.IDPCertificate,
		IDPCertificateRaw:       cfg.IDPCertificateRaw,
		SPEntityID:              cfg.SPEntityID,
		SPAssertionConsumerURL:  cfg.SPAssertionConsumerURL,
		SPPrivateKey:            cfg.SPPrivateKey,
		SPCertificate:           cfg.SPCertificate,
		NameIDFormat:            cfg.NameIDFormat,
		SignRequests:            cfg.SignRequests,
		RequireSignedResponse:   cfg.RequireSignedResponse,
		MaxClockSkew:            cfg.MaxClockSkew,
		UsernameAttribute:       cfg.UsernameAttribute,
		EmailAttribute:          cfg.EmailAttribute,
		GroupsAttribute:         cfg.GroupsAttribute,
	}
}

// convertToSSOOIDCConfig converts config.OIDCConfig to sso.OIDCConfig
func convertToSSOOIDCConfig(cfg *config.OIDCConfig) *sso.OIDCConfig {
	if cfg == nil {
		return nil
	}
	return &sso.OIDCConfig{
		Enabled:          cfg.Enabled,
		ProviderURL:      cfg.ProviderURL,
		ClientID:         cfg.ClientID,
		ClientSecret:     cfg.ClientSecret,
		RedirectURL:      cfg.RedirectURL,
		Scopes:           cfg.Scopes,
		UsernameClai:     cfg.UsernameClai,
		EmailClaim:       cfg.EmailClaim,
		GroupsClaim:      cfg.GroupsClaim,
		VerifyIssuer:     cfg.VerifyIssuer,
		MaxClockSkew:     cfg.MaxClockSkew,
		InsecureSkipTLS:  cfg.InsecureSkipTLS,
	}
}