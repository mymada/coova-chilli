package cmdsock

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"coovachilli-go/pkg/core"
	"github.com/rs/zerolog"
)

// Command represents a command and its response channel
type Command struct {
	Cmd        string
	ResponseCh chan string
}

// Listener holds the state for the command socket listener.
type Listener struct {
	path           string
	logger         zerolog.Logger
	cmdChan        chan<- Command
	sessionManager *core.SessionManager
}

// NewListener creates a new command socket listener.
func NewListener(path string, cmdChan chan<- Command, sm *core.SessionManager, logger zerolog.Logger) *Listener {
	return &Listener{
		path:           path,
		logger:         logger.With().Str("component", "cmdsock").Logger(),
		cmdChan:        cmdChan,
		sessionManager: sm,
	}
}

// Start starts listening for connections on the Unix socket.
func (l *Listener) Start() {
	if l.path == "" {
		l.logger.Info().Msg("Command socket path is not configured, listener disabled.")
		return
	}

	// Remove old socket file if it exists
	if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) {
		l.logger.Fatal().Err(err).Msg("Failed to remove old command socket")
	}

	listener, err := net.Listen("unix", l.path)
	if err != nil {
		l.logger.Fatal().Err(err).Msg("Failed to start command socket listener")
		return
	}
	defer listener.Close()

	l.logger.Info().Str("path", l.path).Msg("Command socket listener started")

	for {
		conn, err := listener.Accept()
		if err != nil {
			l.logger.Error().Err(err).Msg("Failed to accept command socket connection")
			continue
		}
		go l.handleConnection(conn)
	}
}

func (l *Listener) handleConnection(conn net.Conn) {
	defer conn.Close()
	l.logger.Info().Str("remote_addr", conn.RemoteAddr().String()).Msg("Accepted command socket connection")

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		cmdStr := strings.TrimSpace(scanner.Text())
		if cmdStr == "" {
			continue
		}
		l.logger.Info().Str("cmd", cmdStr).Msg("Received command")

		// Process command directly for some cases, or send to channel for others
		response := l.handleCommand(cmdStr)

		// Write response back to client
		if _, err := fmt.Fprintf(conn, "%s\n", response); err != nil {
			l.logger.Error().Err(err).Msg("Failed to write response to command socket")
		}
	}

	if err := scanner.Err(); err != nil {
		l.logger.Error().Err(err).Msg("Error reading from command socket")
	}
}

func (l *Listener) handleCommand(cmdStr string) string {
	parts := strings.Fields(cmdStr)
	if len(parts) == 0 {
		return "ERROR: Empty command"
	}

	cmd := strings.ToLower(parts[0])
	switch cmd {
	case "list":
		return l.handleListSessions()
	case "show":
		if len(parts) < 2 {
			return "ERROR: show command requires a session identifier"
		}
		return l.handleShowSession(parts[1])
	case "disconnect", "kick":
		if len(parts) < 2 {
			return "ERROR: disconnect command requires a session identifier (MAC or IP)"
		}
		// Send to command channel for processing by main loop
		responseCh := make(chan string, 1)
		l.cmdChan <- Command{Cmd: cmdStr, ResponseCh: responseCh}
		select {
		case response := <-responseCh:
			return response
		}
	case "help":
		return l.handleHelp()
	case "version":
		return "CoovaChilli-Go v1.0.0"
	case "reload":
		responseCh := make(chan string, 1)
		l.cmdChan <- Command{Cmd: cmdStr, ResponseCh: responseCh}
		select {
		case response := <-responseCh:
			return response
		}
	default:
		return fmt.Sprintf("ERROR: Unknown command: %s (type 'help' for available commands)", cmd)
	}
	return "OK"
}

func (l *Listener) handleListSessions() string {
	sessions := l.sessionManager.GetAllSessions()
	if len(sessions) == 0 {
		return "No active sessions"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Total sessions: %d\n", len(sessions)))
	sb.WriteString("MAC Address       | IP Address      | Username         | Authenticated\n")
	sb.WriteString("------------------+-----------------+------------------+--------------\n")

	for _, s := range sessions {
		s.RLock()
		mac := s.HisMAC.String()
		ip := s.HisIP.String()
		username := s.Redir.Username
		if username == "" {
			username = "-"
		}
		authenticated := "No"
		if s.Authenticated {
			authenticated = "Yes"
		}
		s.RUnlock()
		sb.WriteString(fmt.Sprintf("%-17s | %-15s | %-16s | %s\n", mac, ip, username, authenticated))
	}

	return sb.String()
}

func (l *Listener) handleShowSession(identifier string) string {
	// Try to find session by IP or MAC
	ip := net.ParseIP(identifier)
	var session *core.Session
	var ok bool

	if ip != nil {
		session, ok = l.sessionManager.GetSessionByIP(ip)
	} else {
		mac, err := net.ParseMAC(identifier)
		if err == nil {
			session, ok = l.sessionManager.GetSessionByMAC(mac)
		}
	}

	if !ok || session == nil {
		return fmt.Sprintf("ERROR: Session not found for identifier: %s", identifier)
	}

	session.RLock()
	defer session.RUnlock()

	var sb strings.Builder
	sb.WriteString("Session Information:\n")
	sb.WriteString(fmt.Sprintf("  MAC Address:      %s\n", session.HisMAC.String()))
	sb.WriteString(fmt.Sprintf("  IP Address:       %s\n", session.HisIP.String()))
	sb.WriteString(fmt.Sprintf("  Username:         %s\n", session.Redir.Username))
	sb.WriteString(fmt.Sprintf("  Authenticated:    %v\n", session.Authenticated))
	sb.WriteString(fmt.Sprintf("  Session ID:       %s\n", session.SessionID))
	sb.WriteString(fmt.Sprintf("  Start Time:       %s\n", session.StartTime.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("  Input Octets:     %d\n", session.InputOctets))
	sb.WriteString(fmt.Sprintf("  Output Octets:    %d\n", session.OutputOctets))
	sb.WriteString(fmt.Sprintf("  Input Packets:    %d\n", session.InputPackets))
	sb.WriteString(fmt.Sprintf("  Output Packets:   %d\n", session.OutputPackets))
	sb.WriteString(fmt.Sprintf("  Bandwidth Up:     %d\n", session.SessionParams.BandwidthMaxUp))
	sb.WriteString(fmt.Sprintf("  Bandwidth Down:   %d\n", session.SessionParams.BandwidthMaxDown))

	return sb.String()
}

func (l *Listener) handleHelp() string {
	return `Available commands:
  list                  - List all active sessions
  show <MAC|IP>         - Show detailed information for a session
  disconnect <MAC|IP>   - Disconnect a session
  kick <MAC|IP>         - Alias for disconnect
  reload                - Reload configuration
  version               - Show version information
  help                  - Show this help message`
}
