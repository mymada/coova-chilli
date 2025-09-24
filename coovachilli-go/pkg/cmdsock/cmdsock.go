package cmdsock

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

// Listener holds the state for the command socket listener.
type Listener struct {
	path   string
	logger zerolog.Logger
	cmdChan chan<- string
}

// NewListener creates a new command socket listener.
func NewListener(path string, cmdChan chan<- string, logger zerolog.Logger) *Listener {
	return &Listener{
		path:   path,
		logger: logger.With().Str("component", "cmdsock").Logger(),
		cmdChan: cmdChan,
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
		cmd := strings.TrimSpace(scanner.Text())
		if cmd == "" {
			continue
		}
		l.logger.Info().Str("cmd", cmd).Msg("Received command")
		l.cmdChan <- cmd
		// TODO: Get a response from the main loop and write it back to the socket.
		// This would require a more complex channel structure (e.g., chan of a struct with a response chan).
		// For now, it's fire-and-forget.
	}

	if err := scanner.Err(); err != nil {
		l.logger.Error().Err(err).Msg("Error reading from command socket")
	}
}
