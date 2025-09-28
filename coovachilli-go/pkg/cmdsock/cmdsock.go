package cmdsock

import (
	"bufio"
	"net"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// CommandRequest encapsulates a command sent over the unix socket and includes a channel for the response.
type CommandRequest struct {
	Command  string
	Response chan string
}

// Listener holds the state for the command socket listener.
type Listener struct {
	path    string
	logger  zerolog.Logger
	cmdChan chan<- CommandRequest
}

// NewListener creates a new command socket listener.
func NewListener(path string, cmdChan chan<- CommandRequest, logger zerolog.Logger) *Listener {
	return &Listener{
		path:    path,
		logger:  logger.With().Str("component", "cmdsock").Logger(),
		cmdChan: cmdChan,
	}
}

// Start starts listening for connections on the Unix socket.
func (l *Listener) Start() {
	if l.path == "" {
		l.logger.Info().Msg("Command socket path is not configured, listener disabled.")
		return
	}

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

		// Create a request with a response channel
		req := CommandRequest{
			Command:  cmdStr,
			Response: make(chan string, 1),
		}

		// Send the request to the main processing loop
		l.cmdChan <- req

		// Wait for a response or timeout
		select {
		case response := <-req.Response:
			if _, err := conn.Write([]byte(response + "\n")); err != nil {
				l.logger.Error().Err(err).Msg("Failed to write response to command socket")
			}
		case <-time.After(2 * time.Second):
			l.logger.Warn().Str("cmd", cmdStr).Msg("Timeout waiting for command response")
			_, _ = conn.Write([]byte("ERROR: Timeout waiting for response\n"))
		}
	}

	if err := scanner.Err(); err != nil {
		l.logger.Error().Err(err).Msg("Error reading from command socket")
	}
}