package cmdsock

import (
	"bufio"
	"net"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestCmdSockListener(t *testing.T) {
	// Setup
	socketPath := "/tmp/coovachilli_test.sock"
	cmdChan := make(chan CommandRequest, 1)
	logger := zerolog.Nop()

	listener := NewListener(socketPath, cmdChan, logger)
	go listener.Start()
	time.Sleep(50 * time.Millisecond) // Give the listener time to start

	// Test client connection
	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	defer conn.Close()

	// Goroutine to handle the command and send a response
	go func() {
		req := <-cmdChan
		require.Equal(t, "test command", req.Command)
		req.Response <- "OK"
	}()

	// Send a command
	_, err = conn.Write([]byte("test command\n"))
	require.NoError(t, err)

	// Read the response
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "OK\n", response)

	// Cleanup
	os.Remove(socketPath)
}