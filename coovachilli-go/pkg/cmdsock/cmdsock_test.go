package cmdsock

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestCmdSockListener(t *testing.T) {
	// Setup
	sockPath := "/tmp/coovachilli-test.sock"
	cmdChan := make(chan Command, 1)
	logger := zerolog.Nop()
	// Pass nil for sessionManager as it's not needed for this specific test
	listener := NewListener(sockPath, cmdChan, nil, logger)

	go listener.Start()
	time.Sleep(50 * time.Millisecond) // Give listener time to start
	defer func() {
		listener.Stop()
		os.Remove(sockPath)
	}()

	// Connect to the socket
	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	defer conn.Close()

	// Write a command that is expected to go to the command channel
	_, err = conn.Write([]byte("reload\n"))
	require.NoError(t, err)

	// Assert that the command is received on the channel
	select {
	case cmd := <-cmdChan:
		require.Equal(t, "reload", cmd.Cmd)
		// Send a dummy response to prevent blocking
		go func() { cmd.ResponseCh <- "OK" }()
	case <-time.After(1 * time.Second):
		t.Fatal("Did not receive command on channel")
	}
}
