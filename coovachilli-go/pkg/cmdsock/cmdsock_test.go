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
	cmdChan := make(chan string, 1)
	logger := zerolog.Nop()
	listener := NewListener(sockPath, cmdChan, logger)

	go listener.Start()
	time.Sleep(50 * time.Millisecond) // Give listener time to start
	defer os.Remove(sockPath)

	// Connect to the socket
	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	defer conn.Close()

	// Write a command
	_, err = conn.Write([]byte("list\n"))
	require.NoError(t, err)

	// Assert that the command is received on the channel
	select {
	case cmd := <-cmdChan:
		require.Equal(t, "list", cmd)
	case <-time.After(1 * time.Second):
		t.Fatal("Did not receive command on channel")
	}
}
