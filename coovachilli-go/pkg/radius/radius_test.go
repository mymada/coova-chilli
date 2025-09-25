package radius

import (
	"net"
	"testing"
	"time"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func TestCoAListener(t *testing.T) {
	// Setup
	cfg := &config.Config{
		CoaPort:      3799,
		RadiusSecret: "secret",
	}
	logger := zerolog.Nop()
	client := NewClient(cfg, logger)
	coaReqChan := make(chan CoAIncomingRequest, 1)

	go client.StartCoAListener(coaReqChan)
	time.Sleep(50 * time.Millisecond) // Give the listener time to start

	// Create a Disconnect-Request packet
	packet := radius.New(radius.CodeDisconnectRequest, []byte(cfg.RadiusSecret))
	rfc2865.UserName_SetString(packet, "testuser")

	// Send the packet to the listener
	conn, err := net.Dial("udp", "127.0.0.1:3799")
	require.NoError(t, err)
	encoded, err := packet.Encode()
	require.NoError(t, err)
	_, err = conn.Write(encoded)
	require.NoError(t, err)
	conn.Close()

	// Assert that the request is received on the channel
	select {
	case req := <-coaReqChan:
		require.Equal(t, radius.CodeDisconnectRequest, req.Packet.Code)
		user := rfc2865.UserName_GetString(req.Packet)
		require.Equal(t, "testuser", user)
	case <-time.After(1 * time.Second):
		t.Fatal("Did not receive CoA request on channel")
	}
}
