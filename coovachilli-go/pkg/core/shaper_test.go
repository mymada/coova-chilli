package core

import (
	"testing"
	"time"

	"coovachilli-go/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestLeakyBucket(t *testing.T) {
	cfg := &config.Config{
		// 1 MB/s limit
		DefBandwidthMaxDown: 1000000 * 8,
	}

	session := &Session{}
	session.SessionParams.BandwidthMaxDown = cfg.DefBandwidthMaxDown
	session.InitializeShaper(cfg)

	// Bucket size should be calculated based on the bandwidth limit
	// (1 MB/s for 1 second = 1,000,000 bytes)
	require.Equal(t, uint64(1000000), session.BucketDownSize)

	// 1. Test that we can send up to the bucket size initially
	packetSize := uint64(200000)
	for i := 0; i < 5; i++ {
		require.False(t, session.ShouldDropPacket(packetSize, false), "Packet %d should not be dropped", i+1)
	}

	// 2. Test that the next packet is dropped because the bucket is full
	require.True(t, session.ShouldDropPacket(packetSize, false), "Packet should be dropped as bucket is full")

	// 3. Wait for the bucket to leak
	// Wait for 0.5 seconds. Leaked bytes = 1,000,000 * 0.5 = 500,000 bytes
	time.Sleep(500 * time.Millisecond)

	// Now we should have space for at least two more packets (2 * 200,000 = 400,000)
	require.False(t, session.ShouldDropPacket(packetSize, false), "Packet should not be dropped after waiting")
	require.False(t, session.ShouldDropPacket(packetSize, false), "Packet should not be dropped after waiting")

	// The bucket should be full again
	require.True(t, session.ShouldDropPacket(packetSize, false), "Packet should be dropped again")
}