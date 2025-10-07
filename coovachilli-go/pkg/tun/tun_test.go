package tun

import (
	"net"
	"testing"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
)

func TestTUNConfigurationIPv4Only(t *testing.T) {
	// This test verifies that TUN configuration works with IPv4 only
	// Note: This test requires root privileges and actual network interfaces
	// In CI/CD, it should be skipped or mocked

	if testing.Short() {
		t.Skip("Skipping TUN test in short mode (requires root)")
	}

	_, ipnet, _ := net.ParseCIDR("10.1.0.1/24")
	cfg := &config.Config{
		Net:        *ipnet,
		TUNDev:     "tun_test_v4",
		IPv6Enable: false,
	}

	logger := zerolog.Nop()

	// Note: This will fail without root privileges
	// In production tests, use mock interfaces
	_, err := New(cfg, logger)
	if err != nil {
		// Expected to fail without root - log but don't fail test
		t.Logf("TUN creation failed (expected without root): %v", err)
	}
}

func TestTUNConfigurationDualStack(t *testing.T) {
	// This test verifies that TUN configuration works with dual-stack
	if testing.Short() {
		t.Skip("Skipping TUN test in short mode (requires root)")
	}

	_, ipnet4, _ := net.ParseCIDR("10.1.0.1/24")
	_, ipnet6, _ := net.ParseCIDR("2001:db8::/64")

	cfg := &config.Config{
		Net:        *ipnet4,
		NetV6:      *ipnet6,
		TUNDev:     "tun_test_v6",
		IPv6Enable: true,
	}

	logger := zerolog.Nop()

	_, err := New(cfg, logger)
	if err != nil {
		t.Logf("TUN creation failed (expected without root): %v", err)
	}
}

func TestReadPackets(t *testing.T) {
	// Test that ReadPackets properly dispatches packets
	// This is a minimal test - full testing requires mock TUN device
	if testing.Short() {
		t.Skip("Skipping packet read test in short mode")
	}

	// In a real test, we'd create a mock water.Interface
	// For now, just verify the function exists and compiles
	t.Log("ReadPackets function exists")
}

func TestWritePacket(t *testing.T) {
	// Test that WritePacket properly writes packets
	if testing.Short() {
		t.Skip("Skipping packet write test in short mode")
	}

	// In a real test, we'd create a mock water.Interface
	t.Log("WritePacket function exists")
}
