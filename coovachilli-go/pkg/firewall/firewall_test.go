package firewall

import (
	"errors"
	"net"
	"os/exec"
	"testing"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// mockIPTablesFirewall is a dummy implementation for testing the factory.
type mockIPTablesFirewall struct{}

func (m *mockIPTablesFirewall) Initialize() error                      { return nil }
func (m *mockIPTablesFirewall) Cleanup()                               {}
func (m *mockIPTablesFirewall) AddAuthenticatedUser(ip net.IP) error   { return nil }
func (m *mockIPTablesFirewall) RemoveAuthenticatedUser(ip net.IP) error { return nil }

func TestNewFirewall(t *testing.T) {
	logger := zerolog.Nop()
	cfg := &config.Config{}

	// Mock the iptables constructor to avoid system calls
	originalNewIPTablesFirewall := newIPTablesFirewall
	newIPTablesFirewall = func(cfg *config.Config, logger zerolog.Logger) (*IPTablesFirewall, error) {
		return &IPTablesFirewall{}, nil
	}
	defer func() { newIPTablesFirewall = originalNewIPTablesFirewall }()

	// --- Test case 1: Auto-detect UFW ---
	cfg.FirewallBackend = "auto"
	originalLookPath := lookPath
	lookPath = func(file string) (string, error) {
		if file == "ufw" {
			return "/usr/sbin/ufw", nil
		}
		return "", errors.New("not found")
	}

	fw, err := New(cfg, logger)
	require.NoError(t, err)
	_, isUfw := fw.(*UfwFirewall)
	require.True(t, isUfw, "Expected UFW firewall backend")

	// --- Test case 2: Auto-detect fallback to iptables ---
	lookPath = func(file string) (string, error) {
		return "", errors.New("not found")
	}
	fw, err = New(cfg, logger)
	require.NoError(t, err)
	_, isIptables := fw.(*IPTablesFirewall)
	require.True(t, isIptables, "Expected iptables firewall backend")

	// --- Test case 3: Explicitly select ufw ---
	cfg.FirewallBackend = "ufw"
	fw, err = New(cfg, logger)
	require.NoError(t, err)
	_, isUfw = fw.(*UfwFirewall)
	require.True(t, isUfw, "Expected UFW firewall backend when explicitly selected")

	// --- Test case 4: Explicitly select iptables ---
	cfg.FirewallBackend = "iptables"
	fw, err = New(cfg, logger)
	require.NoError(t, err)
	_, isIptables = fw.(*IPTablesFirewall)
	require.True(t, isIptables, "Expected iptables firewall backend when explicitly selected")

	// Restore original functions
	lookPath = originalLookPath
}

func TestUfwFirewallCommands(t *testing.T) {
	cfg := &config.Config{
		TUNDev: "tun0",
	}
	logger := zerolog.Nop()

	var executedCmds [][]string

	// Mock the ufw command execution
	originalUfwCommand := ufwCommand
	ufwCommand = func(name string, arg ...string) *exec.Cmd {
		require.Equal(t, "ufw", name)
		executedCmds = append(executedCmds, arg)
		// Return a dummy command that will succeed
		return exec.Command("true")
	}
	defer func() { ufwCommand = originalUfwCommand }()

	fw, err := newUfwFirewall(cfg, logger)
	require.NoError(t, err)

	// Test AddAuthenticatedUser
	ip := net.ParseIP("10.1.0.123")
	err = fw.AddAuthenticatedUser(ip)
	require.NoError(t, err)
	require.Contains(t, executedCmds, []string{"insert", "1", "route", "allow", "in", "on", "tun0", "from", "10.1.0.123"})

	// Test RemoveAuthenticatedUser
	err = fw.RemoveAuthenticatedUser(ip)
	require.NoError(t, err)
	require.Contains(t, executedCmds, []string{"delete", "route", "allow", "in", "on", "tun0", "from", "10.1.0.123"})
}