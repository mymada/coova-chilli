package firewall

import (
	"fmt"
	"net"
	"testing"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// mockIPTables is a mock implementation of the iptables.IPTables interface.
type mockIPTables struct {
	commands [][]string
}

func (m *mockIPTables) Append(table, chain string, rulespec ...string) error {
	cmd := append([]string{"-A", table, chain}, rulespec...)
	m.commands = append(m.commands, cmd)
	return nil
}

func (m *mockIPTables) Insert(table, chain string, pos int, rulespec ...string) error {
	cmd := append([]string{"-I", table, chain, fmt.Sprintf("%d", pos)}, rulespec...)
	m.commands = append(m.commands, cmd)
	return nil
}

func (m *mockIPTables) Delete(table, chain string, rulespec ...string) error {
	cmd := append([]string{"-D", table, chain}, rulespec...)
	m.commands = append(m.commands, cmd)
	return nil
}

func (m *mockIPTables) NewChain(table, chain string) error {
	cmd := append([]string{"-N", table, chain})
	m.commands = append(m.commands, cmd)
	return nil
}

func (m *mockIPTables) ClearChain(table, chain string) error {
	cmd := append([]string{"-X", table, chain})
	m.commands = append(m.commands, cmd)
	return nil
}

func (m *mockIPTables) DeleteChain(table, chain string) error {
	cmd := append([]string{"-X", table, chain})
	m.commands = append(m.commands, cmd)
	return nil
}

func (m *mockIPTables) Exists(table, chain string, rulespec ...string) (bool, error) {
	// For the mock, assume chains don't exist initially so they are always created.
	return false, nil
}

func (m *mockIPTables) ListChains(table string) ([]string, error) {
	// Return an empty list, can be expanded if needed for more complex tests.
	return []string{}, nil
}

// Ensure mockIPTables satisfies the IPTables interface
var _ IPTables = &mockIPTables{}

func TestFirewall_Initialize_OpenPorts(t *testing.T) {
	cfg := &config.Config{
		TUNDev: "tun0",
		Net: net.IPNet{
			IP:   net.ParseIP("10.0.0.0"),
			Mask: net.CIDRMask(24, 32),
		},
		TCPPorts: []int{8080, 8443},
		UDPPorts: []int{53, 123},
	}
	logger := zerolog.Nop()
	mockIPT := &mockIPTables{}

	fw := &Firewall{
		cfg:    cfg,
		ipt:    mockIPT,
		logger: logger,
	}

	err := fw.Initialize()
	require.NoError(t, err)

	expectedCommands := [][]string{
		{"-A", "filter", "chilli", "-p", "tcp", "--dport", "8080", "-j", "ACCEPT"},
		{"-A", "filter", "chilli", "-p", "tcp", "--dport", "8443", "-j", "ACCEPT"},
		{"-A", "filter", "chilli", "-p", "udp", "--dport", "53", "-j", "ACCEPT"},
		{"-A", "filter", "chilli", "-p", "udp", "--dport", "123", "-j", "ACCEPT"},
	}

	// Check that the expected commands were called
	for _, expected := range expectedCommands {
		found := false
		for _, actual := range mockIPT.commands {
			if equal(expected, actual) {
				found = true
				break
			}
		}
		require.True(t, found, "Expected command not found: %v", expected)
	}
}

// equal checks if two string slices are equal.
func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}