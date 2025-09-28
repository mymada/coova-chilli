package firewall

import (
	"fmt"
	"net"
	"testing"
	"time"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// mockIPTables is a mock implementation of the IPTables interface.
type mockIPTables struct {
	commands [][]string
	exists   map[string]bool
}

func newMockIPTables() *mockIPTables {
	return &mockIPTables{
		commands: make([][]string, 0),
		exists:   make(map[string]bool),
	}
}
func (m *mockIPTables) Append(table, chain string, rulespec ...string) error {
	cmd := append([]string{"-A", table, chain}, rulespec...)
	m.commands = append(m.commands, cmd)
	m.exists[fmt.Sprintf("%s:%s:%v", table, chain, rulespec)] = true
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
	m.exists[fmt.Sprintf("%s:%s:%v", table, chain, rulespec)] = false
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
	key := fmt.Sprintf("%s:%s:%v", table, chain, rulespec)
	return m.exists[key], nil
}
func (m *mockIPTables) ListChains(table string) ([]string, error) {
	return []string{}, nil
}

var _ IPTables = &mockIPTables{}

// mockCommandRunner is a mock implementation of the CommandRunner interface.
type mockCommandRunner struct {
	commands [][]string
}

func (m *mockCommandRunner) Run(name string, args ...string) error {
	cmd := append([]string{name}, args...)
	m.commands = append(m.commands, cmd)
	return nil
}
var _ CommandRunner = &mockCommandRunner{}

// Helper to check if a command exists in the mock's history
func commandExists(commands [][]string, expected []string) bool {
	for _, cmd := range commands {
		if equal(cmd, expected) {
			return true
		}
	}
	return false
}

func TestFirewall_BandwidthShaping(t *testing.T) {
	cfg := &config.Config{TUNDev: "tun0"}
	logger := zerolog.Nop()
	mockIPT := newMockIPTables()
	mockRunner := &mockCommandRunner{}
	fw := &Firewall{
		cfg:                   cfg,
		ipt:                   mockIPT,
		logger:                logger,
		runner:                mockRunner,
		dynamicWalledGarden:   make(map[string]dynamicWalledGardenEntry),
	}

	userIP := net.ParseIP("10.0.0.99")
	bwUp := uint64(512000)
	bwDown := uint64(1024000)

	// Test AddAuthenticatedUser
	err := fw.AddAuthenticatedUser(userIP, bwUp, bwDown)
	require.NoError(t, err)

	expectedAdd := [][]string{
		{"tc", "class", "add", "dev", "tun0", "parent", "1:", "classid", "1:63", "htb", "rate", "1024kbit"},
		{"tc", "filter", "add", "dev", "tun0", "protocol", "ip", "parent", "1:0", "prio", "1", "u32", "match", "ip", "dst", "10.0.0.99/32", "flowid", "1:63"},
		{"tc", "class", "add", "dev", "ifb0", "parent", "2:", "classid", "2:63", "htb", "rate", "512kbit"},
		{"tc", "filter", "add", "dev", "ifb0", "protocol", "ip", "parent", "2:0", "prio", "1", "u32", "match", "ip", "src", "10.0.0.99/32", "flowid", "2:63"},
	}
	for _, expected := range expectedAdd {
		require.True(t, commandExists(mockRunner.commands, expected), "Expected TC command not found: %v", expected)
	}

	// Test UpdateUserBandwidth
	mockRunner.commands = nil // Reset mock
	err = fw.UpdateUserBandwidth(userIP, 256000, 2048000)
	require.NoError(t, err)
	expectedUpdate := [][]string{
		{"tc", "class", "change", "dev", "tun0", "parent", "1:", "classid", "1:63", "htb", "rate", "2048kbit"},
		{"tc", "class", "change", "dev", "ifb0", "parent", "2:", "classid", "2:63", "htb", "rate", "256kbit"},
	}
	for _, expected := range expectedUpdate {
		require.True(t, commandExists(mockRunner.commands, expected), "Expected TC command not found: %v", expected)
	}

	// Test RemoveAuthenticatedUser
	mockRunner.commands = nil // Reset mock
	err = fw.RemoveAuthenticatedUser(userIP)
	require.NoError(t, err)
	expectedRemove := [][]string{
		{"tc", "filter", "del", "dev", "tun0", "protocol", "ip", "parent", "1:0", "prio", "1", "u32", "match", "ip", "dst", "10.0.0.99/32", "flowid", "1:63"},
		{"tc", "class", "del", "dev", "tun0", "parent", "1:", "classid", "1:63"},
		{"tc", "filter", "del", "dev", "ifb0", "protocol", "ip", "parent", "2:0", "prio", "1", "u32", "match", "ip", "src", "10.0.0.99/32", "flowid", "2:63"},
		{"tc", "class", "del", "dev", "ifb0", "parent", "2:", "classid", "2:63"},
	}
	for _, expected := range expectedRemove {
		require.True(t, commandExists(mockRunner.commands, expected), "Expected TC command not found: %v", expected)
	}
}

func TestFirewall_DynamicWalledGarden(t *testing.T) {
	cfg := &config.Config{}
	logger := zerolog.Nop()
	mockIPT := newMockIPTables()
	fw := &Firewall{
		cfg:                   cfg,
		ipt:                   mockIPT,
		logger:                logger,
		dynamicWalledGarden:   make(map[string]dynamicWalledGardenEntry),
	}

	ip1 := net.ParseIP("8.8.8.8")
	ip2 := net.ParseIP("8.8.4.4")

	// Add two IPs with different TTLs
	err := fw.AddToWalledGarden(ip1, 2) // Expires in 2 seconds
	require.NoError(t, err)
	err = fw.AddToWalledGarden(ip2, 10) // Expires in 10 seconds
	require.NoError(t, err)

	require.Len(t, fw.dynamicWalledGarden, 2, "Should have two entries in the map")
	require.Len(t, mockIPT.commands, 2, "Should have two iptables append commands")

	// Call reaper, nothing should expire yet
	fw.reapWalledGardenEntries()
	require.Len(t, fw.dynamicWalledGarden, 2, "No entries should have been reaped yet")

	// Manipulate time to simulate expiration
	fw.dynamicWalledGardenMu.Lock()
	entry1 := fw.dynamicWalledGarden[ip1.String()]
	entry1.ExpiresAt = time.Now().Add(-1 * time.Second) // Set expiration to the past
	fw.dynamicWalledGarden[ip1.String()] = entry1
	fw.dynamicWalledGardenMu.Unlock()

	// Call reaper again, ip1 should be removed
	fw.reapWalledGardenEntries()
	require.Len(t, fw.dynamicWalledGarden, 1, "One entry should have been reaped")
	_, exists := fw.dynamicWalledGarden[ip1.String()]
	require.False(t, exists, "ip1 should have been removed from the map")
	require.Len(t, mockIPT.commands, 3, "An iptables delete command should have been issued")
	expectedDelete := []string{"-D", "filter", "chilli_walled_garden", "-d", "8.8.8.8", "-j", "ACCEPT"}
	require.True(t, commandExists(mockIPT.commands, expectedDelete), "Expected iptables delete command was not found")
}

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