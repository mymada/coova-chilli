package firewall

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockFS is a simple in-memory filesystem for testing.
type mockFS struct {
	mu    sync.Mutex
	files map[string]string
}

func newMockFS() *mockFS {
	return &mockFS{
		files: make(map[string]string),
	}
}

func (fs *mockFS) ReadFile(path string) ([]byte, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	content, ok := fs.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return []byte(content), nil
}

func (fs *mockFS) WriteFile(path string, data []byte, perm os.FileMode) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.files[path] = string(data)
	return nil
}

func (fs *mockFS) GetFileContent(path string) string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.files[path]
}

func setupTestManager(fs *mockFS) *ufwConfigManager {
	m := newUfwConfigManager(zerolog.Nop())
	m.readFile = fs.ReadFile
	m.writeFile = fs.WriteFile
	return m
}

func TestEnsureUfwIpForwarding(t *testing.T) {
	t.Run("setting is commented", func(t *testing.T) {
		fs := newMockFS()
		fs.files[ufwSysctlConf] = "#" + ipForwardSetting
		m := setupTestManager(fs)

		err := m.ensureUfwIpForwarding()
		require.NoError(t, err)

		content := fs.GetFileContent(ufwSysctlConf)
		assert.True(t, strings.Contains(content, ipForwardSetting))
		assert.False(t, strings.Contains(content, "#"+ipForwardSetting))
	})

	t.Run("setting is missing", func(t *testing.T) {
		fs := newMockFS()
		fs.files[ufwSysctlConf] = "some other content"
		m := setupTestManager(fs)

		err := m.ensureUfwIpForwarding()
		require.NoError(t, err)

		content := fs.GetFileContent(ufwSysctlConf)
		assert.Contains(t, content, ipForwardSetting)
	})

	t.Run("setting is correct", func(t *testing.T) {
		originalContent := "net/ipv4/ip_forward=1"
		fs := newMockFS()
		fs.files[ufwSysctlConf] = originalContent
		m := setupTestManager(fs)

		err := m.ensureUfwIpForwarding()
		require.NoError(t, err)

		content := fs.GetFileContent(ufwSysctlConf)
		assert.Equal(t, originalContent, content)
	})
}

func TestEnsureUfwNatMasquerade(t *testing.T) {
	const extIf = "eth0"
	const tunNet = "10.1.0.0/24"
	const baseBeforeRules = "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT"
	masqueradeRule := fmt.Sprintf("-A POSTROUTING -s %s -o %s -j MASQUERADE", tunNet, extIf)

	t.Run("nat table is missing", func(t *testing.T) {
		fs := newMockFS()
		fs.files[ufwBeforeRules] = baseBeforeRules
		m := setupTestManager(fs)

		err := m.ensureUfwNatMasquerade(extIf, tunNet)
		require.NoError(t, err)

		content := fs.GetFileContent(ufwBeforeRules)
		assert.Contains(t, content, "*nat")
		assert.Contains(t, content, masqueradeRule)
		assert.True(t, strings.Index(content, "*nat") < strings.Index(content, "*filter"))
	})

	t.Run("nat table exists but rule is missing", func(t *testing.T) {
		fs := newMockFS()
		fs.files[ufwBeforeRules] = "*nat\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n" + baseBeforeRules
		m := setupTestManager(fs)

		err := m.ensureUfwNatMasquerade(extIf, tunNet)
		require.NoError(t, err)

		content := fs.GetFileContent(ufwBeforeRules)
		assert.Contains(t, content, masqueradeRule)
	})

	t.Run("rule already exists", func(t *testing.T) {
		originalContent := "*nat\n:POSTROUTING ACCEPT [0:0]\n" + masqueradeRule + "\nCOMMIT\n" + baseBeforeRules
		fs := newMockFS()
		fs.files[ufwBeforeRules] = originalContent
		m := setupTestManager(fs)

		err := m.ensureUfwNatMasquerade(extIf, tunNet)
		require.NoError(t, err)

		content := fs.GetFileContent(ufwBeforeRules)
		assert.Equal(t, originalContent, content)
	})
}