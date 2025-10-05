package firewall

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

const (
	ufwSysctlConf    = "/etc/ufw/sysctl.conf"
	ufwBeforeRules   = "/etc/ufw/before.rules"
	ipForwardSetting = "net/ipv4/ip_forward=1"
)

// ufwConfigManager handles the modification of UFW's configuration files.
type ufwConfigManager struct {
	logger zerolog.Logger
	// VFS helpers for testing
	readFile  func(string) ([]byte, error)
	writeFile func(string, []byte, os.FileMode) error
}

func newUfwConfigManager(logger zerolog.Logger) *ufwConfigManager {
	return &ufwConfigManager{
		logger:    logger.With().Str("component", "ufw_config").Logger(),
		readFile:  os.ReadFile,
		writeFile: os.WriteFile,
	}
}

// ensureUfwIpForwarding checks and enables IP forwarding in UFW's sysctl config.
func (m *ufwConfigManager) ensureUfwIpForwarding() error {
	m.logger.Info().Msg("Ensuring IP forwarding is enabled for UFW...")
	content, err := m.readFile(ufwSysctlConf)
	if err != nil {
		if os.IsNotExist(err) {
			m.logger.Warn().Str("file", ufwSysctlConf).Msg("File does not exist, cannot enable IP forwarding automatically.")
			return nil // Non-fatal, as it might be enabled elsewhere.
		}
		return fmt.Errorf("could not read %s: %w", ufwSysctlConf, err)
	}

	lines := strings.Split(string(content), "\n")
	found := false
	modified := false
	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasSuffix(trimmedLine, ipForwardSetting) {
			if strings.HasPrefix(trimmedLine, "#") {
				m.logger.Debug().Msg("IP forwarding setting is commented, uncommenting.")
				lines[i] = ipForwardSetting // Uncomment the line
				modified = true
			}
			found = true
			break
		}
	}

	if !found {
		m.logger.Debug().Msg("IP forwarding setting not found, adding it.")
		lines = append(lines, "", "# Enable IP forwarding for CoovaChilli-Go", ipForwardSetting)
		modified = true
	}

	if modified {
		newContent := strings.Join(lines, "\n")
		m.logger.Info().Msgf("Writing updated IP forwarding configuration to %s", ufwSysctlConf)
		if err := m.writeFile(ufwSysctlConf, []byte(newContent), 0644); err != nil {
			return fmt.Errorf("failed to write updated content to %s: %w", ufwSysctlConf, err)
		}
	} else {
		m.logger.Info().Msg("IP forwarding is already correctly configured.")
	}

	return nil
}

// ensureUfwNatMasquerade ensures the necessary NAT MASQUERADE rules are in /etc/ufw/before.rules.
func (m *ufwConfigManager) ensureUfwNatMasquerade(extIf string, tunNet string) error {
	m.logger.Info().Msg("Ensuring UFW NAT MASQUERADE rule exists...")
	if extIf == "" || tunNet == "" {
		m.logger.Warn().Msg("External interface or TUN network not configured, skipping NAT MASQUERADE setup.")
		return nil
	}

	content, err := m.readFile(ufwBeforeRules)
	if err != nil {
		if os.IsNotExist(err) {
			m.logger.Warn().Str("file", ufwBeforeRules).Msg("File does not exist, cannot add NAT rule.")
			return nil // Non-fatal
		}
		return fmt.Errorf("could not read %s: %w", ufwBeforeRules, err)
	}

	masqueradeRule := fmt.Sprintf("-A POSTROUTING -s %s -o %s -j MASQUERADE", tunNet, extIf)
	if bytes.Contains(content, []byte(masqueradeRule)) {
		m.logger.Info().Msg("UFW MASQUERADE rule already exists.")
		return nil
	}

	natTableMarker := []byte("*nat")
	if !bytes.Contains(content, natTableMarker) {
		return m.addNatTable(content, masqueradeRule)
	}
	return m.addRuleToNatTable(content, masqueradeRule)
}

func (m *ufwConfigManager) addNatTable(content []byte, rule string) error {
	m.logger.Info().Msg("No *nat table found in before.rules, adding new table.")
	filterTableMarker := []byte("*filter")
	insertionPoint := bytes.Index(content, filterTableMarker)
	if insertionPoint == -1 {
		return fmt.Errorf("could not find '%s' marker in %s; cannot add NAT table", filterTableMarker, ufwBeforeRules)
	}

	var natRules strings.Builder
	natRules.WriteString("\n# NAT table rules for CoovaChilli-Go\n")
	natRules.WriteString("*nat\n")
	natRules.WriteString(":POSTROUTING ACCEPT [0:0]\n")
	natRules.WriteString(rule + "\n")
	natRules.WriteString("COMMIT\n")

	var newContent bytes.Buffer
	newContent.Write(content[:insertionPoint])
	newContent.WriteString(natRules.String())
	newContent.Write(content[insertionPoint:])

	return m.writeUfwFile(ufwBeforeRules, newContent.Bytes(), content)
}

func (m *ufwConfigManager) addRuleToNatTable(content []byte, rule string) error {
	m.logger.Info().Msg("Found existing *nat table, adding MASQUERADE rule.")
	commitMarker := []byte("COMMIT")
	natTableStart := bytes.Index(content, []byte("*nat"))
	natTableSection := content[natTableStart:]
	commitInNat := bytes.Index(natTableSection, commitMarker)

	if commitInNat == -1 {
		return fmt.Errorf("found *nat table in %s but no subsequent COMMIT; cannot add rule", ufwBeforeRules)
	}

	insertionPoint := natTableStart + commitInNat

	var newContent bytes.Buffer
	newContent.Write(content[:insertionPoint])
	newContent.WriteString("# CoovaChilli-Go MASQUERADE rule\n")
	newContent.WriteString(rule + "\n")
	newContent.Write(content[insertionPoint:])

	return m.writeUfwFile(ufwBeforeRules, newContent.Bytes(), content)
}

func (m *ufwConfigManager) writeUfwFile(path string, newContent, originalContent []byte) error {
	m.logger.Info().Msgf("Writing updated configuration to %s", path)
	backupPath := path + ".coova-go.bak"
	if err := m.writeFile(backupPath, originalContent, 0644); err != nil {
		m.logger.Warn().Err(err).Str("path", backupPath).Msg("Failed to create backup file")
	}
	return m.writeFile(path, newContent, 0644)
}