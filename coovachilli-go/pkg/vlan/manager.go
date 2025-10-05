package vlan

import (
	"fmt"
	"net"
	"sync"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
)

// VLANManager manages VLAN configurations and assignments
type VLANManager struct {
	cfg    *config.VLANConfig
	logger zerolog.Logger
	mu     sync.RWMutex

	// VLAN assignments
	userVLANs    map[string]uint16 // username -> VLAN ID
	sessionVLANs map[string]uint16 // session ID -> VLAN ID
	macVLANs     map[string]uint16 // MAC address -> VLAN ID

	// VLAN pools
	vlans map[uint16]*VLANInfo

	// Statistics
	stats VLANStats
}

// VLANInfo contains information about a VLAN
type VLANInfo struct {
	ID          uint16
	Name        string
	Description string
	IPNetwork   *net.IPNet
	Gateway     net.IP
	DNS         []net.IP
	Isolated    bool // Client isolation within VLAN
	UserCount   int
}

// VLANStats tracks VLAN statistics
type VLANStats struct {
	TotalVLANs       int
	ActiveVLANs      int
	TotalAssignments uint64
	VLANUsage        map[uint16]int // VLAN ID -> user count
}

// NewVLANManager creates a new VLAN manager
func NewVLANManager(cfg *config.VLANConfig, logger zerolog.Logger) (*VLANManager, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	vm := &VLANManager{
		cfg:          cfg,
		logger:       logger.With().Str("component", "vlan").Logger(),
		userVLANs:    make(map[string]uint16),
		sessionVLANs: make(map[string]uint16),
		macVLANs:     make(map[string]uint16),
		vlans:        make(map[uint16]*VLANInfo),
		stats: VLANStats{
			VLANUsage: make(map[uint16]int),
		},
	}

	// Initialize configured VLANs
	if err := vm.loadVLANs(); err != nil {
		return nil, err
	}

	vm.logger.Info().Int("vlans", len(vm.vlans)).Msg("VLAN manager initialized")
	return vm, nil
}

// loadVLANs loads VLAN configurations
func (vm *VLANManager) loadVLANs() error {
	// Load VLANs from configuration
	for _, vlanCfg := range vm.cfg.VLANs {
		_, ipnet, err := net.ParseCIDR(vlanCfg.Network)
		if err != nil {
			return fmt.Errorf("invalid network for VLAN %d: %w", vlanCfg.ID, err)
		}

		vlanInfo := &VLANInfo{
			ID:          vlanCfg.ID,
			Name:        vlanCfg.Name,
			Description: vlanCfg.Description,
			IPNetwork:   ipnet,
			Gateway:     net.ParseIP(vlanCfg.Gateway),
			DNS:         parseIPList(vlanCfg.DNS),
			Isolated:    vlanCfg.Isolated,
			UserCount:   0,
		}

		vm.vlans[vlanCfg.ID] = vlanInfo
		vm.logger.Debug().
			Uint16("vlan_id", vlanCfg.ID).
			Str("name", vlanCfg.Name).
			Str("network", vlanCfg.Network).
			Msg("Loaded VLAN configuration")
	}

	vm.stats.TotalVLANs = len(vm.vlans)
	return nil
}

// AssignVLAN assigns a VLAN to a user/session
func (vm *VLANManager) AssignVLAN(sessionID, username string, mac net.HardwareAddr, vlanID uint16) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Validate VLAN exists
	vlan, exists := vm.vlans[vlanID]
	if !exists {
		return fmt.Errorf("VLAN %d does not exist", vlanID)
	}

	// Assign to session
	vm.sessionVLANs[sessionID] = vlanID

	// Assign to user if provided
	if username != "" {
		vm.userVLANs[username] = vlanID
	}

	// Assign to MAC if provided
	if mac != nil {
		vm.macVLANs[mac.String()] = vlanID
	}

	// Update statistics
	vlan.UserCount++
	vm.stats.VLANUsage[vlanID]++
	vm.stats.TotalAssignments++

	vm.logger.Info().
		Uint16("vlan_id", vlanID).
		Str("vlan_name", vlan.Name).
		Str("session", sessionID).
		Str("username", username).
		Msg("VLAN assigned")

	return nil
}

// GetVLANBySession returns the VLAN ID for a session
func (vm *VLANManager) GetVLANBySession(sessionID string) (uint16, bool) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	vlanID, exists := vm.sessionVLANs[sessionID]
	return vlanID, exists
}

// GetVLANByUser returns the VLAN ID for a user
func (vm *VLANManager) GetVLANByUser(username string) (uint16, bool) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	vlanID, exists := vm.userVLANs[username]
	return vlanID, exists
}

// GetVLANByMAC returns the VLAN ID for a MAC address
func (vm *VLANManager) GetVLANByMAC(mac net.HardwareAddr) (uint16, bool) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	vlanID, exists := vm.macVLANs[mac.String()]
	return vlanID, exists
}

// GetVLANInfo returns information about a VLAN
func (vm *VLANManager) GetVLANInfo(vlanID uint16) (*VLANInfo, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	vlan, exists := vm.vlans[vlanID]
	if !exists {
		return nil, fmt.Errorf("VLAN %d does not exist", vlanID)
	}

	// Return a copy to prevent external modifications
	return &VLANInfo{
		ID:          vlan.ID,
		Name:        vlan.Name,
		Description: vlan.Description,
		IPNetwork:   vlan.IPNetwork,
		Gateway:     vlan.Gateway,
		DNS:         vlan.DNS,
		Isolated:    vlan.Isolated,
		UserCount:   vlan.UserCount,
	}, nil
}

// ReleaseVLAN releases VLAN assignments for a session
func (vm *VLANManager) ReleaseVLAN(sessionID string) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if vlanID, exists := vm.sessionVLANs[sessionID]; exists {
		if vlan, ok := vm.vlans[vlanID]; ok {
			vlan.UserCount--
			if vlan.UserCount < 0 {
				vlan.UserCount = 0
			}
			vm.stats.VLANUsage[vlanID]--
		}
		delete(vm.sessionVLANs, sessionID)

		vm.logger.Debug().
			Uint16("vlan_id", vlanID).
			Str("session", sessionID).
			Msg("VLAN released")
	}
}

// GetDefaultVLAN returns the default VLAN for new users
func (vm *VLANManager) GetDefaultVLAN() (uint16, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	if vm.cfg.DefaultVLAN == 0 {
		return 0, fmt.Errorf("no default VLAN configured")
	}

	if _, exists := vm.vlans[vm.cfg.DefaultVLAN]; !exists {
		return 0, fmt.Errorf("default VLAN %d does not exist", vm.cfg.DefaultVLAN)
	}

	return vm.cfg.DefaultVLAN, nil
}

// GetVLANByRole assigns VLAN based on user role
func (vm *VLANManager) GetVLANByRole(role string) (uint16, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	if vlanID, exists := vm.cfg.RoleVLANs[role]; exists {
		if _, ok := vm.vlans[vlanID]; ok {
			return vlanID, nil
		}
		return 0, fmt.Errorf("VLAN %d for role %s does not exist", vlanID, role)
	}

	// Fall back to default VLAN
	if vm.cfg.DefaultVLAN != 0 {
		return vm.cfg.DefaultVLAN, nil
	}

	return 0, fmt.Errorf("no VLAN configured for role %s", role)
}

// GetStats returns current VLAN statistics
func (vm *VLANManager) GetStats() VLANStats {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	activeVLANs := 0
	for _, count := range vm.stats.VLANUsage {
		if count > 0 {
			activeVLANs++
		}
	}

	return VLANStats{
		TotalVLANs:       vm.stats.TotalVLANs,
		ActiveVLANs:      activeVLANs,
		TotalAssignments: vm.stats.TotalAssignments,
		VLANUsage:        copyVLANUsage(vm.stats.VLANUsage),
	}
}

// ListVLANs returns all configured VLANs
func (vm *VLANManager) ListVLANs() []*VLANInfo {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	vlans := make([]*VLANInfo, 0, len(vm.vlans))
	for _, vlan := range vm.vlans {
		vlans = append(vlans, &VLANInfo{
			ID:          vlan.ID,
			Name:        vlan.Name,
			Description: vlan.Description,
			IPNetwork:   vlan.IPNetwork,
			Gateway:     vlan.Gateway,
			DNS:         vlan.DNS,
			Isolated:    vlan.Isolated,
			UserCount:   vlan.UserCount,
		})
	}

	return vlans
}

// Helper functions
func parseIPList(ips []string) []net.IP {
	result := make([]net.IP, 0, len(ips))
	for _, ipStr := range ips {
		if ip := net.ParseIP(ipStr); ip != nil {
			result = append(result, ip)
		}
	}
	return result
}

func copyVLANUsage(usage map[uint16]int) map[uint16]int {
	result := make(map[uint16]int, len(usage))
	for k, v := range usage {
		result[k] = v
	}
	return result
}
