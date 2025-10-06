package roles

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// RoleConfig holds role management configuration
type RoleConfig struct {
	Enabled     bool   `yaml:"enabled" envconfig:"ROLES_ENABLED"`
	RolesDir    string `yaml:"roles_dir" envconfig:"ROLES_DIR"`
	DefaultRole string `yaml:"default_role" envconfig:"DEFAULT_ROLE"`
}

// Role represents a user role with permissions and restrictions
type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Priority    int      `json:"priority"` // Higher priority takes precedence
	Permissions []string `json:"permissions"`

	// Network access
	VLANID          uint16   `json:"vlan_id"`
	AllowedNetworks []string `json:"allowed_networks"` // CIDR ranges
	BlockedNetworks []string `json:"blocked_networks"`

	// Bandwidth limits
	MaxBandwidthDown uint64 `json:"max_bandwidth_down"` // bytes/sec
	MaxBandwidthUp   uint64 `json:"max_bandwidth_up"`

	// Session limits
	MaxSessionDuration    time.Duration `json:"max_session_duration"`
	MaxConcurrentSessions int           `json:"max_concurrent_sessions"`
	MaxDailyData          uint64        `json:"max_daily_data"`   // bytes
	MaxMonthlyData        uint64        `json:"max_monthly_data"` // bytes

	// Time restrictions
	AllowedDaysOfWeek []int    `json:"allowed_days_of_week"` // 0=Sunday, 6=Saturday
	AllowedTimeStart  string   `json:"allowed_time_start"`   // HH:MM format
	AllowedTimeEnd    string   `json:"allowed_time_end"`     // HH:MM format

	// Features
	PortalAccess       bool     `json:"portal_access"`
	APIAccess          bool     `json:"api_access"`
	AdminAccess        bool     `json:"admin_access"`
	CanCreateGuests    bool     `json:"can_create_guests"`
	CanApproveGuests   bool     `json:"can_approve_guests"`
	CanViewLogs        bool     `json:"can_view_logs"`
	CanModifyPolicies  bool     `json:"can_modify_policies"`
	AllowedServices    []string `json:"allowed_services"` // http, https, ssh, etc.

	// QoS
	QoSClass string `json:"qos_class"` // low, medium, high, premium

	// Metadata
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Active    bool      `json:"active"`
}

// UserRole represents a user's role assignment
type UserRole struct {
	Username  string    `json:"username"`
	RoleID    string    `json:"role_id"`
	AssignedBy string   `json:"assigned_by"`
	AssignedAt time.Time `json:"assigned_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"` // Temporary role assignment
}

// RoleManager manages user roles and permissions
type RoleManager struct {
	config    *RoleConfig
	logger    zerolog.Logger
	mu        sync.RWMutex
	roles     map[string]*Role
	userRoles map[string]*UserRole // username -> role
	stats     RoleStats
}

// RoleStats tracks role statistics
type RoleStats struct {
	TotalRoles   int
	ActiveRoles  int
	TotalUsers   int
	RoleUsage    map[string]int // role ID -> user count
}

// NewRoleManager creates a new role manager
func NewRoleManager(config *RoleConfig, logger zerolog.Logger) (*RoleManager, error) {
	if !config.Enabled {
		return nil, nil
	}

	// Set defaults
	if config.RolesDir == "" {
		config.RolesDir = "/etc/coovachilli/roles"
	}
	if config.DefaultRole == "" {
		config.DefaultRole = "user"
	}

	if err := os.MkdirAll(config.RolesDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create roles directory: %w", err)
	}

	rm := &RoleManager{
		config:    config,
		logger:    logger.With().Str("component", "role-manager").Logger(),
		roles:     make(map[string]*Role),
		userRoles: make(map[string]*UserRole),
		stats: RoleStats{
			RoleUsage: make(map[string]int),
		},
	}

	// Load existing roles
	if err := rm.loadRoles(); err != nil {
		return nil, fmt.Errorf("failed to load roles: %w", err)
	}

	// Create default roles if none exist
	if len(rm.roles) == 0 {
		rm.createDefaultRoles()
	}

	rm.logger.Info().
		Int("roles", len(rm.roles)).
		Str("default_role", config.DefaultRole).
		Msg("Role manager initialized")

	return rm, nil
}

// createDefaultRoles creates default system roles
func (rm *RoleManager) createDefaultRoles() {
	defaultRoles := []*Role{
		{
			ID:          "admin",
			Name:        "Administrator",
			Description: "Full system access",
			Priority:    100,
			Permissions: []string{"*"},
			MaxBandwidthDown: 1000 * 1024 * 1024, // 1 Gbps
			MaxBandwidthUp:   1000 * 1024 * 1024,
			MaxConcurrentSessions: 10,
			PortalAccess:      true,
			APIAccess:         true,
			AdminAccess:       true,
			CanCreateGuests:   true,
			CanApproveGuests:  true,
			CanViewLogs:       true,
			CanModifyPolicies: true,
			QoSClass:          "premium",
			Active:            true,
			CreatedAt:         time.Now(),
			UpdatedAt:         time.Now(),
		},
		{
			ID:          "employee",
			Name:        "Employee",
			Description: "Standard employee access",
			Priority:    50,
			Permissions: []string{"network.access", "portal.view"},
			VLANID:      10,
			MaxBandwidthDown: 100 * 1024 * 1024, // 100 Mbps
			MaxBandwidthUp:   50 * 1024 * 1024,  // 50 Mbps
			MaxSessionDuration: 12 * time.Hour,
			MaxConcurrentSessions: 3,
			PortalAccess:     true,
			APIAccess:        false,
			AdminAccess:      false,
			CanCreateGuests:  true,
			CanApproveGuests: false,
			QoSClass:         "high",
			Active:           true,
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		},
		{
			ID:          "guest",
			Name:        "Guest",
			Description: "Limited guest access",
			Priority:    10,
			Permissions: []string{"network.access"},
			VLANID:      20,
			MaxBandwidthDown: 10 * 1024 * 1024, // 10 Mbps
			MaxBandwidthUp:   5 * 1024 * 1024,  // 5 Mbps
			MaxSessionDuration: 4 * time.Hour,
			MaxConcurrentSessions: 1,
			MaxDailyData: 500 * 1024 * 1024, // 500 MB
			PortalAccess:     true,
			APIAccess:        false,
			AdminAccess:      false,
			CanCreateGuests:  false,
			CanApproveGuests: false,
			AllowedServices:  []string{"http", "https", "dns"},
			QoSClass:         "low",
			Active:           true,
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		},
		{
			ID:          "user",
			Name:        "Regular User",
			Description: "Standard user access",
			Priority:    20,
			Permissions: []string{"network.access", "portal.view"},
			VLANID:      30,
			MaxBandwidthDown: 50 * 1024 * 1024, // 50 Mbps
			MaxBandwidthUp:   25 * 1024 * 1024, // 25 Mbps
			MaxSessionDuration: 8 * time.Hour,
			MaxConcurrentSessions: 2,
			PortalAccess:     true,
			APIAccess:        false,
			AdminAccess:      false,
			CanCreateGuests:  false,
			CanApproveGuests: false,
			QoSClass:         "medium",
			Active:           true,
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		},
		{
			ID:          "vip",
			Name:        "VIP User",
			Description: "Premium user access",
			Priority:    75,
			Permissions: []string{"network.access", "portal.view", "priority.support"},
			VLANID:      40,
			MaxBandwidthDown: 500 * 1024 * 1024, // 500 Mbps
			MaxBandwidthUp:   250 * 1024 * 1024, // 250 Mbps
			MaxConcurrentSessions: 5,
			PortalAccess:     true,
			APIAccess:        true,
			AdminAccess:      false,
			CanCreateGuests:  true,
			CanApproveGuests: true,
			QoSClass:         "premium",
			Active:           true,
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		},
	}

	for _, role := range defaultRoles {
		rm.roles[role.ID] = role
		rm.saveRole(role)
	}

	rm.logger.Info().Int("count", len(defaultRoles)).Msg("Created default roles")
}

// CreateRole creates a new role
func (rm *RoleManager) CreateRole(role *Role) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if role.ID == "" {
		return fmt.Errorf("role ID is required")
	}

	if _, exists := rm.roles[role.ID]; exists {
		return fmt.Errorf("role already exists: %s", role.ID)
	}

	now := time.Now()
	role.CreatedAt = now
	role.UpdatedAt = now

	rm.roles[role.ID] = role

	if err := rm.saveRole(role); err != nil {
		delete(rm.roles, role.ID)
		return err
	}

	rm.logger.Info().
		Str("role_id", role.ID).
		Str("name", role.Name).
		Int("priority", role.Priority).
		Msg("Role created")

	return nil
}

// UpdateRole updates an existing role
func (rm *RoleManager) UpdateRole(role *Role) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if _, exists := rm.roles[role.ID]; !exists {
		return fmt.Errorf("role not found: %s", role.ID)
	}

	role.UpdatedAt = time.Now()
	rm.roles[role.ID] = role

	if err := rm.saveRole(role); err != nil {
		return err
	}

	rm.logger.Info().Str("role_id", role.ID).Msg("Role updated")
	return nil
}

// DeleteRole deletes a role
func (rm *RoleManager) DeleteRole(roleID string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Check if role is in use
	if rm.stats.RoleUsage[roleID] > 0 {
		return fmt.Errorf("cannot delete role: %d users assigned", rm.stats.RoleUsage[roleID])
	}

	delete(rm.roles, roleID)

	// Delete from disk
	filename := filepath.Join(rm.config.RolesDir, roleID+".json")
	if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete role file: %w", err)
	}

	rm.logger.Info().Str("role_id", roleID).Msg("Role deleted")
	return nil
}

// AssignRole assigns a role to a user
func (rm *RoleManager) AssignRole(username, roleID, assignedBy string, expiresAt *time.Time) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Verify role exists
	if _, exists := rm.roles[roleID]; !exists {
		return fmt.Errorf("role not found: %s", roleID)
	}

	// Check if user already has a role
	if existing, exists := rm.userRoles[username]; exists {
		// Update role usage stats
		rm.stats.RoleUsage[existing.RoleID]--
	} else {
		rm.stats.TotalUsers++
	}

	userRole := &UserRole{
		Username:   username,
		RoleID:     roleID,
		AssignedBy: assignedBy,
		AssignedAt: time.Now(),
		ExpiresAt:  expiresAt,
	}

	rm.userRoles[username] = userRole
	rm.stats.RoleUsage[roleID]++

	rm.logger.Info().
		Str("username", username).
		Str("role_id", roleID).
		Str("assigned_by", assignedBy).
		Msg("Role assigned to user")

	return nil
}

// GetUserRole retrieves the role assigned to a user
func (rm *RoleManager) GetUserRole(username string) (*Role, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	userRole, exists := rm.userRoles[username]
	if !exists {
		// Return default role
		if defaultRole, exists := rm.roles[rm.config.DefaultRole]; exists {
			return defaultRole, nil
		}
		return nil, fmt.Errorf("no role assigned and default role not found")
	}

	// Check expiration
	if userRole.ExpiresAt != nil && time.Now().After(*userRole.ExpiresAt) {
		// Role expired, return default
		if defaultRole, exists := rm.roles[rm.config.DefaultRole]; exists {
			return defaultRole, nil
		}
		return nil, fmt.Errorf("role expired and default role not found")
	}

	role, exists := rm.roles[userRole.RoleID]
	if !exists {
		return nil, fmt.Errorf("assigned role not found: %s", userRole.RoleID)
	}

	if !role.Active {
		return nil, fmt.Errorf("assigned role is not active")
	}

	return role, nil
}

// HasPermission checks if a user has a specific permission
func (rm *RoleManager) HasPermission(username, permission string) bool {
	role, err := rm.GetUserRole(username)
	if err != nil {
		return false
	}

	// Check for wildcard permission
	for _, perm := range role.Permissions {
		if perm == "*" || perm == permission {
			return true
		}
	}

	return false
}

// CheckTimeRestriction checks if user can access network at current time
func (rm *RoleManager) CheckTimeRestriction(username string) (bool, error) {
	role, err := rm.GetUserRole(username)
	if err != nil {
		return false, err
	}

	now := time.Now()

	// Check day of week
	if len(role.AllowedDaysOfWeek) > 0 {
		currentDay := int(now.Weekday())
		allowed := false
		for _, day := range role.AllowedDaysOfWeek {
			if day == currentDay {
				allowed = true
				break
			}
		}
		if !allowed {
			return false, fmt.Errorf("access not allowed on %s", now.Weekday())
		}
	}

	// Check time range
	if role.AllowedTimeStart != "" && role.AllowedTimeEnd != "" {
		currentTime := now.Format("15:04")
		if currentTime < role.AllowedTimeStart || currentTime > role.AllowedTimeEnd {
			return false, fmt.Errorf("access not allowed at this time (allowed: %s - %s)",
				role.AllowedTimeStart, role.AllowedTimeEnd)
		}
	}

	return true, nil
}

// ListRoles returns all roles
func (rm *RoleManager) ListRoles() []*Role {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	roles := make([]*Role, 0, len(rm.roles))
	for _, role := range rm.roles {
		roles = append(roles, role)
	}

	return roles
}

// GetRole retrieves a role by ID
func (rm *RoleManager) GetRole(roleID string) (*Role, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	role, exists := rm.roles[roleID]
	if !exists {
		return nil, fmt.Errorf("role not found: %s", roleID)
	}

	return role, nil
}

// saveRole saves a role to disk
func (rm *RoleManager) saveRole(role *Role) error {
	filename := filepath.Join(rm.config.RolesDir, role.ID+".json")
	data, err := json.MarshalIndent(role, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal role: %w", err)
	}

	return ioutil.WriteFile(filename, data, 0644)
}

// loadRoles loads all roles from disk
func (rm *RoleManager) loadRoles() error {
	files, err := ioutil.ReadDir(rm.config.RolesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			roleFile := filepath.Join(rm.config.RolesDir, file.Name())
			data, err := ioutil.ReadFile(roleFile)
			if err != nil {
				rm.logger.Warn().Err(err).Str("file", file.Name()).Msg("Failed to read role file")
				continue
			}

			var role Role
			if err := json.Unmarshal(data, &role); err != nil {
				rm.logger.Warn().Err(err).Str("file", file.Name()).Msg("Failed to parse role file")
				continue
			}

			rm.roles[role.ID] = &role
		}
	}

	rm.logger.Info().Int("count", len(rm.roles)).Msg("Loaded roles from disk")
	return nil
}

// GetStats returns role statistics
func (rm *RoleManager) GetStats() RoleStats {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	stats := rm.stats
	stats.TotalRoles = len(rm.roles)

	// Count active roles
	activeCount := 0
	for _, role := range rm.roles {
		if role.Active {
			activeCount++
		}
	}
	stats.ActiveRoles = activeCount

	return stats
}
