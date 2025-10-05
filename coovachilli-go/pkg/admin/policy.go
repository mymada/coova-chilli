package admin

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// UserGroup represents a group of users with common policies
type UserGroup struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Members     []string `json:"members"`      // Usernames
	Policies    []string `json:"policies"`     // Policy IDs
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Policy defines access rules and restrictions
type Policy struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Rules       PolicyRules   `json:"rules"`
	Priority    int           `json:"priority"`
	Enabled     bool          `json:"enabled"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

// PolicyRules contains specific policy rules
type PolicyRules struct {
	// Bandwidth limits
	MaxBandwidthDown uint64 `json:"max_bandwidth_down"` // bytes/sec
	MaxBandwidthUp   uint64 `json:"max_bandwidth_up"`   // bytes/sec

	// Session limits
	MaxSessionDuration time.Duration `json:"max_session_duration"`
	MaxConcurrentSessions int        `json:"max_concurrent_sessions"`

	// Data limits
	MaxDailyData   uint64 `json:"max_daily_data"`   // bytes
	MaxMonthlyData uint64 `json:"max_monthly_data"` // bytes

	// Time restrictions
	AllowedTimeRanges []TimeRange `json:"allowed_time_ranges"`

	// Network access
	VLANID          uint16   `json:"vlan_id"`
	AllowedDomains  []string `json:"allowed_domains"`
	BlockedDomains  []string `json:"blocked_domains"`
	AllowedIPs      []string `json:"allowed_ips"`
	BlockedIPs      []string `json:"blocked_ips"`

	// Protocol restrictions
	AllowedProtocols []string `json:"allowed_protocols"` // tcp, udp, icmp
	AllowedPorts     []int    `json:"allowed_ports"`

	// QoS
	QoSClass string `json:"qos_class"` // low, medium, high, premium
}

// TimeRange represents an allowed time window
type TimeRange struct {
	DaysOfWeek []int  `json:"days_of_week"` // 0=Sunday, 6=Saturday
	StartTime  string `json:"start_time"`   // HH:MM format
	EndTime    string `json:"end_time"`     // HH:MM format
}

// PolicyManager manages user groups and policies
type PolicyManager struct {
	mu            sync.RWMutex
	groups        map[string]*UserGroup
	policies      map[string]*Policy
	userGroups    map[string][]string // username -> group IDs
	policyDir     string
	logger        zerolog.Logger
}

// NewPolicyManager creates a new policy manager
func NewPolicyManager(policyDir string, logger zerolog.Logger) (*PolicyManager, error) {
	if err := os.MkdirAll(policyDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create policy directory: %w", err)
	}

	pm := &PolicyManager{
		groups:     make(map[string]*UserGroup),
		policies:   make(map[string]*Policy),
		userGroups: make(map[string][]string),
		policyDir:  policyDir,
		logger:     logger.With().Str("component", "policy-manager").Logger(),
	}

	// Load existing groups and policies
	if err := pm.loadFromDisk(); err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	return pm, nil
}

// CreateGroup creates a new user group
func (pm *PolicyManager) CreateGroup(name, description string, members []string) (*UserGroup, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	group := &UserGroup{
		ID:          generateGroupID(name),
		Name:        name,
		Description: description,
		Members:     members,
		Policies:    []string{},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	pm.groups[group.ID] = group

	// Update user-group mapping
	for _, username := range members {
		pm.userGroups[username] = append(pm.userGroups[username], group.ID)
	}

	if err := pm.saveGroup(group); err != nil {
		return nil, err
	}

	pm.logger.Info().
		Str("group_id", group.ID).
		Str("name", name).
		Int("members", len(members)).
		Msg("User group created")

	return group, nil
}

// CreatePolicy creates a new policy
func (pm *PolicyManager) CreatePolicy(name, description string, rules PolicyRules, priority int) (*Policy, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	policy := &Policy{
		ID:          generatePolicyID(name),
		Name:        name,
		Description: description,
		Rules:       rules,
		Priority:    priority,
		Enabled:     true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	pm.policies[policy.ID] = policy

	if err := pm.savePolicy(policy); err != nil {
		return nil, err
	}

	pm.logger.Info().
		Str("policy_id", policy.ID).
		Str("name", name).
		Int("priority", priority).
		Msg("Policy created")

	return policy, nil
}

// AttachPolicyToGroup attaches a policy to a group
func (pm *PolicyManager) AttachPolicyToGroup(groupID, policyID string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	group, exists := pm.groups[groupID]
	if !exists {
		return fmt.Errorf("group not found: %s", groupID)
	}

	if _, exists := pm.policies[policyID]; !exists {
		return fmt.Errorf("policy not found: %s", policyID)
	}

	// Check if already attached
	for _, pid := range group.Policies {
		if pid == policyID {
			return fmt.Errorf("policy already attached to group")
		}
	}

	group.Policies = append(group.Policies, policyID)
	group.UpdatedAt = time.Now()

	if err := pm.saveGroup(group); err != nil {
		return err
	}

	pm.logger.Info().
		Str("group_id", groupID).
		Str("policy_id", policyID).
		Msg("Policy attached to group")

	return nil
}

// GetPoliciesForUser returns all policies applicable to a user
func (pm *PolicyManager) GetPoliciesForUser(username string) []*Policy {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	groupIDs, exists := pm.userGroups[username]
	if !exists {
		return nil
	}

	policyMap := make(map[string]*Policy)

	for _, groupID := range groupIDs {
		group, exists := pm.groups[groupID]
		if !exists {
			continue
		}

		for _, policyID := range group.Policies {
			policy, exists := pm.policies[policyID]
			if exists && policy.Enabled {
				policyMap[policyID] = policy
			}
		}
	}

	// Convert to slice and sort by priority
	policies := make([]*Policy, 0, len(policyMap))
	for _, policy := range policyMap {
		policies = append(policies, policy)
	}

	// Sort by priority (higher first)
	for i := 0; i < len(policies)-1; i++ {
		for j := i + 1; j < len(policies); j++ {
			if policies[j].Priority > policies[i].Priority {
				policies[i], policies[j] = policies[j], policies[i]
			}
		}
	}

	return policies
}

// matchIPPattern checks if an IP matches a pattern (exact IP or CIDR)
func matchIPPattern(pattern string, ip net.IP) bool {
	// Try parsing as CIDR first
	_, ipNet, err := net.ParseCIDR(pattern)
	if err == nil {
		return ipNet.Contains(ip)
	}

	// Fall back to exact IP match
	patternIP := net.ParseIP(pattern)
	if patternIP == nil {
		return false
	}

	return patternIP.Equal(ip)
}

// matchDomainPattern checks if a domain matches a pattern (exact or wildcard)
// Supports: "example.com", "*.example.com", "sub.*.example.com"
func matchDomainPattern(pattern, domain string) bool {
	// Exact match
	if pattern == domain {
		return true
	}

	// No wildcard
	if !strings.Contains(pattern, "*") {
		return false
	}

	// Wildcard match
	// Convert pattern to regex-like matching
	parts := strings.Split(pattern, "*")

	// Must start with first part (unless pattern starts with *)
	if !strings.HasPrefix(pattern, "*") {
		if !strings.HasPrefix(domain, parts[0]) {
			return false
		}
		domain = domain[len(parts[0]):]
	} else {
		// Pattern starts with *, remove first empty part
		parts = parts[1:]
	}

	// Must end with last part (unless pattern ends with *)
	if !strings.HasSuffix(pattern, "*") {
		if !strings.HasSuffix(domain, parts[len(parts)-1]) {
			return false
		}
		domain = domain[:len(domain)-len(parts[len(parts)-1])]
		parts = parts[:len(parts)-1]
	} else {
		// Pattern ends with *, remove last empty part
		parts = parts[:len(parts)-1]
	}

	// Check all middle parts appear in order
	for _, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(domain, part)
		if idx == -1 {
			return false
		}
		domain = domain[idx+len(part):]
	}

	return true
}

// CheckAccess checks if a user has access based on policies
// Now supports CIDR ranges for IPs and wildcard patterns for domains
func (pm *PolicyManager) CheckAccess(username string, ip net.IP, domain string) (bool, string) {
	policies := pm.GetPoliciesForUser(username)

	if len(policies) == 0 {
		// No policies = allow by default
		return true, "no-policy"
	}

	// Check each policy (higher priority first)
	for _, policy := range policies {
		// Check IP blocklist (supports CIDR)
		if ip != nil {
			for _, blockedPattern := range policy.Rules.BlockedIPs {
				if matchIPPattern(blockedPattern, ip) {
					return false, fmt.Sprintf("blocked-by-policy:%s", policy.ID)
				}
			}

			// Check IP allowlist (if defined, supports CIDR)
			if len(policy.Rules.AllowedIPs) > 0 {
				allowed := false
				for _, allowedPattern := range policy.Rules.AllowedIPs {
					if matchIPPattern(allowedPattern, ip) {
						allowed = true
						break
					}
				}
				if !allowed {
					return false, fmt.Sprintf("not-in-allowlist:%s", policy.ID)
				}
			}
		}

		// Check domain blocklist (supports wildcards)
		if domain != "" {
			for _, blockedPattern := range policy.Rules.BlockedDomains {
				if matchDomainPattern(blockedPattern, domain) {
					return false, fmt.Sprintf("blocked-domain:%s", policy.ID)
				}
			}

			// Check domain allowlist (if defined, supports wildcards)
			if len(policy.Rules.AllowedDomains) > 0 {
				allowed := false
				for _, allowedPattern := range policy.Rules.AllowedDomains {
					if matchDomainPattern(allowedPattern, domain) {
						allowed = true
						break
					}
				}
				if !allowed {
					return false, fmt.Sprintf("not-in-domain-allowlist:%s", policy.ID)
				}
			}
		}
	}

	return true, "allowed"
}

// saveGroup saves a group to disk
func (pm *PolicyManager) saveGroup(group *UserGroup) error {
	filename := filepath.Join(pm.policyDir, "groups", group.ID+".json")
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(group, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, data, 0644)
}

// savePolicy saves a policy to disk
func (pm *PolicyManager) savePolicy(policy *Policy) error {
	filename := filepath.Join(pm.policyDir, "policies", policy.ID+".json")
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, data, 0644)
}

// loadFromDisk loads all groups and policies from disk
func (pm *PolicyManager) loadFromDisk() error {
	// Load groups
	groupsDir := filepath.Join(pm.policyDir, "groups")
	if _, err := os.Stat(groupsDir); !os.IsNotExist(err) {
		files, err := ioutil.ReadDir(groupsDir)
		if err != nil {
			return err
		}

		for _, file := range files {
			if filepath.Ext(file.Name()) == ".json" {
				data, err := ioutil.ReadFile(filepath.Join(groupsDir, file.Name()))
				if err != nil {
					continue
				}

				var group UserGroup
				if err := json.Unmarshal(data, &group); err != nil {
					continue
				}

				pm.groups[group.ID] = &group

				// Update user-group mapping
				for _, username := range group.Members {
					pm.userGroups[username] = append(pm.userGroups[username], group.ID)
				}
			}
		}
	}

	// Load policies
	policiesDir := filepath.Join(pm.policyDir, "policies")
	if _, err := os.Stat(policiesDir); !os.IsNotExist(err) {
		files, err := ioutil.ReadDir(policiesDir)
		if err != nil {
			return err
		}

		for _, file := range files {
			if filepath.Ext(file.Name()) == ".json" {
				data, err := ioutil.ReadFile(filepath.Join(policiesDir, file.Name()))
				if err != nil {
					continue
				}

				var policy Policy
				if err := json.Unmarshal(data, &policy); err != nil {
					continue
				}

				pm.policies[policy.ID] = &policy
			}
		}
	}

	pm.logger.Info().
		Int("groups", len(pm.groups)).
		Int("policies", len(pm.policies)).
		Msg("Loaded policies from disk")

	return nil
}

// ListGroups returns all user groups
func (pm *PolicyManager) ListGroups() []*UserGroup {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	groups := make([]*UserGroup, 0, len(pm.groups))
	for _, group := range pm.groups {
		groups = append(groups, group)
	}

	return groups
}

// ListPolicies returns all policies
func (pm *PolicyManager) ListPolicies() []*Policy {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	policies := make([]*Policy, 0, len(pm.policies))
	for _, policy := range pm.policies {
		policies = append(policies, policy)
	}

	return policies
}

func generateGroupID(name string) string {
	return fmt.Sprintf("group-%s-%d", sanitizeName(name), time.Now().Unix())
}

func generatePolicyID(name string) string {
	return fmt.Sprintf("policy-%s-%d", sanitizeName(name), time.Now().Unix())
}
