package filter

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
)

// FilterAction defines what action to take when a domain matches a filter rule
type FilterAction string

const (
	ActionAllow FilterAction = "allow"
	ActionBlock FilterAction = "block"
	ActionLog   FilterAction = "log"
)

// FilterRule represents a single filtering rule
type FilterRule struct {
	Pattern string
	Regex   *regexp.Regexp
	Action  FilterAction
	Category string
}

// URLFilter provides advanced URL and DNS filtering capabilities
type URLFilter struct {
	cfg           *config.URLFilterConfig
	logger        zerolog.Logger
	mu            sync.RWMutex
	domainRules   []FilterRule
	blockedDomains map[string]struct{}
	blockedIPs    map[string]struct{}
	stats         FilterStats
}

// FilterStats tracks filtering statistics
type FilterStats struct {
	TotalQueries   uint64
	BlockedQueries uint64
	AllowedQueries uint64
	LoggedQueries  uint64
}

// NewURLFilter creates a new URL/DNS filter
func NewURLFilter(cfg *config.URLFilterConfig, logger zerolog.Logger) (*URLFilter, error) {
	f := &URLFilter{
		cfg:            cfg,
		logger:         logger.With().Str("component", "urlfilter").Logger(),
		domainRules:    make([]FilterRule, 0),
		blockedDomains: make(map[string]struct{}),
		blockedIPs:     make(map[string]struct{}),
	}

	if err := f.loadRules(); err != nil {
		return nil, fmt.Errorf("failed to load filter rules: %w", err)
	}

	return f, nil
}

// loadRules loads filtering rules from configured files
func (f *URLFilter) loadRules() error {
	// Load domain blocklist
	if f.cfg.DomainBlocklistPath != "" {
		if err := f.loadDomainBlocklist(f.cfg.DomainBlocklistPath); err != nil {
			return fmt.Errorf("failed to load domain blocklist: %w", err)
		}
	}

	// Load IP blocklist
	if f.cfg.IPBlocklistPath != "" {
		if err := f.loadIPBlocklist(f.cfg.IPBlocklistPath); err != nil {
			return fmt.Errorf("failed to load IP blocklist: %w", err)
		}
	}

	// Load category rules
	if f.cfg.CategoryRulesPath != "" {
		if err := f.loadCategoryRules(f.cfg.CategoryRulesPath); err != nil {
			return fmt.Errorf("failed to load category rules: %w", err)
		}
	}

	f.logger.Info().
		Int("blocked_domains", len(f.blockedDomains)).
		Int("blocked_ips", len(f.blockedIPs)).
		Int("category_rules", len(f.domainRules)).
		Msg("Loaded URL filter rules")

	return nil
}

// loadDomainBlocklist loads blocked domains from a file
func (f *URLFilter) loadDomainBlocklist(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" && !strings.HasPrefix(domain, "#") {
			f.blockedDomains[strings.ToLower(domain)] = struct{}{}
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	f.logger.Info().Int("count", count).Msg("Loaded domain blocklist")
	return nil
}

// loadIPBlocklist loads blocked IPs from a file
func (f *URLFilter) loadIPBlocklist(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		ipStr := strings.TrimSpace(scanner.Text())
		if ipStr != "" && !strings.HasPrefix(ipStr, "#") {
			if ip := net.ParseIP(ipStr); ip != nil {
				f.blockedIPs[ip.String()] = struct{}{}
				count++
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	f.logger.Info().Int("count", count).Msg("Loaded IP blocklist")
	return nil
}

// loadCategoryRules loads category-based filtering rules
// Format: category:action:pattern (e.g., "adult:block:.*porn.*")
func (f *URLFilter) loadCategoryRules(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			f.logger.Warn().Str("line", line).Msg("Invalid category rule format, skipping")
			continue
		}

		category := parts[0]
		action := FilterAction(parts[1])
		pattern := parts[2]

		// Validate action
		if action != ActionAllow && action != ActionBlock && action != ActionLog {
			f.logger.Warn().Str("action", string(action)).Msg("Invalid action, skipping")
			continue
		}

		// Compile regex pattern
		regex, err := regexp.Compile(pattern)
		if err != nil {
			f.logger.Warn().Err(err).Str("pattern", pattern).Msg("Failed to compile regex, skipping")
			continue
		}

		f.domainRules = append(f.domainRules, FilterRule{
			Pattern:  pattern,
			Regex:    regex,
			Action:   action,
			Category: category,
		})
		count++
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	f.logger.Info().Int("count", count).Msg("Loaded category rules")
	return nil
}

// CheckDomain checks if a domain should be blocked or allowed
func (f *URLFilter) CheckDomain(domain string) (FilterAction, string) {
	if !f.cfg.Enabled {
		return ActionAllow, ""
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	f.stats.TotalQueries++

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	// Check exact domain blocklist first
	if _, blocked := f.blockedDomains[domain]; blocked {
		f.stats.BlockedQueries++
		f.logger.Debug().Str("domain", domain).Msg("Domain blocked by blocklist")
		return ActionBlock, "blocklist"
	}

	// Check wildcard matches in blocklist
	parts := strings.Split(domain, ".")
	for i := range parts {
		wildcardDomain := "*." + strings.Join(parts[i:], ".")
		if _, blocked := f.blockedDomains[wildcardDomain]; blocked {
			f.stats.BlockedQueries++
			f.logger.Debug().Str("domain", domain).Str("rule", wildcardDomain).Msg("Domain blocked by wildcard")
			return ActionBlock, "wildcard"
		}
	}

	// Check category rules
	for _, rule := range f.domainRules {
		if rule.Regex.MatchString(domain) {
			switch rule.Action {
			case ActionBlock:
				f.stats.BlockedQueries++
				f.logger.Debug().Str("domain", domain).Str("category", rule.Category).Msg("Domain blocked by category rule")
				return ActionBlock, rule.Category
			case ActionLog:
				f.stats.LoggedQueries++
				f.logger.Info().Str("domain", domain).Str("category", rule.Category).Msg("Domain logged by category rule")
				return ActionLog, rule.Category
			case ActionAllow:
				f.stats.AllowedQueries++
				return ActionAllow, rule.Category
			}
		}
	}

	// Default action based on configuration
	if f.cfg.DefaultAction == "block" {
		f.stats.BlockedQueries++
		return ActionBlock, "default"
	}

	f.stats.AllowedQueries++
	return ActionAllow, ""
}

// CheckIP checks if an IP should be blocked
func (f *URLFilter) CheckIP(ip net.IP) bool {
	if !f.cfg.Enabled {
		return false
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	_, blocked := f.blockedIPs[ip.String()]
	if blocked {
		f.logger.Debug().Str("ip", ip.String()).Msg("IP blocked")
	}
	return blocked
}

// AddBlockedDomain dynamically adds a domain to the blocklist
func (f *URLFilter) AddBlockedDomain(domain string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	f.blockedDomains[domain] = struct{}{}
	f.logger.Info().Str("domain", domain).Msg("Domain added to blocklist")
}

// RemoveBlockedDomain removes a domain from the blocklist
func (f *URLFilter) RemoveBlockedDomain(domain string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	delete(f.blockedDomains, domain)
	f.logger.Info().Str("domain", domain).Msg("Domain removed from blocklist")
}

// GetStats returns current filtering statistics
func (f *URLFilter) GetStats() FilterStats {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.stats
}

// ReloadRules reloads all filtering rules from disk
func (f *URLFilter) ReloadRules() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Clear existing rules
	f.domainRules = make([]FilterRule, 0)
	f.blockedDomains = make(map[string]struct{})
	f.blockedIPs = make(map[string]struct{})

	if err := f.loadRules(); err != nil {
		return err
	}

	f.logger.Info().Msg("Filter rules reloaded successfully")
	return nil
}
