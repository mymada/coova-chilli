package admin

import (
	"coovachilli-go/pkg/config"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// Site represents a CoovaChilli site/instance
type Site struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Endpoint    string         `json:"endpoint"`  // Admin API endpoint
	AuthToken   string         `json:"-"`         // API auth token (not exposed)
	Location    SiteLocation   `json:"location"`
	Status      SiteStatus     `json:"status"`
	LastSync    time.Time      `json:"last_sync"`
	Stats       SiteStats      `json:"stats"`
}

// SiteLocation holds geographic location info
type SiteLocation struct {
	Address   string  `json:"address"`
	City      string  `json:"city"`
	Country   string  `json:"country"`
	Latitude  float64 `json:"latitude,omitempty"`
	Longitude float64 `json:"longitude,omitempty"`
}

// SiteStatus represents the operational status of a site
type SiteStatus struct {
	Online           bool      `json:"online"`
	LastChecked      time.Time `json:"last_checked"`
	ResponseTime     int64     `json:"response_time_ms"`
	Version          string    `json:"version"`
	Error            string    `json:"error,omitempty"`
}

// SiteStats holds aggregated statistics for a site
type SiteStats struct {
	ActiveSessions    int     `json:"active_sessions"`
	TotalSessions     uint64  `json:"total_sessions"`
	InputOctets       uint64  `json:"input_octets"`
	OutputOctets      uint64  `json:"output_octets"`
	UniqueUsers       int     `json:"unique_users"`
	SuccessfulAuths   uint64  `json:"successful_auths"`
	FailedAuths       uint64  `json:"failed_auths"`
	Uptime            string  `json:"uptime"`
}

// MultiSiteManager manages multiple CoovaChilli sites
type MultiSiteManager struct {
	mu       sync.RWMutex
	sites    map[string]*Site
	logger   zerolog.Logger
	enabled  bool
	httpClient *http.Client
}

// NewMultiSiteManager creates a new multi-site manager
func NewMultiSiteManager(logger zerolog.Logger, enabled bool) *MultiSiteManager {
	return &MultiSiteManager{
		sites:   make(map[string]*Site),
		logger:  logger.With().Str("component", "multisite").Logger(),
		enabled: enabled,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// AddSite adds a new site to management
func (msm *MultiSiteManager) AddSite(site *Site) error {
	msm.mu.Lock()
	defer msm.mu.Unlock()

	if site.ID == "" {
		site.ID = generateSiteID(site.Name)
	}

	msm.sites[site.ID] = site
	msm.logger.Info().
		Str("site_id", site.ID).
		Str("name", site.Name).
		Str("endpoint", site.Endpoint).
		Msg("Site added")

	return nil
}

// RemoveSite removes a site from management
func (msm *MultiSiteManager) RemoveSite(id string) error {
	msm.mu.Lock()
	defer msm.mu.Unlock()

	if _, exists := msm.sites[id]; !exists {
		return fmt.Errorf("site not found: %s", id)
	}

	delete(msm.sites, id)
	msm.logger.Info().Str("site_id", id).Msg("Site removed")
	return nil
}

// GetSite retrieves a site by ID
func (msm *MultiSiteManager) GetSite(id string) (*Site, error) {
	msm.mu.RLock()
	defer msm.mu.RUnlock()

	site, exists := msm.sites[id]
	if !exists {
		return nil, fmt.Errorf("site not found: %s", id)
	}

	return site, nil
}

// ListSites returns all managed sites
func (msm *MultiSiteManager) ListSites() []*Site {
	msm.mu.RLock()
	defer msm.mu.RUnlock()

	sites := make([]*Site, 0, len(msm.sites))
	for _, site := range msm.sites {
		sites = append(sites, site)
	}

	return sites
}

// SyncSiteStats synchronizes statistics from a remote site
func (msm *MultiSiteManager) SyncSiteStats(siteID string) error {
	site, err := msm.GetSite(siteID)
	if err != nil {
		return err
	}

	// Call remote site's API
	start := time.Now()
	stats, err := msm.fetchRemoteStats(site)
	responseTime := time.Since(start).Milliseconds()

	msm.mu.Lock()
	defer msm.mu.Unlock()

	site.Status.LastChecked = time.Now()
	site.Status.ResponseTime = responseTime

	if err != nil {
		site.Status.Online = false
		site.Status.Error = err.Error()
		msm.logger.Error().
			Err(err).
			Str("site_id", siteID).
			Msg("Failed to sync site stats")
		return err
	}

	site.Status.Online = true
	site.Status.Error = ""
	site.Stats = *stats
	site.LastSync = time.Now()

	return nil
}

// SyncAllSites synchronizes statistics from all sites
func (msm *MultiSiteManager) SyncAllSites() {
	sites := msm.ListSites()

	var wg sync.WaitGroup
	for _, site := range sites {
		wg.Add(1)
		go func(siteID string) {
			defer wg.Done()
			msm.SyncSiteStats(siteID)
		}(site.ID)
	}

	wg.Wait()
}

// fetchRemoteStats fetches statistics from remote site API
func (msm *MultiSiteManager) fetchRemoteStats(site *Site) (*SiteStats, error) {
	endpoint := site.Endpoint + "/api/v1/dashboard/stats"

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	// Add auth token
	if site.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+site.AuthToken)
	}

	resp, err := msm.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var stats SiteStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, err
	}

	return &stats, nil
}

// GetAggregatedStats returns aggregated statistics across all sites
func (msm *MultiSiteManager) GetAggregatedStats() map[string]interface{} {
	msm.mu.RLock()
	defer msm.mu.RUnlock()

	var totalActiveSessions int
	var totalSessions uint64
	var totalInputOctets uint64
	var totalOutputOctets uint64
	var totalUniqueUsers int
	var totalSuccessfulAuths uint64
	var totalFailedAuths uint64
	var onlineSites int

	for _, site := range msm.sites {
		if site.Status.Online {
			onlineSites++
		}
		totalActiveSessions += site.Stats.ActiveSessions
		totalSessions += site.Stats.TotalSessions
		totalInputOctets += site.Stats.InputOctets
		totalOutputOctets += site.Stats.OutputOctets
		totalUniqueUsers += site.Stats.UniqueUsers
		totalSuccessfulAuths += site.Stats.SuccessfulAuths
		totalFailedAuths += site.Stats.FailedAuths
	}

	return map[string]interface{}{
		"total_sites":          len(msm.sites),
		"online_sites":         onlineSites,
		"offline_sites":        len(msm.sites) - onlineSites,
		"total_active_sessions": totalActiveSessions,
		"total_sessions":       totalSessions,
		"total_input_octets":   totalInputOctets,
		"total_output_octets":  totalOutputOctets,
		"total_unique_users":   totalUniqueUsers,
		"successful_auths":     totalSuccessfulAuths,
		"failed_auths":         totalFailedAuths,
	}
}

// StartAutoSync starts automatic synchronization of all sites
func (msm *MultiSiteManager) StartAutoSync(interval time.Duration) {
	if !msm.enabled {
		msm.logger.Info().Msg("Multi-site management is disabled")
		return
	}

	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			msm.logger.Debug().Msg("Auto-syncing all sites")
			msm.SyncAllSites()
		}
	}()
}

// generateSiteID generates a unique site ID from name
func generateSiteID(name string) string {
	return fmt.Sprintf("site-%s-%d", sanitizeName(name), time.Now().Unix())
}

// sanitizeName removes special characters from name
func sanitizeName(name string) string {
	// Simple sanitization - replace spaces with dashes, remove special chars
	result := ""
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			result += string(r)
		} else if r == ' ' {
			result += "-"
		}
	}
	return result
}

// LoadSitesFromConfig loads sites from configuration
func (msm *MultiSiteManager) LoadSitesFromConfig(cfg *config.Config) error {
	// TODO: Add MultiSiteConfig to config.Config
	// For now, this is a placeholder
	msm.logger.Info().Msg("Multi-site config loading not yet implemented")
	return nil
}
