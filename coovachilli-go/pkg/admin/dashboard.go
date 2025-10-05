package admin

import (
	"coovachilli-go/pkg/core"
	"sync"
	"time"
)

// DashboardStats holds comprehensive dashboard statistics
type DashboardStats struct {
	mu sync.RWMutex

	// Server Stats
	Uptime            time.Duration
	StartTime         time.Time
	Version           string

	// Session Stats
	ActiveSessions    int
	TotalSessions     uint64
	AuthenticatedSessions int

	// Traffic Stats
	TotalInputOctets  uint64
	TotalOutputOctets uint64
	TotalInputPackets uint64
	TotalOutputPackets uint64

	// Bandwidth (bytes/sec)
	CurrentInputRate  float64
	CurrentOutputRate float64
	PeakInputRate     float64
	PeakOutputRate    float64

	// User Stats
	UniqueUsers       int
	TopUsers          []UserStats

	// Network Stats
	VLANDistribution  map[uint16]int

	// Security Stats
	BlockedThreats    uint64
	IDSEvents         uint64
	FilteredDomains   uint64

	// Authentication Stats
	SuccessfulAuths   uint64
	FailedAuths       uint64

	// Resource Stats
	MemoryUsageMB     float64
	CPUUsagePercent   float64
}

// UserStats holds per-user statistics
type UserStats struct {
	Username      string
	SessionCount  int
	InputOctets   uint64
	OutputOctets  uint64
	LastSeen      time.Time
}

// Dashboard manages real-time dashboard statistics
type Dashboard struct {
	stats         *DashboardStats
	sessionMgr    *core.SessionManager
	ticker        *time.Ticker
	stopCh        chan struct{}
}

// NewDashboard creates a new dashboard manager
func NewDashboard(sessionMgr *core.SessionManager) *Dashboard {
	return &Dashboard{
		stats: &DashboardStats{
			StartTime:        core.StartTime,
			VLANDistribution: make(map[uint16]int),
			TopUsers:         make([]UserStats, 0),
		},
		sessionMgr: sessionMgr,
		stopCh:     make(chan struct{}),
	}
}

// Start begins periodic stats collection
func (d *Dashboard) Start(interval time.Duration) {
	d.ticker = time.NewTicker(interval)
	go d.collectLoop()
}

// Stop stops the dashboard collection
func (d *Dashboard) Stop() {
	if d.ticker != nil {
		d.ticker.Stop()
	}
	close(d.stopCh)
}

// collectLoop periodically collects statistics
func (d *Dashboard) collectLoop() {
	for {
		select {
		case <-d.ticker.C:
			d.collectStats()
		case <-d.stopCh:
			return
		}
	}
}

// collectStats gathers current statistics from all sources
func (d *Dashboard) collectStats() {
	d.stats.mu.Lock()
	defer d.stats.mu.Unlock()

	// Update uptime
	d.stats.Uptime = time.Since(d.stats.StartTime)

	// Get all sessions
	sessions := d.sessionMgr.GetAllSessions()
	d.stats.ActiveSessions = len(sessions)

	// Reset counters for this collection cycle
	d.stats.AuthenticatedSessions = 0
	d.stats.TotalInputOctets = 0
	d.stats.TotalOutputOctets = 0
	d.stats.TotalInputPackets = 0
	d.stats.TotalOutputPackets = 0

	vlanDist := make(map[uint16]int)
	userStats := make(map[string]*UserStats)

	// Collect per-session stats
	for _, session := range sessions {
		session.RLock()

		if session.Authenticated {
			d.stats.AuthenticatedSessions++
		}

		d.stats.TotalInputOctets += session.InputOctets
		d.stats.TotalOutputOctets += session.OutputOctets
		d.stats.TotalInputPackets += session.InputPackets
		d.stats.TotalOutputPackets += session.OutputPackets

		// VLAN distribution
		vlanDist[session.VLANID]++

		// Per-user stats
		username := session.Redir.Username
		if username != "" {
			if us, exists := userStats[username]; exists {
				us.SessionCount++
				us.InputOctets += session.InputOctets
				us.OutputOctets += session.OutputOctets
				if session.LastSeen.After(us.LastSeen) {
					us.LastSeen = session.LastSeen
				}
			} else {
				userStats[username] = &UserStats{
					Username:     username,
					SessionCount: 1,
					InputOctets:  session.InputOctets,
					OutputOctets: session.OutputOctets,
					LastSeen:     session.LastSeen,
				}
			}
		}

		session.RUnlock()
	}

	d.stats.VLANDistribution = vlanDist
	d.stats.UniqueUsers = len(userStats)

	// Convert user stats to sorted slice (top 10)
	topUsers := make([]UserStats, 0, len(userStats))
	for _, us := range userStats {
		topUsers = append(topUsers, *us)
	}

	// Sort by total traffic (input + output)
	for i := 0; i < len(topUsers)-1; i++ {
		for j := i + 1; j < len(topUsers); j++ {
			if (topUsers[j].InputOctets + topUsers[j].OutputOctets) >
			   (topUsers[i].InputOctets + topUsers[i].OutputOctets) {
				topUsers[i], topUsers[j] = topUsers[j], topUsers[i]
			}
		}
	}

	// Keep only top 10
	if len(topUsers) > 10 {
		topUsers = topUsers[:10]
	}
	d.stats.TopUsers = topUsers
}

// GetStats returns a copy of current stats
func (d *Dashboard) GetStats() DashboardStats {
	d.stats.mu.RLock()
	defer d.stats.mu.RUnlock()

	// Create a deep copy
	stats := *d.stats

	// Copy maps
	stats.VLANDistribution = make(map[uint16]int, len(d.stats.VLANDistribution))
	for k, v := range d.stats.VLANDistribution {
		stats.VLANDistribution[k] = v
	}

	// Copy top users slice
	stats.TopUsers = make([]UserStats, len(d.stats.TopUsers))
	copy(stats.TopUsers, d.stats.TopUsers)

	return stats
}

// UpdateSecurityStats updates security-related statistics
func (d *Dashboard) UpdateSecurityStats(blockedThreats, idsEvents, filteredDomains uint64) {
	d.stats.mu.Lock()
	defer d.stats.mu.Unlock()

	d.stats.BlockedThreats += blockedThreats
	d.stats.IDSEvents += idsEvents
	d.stats.FilteredDomains += filteredDomains
}

// UpdateAuthStats updates authentication statistics
func (d *Dashboard) UpdateAuthStats(successful, failed uint64) {
	d.stats.mu.Lock()
	defer d.stats.mu.Unlock()

	d.stats.SuccessfulAuths += successful
	d.stats.FailedAuths += failed
}

// IncrementTotalSessions increments the total session counter
func (d *Dashboard) IncrementTotalSessions() {
	d.stats.mu.Lock()
	defer d.stats.mu.Unlock()

	d.stats.TotalSessions++
}
