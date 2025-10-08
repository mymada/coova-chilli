package dhcp

import (
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// DHCPRateLimiter provides MAC-based rate limiting for DHCP requests
type DHCPRateLimiter struct {
	mu           sync.Mutex
	requests     map[string][]time.Time
	maxPerMinute int
	logger       zerolog.Logger
	stopCh       chan struct{}
}

// NewDHCPRateLimiter creates a new DHCP rate limiter
func NewDHCPRateLimiter(logger zerolog.Logger) *DHCPRateLimiter {
	return &DHCPRateLimiter{
		requests:     make(map[string][]time.Time),
		maxPerMinute: 10, // Max 10 DHCP requests per minute per MAC
		logger:       logger.With().Str("component", "dhcp-ratelimit").Logger(),
		stopCh:       make(chan struct{}),
	}
}

// IsAllowed checks if a MAC address is allowed to make a DHCP request
func (rl *DHCPRateLimiter) IsAllowed(mac string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-1 * time.Minute)

	// Clean up old requests
	validRequests := []time.Time{}
	for _, t := range rl.requests[mac] {
		if t.After(cutoff) {
			validRequests = append(validRequests, t)
		}
	}

	rl.requests[mac] = validRequests

	// Check if too many requests
	if len(validRequests) >= rl.maxPerMinute {
		rl.logger.Warn().
			Str("mac", mac).
			Int("requests", len(validRequests)).
			Msg("DHCP rate limit exceeded - possible pool exhaustion attack")
		return false
	}

	// Record this request
	rl.requests[mac] = append(validRequests, now)
	return true
}

// Start begins the background cleanup goroutine.
func (rl *DHCPRateLimiter) Start() {
	go rl.cleanupLoop()
}

// Stop terminates the background cleanup goroutine.
func (rl *DHCPRateLimiter) Stop() {
	close(rl.stopCh)
}

// cleanupLoop periodically removes old data
func (rl *DHCPRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			cutoff := now.Add(-1 * time.Minute)

			for mac, requests := range rl.requests {
				validRequests := []time.Time{}
				for _, t := range requests {
					if t.After(cutoff) {
						validRequests = append(validRequests, t)
					}
				}

				if len(validRequests) == 0 {
					delete(rl.requests, mac)
				} else {
					rl.requests[mac] = validRequests
				}
			}
			rl.mu.Unlock()
		case <-rl.stopCh:
			return
		}
	}
}
