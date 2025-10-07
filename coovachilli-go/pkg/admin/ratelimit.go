package admin

import (
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// RateLimiter provides IP-based rate limiting and banning for the admin API
type RateLimiter struct {
	mu           sync.Mutex
	attempts     map[string][]time.Time
	banned       map[string]time.Time
	maxAttempts  int
	window       time.Duration
	banDuration  time.Duration
	logger       zerolog.Logger
}

// NewRateLimiter creates a new rate limiter for admin API
func NewRateLimiter(logger zerolog.Logger) *RateLimiter {
	return &RateLimiter{
		attempts:    make(map[string][]time.Time),
		banned:      make(map[string]time.Time),
		maxAttempts: 5,           // Max 5 failed attempts
		window:      1 * time.Minute, // Within 1 minute
		banDuration: 15 * time.Minute, // Ban for 15 minutes
		logger:      logger.With().Str("component", "admin-ratelimit").Logger(),
	}
}

// IsAllowed checks if an IP is allowed to make a request
func (rl *RateLimiter) IsAllowed(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Check if IP is currently banned
	if bannedUntil, exists := rl.banned[ip]; exists {
		if time.Now().Before(bannedUntil) {
			rl.logger.Warn().
				Str("ip", ip).
				Time("banned_until", bannedUntil).
				Msg("Blocked request from banned IP")
			return false
		}
		// Ban expired, remove it
		delete(rl.banned, ip)
		rl.logger.Info().Str("ip", ip).Msg("Ban expired for IP")
	}

	// Clean up old attempts outside the time window
	now := time.Now()
	cutoff := now.Add(-rl.window)
	validAttempts := []time.Time{}

	for _, t := range rl.attempts[ip] {
		if t.After(cutoff) {
			validAttempts = append(validAttempts, t)
		}
	}

	rl.attempts[ip] = validAttempts

	// Check if too many attempts
	if len(validAttempts) >= rl.maxAttempts {
		// Ban the IP
		rl.banned[ip] = now.Add(rl.banDuration)
		rl.logger.Warn().
			Str("ip", ip).
			Int("attempts", len(validAttempts)).
			Dur("ban_duration", rl.banDuration).
			Msg("IP banned due to excessive failed attempts")
		return false
	}

	return true
}

// RecordAttempt records an authentication attempt
func (rl *RateLimiter) RecordAttempt(ip string, success bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if success {
		// Clear attempts on successful auth
		delete(rl.attempts, ip)
		// Also remove ban if exists
		delete(rl.banned, ip)
		rl.logger.Debug().Str("ip", ip).Msg("Successful auth, cleared rate limit counters")
		return
	}

	// Record failed attempt
	rl.attempts[ip] = append(rl.attempts[ip], time.Now())
	rl.logger.Debug().
		Str("ip", ip).
		Int("total_attempts", len(rl.attempts[ip])).
		Msg("Recorded failed authentication attempt")
}

// GetBannedIPs returns a list of currently banned IPs (for monitoring)
func (rl *RateLimiter) GetBannedIPs() map[string]time.Time {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Clean expired bans first
	now := time.Now()
	for ip, bannedUntil := range rl.banned {
		if now.After(bannedUntil) {
			delete(rl.banned, ip)
		}
	}

	// Return a copy
	banned := make(map[string]time.Time)
	for ip, until := range rl.banned {
		banned[ip] = until
	}

	return banned
}

// Cleanup periodically cleans up old data
func (rl *RateLimiter) Cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()

		now := time.Now()
		cutoff := now.Add(-rl.window)

		// Clean old attempts
		for ip, attempts := range rl.attempts {
			validAttempts := []time.Time{}
			for _, t := range attempts {
				if t.After(cutoff) {
					validAttempts = append(validAttempts, t)
				}
			}

			if len(validAttempts) == 0 {
				delete(rl.attempts, ip)
			} else {
				rl.attempts[ip] = validAttempts
			}
		}

		// Clean expired bans
		for ip, bannedUntil := range rl.banned {
			if now.After(bannedUntil) {
				delete(rl.banned, ip)
			}
		}

		rl.mu.Unlock()
	}
}
