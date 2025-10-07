package http

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/time/rate"
)

// RateLimiterMiddleware holds the state for the rate limiting middleware.
type RateLimiterMiddleware struct {
	logger         zerolog.Logger
	clients        map[string]*rateLimiterEntry
	mu             sync.Mutex
	rate           rate.Limit
	burst          int
	enabled        bool
}

// rateLimiterEntry tracks a rate limiter and its last access time
type rateLimiterEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

// NewRateLimiter creates a new rate limiting middleware.
func NewRateLimiter(logger zerolog.Logger, enabled bool, r float64, b int) *RateLimiterMiddleware {
	rl := &RateLimiterMiddleware{
		logger:  logger,
		clients: make(map[string]*rateLimiterEntry),
		rate:    rate.Limit(r),
		burst:   b,
		enabled: enabled,
	}

	// ✅ OPTIMIZATION: Start automatic cleanup of stale entries
	if enabled {
		go rl.cleanupStaleClients()
	}

	return rl
}

// getClientLimiter retrieves or creates a rate limiter for a given IP address.
func (rl *RateLimiterMiddleware) getClientLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, exists := rl.clients[ip]
	if !exists {
		entry = &rateLimiterEntry{
			limiter:    rate.NewLimiter(rl.rate, rl.burst),
			lastAccess: time.Now(),
		}
		rl.clients[ip] = entry
	} else {
		entry.lastAccess = time.Now()
	}
	return entry.limiter
}

// ✅ OPTIMIZATION: Cleanup stale rate limiters to prevent memory leak
func (rl *RateLimiterMiddleware) cleanupStaleClients() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		staleThreshold := 30 * time.Minute
		removed := 0

		for ip, entry := range rl.clients {
			if now.Sub(entry.lastAccess) > staleThreshold {
				delete(rl.clients, ip)
				removed++
			}
		}

		if removed > 0 {
			rl.logger.Debug().Int("removed", removed).Int("remaining", len(rl.clients)).Msg("Cleaned up stale rate limiters")
		}
		rl.mu.Unlock()
	}
}

// Middleware is the actual middleware handler.
func (rl *RateLimiterMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.enabled {
			next.ServeHTTP(w, r)
			return
		}

		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			rl.logger.Warn().Err(err).Msg("Failed to get client IP for rate limiting")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		limiter := rl.getClientLimiter(ip)
		if !limiter.Allow() {
			rl.logger.Warn().Str("ip", ip).Msg("Rate limit exceeded")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}