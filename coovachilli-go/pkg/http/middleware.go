package http

import (
	"net"
	"net/http"
	"sync"

	"github.com/rs/zerolog"
	"golang.org/x/time/rate"
)

// RateLimiterMiddleware holds the state for the rate limiting middleware.
type RateLimiterMiddleware struct {
	logger         zerolog.Logger
	clients        map[string]*rate.Limiter
	mu             sync.Mutex
	rate           rate.Limit
	burst          int
	enabled        bool
}

// NewRateLimiter creates a new rate limiting middleware.
func NewRateLimiter(logger zerolog.Logger, enabled bool, r float64, b int) *RateLimiterMiddleware {
	return &RateLimiterMiddleware{
		logger:  logger,
		clients: make(map[string]*rate.Limiter),
		rate:    rate.Limit(r),
		burst:   b,
		enabled: enabled,
	}
}

// getClientLimiter retrieves or creates a rate limiter for a given IP address.
func (rl *RateLimiterMiddleware) getClientLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.clients[ip]
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.clients[ip] = limiter
	}
	return limiter
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