package token

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// TokenType represents the type of token
type TokenType string

const (
	TokenTypeSession TokenType = "session" // UAM session token
	TokenTypeSSO     TokenType = "sso"     // SSO session token
	TokenTypeFAS     TokenType = "fas"     // FAS authentication token
)

// Token represents a unified session token
type Token struct {
	Value          string
	Type           TokenType
	CoreSessionID  string    // Reference to core.Session
	AuthSessionID  string    // Reference to auth.AuthSession (optional)
	Username       string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	LastActivity   time.Time
	Attributes     map[string]interface{}
}

// Manager manages all session tokens
type Manager struct {
	mu     sync.RWMutex
	tokens map[string]*Token
}

// NewManager creates a new token manager
func NewManager() *Manager {
	return &Manager{
		tokens: make(map[string]*Token),
	}
}

// GenerateToken creates a new secure token
func (m *Manager) GenerateToken(tokenType TokenType, coreSessionID, username string, expiresAt time.Time) (*Token, error) {
	// Generate cryptographically secure random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random token: %w", err)
	}

	tokenValue := hex.EncodeToString(tokenBytes)

	token := &Token{
		Value:         tokenValue,
		Type:          tokenType,
		CoreSessionID: coreSessionID,
		Username:      username,
		CreatedAt:     time.Now(),
		ExpiresAt:     expiresAt,
		LastActivity:  time.Now(),
		Attributes:    make(map[string]interface{}),
	}

	m.mu.Lock()
	m.tokens[tokenValue] = token
	m.mu.Unlock()

	return token, nil
}

// ValidateToken checks if a token is valid and updates last activity
func (m *Manager) ValidateToken(tokenValue string) (*Token, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	token, exists := m.tokens[tokenValue]
	if !exists {
		return nil, false
	}

	// Check expiration
	if time.Now().After(token.ExpiresAt) {
		delete(m.tokens, tokenValue)
		return nil, false
	}

	// Update last activity
	token.LastActivity = time.Now()

	return token, true
}

// GetToken retrieves a token without validation
func (m *Manager) GetToken(tokenValue string) (*Token, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	token, exists := m.tokens[tokenValue]
	return token, exists
}

// LinkAuthSession links an auth.AuthSession to an existing token
func (m *Manager) LinkAuthSession(tokenValue, authSessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	token, exists := m.tokens[tokenValue]
	if !exists {
		return fmt.Errorf("token not found")
	}

	token.AuthSessionID = authSessionID
	return nil
}

// RevokeToken removes a token
func (m *Manager) RevokeToken(tokenValue string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.tokens, tokenValue)
}

// RevokeBySessionID removes all tokens associated with a session
func (m *Manager) RevokeBySessionID(coreSessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for tokenValue, token := range m.tokens {
		if token.CoreSessionID == coreSessionID {
			delete(m.tokens, tokenValue)
		}
	}
}

// CleanupExpired removes all expired tokens
func (m *Manager) CleanupExpired() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	removed := 0

	for tokenValue, token := range m.tokens {
		if now.After(token.ExpiresAt) {
			delete(m.tokens, tokenValue)
			removed++
		}
	}

	return removed
}

// GetStats returns token statistics
func (m *Manager) GetStats() map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := map[string]int{
		"total":   len(m.tokens),
		"session": 0,
		"sso":     0,
		"fas":     0,
	}

	for _, token := range m.tokens {
		switch token.Type {
		case TokenTypeSession:
			stats["session"]++
		case TokenTypeSSO:
			stats["sso"]++
		case TokenTypeFAS:
			stats["fas"]++
		}
	}

	return stats
}

// StartCleanup starts a background goroutine to clean expired tokens
func (m *Manager) StartCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			removed := m.CleanupExpired()
			if removed > 0 {
				// Log could be added here if logger is available
				_ = removed
			}
		}
	}()
}
