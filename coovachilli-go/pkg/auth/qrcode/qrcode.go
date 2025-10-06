package qrcode

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"sync"
	"time"

	"github.com/rs/zerolog"
	qrcode "github.com/skip2/go-qrcode"
)

// QRCodeConfig holds QR code authentication configuration
type QRCodeConfig struct {
	Enabled         bool          `yaml:"enabled" envconfig:"QRCODE_ENABLED"`
	TokenExpiry     time.Duration `yaml:"token_expiry" envconfig:"QRCODE_TOKEN_EXPIRY"`
	CleanupInterval time.Duration `yaml:"cleanup_interval" envconfig:"QRCODE_CLEANUP_INTERVAL"`
	QRSize          int           `yaml:"qr_size" envconfig:"QRCODE_SIZE"`
	BaseURL         string        `yaml:"base_url" envconfig:"QRCODE_BASE_URL"` // e.g., https://portal.example.com
}

// QRToken represents a QR code authentication token
type QRToken struct {
	Token       string    `json:"token"`
	Username    string    `json:"username,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Used        bool      `json:"used"`
	UsedAt      *time.Time `json:"used_at,omitempty"`
	SessionData map[string]interface{} `json:"session_data,omitempty"`
	IPAddress   string    `json:"ip_address,omitempty"`
}

// QRAuthManager manages QR code authentication
type QRAuthManager struct {
	config  *QRCodeConfig
	logger  zerolog.Logger
	mu      sync.RWMutex
	tokens  map[string]*QRToken
	stats   QRStats
}

// QRStats tracks QR code authentication statistics
type QRStats struct {
	TokensGenerated uint64
	TokensUsed      uint64
	TokensExpired   uint64
	ActiveTokens    int
}

// NewQRAuthManager creates a new QR code authentication manager
func NewQRAuthManager(config *QRCodeConfig, logger zerolog.Logger) (*QRAuthManager, error) {
	if !config.Enabled {
		return nil, nil
	}

	// Set defaults
	if config.TokenExpiry == 0 {
		config.TokenExpiry = 5 * time.Minute
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 1 * time.Minute
	}
	if config.QRSize == 0 {
		config.QRSize = 256
	}

	qm := &QRAuthManager{
		config: config,
		logger: logger.With().Str("component", "qrcode-auth").Logger(),
		tokens: make(map[string]*QRToken),
	}

	// Start cleanup goroutine
	go qm.cleanupExpired()

	qm.logger.Info().
		Dur("token_expiry", config.TokenExpiry).
		Int("qr_size", config.QRSize).
		Msg("QR code authentication manager initialized")

	return qm, nil
}

// GenerateQRToken generates a new QR code token
func (qm *QRAuthManager) GenerateQRToken(username string, sessionData map[string]interface{}) (*QRToken, error) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	// Generate secure random token
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	now := time.Now()
	qrToken := &QRToken{
		Token:       token,
		Username:    username,
		CreatedAt:   now,
		ExpiresAt:   now.Add(qm.config.TokenExpiry),
		Used:        false,
		SessionData: sessionData,
	}

	qm.tokens[token] = qrToken
	qm.stats.TokensGenerated++
	qm.stats.ActiveTokens = len(qm.tokens)

	qm.logger.Info().
		Str("token", token[:16]+"...").
		Str("username", username).
		Time("expires_at", qrToken.ExpiresAt).
		Msg("QR token generated")

	return qrToken, nil
}

// GenerateQRCode generates a QR code image for a token
func (qm *QRAuthManager) GenerateQRCode(token string) ([]byte, error) {
	qm.mu.RLock()
	qrToken, exists := qm.tokens[token]
	qm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("token not found")
	}

	if time.Now().After(qrToken.ExpiresAt) {
		return nil, fmt.Errorf("token expired")
	}

	// Create auth URL
	authURL := fmt.Sprintf("%s/qr-auth?token=%s", qm.config.BaseURL, token)

	// Generate QR code
	qr, err := qrcode.New(authURL, qrcode.Medium)
	if err != nil {
		return nil, fmt.Errorf("failed to create QR code: %w", err)
	}

	// Encode to PNG
	pngBytes, err := qr.PNG(qm.config.QRSize)
	if err != nil {
		return nil, fmt.Errorf("failed to encode QR code: %w", err)
	}

	return pngBytes, nil
}

// GenerateQRCodePNG generates a QR code and writes it to a writer
func (qm *QRAuthManager) GenerateQRCodePNG(token string, w io.Writer) error {
	pngBytes, err := qm.GenerateQRCode(token)
	if err != nil {
		return err
	}

	_, err = w.Write(pngBytes)
	return err
}

// ValidateToken validates a QR code token
func (qm *QRAuthManager) ValidateToken(token string, ipAddress string) (*QRToken, error) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	qrToken, exists := qm.tokens[token]
	if !exists {
		return nil, fmt.Errorf("invalid token")
	}

	// Check expiration
	if time.Now().After(qrToken.ExpiresAt) {
		delete(qm.tokens, token)
		qm.stats.TokensExpired++
		qm.stats.ActiveTokens = len(qm.tokens)
		return nil, fmt.Errorf("token expired")
	}

	// Check if already used
	if qrToken.Used {
		return nil, fmt.Errorf("token already used")
	}

	// Mark as used
	now := time.Now()
	qrToken.Used = true
	qrToken.UsedAt = &now
	qrToken.IPAddress = ipAddress

	qm.stats.TokensUsed++

	qm.logger.Info().
		Str("token", token[:16]+"...").
		Str("username", qrToken.Username).
		Str("ip", ipAddress).
		Msg("QR token validated")

	return qrToken, nil
}

// RevokeToken revokes a token before it expires
func (qm *QRAuthManager) RevokeToken(token string) error {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	if _, exists := qm.tokens[token]; !exists {
		return fmt.Errorf("token not found")
	}

	delete(qm.tokens, token)
	qm.stats.ActiveTokens = len(qm.tokens)

	qm.logger.Info().
		Str("token", token[:16]+"...").
		Msg("QR token revoked")

	return nil
}

// GetToken retrieves token information
func (qm *QRAuthManager) GetToken(token string) (*QRToken, error) {
	qm.mu.RLock()
	defer qm.mu.RUnlock()

	qrToken, exists := qm.tokens[token]
	if !exists {
		return nil, fmt.Errorf("token not found")
	}

	// Return a copy to prevent external modifications
	copy := *qrToken
	return &copy, nil
}

// cleanupExpired periodically removes expired tokens
func (qm *QRAuthManager) cleanupExpired() {
	ticker := time.NewTicker(qm.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		qm.mu.Lock()
		now := time.Now()
		expired := 0

		for token, qrToken := range qm.tokens {
			if now.After(qrToken.ExpiresAt) {
				delete(qm.tokens, token)
				expired++
			}
		}

		qm.stats.TokensExpired += uint64(expired)
		qm.stats.ActiveTokens = len(qm.tokens)
		qm.mu.Unlock()

		if expired > 0 {
			qm.logger.Debug().
				Int("expired", expired).
				Msg("Cleaned up expired QR tokens")
		}
	}
}

// GetStats returns current QR code authentication statistics
func (qm *QRAuthManager) GetStats() QRStats {
	qm.mu.RLock()
	defer qm.mu.RUnlock()

	stats := qm.stats
	stats.ActiveTokens = len(qm.tokens)
	return stats
}

// ListActiveTokens returns all active tokens (admin function)
func (qm *QRAuthManager) ListActiveTokens() []*QRToken {
	qm.mu.RLock()
	defer qm.mu.RUnlock()

	tokens := make([]*QRToken, 0, len(qm.tokens))
	for _, token := range qm.tokens {
		if !token.Used && time.Now().Before(token.ExpiresAt) {
			copy := *token
			tokens = append(tokens, &copy)
		}
	}

	return tokens
}

// QRAuthData represents the data encoded in a QR code
type QRAuthData struct {
	Token     string                 `json:"token"`
	ExpiresAt int64                  `json:"expires_at"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// GenerateQRAuthData creates QR code authentication data
func (qm *QRAuthManager) GenerateQRAuthData(username string, metadata map[string]interface{}) (*QRAuthData, error) {
	token, err := qm.GenerateQRToken(username, metadata)
	if err != nil {
		return nil, err
	}

	return &QRAuthData{
		Token:     token.Token,
		ExpiresAt: token.ExpiresAt.Unix(),
		Metadata:  metadata,
	}, nil
}

// EncodeQRAuthData encodes auth data as JSON for QR code
func EncodeQRAuthData(data *QRAuthData) (string, error) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

// DecodeQRAuthData decodes auth data from QR code
func DecodeQRAuthData(jsonStr string) (*QRAuthData, error) {
	var data QRAuthData
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return nil, err
	}
	return &data, nil
}
