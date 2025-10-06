package sms

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// SMSConfig holds SMS authentication configuration
type SMSConfig struct {
	Enabled         bool          `yaml:"enabled" envconfig:"SMS_ENABLED"`
	Provider        string        `yaml:"provider" envconfig:"SMS_PROVIDER"` // twilio, nexmo, aws-sns
	CodeLength      int           `yaml:"code_length" envconfig:"SMS_CODE_LENGTH"`
	CodeExpiry      time.Duration `yaml:"code_expiry" envconfig:"SMS_CODE_EXPIRY"`
	MaxAttempts     int           `yaml:"max_attempts" envconfig:"SMS_MAX_ATTEMPTS"`
	RateLimitWindow time.Duration `yaml:"rate_limit_window" envconfig:"SMS_RATE_LIMIT_WINDOW"`
	MaxPerWindow    int           `yaml:"max_per_window" envconfig:"SMS_MAX_PER_WINDOW"`

	// Twilio configuration
	TwilioAccountSID string `yaml:"twilio_account_sid" envconfig:"TWILIO_ACCOUNT_SID"`
	TwilioAuthToken  string `yaml:"twilio_auth_token" envconfig:"TWILIO_AUTH_TOKEN"`
	TwilioFromNumber string `yaml:"twilio_from_number" envconfig:"TWILIO_FROM_NUMBER"`

	// Nexmo/Vonage configuration
	NexmoAPIKey    string `yaml:"nexmo_api_key" envconfig:"NEXMO_API_KEY"`
	NexmoAPISecret string `yaml:"nexmo_api_secret" envconfig:"NEXMO_API_SECRET"`
	NexmoFromName  string `yaml:"nexmo_from_name" envconfig:"NEXMO_FROM_NAME"`

	// AWS SNS configuration
	AWSRegion          string `yaml:"aws_region" envconfig:"AWS_REGION"`
	AWSAccessKeyID     string `yaml:"aws_access_key_id" envconfig:"AWS_ACCESS_KEY_ID"`
	AWSSecretAccessKey string `yaml:"aws_secret_access_key" envconfig:"AWS_SECRET_ACCESS_KEY"`
}

// SMSCode represents a verification code sent via SMS
type SMSCode struct {
	Code        string    `json:"code"`
	PhoneNumber string    `json:"phone_number"`
	Username    string    `json:"username,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Attempts    int       `json:"attempts"`
	Verified    bool      `json:"verified"`
	VerifiedAt  *time.Time `json:"verified_at,omitempty"`
}

// RateLimitEntry tracks SMS sending rate limits
type RateLimitEntry struct {
	Count     int
	WindowStart time.Time
}

// SMSAuthManager manages SMS authentication
type SMSAuthManager struct {
	config     *SMSConfig
	logger     zerolog.Logger
	mu         sync.RWMutex
	codes      map[string]*SMSCode // phone number -> code
	rateLimits map[string]*RateLimitEntry // phone number -> rate limit
	provider   SMSProvider
	stats      SMSStats
}

// SMSStats tracks SMS authentication statistics
type SMSStats struct {
	CodesSent      uint64
	CodesVerified  uint64
	CodesExpired   uint64
	FailedAttempts uint64
	RateLimited    uint64
}

// SMSProvider is the interface for SMS providers
type SMSProvider interface {
	SendSMS(phoneNumber, message string) error
	Name() string
}

// NewSMSAuthManager creates a new SMS authentication manager
func NewSMSAuthManager(config *SMSConfig, logger zerolog.Logger) (*SMSAuthManager, error) {
	if !config.Enabled {
		return nil, nil
	}

	// Set defaults
	if config.CodeLength == 0 {
		config.CodeLength = 6
	}
	if config.CodeExpiry == 0 {
		config.CodeExpiry = 5 * time.Minute
	}
	if config.MaxAttempts == 0 {
		config.MaxAttempts = 3
	}
	if config.RateLimitWindow == 0 {
		config.RateLimitWindow = 1 * time.Hour
	}
	if config.MaxPerWindow == 0 {
		config.MaxPerWindow = 5
	}

	sm := &SMSAuthManager{
		config:     config,
		logger:     logger.With().Str("component", "sms-auth").Logger(),
		codes:      make(map[string]*SMSCode),
		rateLimits: make(map[string]*RateLimitEntry),
	}

	// Initialize SMS provider
	var err error
	sm.provider, err = sm.initProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize SMS provider: %w", err)
	}

	// Start cleanup goroutine
	go sm.cleanupExpired()

	sm.logger.Info().
		Str("provider", config.Provider).
		Int("code_length", config.CodeLength).
		Dur("code_expiry", config.CodeExpiry).
		Msg("SMS authentication manager initialized")

	return sm, nil
}

// initProvider initializes the SMS provider
func (sm *SMSAuthManager) initProvider() (SMSProvider, error) {
	switch sm.config.Provider {
	case "twilio":
		return NewTwilioProvider(sm.config, sm.logger)
	case "nexmo", "vonage":
		return NewNexmoProvider(sm.config, sm.logger)
	case "aws-sns":
		return NewAWSSNSProvider(sm.config, sm.logger)
	case "mock":
		return NewMockProvider(sm.logger), nil
	default:
		return nil, fmt.Errorf("unsupported SMS provider: %s", sm.config.Provider)
	}
}

// SendCode sends a verification code via SMS
func (sm *SMSAuthManager) SendCode(phoneNumber, username string) (*SMSCode, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Normalize phone number
	phoneNumber = normalizePhoneNumber(phoneNumber)

	// Check rate limit
	if err := sm.checkRateLimit(phoneNumber); err != nil {
		sm.stats.RateLimited++
		return nil, err
	}

	// Generate verification code
	code, err := generateCode(sm.config.CodeLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate code: %w", err)
	}

	now := time.Now()
	smsCode := &SMSCode{
		Code:        code,
		PhoneNumber: phoneNumber,
		Username:    username,
		CreatedAt:   now,
		ExpiresAt:   now.Add(sm.config.CodeExpiry),
		Attempts:    0,
		Verified:    false,
	}

	// Store code
	sm.codes[phoneNumber] = smsCode

	// Send SMS
	message := fmt.Sprintf("Your verification code is: %s. Valid for %d minutes.",
		code, int(sm.config.CodeExpiry.Minutes()))

	if err := sm.provider.SendSMS(phoneNumber, message); err != nil {
		delete(sm.codes, phoneNumber)
		return nil, fmt.Errorf("failed to send SMS: %w", err)
	}

	// Update rate limit
	sm.updateRateLimit(phoneNumber)
	sm.stats.CodesSent++

	sm.logger.Info().
		Str("phone", maskPhoneNumber(phoneNumber)).
		Str("username", username).
		Msg("SMS verification code sent")

	return smsCode, nil
}

// VerifyCode verifies a code entered by the user
func (sm *SMSAuthManager) VerifyCode(phoneNumber, code string) (bool, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	phoneNumber = normalizePhoneNumber(phoneNumber)

	smsCode, exists := sm.codes[phoneNumber]
	if !exists {
		return false, fmt.Errorf("no code found for this phone number")
	}

	// Check expiration
	if time.Now().After(smsCode.ExpiresAt) {
		delete(sm.codes, phoneNumber)
		sm.stats.CodesExpired++
		return false, fmt.Errorf("code expired")
	}

	// Check if already verified
	if smsCode.Verified {
		return false, fmt.Errorf("code already used")
	}

	// Increment attempt counter
	smsCode.Attempts++

	// Check max attempts
	if smsCode.Attempts > sm.config.MaxAttempts {
		delete(sm.codes, phoneNumber)
		sm.stats.FailedAttempts++
		return false, fmt.Errorf("maximum attempts exceeded")
	}

	// Verify code
	if smsCode.Code != code {
		sm.stats.FailedAttempts++
		return false, fmt.Errorf("invalid code")
	}

	// Mark as verified
	now := time.Now()
	smsCode.Verified = true
	smsCode.VerifiedAt = &now
	sm.stats.CodesVerified++

	sm.logger.Info().
		Str("phone", maskPhoneNumber(phoneNumber)).
		Str("username", smsCode.Username).
		Msg("SMS code verified successfully")

	return true, nil
}

// checkRateLimit checks if phone number has exceeded rate limit
func (sm *SMSAuthManager) checkRateLimit(phoneNumber string) error {
	entry, exists := sm.rateLimits[phoneNumber]
	if !exists {
		return nil
	}

	// Check if window has expired
	if time.Since(entry.WindowStart) > sm.config.RateLimitWindow {
		delete(sm.rateLimits, phoneNumber)
		return nil
	}

	// Check count
	if entry.Count >= sm.config.MaxPerWindow {
		return fmt.Errorf("rate limit exceeded: maximum %d SMS per %v",
			sm.config.MaxPerWindow, sm.config.RateLimitWindow)
	}

	return nil
}

// updateRateLimit updates the rate limit counter
func (sm *SMSAuthManager) updateRateLimit(phoneNumber string) {
	entry, exists := sm.rateLimits[phoneNumber]
	if !exists {
		sm.rateLimits[phoneNumber] = &RateLimitEntry{
			Count:       1,
			WindowStart: time.Now(),
		}
		return
	}

	// Reset if window expired
	if time.Since(entry.WindowStart) > sm.config.RateLimitWindow {
		entry.Count = 1
		entry.WindowStart = time.Now()
	} else {
		entry.Count++
	}
}

// cleanupExpired periodically removes expired codes
func (sm *SMSAuthManager) cleanupExpired() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sm.mu.Lock()
		now := time.Now()
		expired := 0

		// Cleanup expired codes
		for phoneNumber, smsCode := range sm.codes {
			if now.After(smsCode.ExpiresAt) || smsCode.Verified {
				delete(sm.codes, phoneNumber)
				expired++
			}
		}

		// Cleanup expired rate limits
		for phoneNumber, entry := range sm.rateLimits {
			if time.Since(entry.WindowStart) > sm.config.RateLimitWindow {
				delete(sm.rateLimits, phoneNumber)
			}
		}

		sm.mu.Unlock()

		if expired > 0 {
			sm.logger.Debug().
				Int("expired", expired).
				Msg("Cleaned up expired SMS codes")
		}
	}
}

// GetStats returns SMS authentication statistics
func (sm *SMSAuthManager) GetStats() SMSStats {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.stats
}

// TwilioProvider implements SMS sending via Twilio
type TwilioProvider struct {
	config *SMSConfig
	logger zerolog.Logger
	client *http.Client
}

func NewTwilioProvider(config *SMSConfig, logger zerolog.Logger) (*TwilioProvider, error) {
	if config.TwilioAccountSID == "" || config.TwilioAuthToken == "" {
		return nil, fmt.Errorf("Twilio credentials not configured")
	}

	return &TwilioProvider{
		config: config,
		logger: logger.With().Str("provider", "twilio").Logger(),
		client: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (t *TwilioProvider) Name() string {
	return "twilio"
}

func (t *TwilioProvider) SendSMS(phoneNumber, message string) error {
	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json",
		t.config.TwilioAccountSID)

	data := url.Values{}
	data.Set("To", phoneNumber)
	data.Set("From", t.config.TwilioFromNumber)
	data.Set("Body", message)

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.SetBasicAuth(t.config.TwilioAccountSID, t.config.TwilioAuthToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Twilio API returned status %d", resp.StatusCode)
	}

	t.logger.Debug().Str("phone", maskPhoneNumber(phoneNumber)).Msg("SMS sent via Twilio")
	return nil
}

// NexmoProvider implements SMS sending via Nexmo/Vonage
type NexmoProvider struct {
	config *SMSConfig
	logger zerolog.Logger
	client *http.Client
}

func NewNexmoProvider(config *SMSConfig, logger zerolog.Logger) (*NexmoProvider, error) {
	if config.NexmoAPIKey == "" || config.NexmoAPISecret == "" {
		return nil, fmt.Errorf("Nexmo credentials not configured")
	}

	return &NexmoProvider{
		config: config,
		logger: logger.With().Str("provider", "nexmo").Logger(),
		client: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (n *NexmoProvider) Name() string {
	return "nexmo"
}

func (n *NexmoProvider) SendSMS(phoneNumber, message string) error {
	apiURL := "https://rest.nexmo.com/sms/json"

	data := url.Values{}
	data.Set("api_key", n.config.NexmoAPIKey)
	data.Set("api_secret", n.config.NexmoAPISecret)
	data.Set("to", phoneNumber)
	data.Set("from", n.config.NexmoFromName)
	data.Set("text", message)

	resp, err := n.client.PostForm(apiURL, data)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Nexmo API returned status %d", resp.StatusCode)
	}

	n.logger.Debug().Str("phone", maskPhoneNumber(phoneNumber)).Msg("SMS sent via Nexmo")
	return nil
}

// AWSSNSProvider implements SMS sending via AWS SNS
type AWSSNSProvider struct {
	config *SMSConfig
	logger zerolog.Logger
}

func NewAWSSNSProvider(config *SMSConfig, logger zerolog.Logger) (*AWSSNSProvider, error) {
	// In a real implementation, initialize AWS SDK here
	return &AWSSNSProvider{
		config: config,
		logger: logger.With().Str("provider", "aws-sns").Logger(),
	}, nil
}

func (a *AWSSNSProvider) Name() string {
	return "aws-sns"
}

func (a *AWSSNSProvider) SendSMS(phoneNumber, message string) error {
	// Stub implementation - real version would use AWS SDK
	a.logger.Debug().
		Str("phone", maskPhoneNumber(phoneNumber)).
		Msg("Would send SMS via AWS SNS")
	return nil
}

// MockProvider is a mock SMS provider for testing
type MockProvider struct {
	logger zerolog.Logger
}

func NewMockProvider(logger zerolog.Logger) *MockProvider {
	return &MockProvider{
		logger: logger.With().Str("provider", "mock").Logger(),
	}
}

func (m *MockProvider) Name() string {
	return "mock"
}

func (m *MockProvider) SendSMS(phoneNumber, message string) error {
	m.logger.Info().
		Str("phone", maskPhoneNumber(phoneNumber)).
		Str("message", message).
		Msg("Mock SMS sent")
	return nil
}

// Helper functions

// generateCode generates a random numeric code
func generateCode(length int) (string, error) {
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(length)), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	// Format with leading zeros
	format := fmt.Sprintf("%%0%dd", length)
	return fmt.Sprintf(format, n), nil
}

// normalizePhoneNumber normalizes phone number format
func normalizePhoneNumber(phoneNumber string) string {
	// Remove common formatting characters
	phoneNumber = strings.ReplaceAll(phoneNumber, " ", "")
	phoneNumber = strings.ReplaceAll(phoneNumber, "-", "")
	phoneNumber = strings.ReplaceAll(phoneNumber, "(", "")
	phoneNumber = strings.ReplaceAll(phoneNumber, ")", "")

	// Ensure it starts with +
	if !strings.HasPrefix(phoneNumber, "+") {
		phoneNumber = "+" + phoneNumber
	}

	return phoneNumber
}

// maskPhoneNumber masks phone number for logging
func maskPhoneNumber(phoneNumber string) string {
	if len(phoneNumber) <= 4 {
		return "****"
	}
	return phoneNumber[:len(phoneNumber)-4] + "****"
}
