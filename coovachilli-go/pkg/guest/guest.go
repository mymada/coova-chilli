package guest

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// GuestConfig holds guest code configuration
type GuestConfig struct {
	Enabled          bool          `yaml:"enabled" envconfig:"GUEST_ENABLED"`
	CodeLength       int           `yaml:"code_length" envconfig:"GUEST_CODE_LENGTH"`
	CodePrefix       string        `yaml:"code_prefix" envconfig:"GUEST_CODE_PREFIX"`
	DefaultDuration  time.Duration `yaml:"default_duration" envconfig:"GUEST_DEFAULT_DURATION"`
	MaxConcurrent    int           `yaml:"max_concurrent" envconfig:"GUEST_MAX_CONCURRENT"`
	CleanupInterval  time.Duration `yaml:"cleanup_interval" envconfig:"GUEST_CLEANUP_INTERVAL"`
	RequireApproval  bool          `yaml:"require_approval" envconfig:"GUEST_REQUIRE_APPROVAL"`
	AllowSelfService bool          `yaml:"allow_self_service" envconfig:"GUEST_ALLOW_SELF_SERVICE"`
}

// GuestCodeStatus represents the status of a guest code
type GuestCodeStatus string

const (
	GuestStatusPending  GuestCodeStatus = "pending"   // Waiting for approval
	GuestStatusActive   GuestCodeStatus = "active"    // Ready to use
	GuestStatusUsed     GuestCodeStatus = "used"      // Code has been used
	GuestStatusExpired  GuestCodeStatus = "expired"   // Code expired
	GuestStatusRevoked  GuestCodeStatus = "revoked"   // Code revoked
	GuestStatusRejected GuestCodeStatus = "rejected"  // Approval rejected
)

// GuestCode represents a guest access code
type GuestCode struct {
	Code         string                 `json:"code"`
	Status       GuestCodeStatus        `json:"status"`
	CreatedAt    time.Time              `json:"created_at"`
	CreatedBy    string                 `json:"created_by"`    // Username who created the code
	ExpiresAt    time.Time              `json:"expires_at"`
	ActivatedAt  *time.Time             `json:"activated_at,omitempty"`
	UsedBy       string                 `json:"used_by,omitempty"`
	GuestName    string                 `json:"guest_name,omitempty"`
	GuestEmail   string                 `json:"guest_email,omitempty"`
	GuestCompany string                 `json:"guest_company,omitempty"`
	Purpose      string                 `json:"purpose,omitempty"`
	ApprovedBy   string                 `json:"approved_by,omitempty"`
	ApprovedAt   *time.Time             `json:"approved_at,omitempty"`
	RejectedBy   string                 `json:"rejected_by,omitempty"`
	RejectedAt   *time.Time             `json:"rejected_at,omitempty"`
	RevokedBy    string                 `json:"revoked_by,omitempty"`
	RevokedAt    *time.Time             `json:"revoked_at,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`

	// Access restrictions
	MaxSessions      int           `json:"max_sessions"`       // Max concurrent sessions
	SessionDuration  time.Duration `json:"session_duration"`   // How long each session can last
	DataQuota        uint64        `json:"data_quota"`         // Total data allowance in bytes
	BandwidthDown    uint64        `json:"bandwidth_down"`     // Download bandwidth limit
	BandwidthUp      uint64        `json:"bandwidth_up"`       // Upload bandwidth limit
	AllowedTimeStart time.Time     `json:"allowed_time_start,omitempty"` // Access window start
	AllowedTimeEnd   time.Time     `json:"allowed_time_end,omitempty"`   // Access window end
}

// SponsoredAccess represents a sponsored guest access request
type SponsoredAccess struct {
	ID           string                 `json:"id"`
	GuestName    string                 `json:"guest_name"`
	GuestEmail   string                 `json:"guest_email"`
	GuestCompany string                 `json:"guest_company,omitempty"`
	Purpose      string                 `json:"purpose"`
	RequestedBy  string                 `json:"requested_by"` // Username requesting access
	RequestedAt  time.Time              `json:"requested_at"`
	SponsorEmail string                 `json:"sponsor_email"`
	Status       GuestCodeStatus        `json:"status"`
	Code         string                 `json:"code,omitempty"` // Generated after approval
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// GuestManager manages guest access codes
type GuestManager struct {
	config           *GuestConfig
	logger           zerolog.Logger
	mu               sync.RWMutex
	codes            map[string]*GuestCode
	sponsoredAccess  map[string]*SponsoredAccess
	stats            GuestStats
}

// GuestStats tracks guest code statistics
type GuestStats struct {
	TotalCodes       uint64
	ActiveCodes      int
	UsedCodes        uint64
	ExpiredCodes     uint64
	RevokedCodes     uint64
	PendingApprovals int
}

// NewGuestManager creates a new guest code manager
func NewGuestManager(config *GuestConfig, logger zerolog.Logger) (*GuestManager, error) {
	if !config.Enabled {
		return nil, nil
	}

	// Set defaults
	if config.CodeLength == 0 {
		config.CodeLength = 8
	}
	if config.CodePrefix == "" {
		config.CodePrefix = "GUEST"
	}
	if config.DefaultDuration == 0 {
		config.DefaultDuration = 24 * time.Hour
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = 100
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 1 * time.Hour
	}

	gm := &GuestManager{
		config:          config,
		logger:          logger.With().Str("component", "guest-manager").Logger(),
		codes:           make(map[string]*GuestCode),
		sponsoredAccess: make(map[string]*SponsoredAccess),
	}

	// Start cleanup goroutine
	go gm.cleanupExpired()

	gm.logger.Info().
		Int("code_length", config.CodeLength).
		Dur("default_duration", config.DefaultDuration).
		Bool("require_approval", config.RequireApproval).
		Msg("Guest manager initialized")

	return gm, nil
}

// GenerateGuestCode generates a new guest access code
func (gm *GuestManager) GenerateGuestCode(createdBy, guestName, guestEmail, purpose string, duration time.Duration, restrictions *GuestCode) (*GuestCode, error) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	// Check max concurrent codes
	if gm.countActiveCodes() >= gm.config.MaxConcurrent {
		return nil, fmt.Errorf("maximum concurrent guest codes reached")
	}

	// Generate unique code
	code, err := gm.generateUniqueCode()
	if err != nil {
		return nil, fmt.Errorf("failed to generate code: %w", err)
	}

	if duration == 0 {
		duration = gm.config.DefaultDuration
	}

	now := time.Now()
	guestCode := &GuestCode{
		Code:       code,
		CreatedAt:  now,
		CreatedBy:  createdBy,
		ExpiresAt:  now.Add(duration),
		GuestName:  guestName,
		GuestEmail: guestEmail,
		Purpose:    purpose,
		Metadata:   make(map[string]interface{}),
	}

	// Set initial status based on approval requirement
	if gm.config.RequireApproval {
		guestCode.Status = GuestStatusPending
	} else {
		guestCode.Status = GuestStatusActive
	}

	// Apply restrictions if provided
	if restrictions != nil {
		guestCode.MaxSessions = restrictions.MaxSessions
		guestCode.SessionDuration = restrictions.SessionDuration
		guestCode.DataQuota = restrictions.DataQuota
		guestCode.BandwidthDown = restrictions.BandwidthDown
		guestCode.BandwidthUp = restrictions.BandwidthUp
		guestCode.AllowedTimeStart = restrictions.AllowedTimeStart
		guestCode.AllowedTimeEnd = restrictions.AllowedTimeEnd
	} else {
		// Set defaults
		guestCode.MaxSessions = 1
		guestCode.SessionDuration = 8 * time.Hour
		guestCode.BandwidthDown = 10 * 1024 * 1024  // 10 Mbps
		guestCode.BandwidthUp = 5 * 1024 * 1024     // 5 Mbps
	}

	gm.codes[code] = guestCode
	gm.stats.TotalCodes++

	gm.logger.Info().
		Str("code", code).
		Str("created_by", createdBy).
		Str("guest_name", guestName).
		Str("status", string(guestCode.Status)).
		Time("expires_at", guestCode.ExpiresAt).
		Msg("Guest code generated")

	return guestCode, nil
}

// generateUniqueCode generates a unique guest code
func (gm *GuestManager) generateUniqueCode() (string, error) {
	maxAttempts := 10
	for i := 0; i < maxAttempts; i++ {
		code, err := generateRandomCode(gm.config.CodeLength)
		if err != nil {
			return "", err
		}

		// Add prefix
		fullCode := gm.config.CodePrefix + "-" + code

		// Check uniqueness
		if _, exists := gm.codes[fullCode]; !exists {
			return fullCode, nil
		}
	}

	return "", fmt.Errorf("failed to generate unique code after %d attempts", maxAttempts)
}

// ValidateGuestCode validates a guest code
func (gm *GuestManager) ValidateGuestCode(code string) (*GuestCode, error) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	guestCode, exists := gm.codes[code]
	if !exists {
		return nil, fmt.Errorf("invalid guest code")
	}

	// Check status
	if guestCode.Status != GuestStatusActive {
		return nil, fmt.Errorf("guest code is %s", guestCode.Status)
	}

	// Check expiration
	if time.Now().After(guestCode.ExpiresAt) {
		guestCode.Status = GuestStatusExpired
		gm.stats.ExpiredCodes++
		return nil, fmt.Errorf("guest code expired")
	}

	// Check time window restrictions
	now := time.Now()
	if !guestCode.AllowedTimeStart.IsZero() && now.Before(guestCode.AllowedTimeStart) {
		return nil, fmt.Errorf("guest code not yet valid (starts at %s)", guestCode.AllowedTimeStart.Format(time.RFC3339))
	}
	if !guestCode.AllowedTimeEnd.IsZero() && now.After(guestCode.AllowedTimeEnd) {
		return nil, fmt.Errorf("guest code time window expired")
	}

	return guestCode, nil
}

// ActivateGuestCode activates a code and marks it as used
func (gm *GuestManager) ActivateGuestCode(code, username string) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	guestCode, exists := gm.codes[code]
	if !exists {
		return fmt.Errorf("guest code not found")
	}

	if guestCode.Status != GuestStatusActive {
		return fmt.Errorf("guest code is not active")
	}

	now := time.Now()
	guestCode.Status = GuestStatusUsed
	guestCode.ActivatedAt = &now
	guestCode.UsedBy = username
	gm.stats.UsedCodes++

	gm.logger.Info().
		Str("code", code).
		Str("used_by", username).
		Msg("Guest code activated")

	return nil
}

// ApproveGuestCode approves a pending guest code
func (gm *GuestManager) ApproveGuestCode(code, approver string) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	guestCode, exists := gm.codes[code]
	if !exists {
		return fmt.Errorf("guest code not found")
	}

	if guestCode.Status != GuestStatusPending {
		return fmt.Errorf("guest code is not pending approval")
	}

	now := time.Now()
	guestCode.Status = GuestStatusActive
	guestCode.ApprovedBy = approver
	guestCode.ApprovedAt = &now

	gm.logger.Info().
		Str("code", code).
		Str("approved_by", approver).
		Msg("Guest code approved")

	return nil
}

// RejectGuestCode rejects a pending guest code
func (gm *GuestManager) RejectGuestCode(code, rejector, reason string) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	guestCode, exists := gm.codes[code]
	if !exists {
		return fmt.Errorf("guest code not found")
	}

	if guestCode.Status != GuestStatusPending {
		return fmt.Errorf("guest code is not pending approval")
	}

	now := time.Now()
	guestCode.Status = GuestStatusRejected
	guestCode.RejectedBy = rejector
	guestCode.RejectedAt = &now
	guestCode.Metadata["rejection_reason"] = reason

	gm.logger.Info().
		Str("code", code).
		Str("rejected_by", rejector).
		Str("reason", reason).
		Msg("Guest code rejected")

	return nil
}

// RevokeGuestCode revokes an active guest code
func (gm *GuestManager) RevokeGuestCode(code, revoker string) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	guestCode, exists := gm.codes[code]
	if !exists {
		return fmt.Errorf("guest code not found")
	}

	if guestCode.Status != GuestStatusActive && guestCode.Status != GuestStatusPending {
		return fmt.Errorf("cannot revoke code in %s status", guestCode.Status)
	}

	now := time.Now()
	guestCode.Status = GuestStatusRevoked
	guestCode.RevokedBy = revoker
	guestCode.RevokedAt = &now
	gm.stats.RevokedCodes++

	gm.logger.Info().
		Str("code", code).
		Str("revoked_by", revoker).
		Msg("Guest code revoked")

	return nil
}

// RequestSponsoredAccess creates a request for sponsored guest access
func (gm *GuestManager) RequestSponsoredAccess(guestName, guestEmail, guestCompany, purpose, requestedBy, sponsorEmail string) (*SponsoredAccess, error) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	access := &SponsoredAccess{
		ID:           generateSponsorID(),
		GuestName:    guestName,
		GuestEmail:   guestEmail,
		GuestCompany: guestCompany,
		Purpose:      purpose,
		RequestedBy:  requestedBy,
		RequestedAt:  time.Now(),
		SponsorEmail: sponsorEmail,
		Status:       GuestStatusPending,
		Metadata:     make(map[string]interface{}),
	}

	gm.sponsoredAccess[access.ID] = access

	gm.logger.Info().
		Str("request_id", access.ID).
		Str("guest_name", guestName).
		Str("sponsor_email", sponsorEmail).
		Msg("Sponsored access request created")

	return access, nil
}

// ApproveSponsoredAccess approves a sponsored access request and generates a code
func (gm *GuestManager) ApproveSponsoredAccess(requestID, approver string, duration time.Duration) (*GuestCode, error) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	request, exists := gm.sponsoredAccess[requestID]
	if !exists {
		return nil, fmt.Errorf("sponsored access request not found")
	}

	if request.Status != GuestStatusPending {
		return nil, fmt.Errorf("request is not pending")
	}

	// Generate code
	code, err := gm.generateUniqueCode()
	if err != nil {
		return nil, err
	}

	if duration == 0 {
		duration = gm.config.DefaultDuration
	}

	now := time.Now()
	guestCode := &GuestCode{
		Code:            code,
		Status:          GuestStatusActive,
		CreatedAt:       now,
		CreatedBy:       approver,
		ExpiresAt:       now.Add(duration),
		GuestName:       request.GuestName,
		GuestEmail:      request.GuestEmail,
		GuestCompany:    request.GuestCompany,
		Purpose:         request.Purpose,
		ApprovedBy:      approver,
		ApprovedAt:      &now,
		MaxSessions:     1,
		SessionDuration: 8 * time.Hour,
		BandwidthDown:   10 * 1024 * 1024,
		BandwidthUp:     5 * 1024 * 1024,
		Metadata:        make(map[string]interface{}),
	}

	gm.codes[code] = guestCode
	request.Status = GuestStatusActive
	request.Code = code
	gm.stats.TotalCodes++

	gm.logger.Info().
		Str("request_id", requestID).
		Str("code", code).
		Str("approved_by", approver).
		Msg("Sponsored access approved")

	return guestCode, nil
}

// ListPendingApprovals returns all codes pending approval
func (gm *GuestManager) ListPendingApprovals() []*GuestCode {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	pending := make([]*GuestCode, 0)
	for _, code := range gm.codes {
		if code.Status == GuestStatusPending {
			pending = append(pending, code)
		}
	}

	return pending
}

// ListActiveCodes returns all active guest codes
func (gm *GuestManager) ListActiveCodes() []*GuestCode {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	active := make([]*GuestCode, 0)
	for _, code := range gm.codes {
		if code.Status == GuestStatusActive && time.Now().Before(code.ExpiresAt) {
			active = append(active, code)
		}
	}

	return active
}

// countActiveCodes counts active codes (must be called with lock held)
func (gm *GuestManager) countActiveCodes() int {
	count := 0
	now := time.Now()
	for _, code := range gm.codes {
		if code.Status == GuestStatusActive && now.Before(code.ExpiresAt) {
			count++
		}
	}
	return count
}

// cleanupExpired periodically removes expired codes
func (gm *GuestManager) cleanupExpired() {
	ticker := time.NewTicker(gm.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		gm.mu.Lock()
		now := time.Now()
		expired := 0

		for code, guestCode := range gm.codes {
			if now.After(guestCode.ExpiresAt) && guestCode.Status != GuestStatusExpired {
				guestCode.Status = GuestStatusExpired
				expired++
			}

			// Remove very old codes (older than 30 days)
			if now.Sub(guestCode.ExpiresAt) > 30*24*time.Hour {
				delete(gm.codes, code)
			}
		}

		gm.stats.ExpiredCodes += uint64(expired)
		gm.mu.Unlock()

		if expired > 0 {
			gm.logger.Debug().
				Int("expired", expired).
				Msg("Marked guest codes as expired")
		}
	}
}

// GetStats returns guest code statistics
func (gm *GuestManager) GetStats() GuestStats {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	stats := gm.stats
	stats.ActiveCodes = gm.countActiveCodes()

	// Count pending approvals
	pendingCount := 0
	for _, code := range gm.codes {
		if code.Status == GuestStatusPending {
			pendingCount++
		}
	}
	stats.PendingApprovals = pendingCount

	return stats
}

// Helper functions

func generateRandomCode(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}

	// Use base32 encoding for readability (no ambiguous characters)
	encoded := base32.StdEncoding.EncodeToString(bytes)

	// Remove padding and take only required length
	encoded = strings.TrimRight(encoded, "=")
	if len(encoded) > length {
		encoded = encoded[:length]
	}

	return encoded, nil
}

func generateSponsorID() string {
	return fmt.Sprintf("sponsor_%d", time.Now().UnixNano())
}
