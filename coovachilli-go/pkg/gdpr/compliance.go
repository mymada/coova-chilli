package gdpr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/argon2"
)

// DataCategory represents GDPR data categories
type DataCategory string

const (
	CategoryIdentity     DataCategory = "identity"      // Name, email, etc.
	CategoryContact      DataCategory = "contact"       // Phone, address
	CategoryTechnical    DataCategory = "technical"     // IP, MAC, session data
	CategoryUsage        DataCategory = "usage"         // Browsing history, bandwidth
	CategoryLocation     DataCategory = "location"      // GPS, network location
	CategoryFinancial    DataCategory = "financial"     // Payment info
)

// DataSubject represents a GDPR data subject (user)
type DataSubject struct {
	ID            string
	Username      string
	Email         string
	ConsentDate   time.Time
	ConsentTypes  []string
	DataRetention time.Duration
	Anonymized    bool
	DeletedAt     *time.Time
}

// PersonalData represents personal data stored
type PersonalData struct {
	SubjectID    string
	Category     DataCategory
	Data         map[string]interface{}
	CollectedAt  time.Time
	Purpose      string
	LegalBasis   string // consent, contract, legal_obligation, legitimate_interest
	RetentionEnd time.Time
	Encrypted    bool
}

// DataRequest represents a GDPR data subject request
type DataRequest struct {
	ID          string
	SubjectID   string
	Type        RequestType
	Status      RequestStatus
	RequestedAt time.Time
	CompletedAt *time.Time
	Result      interface{}
}

// RequestType represents types of GDPR requests
type RequestType string

const (
	RequestAccess      RequestType = "access"        // Right to access
	RequestRectify     RequestType = "rectify"       // Right to rectification
	RequestErase       RequestType = "erase"         // Right to erasure
	RequestRestrict    RequestType = "restrict"      // Right to restriction
	RequestPortability RequestType = "portability"   // Right to data portability
	RequestObject      RequestType = "object"        // Right to object
)

// RequestStatus represents the status of a GDPR request
type RequestStatus string

const (
	StatusPending    RequestStatus = "pending"
	StatusProcessing RequestStatus = "processing"
	StatusCompleted  RequestStatus = "completed"
	StatusRejected   RequestStatus = "rejected"
)

// GDPRManager manages GDPR compliance
type GDPRManager struct {
	cfg        *config.GDPRConfig
	logger     zerolog.Logger
	mu         sync.RWMutex

	subjects   map[string]*DataSubject
	data       map[string][]*PersonalData // subjectID -> data
	requests   map[string]*DataRequest
	auditLog   []AuditEntry

	encryptionKey []byte
	salt          []byte  // Salt for key derivation
	keyVersion    uint32  // For key rotation support
}

// AuditEntry represents a GDPR audit log entry
type AuditEntry struct {
	Timestamp time.Time
	Action    string
	SubjectID string
	Details   string
	Actor     string
}

// Argon2id parameters (OWASP recommendations 2024)
const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2KeyLen  = 32
	saltSize      = 32
)

// NewGDPRManager creates a new GDPR compliance manager
func NewGDPRManager(cfg *config.GDPRConfig, logger zerolog.Logger) (*GDPRManager, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	// Determine salt path
	saltPath := "/var/lib/coovachilli/gdpr.salt"
	if cfg.SaltPath != "" {
		saltPath = cfg.SaltPath
	}

	// Load or generate salt
	salt, err := loadOrGenerateSalt(saltPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load salt: %w", err)
	}

	// Derive encryption key using Argon2id (much stronger than SHA256)
	encKey := argon2.IDKey(
		[]byte(cfg.EncryptionKey),
		salt,
		argon2Time,
		argon2Memory,
		argon2Threads,
		argon2KeyLen,
	)

	gm := &GDPRManager{
		cfg:           cfg,
		logger:        logger.With().Str("component", "gdpr").Logger(),
		subjects:      make(map[string]*DataSubject),
		data:          make(map[string][]*PersonalData),
		requests:      make(map[string]*DataRequest),
		auditLog:      make([]AuditEntry, 0),
		encryptionKey: encKey,
		salt:          salt,
		keyVersion:    1, // Initial version
	}

	// Start background tasks
	go gm.dataRetentionWorker()

	gm.logger.Info().
		Str("salt_path", saltPath).
		Uint32("key_version", gm.keyVersion).
		Msg("GDPR compliance manager initialized with Argon2id key derivation")

	return gm, nil
}

// loadOrGenerateSalt loads an existing salt or generates a new one
func loadOrGenerateSalt(saltPath string) ([]byte, error) {
	// Try to load existing salt
	data, err := ioutil.ReadFile(saltPath)
	if err == nil && len(data) == saltSize {
		return data, nil
	}

	// Generate new salt
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(saltPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create salt directory: %w", err)
	}

	// Save salt with restricted permissions
	if err := ioutil.WriteFile(saltPath, salt, 0400); err != nil {
		return nil, fmt.Errorf("failed to save salt: %w", err)
	}

	return salt, nil
}

// RegisterSubject registers a new data subject
func (gm *GDPRManager) RegisterSubject(id, username, email string, consentTypes []string) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	subject := &DataSubject{
		ID:            id,
		Username:      username,
		Email:         email,
		ConsentDate:   time.Now(),
		ConsentTypes:  consentTypes,
		DataRetention: time.Duration(gm.cfg.DataRetentionDays) * 24 * time.Hour,
		Anonymized:    false,
	}

	gm.subjects[id] = subject
	gm.logAudit("SUBJECT_REGISTERED", id, fmt.Sprintf("User %s registered with consent: %v", username, consentTypes), "system")

	gm.logger.Info().
		Str("subject_id", id).
		Str("username", username).
		Strs("consent", consentTypes).
		Msg("Data subject registered")

	return nil
}

// StorePersonalData stores personal data with encryption if required
func (gm *GDPRManager) StorePersonalData(subjectID string, category DataCategory, data map[string]interface{}, purpose, legalBasis string) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	subject, exists := gm.subjects[subjectID]
	if !exists {
		return fmt.Errorf("subject %s not found", subjectID)
	}

	// Encrypt sensitive data
	shouldEncrypt := gm.cfg.EncryptPersonalData && (category == CategoryIdentity || category == CategoryFinancial)

	personalData := &PersonalData{
		SubjectID:    subjectID,
		Category:     category,
		Data:         data,
		CollectedAt:  time.Now(),
		Purpose:      purpose,
		LegalBasis:   legalBasis,
		RetentionEnd: time.Now().Add(subject.DataRetention),
		Encrypted:    shouldEncrypt,
	}

	if shouldEncrypt {
		encryptedData, err := gm.encryptData(data)
		if err != nil {
			return fmt.Errorf("failed to encrypt data: %w", err)
		}
		personalData.Data = map[string]interface{}{"encrypted": encryptedData}
	}

	if gm.data[subjectID] == nil {
		gm.data[subjectID] = make([]*PersonalData, 0)
	}
	gm.data[subjectID] = append(gm.data[subjectID], personalData)

	gm.logAudit("DATA_STORED", subjectID, fmt.Sprintf("Category: %s, Purpose: %s", category, purpose), "system")

	return nil
}

// RequestAccess handles GDPR right to access request
func (gm *GDPRManager) RequestAccess(subjectID string) (*DataRequest, error) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	request := &DataRequest{
		ID:          generateID(),
		SubjectID:   subjectID,
		Type:        RequestAccess,
		Status:      StatusPending,
		RequestedAt: time.Now(),
	}

	gm.requests[request.ID] = request
	gm.logAudit("ACCESS_REQUESTED", subjectID, "User requested access to personal data", subjectID)

	// Process in background
	go gm.processAccessRequest(request.ID)

	return request, nil
}

// RequestErasure handles GDPR right to erasure (right to be forgotten)
func (gm *GDPRManager) RequestErasure(subjectID string, reason string) (*DataRequest, error) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	request := &DataRequest{
		ID:          generateID(),
		SubjectID:   subjectID,
		Type:        RequestErase,
		Status:      StatusPending,
		RequestedAt: time.Now(),
	}

	gm.requests[request.ID] = request
	gm.logAudit("ERASURE_REQUESTED", subjectID, fmt.Sprintf("Reason: %s", reason), subjectID)

	// Process in background
	go gm.processErasureRequest(request.ID)

	return request, nil
}

// RequestPortability handles GDPR right to data portability
func (gm *GDPRManager) RequestPortability(subjectID string) (*DataRequest, error) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	request := &DataRequest{
		ID:          generateID(),
		SubjectID:   subjectID,
		Type:        RequestPortability,
		Status:      StatusPending,
		RequestedAt: time.Now(),
	}

	gm.requests[request.ID] = request
	gm.logAudit("PORTABILITY_REQUESTED", subjectID, "User requested data portability", subjectID)

	// Process in background
	go gm.processPortabilityRequest(request.ID)

	return request, nil
}

// processAccessRequest processes a data access request
func (gm *GDPRManager) processAccessRequest(requestID string) {
	gm.mu.Lock()
	request := gm.requests[requestID]
	request.Status = StatusProcessing
	gm.mu.Unlock()

	// Collect all personal data
	gm.mu.RLock()
	allData := make(map[DataCategory][]map[string]interface{})
	if dataList, exists := gm.data[request.SubjectID]; exists {
		for _, pd := range dataList {
			data := pd.Data
			if pd.Encrypted {
				// Decrypt data
				if encStr, ok := pd.Data["encrypted"].(string); ok {
					decrypted, err := gm.decryptData(encStr)
					if err == nil {
						data = decrypted
					}
				}
			}
			allData[pd.Category] = append(allData[pd.Category], data)
		}
	}
	gm.mu.RUnlock()

	// Update request
	gm.mu.Lock()
	request.Status = StatusCompleted
	now := time.Now()
	request.CompletedAt = &now
	request.Result = allData
	gm.logAudit("ACCESS_COMPLETED", request.SubjectID, "Data access request completed", "system")
	gm.mu.Unlock()

	gm.logger.Info().Str("request_id", requestID).Msg("Access request completed")
}

// processErasureRequest processes a data erasure request
func (gm *GDPRManager) processErasureRequest(requestID string) {
	gm.mu.Lock()
	request := gm.requests[requestID]
	request.Status = StatusProcessing

	// Anonymize or delete data based on configuration
	if gm.cfg.AnonymizeInsteadOfDelete {
		gm.anonymizeSubject(request.SubjectID)
	} else {
		delete(gm.data, request.SubjectID)
		if subject, exists := gm.subjects[request.SubjectID]; exists {
			now := time.Now()
			subject.DeletedAt = &now
		}
	}

	request.Status = StatusCompleted
	now := time.Now()
	request.CompletedAt = &now

	gm.logAudit("ERASURE_COMPLETED", request.SubjectID, "Data erasure request completed", "system")
	gm.mu.Unlock()

	gm.logger.Info().Str("request_id", requestID).Msg("Erasure request completed")
}

// processPortabilityRequest processes a data portability request
func (gm *GDPRManager) processPortabilityRequest(requestID string) {
	gm.mu.Lock()
	request := gm.requests[requestID]
	request.Status = StatusProcessing
	gm.mu.Unlock()

	// Export data in JSON format
	gm.mu.RLock()
	exportData := make(map[string]interface{})
	if subject, exists := gm.subjects[request.SubjectID]; exists {
		exportData["subject"] = subject
	}
	if dataList, exists := gm.data[request.SubjectID]; exists {
		exportData["data"] = dataList
	}
	gm.mu.RUnlock()

	jsonData, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		gm.mu.Lock()
		request.Status = StatusRejected
		gm.mu.Unlock()
		return
	}

	gm.mu.Lock()
	request.Status = StatusCompleted
	now := time.Now()
	request.CompletedAt = &now
	request.Result = string(jsonData)
	gm.logAudit("PORTABILITY_COMPLETED", request.SubjectID, "Data portability request completed", "system")
	gm.mu.Unlock()

	gm.logger.Info().Str("request_id", requestID).Msg("Portability request completed")
}

// anonymizeSubject anonymizes a data subject
func (gm *GDPRManager) anonymizeSubject(subjectID string) {
	if subject, exists := gm.subjects[subjectID]; exists {
		subject.Username = "anonymized_" + generateID()[:8]
		subject.Email = "anonymized@example.com"
		subject.Anonymized = true
	}

	// Anonymize personal data
	if dataList, exists := gm.data[subjectID]; exists {
		for _, pd := range dataList {
			pd.Data = map[string]interface{}{"anonymized": true}
		}
	}
}

// dataRetentionWorker periodically checks and deletes expired data
func (gm *GDPRManager) dataRetentionWorker() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		gm.mu.Lock()
		now := time.Now()

		for subjectID, dataList := range gm.data {
			newList := make([]*PersonalData, 0)
			for _, pd := range dataList {
				if now.After(pd.RetentionEnd) {
					gm.logger.Info().
						Str("subject_id", subjectID).
						Str("category", string(pd.Category)).
						Msg("Deleting expired personal data")
					gm.logAudit("DATA_EXPIRED", subjectID, fmt.Sprintf("Category: %s", pd.Category), "system")
				} else {
					newList = append(newList, pd)
				}
			}
			gm.data[subjectID] = newList
		}

		gm.mu.Unlock()
	}
}

// GetAuditLog returns the GDPR audit log
func (gm *GDPRManager) GetAuditLog() []AuditEntry {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	// Return a copy
	result := make([]AuditEntry, len(gm.auditLog))
	copy(result, gm.auditLog)
	return result
}

// ExportAuditLog exports audit log to file
func (gm *GDPRManager) ExportAuditLog(filename string) error {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	data, err := json.MarshalIndent(gm.auditLog, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0600)
}

// logAudit adds an entry to the audit log
func (gm *GDPRManager) logAudit(action, subjectID, details, actor string) {
	entry := AuditEntry{
		Timestamp: time.Now(),
		Action:    action,
		SubjectID: subjectID,
		Details:   details,
		Actor:     actor,
	}
	gm.auditLog = append(gm.auditLog, entry)

	// Keep only last 10000 entries
	if len(gm.auditLog) > 10000 {
		gm.auditLog = gm.auditLog[len(gm.auditLog)-10000:]
	}
}

// encryptData encrypts data using AES-256-GCM
func (gm *GDPRManager) encryptData(data map[string]interface{}) (string, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(gm.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Prepend version for key rotation support (4 bytes)
	versionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBytes, gm.keyVersion)

	// Encrypt with version as additional authenticated data
	ciphertext := gcm.Seal(nonce, nonce, jsonData, versionBytes)

	// Format: [version(4)][nonce(12)][ciphertext]
	result := append(versionBytes, ciphertext...)

	return base64.StdEncoding.EncodeToString(result), nil
}

// decryptData decrypts data encrypted with encryptData (supports key versioning)
func (gm *GDPRManager) decryptData(encryptedStr string) (map[string]interface{}, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedStr)
	if err != nil {
		return nil, err
	}

	if len(data) < 4 {
		return nil, fmt.Errorf("invalid encrypted data: too short")
	}

	// Read version (4 bytes)
	version := binary.BigEndian.Uint32(data[:4])
	ciphertext := data[4:]

	// For now, we only support current version
	// In future, we could load old keys from secure storage
	if version != gm.keyVersion {
		return nil, fmt.Errorf("unsupported key version %d (current: %d)", version, gm.keyVersion)
	}

	block, err := aes.NewCipher(gm.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Reconstruct AAD (version bytes)
	versionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBytes, version)

	plaintext, err := gcm.Open(nil, nonce, ciphertext, versionBytes)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(plaintext, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// generateID generates a unique ID
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
