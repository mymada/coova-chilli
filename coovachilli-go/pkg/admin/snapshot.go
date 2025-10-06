package admin

import (
	"coovachilli-go/pkg/config"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"gopkg.in/yaml.v2"
)

// Snapshot represents a configuration snapshot
type Snapshot struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	CreatedAt   time.Time              `json:"created_at"`
	Config      map[string]interface{} `json:"config"`
	Checksum    string                 `json:"checksum"` // Deprecated, kept for backward compat
	Signature   string                 `json:"signature"` // HMAC-SHA256 signature
}

// SnapshotManager handles configuration snapshots
type SnapshotManager struct {
	mu            sync.RWMutex
	snapshots     map[string]*Snapshot
	snapshotDir   string
	currentConfig *config.Config
	hmacKey       []byte // HMAC key for snapshot integrity
}

// NewSnapshotManager creates a new snapshot manager
func NewSnapshotManager(snapshotDir string, cfg *config.Config) (*SnapshotManager, error) {
	if err := os.MkdirAll(snapshotDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create snapshot directory: %w", err)
	}

	sm := &SnapshotManager{
		snapshots:     make(map[string]*Snapshot),
		snapshotDir:   snapshotDir,
		currentConfig: cfg,
	}

	// Load or generate HMAC key
	if err := sm.loadOrGenerateHMACKey(); err != nil {
		return nil, fmt.Errorf("failed to load HMAC key: %w", err)
	}

	// Load existing snapshots
	if err := sm.loadSnapshots(); err != nil {
		return nil, fmt.Errorf("failed to load snapshots: %w", err)
	}

	return sm, nil
}

// loadOrGenerateHMACKey loads existing HMAC key or generates a new one
func (sm *SnapshotManager) loadOrGenerateHMACKey() error {
	keyPath := filepath.Join(sm.snapshotDir, ".hmac_key")

	// Try to load existing key
	if data, err := ioutil.ReadFile(keyPath); err == nil {
		sm.hmacKey = data
		return nil
	}

	// Generate new key (32 bytes = 256 bits)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate HMAC key: %w", err)
	}

	// Save key with restrictive permissions
	if err := ioutil.WriteFile(keyPath, key, 0600); err != nil {
		return fmt.Errorf("failed to save HMAC key: %w", err)
	}

	sm.hmacKey = key
	return nil
}

// loadSnapshots loads all snapshots from disk
func (sm *SnapshotManager) loadSnapshots() error {
	files, err := ioutil.ReadDir(sm.snapshotDir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			snapshotPath := filepath.Join(sm.snapshotDir, file.Name())
			data, err := ioutil.ReadFile(snapshotPath)
			if err != nil {
				continue
			}

			var snapshot Snapshot
			if err := json.Unmarshal(data, &snapshot); err != nil {
				continue
			}

			sm.snapshots[snapshot.ID] = &snapshot
		}
	}

	return nil
}

// CreateSnapshot creates a new configuration snapshot
func (sm *SnapshotManager) CreateSnapshot(name, description string) (*Snapshot, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Serialize current config to map
	configData, err := sm.serializeConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize config: %w", err)
	}

	// Calculate checksum (deprecated, kept for compatibility)
	checksum := sm.calculateChecksum(configData)

	// Calculate HMAC signature for integrity
	signature := sm.calculateSignature(configData)

	// Create snapshot
	snapshot := &Snapshot{
		ID:          generateSnapshotID(),
		Name:        name,
		Description: description,
		CreatedAt:   time.Now(),
		Config:      configData,
		Checksum:    checksum,
		Signature:   signature,
	}

	// Save to disk
	if err := sm.saveSnapshot(snapshot); err != nil {
		return nil, fmt.Errorf("failed to save snapshot: %w", err)
	}

	sm.snapshots[snapshot.ID] = snapshot
	return snapshot, nil
}

// GetSnapshot retrieves a snapshot by ID
func (sm *SnapshotManager) GetSnapshot(id string) (*Snapshot, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	snapshot, exists := sm.snapshots[id]
	if !exists {
		return nil, fmt.Errorf("snapshot not found: %s", id)
	}

	return snapshot, nil
}

// ListSnapshots returns all snapshots sorted by creation time
func (sm *SnapshotManager) ListSnapshots() []*Snapshot {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	snapshots := make([]*Snapshot, 0, len(sm.snapshots))
	for _, snapshot := range sm.snapshots {
		snapshots = append(snapshots, snapshot)
	}

	// Sort by creation time (newest first)
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].CreatedAt.After(snapshots[j].CreatedAt)
	})

	return snapshots
}

// RestoreSnapshot restores configuration from a snapshot
func (sm *SnapshotManager) RestoreSnapshot(id string, configPath string) error {
	sm.mu.RLock()
	snapshot, exists := sm.snapshots[id]
	sm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("snapshot not found: %s", id)
	}

	// Verify HMAC signature (integrity check)
	if snapshot.Signature != "" {
		expectedSignature := sm.calculateSignature(snapshot.Config)
		if !hmac.Equal([]byte(expectedSignature), []byte(snapshot.Signature)) {
			return fmt.Errorf("snapshot signature verification failed - data may be corrupted or tampered")
		}
	} else {
		// Fallback to checksum for old snapshots (backward compatibility)
		currentChecksum := sm.calculateChecksum(snapshot.Config)
		if currentChecksum != snapshot.Checksum {
			return fmt.Errorf("snapshot checksum mismatch - data may be corrupted")
		}
	}

	// Convert to YAML
	yamlData, err := yaml.Marshal(snapshot.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config to YAML: %w", err)
	}

	// Backup current config
	backupPath := configPath + ".backup." + time.Now().Format("20060102-150405")
	if err := copyFile(configPath, backupPath); err != nil {
		return fmt.Errorf("failed to backup current config: %w", err)
	}

	// Write new config
	if err := ioutil.WriteFile(configPath, yamlData, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// DeleteSnapshot deletes a snapshot
func (sm *SnapshotManager) DeleteSnapshot(id string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.snapshots[id]; !exists {
		return fmt.Errorf("snapshot not found: %s", id)
	}

	// Delete from disk
	snapshotPath := filepath.Join(sm.snapshotDir, id+".json")
	if err := os.Remove(snapshotPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete snapshot file: %w", err)
	}

	delete(sm.snapshots, id)
	return nil
}

// serializeConfig converts config to a map for storage
func (sm *SnapshotManager) serializeConfig() (map[string]interface{}, error) {
	// Convert config struct to JSON then to map
	jsonData, err := json.Marshal(sm.currentConfig)
	if err != nil {
		return nil, err
	}

	var configMap map[string]interface{}
	if err := json.Unmarshal(jsonData, &configMap); err != nil {
		return nil, err
	}

	return configMap, nil
}

// calculateChecksum calculates SHA256 checksum of config data (deprecated)
func (sm *SnapshotManager) calculateChecksum(configData map[string]interface{}) string {
	jsonData, _ := json.Marshal(configData)
	hash := sha256.Sum256(jsonData)
	return hex.EncodeToString(hash[:])
}

// calculateSignature calculates HMAC-SHA256 signature of config data
func (sm *SnapshotManager) calculateSignature(configData map[string]interface{}) string {
	jsonData, _ := json.Marshal(configData)
	mac := hmac.New(sha256.New, sm.hmacKey)
	mac.Write(jsonData)
	return hex.EncodeToString(mac.Sum(nil))
}

// saveSnapshot saves a snapshot to disk
func (sm *SnapshotManager) saveSnapshot(snapshot *Snapshot) error {
	snapshotPath := filepath.Join(sm.snapshotDir, snapshot.ID+".json")
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(snapshotPath, data, 0644)
}

// generateSnapshotID generates a unique snapshot ID
func generateSnapshotID() string {
	return fmt.Sprintf("snapshot-%d", time.Now().Unix())
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	data, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(dst, data, 0644)
}

// No handlers here anymore, they have been moved to api.go
