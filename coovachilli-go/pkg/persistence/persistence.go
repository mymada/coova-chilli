package persistence

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"coovachilli-go/pkg/core"
	"github.com/rs/zerolog"
)

// SaveSessions marshals the session map to JSON and writes it to the specified file.
// It uses a mutex to prevent concurrent writes to the session map during serialization.
func SaveSessions(sessions map[string]*core.Session, sessionMutex *sync.RWMutex, path string, logger zerolog.Logger) error {
	logger.Info().Str("path", path).Int("count", len(sessions)).Msg("Saving active sessions to disk")

	// We need a deep copy of the sessions to avoid locking the session manager
	// for the duration of the potentially slow disk I/O.
	sessionMutex.RLock()
	sessionsCopy := make(map[string]*core.Session, len(sessions))
	for k, v := range sessions {
		// Note: This is a shallow copy of the session pointer.
		// For JSON marshaling this is okay, but if the session struct contained
		// non-exportable fields or complex types requiring deep copy, this would need adjustment.
		sessionsCopy[k] = v
	}
	sessionMutex.RUnlock()

	if len(sessionsCopy) == 0 {
		logger.Info().Msg("No active sessions to save.")
		// Ensure an empty file is written to signify no sessions, rather than leaving a stale file.
		return os.WriteFile(path, []byte("[]"), 0640)
	}

	data, err := json.MarshalIndent(sessionsCopy, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sessions to JSON: %w", err)
	}

	// Write to a temporary file first to ensure atomicity
	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0640); err != nil {
		return fmt.Errorf("failed to write to temporary session file: %w", err)
	}

	// Rename the temporary file to the final destination
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("failed to rename temporary session file: %w", err)
	}

	logger.Info().Str("path", path).Msg("Successfully saved sessions.")
	return nil
}

// LoadSessions reads the session file from disk and unmarshals it into a session map.
func LoadSessions(path string, logger zerolog.Logger) (map[string]*core.Session, error) {
	logger.Info().Str("path", path).Msg("Attempting to load sessions from disk")

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Info().Str("path", path).Msg("Session file does not exist, starting with no sessions.")
			return make(map[string]*core.Session), nil
		}
		return nil, fmt.Errorf("failed to read session file: %w", err)
	}

	if len(data) == 0 || string(data) == "[]" {
		logger.Info().Msg("Session file is empty, starting with no sessions.")
		return make(map[string]*core.Session), nil
	}

	var sessions map[string]*core.Session
	if err := json.Unmarshal(data, &sessions); err != nil {
		logger.Error().Err(err).Str("path", path).Msg("Failed to unmarshal session data. Starting with empty session list.")
		// Return an empty map instead of an error to allow the application to start fresh
		// even if the session file is corrupted.
		return make(map[string]*core.Session), nil
	}

	logger.Info().Int("count", len(sessions)).Msg("Successfully loaded sessions from disk.")
	return sessions, nil
}