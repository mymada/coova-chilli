package logexport

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileExporter(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "log_export_*.jsonl")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	exporter, err := NewFileExporter(tmpFile.Name(), zerolog.Nop())
	require.NoError(t, err)
	defer exporter.Close()

	event := LogEvent{
		Timestamp: time.Now(),
		Level:     "info",
		Component: "test",
		Event:     "user_login",
		Message:   "User logged in",
		Username:  "testuser",
		IP:        "192.0.2.1",
	}

	err = exporter.Export(event)
	require.NoError(t, err)

	// Read back and verify
	data, err := os.ReadFile(tmpFile.Name())
	require.NoError(t, err)

	var readEvent LogEvent
	err = json.Unmarshal(data, &readEvent)
	require.NoError(t, err)

	assert.Equal(t, event.Level, readEvent.Level)
	assert.Equal(t, event.Component, readEvent.Component)
	assert.Equal(t, event.Event, readEvent.Event)
	assert.Equal(t, event.Message, readEvent.Message)
	assert.Equal(t, event.Username, readEvent.Username)
	assert.Equal(t, event.IP, readEvent.IP)
}

func TestManager(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "log_export_*.jsonl")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	cfg := &config.LogExportConfig{
		Enabled:   true,
		Exporters: []string{"file"},
		FilePath:  tmpFile.Name(),
	}

	manager, err := NewManager(cfg, zerolog.Nop())
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	event := LogEvent{
		Timestamp: time.Now(),
		Level:     "warn",
		Component: "auth",
		Event:     "auth_failed",
		Message:   "Authentication failed",
		Username:  "baduser",
		IP:        "203.0.113.5",
	}

	manager.Export(event)

	// Give it time to process
	time.Sleep(100 * time.Millisecond)

	// Verify file content
	data, err := os.ReadFile(tmpFile.Name())
	require.NoError(t, err)
	assert.Contains(t, string(data), "auth_failed")
	assert.Contains(t, string(data), "baduser")
}

func TestLogEventWriter(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "log_export_*.jsonl")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	cfg := &config.LogExportConfig{
		Enabled:   true,
		Exporters: []string{"file"},
		FilePath:  tmpFile.Name(),
	}

	manager, err := NewManager(cfg, zerolog.Nop())
	require.NoError(t, err)
	defer manager.Close()

	writer := NewLogEventWriter(manager)

	// Simulate zerolog output
	logJSON := `{"level":"info","component":"dhcp","message":"DHCP lease granted","user":"testuser","ip":"10.0.0.5"}`
	n, err := writer.Write([]byte(logJSON))
	require.NoError(t, err)
	assert.Equal(t, len(logJSON), n)

	// Give it time to process
	time.Sleep(100 * time.Millisecond)

	// Verify file content
	data, err := os.ReadFile(tmpFile.Name())
	require.NoError(t, err)
	assert.Contains(t, string(data), "DHCP lease granted")
	assert.Contains(t, string(data), "testuser")
}

func TestManagerDisabled(t *testing.T) {
	cfg := &config.LogExportConfig{
		Enabled: false,
	}

	manager, err := NewManager(cfg, zerolog.Nop())
	require.NoError(t, err)
	assert.Nil(t, manager)
}
