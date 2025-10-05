package logexport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
)

// LogEvent represents a structured log event to be exported
type LogEvent struct {
	Timestamp  time.Time              `json:"timestamp"`
	Level      string                 `json:"level"`
	Component  string                 `json:"component"`
	Event      string                 `json:"event"`
	Message    string                 `json:"message"`
	SessionID  string                 `json:"session_id,omitempty"`
	Username   string                 `json:"username,omitempty"`
	IP         string                 `json:"ip,omitempty"`
	MAC        string                 `json:"mac,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// Exporter is the interface that all log exporters must implement
type Exporter interface {
	Export(event LogEvent) error
	Close() error
}

// Manager manages multiple log exporters
type Manager struct {
	cfg       *config.LogExportConfig
	logger    zerolog.Logger
	exporters []Exporter
	eventChan chan LogEvent
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewManager creates a new log export manager
func NewManager(cfg *config.LogExportConfig, logger zerolog.Logger) (*Manager, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		cfg:       cfg,
		logger:    logger.With().Str("component", "logexport").Logger(),
		exporters: make([]Exporter, 0),
		eventChan: make(chan LogEvent, 1000), // Buffer 1000 events
		ctx:       ctx,
		cancel:    cancel,
	}

	// Initialize configured exporters
	for _, exporterType := range cfg.Exporters {
		var exporter Exporter
		var err error

		switch exporterType {
		case "syslog":
			exporter, err = NewSyslogExporter(cfg.SyslogAddr, cfg.SyslogProto, logger)
		case "file":
			exporter, err = NewFileExporter(cfg.FilePath, logger)
		case "elasticsearch":
			exporter, err = NewElasticsearchExporter(cfg.ESEndpoint, cfg.ESIndex, logger)
		case "s3":
			// S3 exporter would require AWS SDK
			m.logger.Warn().Str("type", exporterType).Msg("S3 exporter not yet implemented")
			continue
		default:
			m.logger.Warn().Str("type", exporterType).Msg("Unknown exporter type")
			continue
		}

		if err != nil {
			m.logger.Error().Err(err).Str("type", exporterType).Msg("Failed to create exporter")
			continue
		}

		m.exporters = append(m.exporters, exporter)
		m.logger.Info().Str("type", exporterType).Msg("Initialized log exporter")
	}

	if len(m.exporters) == 0 {
		m.logger.Warn().Msg("No log exporters configured")
		return m, nil
	}

	// Start export worker
	m.wg.Add(1)
	go m.exportWorker()

	return m, nil
}

// exportWorker processes log events from the channel
func (m *Manager) exportWorker() {
	defer m.wg.Done()

	for {
		select {
		case event := <-m.eventChan:
			for _, exporter := range m.exporters {
				if err := exporter.Export(event); err != nil {
					m.logger.Error().Err(err).Msg("Failed to export log event")
				}
			}
		case <-m.ctx.Done():
			m.logger.Info().Msg("Log export worker stopping")
			return
		}
	}
}

// Export queues a log event for export
func (m *Manager) Export(event LogEvent) {
	if !m.cfg.Enabled || len(m.exporters) == 0 {
		return
	}

	select {
	case m.eventChan <- event:
	default:
		m.logger.Warn().Msg("Log export queue full, dropping event")
	}
}

// Close stops the manager and closes all exporters
func (m *Manager) Close() error {
	if m == nil {
		return nil
	}

	m.cancel()
	m.wg.Wait()

	var lastErr error
	for _, exporter := range m.exporters {
		if err := exporter.Close(); err != nil {
			m.logger.Error().Err(err).Msg("Error closing exporter")
			lastErr = err
		}
	}

	close(m.eventChan)
	return lastErr
}

// SyslogExporter exports logs to a syslog server
type SyslogExporter struct {
	conn   net.Conn
	logger zerolog.Logger
	mu     sync.Mutex
}

// NewSyslogExporter creates a new syslog exporter
func NewSyslogExporter(addr, proto string, logger zerolog.Logger) (*SyslogExporter, error) {
	if addr == "" {
		return nil, fmt.Errorf("syslog address is required")
	}

	if proto == "" {
		proto = "udp"
	}

	conn, err := net.Dial(proto, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to syslog: %w", err)
	}

	return &SyslogExporter{
		conn:   conn,
		logger: logger,
	}, nil
}

// Export sends a log event to syslog
func (e *SyslogExporter) Export(event LogEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Format as RFC3164 syslog message
	priority := 134 // local0.info
	hostname, _ := os.Hostname()
	timestamp := event.Timestamp.Format("Jan 02 15:04:05")

	message := fmt.Sprintf("<%d>%s %s coovachilli[%s]: %s",
		priority, timestamp, hostname, event.Component, event.Message)

	if event.SessionID != "" {
		message += fmt.Sprintf(" session=%s", event.SessionID)
	}
	if event.Username != "" {
		message += fmt.Sprintf(" user=%s", event.Username)
	}

	message += "\n"

	_, err := e.conn.Write([]byte(message))
	return err
}

// Close closes the syslog connection
func (e *SyslogExporter) Close() error {
	return e.conn.Close()
}

// FileExporter exports logs to a file
type FileExporter struct {
	file   *os.File
	logger zerolog.Logger
	mu     sync.Mutex
}

// NewFileExporter creates a new file exporter
func NewFileExporter(path string, logger zerolog.Logger) (*FileExporter, error) {
	if path == "" {
		return nil, fmt.Errorf("file path is required")
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	return &FileExporter{
		file:   file,
		logger: logger,
	}, nil
}

// Export writes a log event to file as JSON
func (e *FileExporter) Export(event LogEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal log event: %w", err)
	}

	_, err = e.file.Write(append(data, '\n'))
	return err
}

// Close closes the log file
func (e *FileExporter) Close() error {
	return e.file.Close()
}

// ElasticsearchExporter exports logs to Elasticsearch
type ElasticsearchExporter struct {
	endpoint string
	index    string
	logger   zerolog.Logger
	client   interface{} // Would be *elasticsearch.Client in real implementation
}

// NewElasticsearchExporter creates a new Elasticsearch exporter
func NewElasticsearchExporter(endpoint, index string, logger zerolog.Logger) (*ElasticsearchExporter, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("elasticsearch endpoint is required")
	}

	if index == "" {
		index = "coovachilli-logs"
	}

	// In a real implementation, initialize Elasticsearch client here
	return &ElasticsearchExporter{
		endpoint: endpoint,
		index:    index,
		logger:   logger,
	}, nil
}

// Export sends a log event to Elasticsearch
func (e *ElasticsearchExporter) Export(event LogEvent) error {
	// This is a stub - real implementation would use Elasticsearch Go client
	e.logger.Debug().
		Str("index", e.index).
		Str("event", event.Event).
		Msg("Would export to Elasticsearch")
	return nil
}

// Close closes the Elasticsearch client
func (e *ElasticsearchExporter) Close() error {
	return nil
}

// LogEventWriter is an io.Writer that converts zerolog output to LogEvents
type LogEventWriter struct {
	manager *Manager
}

// NewLogEventWriter creates a writer that exports zerolog events
func NewLogEventWriter(manager *Manager) io.Writer {
	return &LogEventWriter{manager: manager}
}

// Write implements io.Writer for zerolog integration
func (w *LogEventWriter) Write(p []byte) (n int, err error) {
	if w.manager == nil || !w.manager.cfg.Enabled {
		return len(p), nil
	}

	var logData map[string]interface{}
	if err := json.Unmarshal(p, &logData); err != nil {
		return len(p), nil // Ignore parse errors
	}

	event := LogEvent{
		Timestamp:  time.Now(),
		Attributes: make(map[string]interface{}),
	}

	// Extract common fields
	if level, ok := logData["level"].(string); ok {
		event.Level = level
	}
	if component, ok := logData["component"].(string); ok {
		event.Component = component
	}
	if msg, ok := logData["message"].(string); ok {
		event.Message = msg
	}
	if evt, ok := logData["event"].(string); ok {
		event.Event = evt
	}
	if sid, ok := logData["session_id"].(string); ok {
		event.SessionID = sid
	}
	if user, ok := logData["user"].(string); ok {
		event.Username = user
	}
	if ip, ok := logData["ip"].(string); ok {
		event.IP = ip
	}
	if mac, ok := logData["mac"].(string); ok {
		event.MAC = mac
	}

	// Store remaining fields as attributes
	for k, v := range logData {
		if k != "level" && k != "component" && k != "message" && k != "event" &&
			k != "session_id" && k != "user" && k != "ip" && k != "mac" {
			event.Attributes[k] = v
		}
	}

	w.manager.Export(event)
	return len(p), nil
}
