package security

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
)

// IntrusionType represents the type of detected intrusion
type IntrusionType string

const (
	IntrusionPortScan      IntrusionType = "port_scan"
	IntrusionBruteForce    IntrusionType = "brute_force"
	IntrusionDDoS          IntrusionType = "ddos"
	IntrusionSQLInjection  IntrusionType = "sql_injection"
	IntrusionXSS           IntrusionType = "xss"
	IntrusionAnomalous     IntrusionType = "anomalous_traffic"
	IntrusionRecon         IntrusionType = "reconnaissance"
)

// IntrusionEvent represents a detected intrusion attempt
type IntrusionEvent struct {
	Type        IntrusionType
	SourceIP    net.IP
	DestIP      net.IP
	DestPort    uint16
	Protocol    string
	Timestamp   time.Time
	Severity    string // low, medium, high, critical
	Description string
	Count       int // Number of times this event occurred
}

// IDS (Intrusion Detection System) monitors network traffic for suspicious activity
type IDS struct {
	cfg              *config.IDSConfig
	logger           zerolog.Logger
	mu               sync.RWMutex

	// Tracking maps
	portScans        map[string]*PortScanTracker
	failedAuths      map[string]*AuthTracker
	connectionRates  map[string]*RateTracker
	anomalies        []IntrusionEvent

	// Statistics
	stats            IDSStats

	// Callbacks
	eventCallback    func(IntrusionEvent)
}

// IDSStats tracks IDS statistics
type IDSStats struct {
	TotalEvents       uint64
	PortScans         uint64
	BruteForceAttempts uint64
	DDoSAttempts      uint64
	BlockedIPs        map[string]time.Time
}

// PortScanTracker tracks port scanning attempts
type PortScanTracker struct {
	PortsScanned map[uint16]time.Time
	FirstSeen    time.Time
	LastSeen     time.Time
}

// AuthTracker tracks authentication attempts
type AuthTracker struct {
	Failures  int
	FirstSeen time.Time
	LastSeen  time.Time
}

// RateTracker tracks connection rates
type RateTracker struct {
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
}

// NewIDS creates a new Intrusion Detection System
func NewIDS(cfg *config.IDSConfig, logger zerolog.Logger) (*IDS, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	ids := &IDS{
		cfg:             cfg,
		logger:          logger.With().Str("component", "ids").Logger(),
		portScans:       make(map[string]*PortScanTracker),
		failedAuths:     make(map[string]*AuthTracker),
		connectionRates: make(map[string]*RateTracker),
		anomalies:       make([]IntrusionEvent, 0),
		stats: IDSStats{
			BlockedIPs: make(map[string]time.Time),
		},
	}

	// Start cleanup goroutine
	go ids.cleanup()

	ids.logger.Info().Msg("Intrusion Detection System initialized")
	return ids, nil
}

// SetEventCallback sets a callback function for intrusion events
func (ids *IDS) SetEventCallback(callback func(IntrusionEvent)) {
	ids.eventCallback = callback
}

// CheckConnection analyzes a network connection for suspicious activity
func (ids *IDS) CheckConnection(srcIP net.IP, dstIP net.IP, dstPort uint16, protocol string) *IntrusionEvent {
	if !ids.cfg.Enabled {
		return nil
	}

	srcKey := srcIP.String()

	ids.mu.Lock()
	defer ids.mu.Unlock()

	// Check connection rate (potential DDoS)
	if ids.cfg.DetectDDoS {
		if event := ids.checkDDoS(srcKey, srcIP); event != nil {
			ids.stats.TotalEvents++
			ids.stats.DDoSAttempts++
			if ids.eventCallback != nil {
				go ids.eventCallback(*event)
			}
			return event
		}
	}

	// Check port scanning
	if ids.cfg.DetectPortScan {
		if event := ids.checkPortScan(srcKey, srcIP, dstPort); event != nil {
			ids.stats.TotalEvents++
			ids.stats.PortScans++
			if ids.eventCallback != nil {
				go ids.eventCallback(*event)
			}
			return event
		}
	}

	return nil
}

// CheckAuthFailure tracks failed authentication attempts
func (ids *IDS) CheckAuthFailure(srcIP net.IP, username string) *IntrusionEvent {
	if !ids.cfg.Enabled || !ids.cfg.DetectBruteForce {
		return nil
	}

	srcKey := srcIP.String()

	ids.mu.Lock()
	defer ids.mu.Unlock()

	tracker, exists := ids.failedAuths[srcKey]
	if !exists {
		tracker = &AuthTracker{
			FirstSeen: time.Now(),
		}
		ids.failedAuths[srcKey] = tracker
	}

	tracker.Failures++
	tracker.LastSeen = time.Now()

	// Check if threshold exceeded
	if tracker.Failures >= ids.cfg.BruteForceThreshold {
		event := &IntrusionEvent{
			Type:        IntrusionBruteForce,
			SourceIP:    srcIP,
			Timestamp:   time.Now(),
			Severity:    "high",
			Description: fmt.Sprintf("Brute force attack detected: %d failed auth attempts", tracker.Failures),
			Count:       tracker.Failures,
		}

		ids.stats.TotalEvents++
		ids.stats.BruteForceAttempts++

		// Reset counter
		delete(ids.failedAuths, srcKey)

		if ids.eventCallback != nil {
			go ids.eventCallback(*event)
		}

		return event
	}

	return nil
}

// checkPortScan detects port scanning activity
func (ids *IDS) checkPortScan(srcKey string, srcIP net.IP, dstPort uint16) *IntrusionEvent {
	tracker, exists := ids.portScans[srcKey]
	if !exists {
		tracker = &PortScanTracker{
			PortsScanned: make(map[uint16]time.Time),
			FirstSeen:    time.Now(),
		}
		ids.portScans[srcKey] = tracker
	}

	tracker.PortsScanned[dstPort] = time.Now()
	tracker.LastSeen = time.Now()

	// Check if scanning multiple ports in short time
	if len(tracker.PortsScanned) >= ids.cfg.PortScanThreshold {
		event := &IntrusionEvent{
			Type:        IntrusionPortScan,
			SourceIP:    srcIP,
			DestPort:    dstPort,
			Timestamp:   time.Now(),
			Severity:    "medium",
			Description: fmt.Sprintf("Port scan detected: %d ports scanned", len(tracker.PortsScanned)),
			Count:       len(tracker.PortsScanned),
		}

		// Reset tracker
		delete(ids.portScans, srcKey)

		return event
	}

	return nil
}

// checkDDoS detects potential DDoS attacks
func (ids *IDS) checkDDoS(srcKey string, srcIP net.IP) *IntrusionEvent {
	tracker, exists := ids.connectionRates[srcKey]
	if !exists {
		tracker = &RateTracker{
			FirstSeen: time.Now(),
		}
		ids.connectionRates[srcKey] = tracker
	}

	tracker.Count++
	tracker.LastSeen = time.Now()

	// Check connection rate within time window
	duration := time.Since(tracker.FirstSeen)
	if duration <= time.Duration(ids.cfg.DDoSTimeWindow)*time.Second {
		if tracker.Count >= ids.cfg.DDoSThreshold {
			event := &IntrusionEvent{
				Type:        IntrusionDDoS,
				SourceIP:    srcIP,
				Timestamp:   time.Now(),
				Severity:    "critical",
				Description: fmt.Sprintf("DDoS attack detected: %d connections in %v", tracker.Count, duration),
				Count:       tracker.Count,
			}

			// Reset tracker
			delete(ids.connectionRates, srcKey)

			return event
		}
	}

	return nil
}

// CheckHTTPRequest analyzes HTTP requests for web attacks
func (ids *IDS) CheckHTTPRequest(srcIP net.IP, method, path, query string) *IntrusionEvent {
	if !ids.cfg.Enabled {
		return nil
	}

	ids.mu.Lock()
	defer ids.mu.Unlock()

	// SQL Injection detection
	if ids.cfg.DetectSQLInjection {
		if ids.detectSQLInjection(query) || ids.detectSQLInjection(path) {
			event := &IntrusionEvent{
				Type:        IntrusionSQLInjection,
				SourceIP:    srcIP,
				Timestamp:   time.Now(),
				Severity:    "critical",
				Description: fmt.Sprintf("SQL injection attempt in %s request to %s", method, path),
			}

			ids.stats.TotalEvents++

			if ids.eventCallback != nil {
				go ids.eventCallback(*event)
			}

			return event
		}
	}

	// XSS detection
	if ids.cfg.DetectXSS {
		if ids.detectXSS(query) || ids.detectXSS(path) {
			event := &IntrusionEvent{
				Type:        IntrusionXSS,
				SourceIP:    srcIP,
				Timestamp:   time.Now(),
				Severity:    "high",
				Description: fmt.Sprintf("XSS attempt in %s request to %s", method, path),
			}

			ids.stats.TotalEvents++

			if ids.eventCallback != nil {
				go ids.eventCallback(*event)
			}

			return event
		}
	}

	return nil
}

// SQL Injection detection patterns (OWASP-based)
var sqlInjectionRegexes = []*regexp.Regexp{
	// UNION-based injection
	regexp.MustCompile(`(?i)\bunion\s+(all\s+)?(select|distinct)`),
	// Boolean-based blind
	regexp.MustCompile(`(?i)(\bor\b|\band\b)\s+[\w'"]+\s*[=<>!]+\s*[\w'"]+`),
	// Time-based blind
	regexp.MustCompile(`(?i)\b(sleep|benchmark|waitfor|pg_sleep)\s*\(`),
	// Stacked queries
	regexp.MustCompile(`;\s*(drop|delete|update|insert|create|alter)\s+`),
	// Comment-based
	regexp.MustCompile(`(--[\s\r\n]|#|/\*.*?\*/)`),
	// String concatenation
	regexp.MustCompile(`(?i)\b(concat|group_concat|char)\s*\(`),
	// Hex/Binary encoding
	regexp.MustCompile(`\b0x[0-9a-fA-F]+\b`),
	// Conditional responses
	regexp.MustCompile(`(?i)\b(case|when|then|else|end)\b.*\b(case|when|then|else|end)\b`),
	// Database fingerprinting
	regexp.MustCompile(`(?i)\b(version|database|user|schema)\s*\(`),
	// Information schema
	regexp.MustCompile(`(?i)\binformation_schema\b`),
}

// detectSQLInjection checks for SQL injection patterns with robust detection
func (ids *IDS) detectSQLInjection(input string) bool {
	// 1. Decode URL encoding (handle double-encoding)
	decoded := input
	for i := 0; i < 3; i++ {
		temp, err := url.QueryUnescape(decoded)
		if err != nil {
			break
		}
		if temp == decoded {
			break // No more decoding needed
		}
		decoded = temp
	}

	// 2. Remove SQL comments
	normalized := removeSQLComments(decoded)

	// 3. Test regex patterns
	for _, regex := range sqlInjectionRegexes {
		if regex.MatchString(normalized) {
			ids.logger.Warn().
				Str("original", input).
				Str("decoded", decoded).
				Str("pattern", regex.String()).
				Msg("SQL injection pattern detected")
			return true
		}
	}

	// 4. Statistical analysis (too many suspicious characters)
	score := calculateSQLSuspicionScore(normalized)
	if score > 5 {
		ids.logger.Warn().
			Str("input", input).
			Int("suspicion_score", score).
			Msg("High SQL injection suspicion score")
		return true
	}

	return false
}

// removeSQLComments removes SQL comments from input
func removeSQLComments(input string) string {
	// Remove /* ... */
	commentRegex := regexp.MustCompile(`/\*.*?\*/`)
	result := commentRegex.ReplaceAllString(input, "")

	// Remove -- comments
	lines := strings.Split(result, "\n")
	var cleaned []string
	for _, line := range lines {
		if idx := strings.Index(line, "--"); idx != -1 {
			line = line[:idx]
		}
		cleaned = append(cleaned, line)
	}

	return strings.Join(cleaned, "\n")
}

// calculateSQLSuspicionScore calculates a suspicion score based on character frequency
func calculateSQLSuspicionScore(input string) int {
	score := 0

	// Count suspicious characters
	for _, ch := range input {
		switch ch {
		case '\'', '"':
			score += 2
		case ';', '-':
			score += 1
		case '(', ')':
			score += 1
		}
	}

	// Penalty for multiple spaces
	if strings.Contains(input, "  ") {
		score++
	}

	// Check for multiple SQL keywords
	keywords := []string{"select", "union", "insert", "update", "delete", "drop", "exec"}
	lower := strings.ToLower(input)
	keywordCount := 0
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			keywordCount++
		}
	}
	score += keywordCount * 2

	return score
}

// XSS detection patterns
var xssRegexes = []*regexp.Regexp{
	// Script tags (various encodings)
	regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`),
	regexp.MustCompile(`(?i)<script[^>]*>`),
	// Event handlers
	regexp.MustCompile(`(?i)\bon\w+\s*=`),
	// JavaScript protocol
	regexp.MustCompile(`(?i)javascript\s*:`),
	// Data protocol with base64
	regexp.MustCompile(`(?i)data:.*base64`),
	// Dangerous tags
	regexp.MustCompile(`(?i)<(iframe|object|embed|applet|meta|link|style)[^>]*>`),
	// eval, alert, etc.
	regexp.MustCompile(`(?i)\b(eval|alert|confirm|prompt|expression)\s*\(`),
	// String.fromCharCode
	regexp.MustCompile(`(?i)String\.fromCharCode`),
	// document.cookie, window.location
	regexp.MustCompile(`(?i)(document\.|window\.)(cookie|location|write)`),
}

// detectXSS checks for XSS attack patterns with improved detection
func (ids *IDS) detectXSS(input string) bool {
	// Decode URL encoding
	decoded := input
	for i := 0; i < 3; i++ {
		temp, err := url.QueryUnescape(decoded)
		if err != nil {
			break
		}
		if temp == decoded {
			break
		}
		decoded = temp
	}

	// Decode HTML entities
	decoded = decodeHTMLEntities(decoded)

	// Test patterns
	for _, regex := range xssRegexes {
		if regex.MatchString(decoded) {
			ids.logger.Warn().
				Str("original", input).
				Str("decoded", decoded).
				Str("pattern", regex.String()).
				Msg("XSS pattern detected")
			return true
		}
	}

	return false
}

// decodeHTMLEntities decodes common HTML entities
func decodeHTMLEntities(input string) string {
	replacements := map[string]string{
		"&lt;":   "<",
		"&gt;":   ">",
		"&quot;": "\"",
		"&#x27;": "'",
		"&#x2F;": "/",
		"&amp;":  "&",
	}

	result := input
	for entity, char := range replacements {
		result = strings.ReplaceAll(result, entity, char)
	}

	return result
}

// BlockIP marks an IP as blocked
func (ids *IDS) BlockIP(ip net.IP, duration time.Duration) {
	ids.mu.Lock()
	defer ids.mu.Unlock()

	ids.stats.BlockedIPs[ip.String()] = time.Now().Add(duration)
	ids.logger.Info().Str("ip", ip.String()).Dur("duration", duration).Msg("IP blocked by IDS")
}

// IsBlocked checks if an IP is currently blocked
func (ids *IDS) IsBlocked(ip net.IP) bool {
	ids.mu.RLock()
	defer ids.mu.RUnlock()

	if blockExpiry, blocked := ids.stats.BlockedIPs[ip.String()]; blocked {
		if time.Now().Before(blockExpiry) {
			return true
		}
		// Block expired, remove it
		delete(ids.stats.BlockedIPs, ip.String())
	}

	return false
}

// GetStats returns current IDS statistics
func (ids *IDS) GetStats() IDSStats {
	ids.mu.RLock()
	defer ids.mu.RUnlock()
	return ids.stats
}

// GetRecentEvents returns recent intrusion events
func (ids *IDS) GetRecentEvents(limit int) []IntrusionEvent {
	ids.mu.RLock()
	defer ids.mu.RUnlock()

	if limit > len(ids.anomalies) {
		limit = len(ids.anomalies)
	}

	return ids.anomalies[len(ids.anomalies)-limit:]
}

// cleanup periodically removes old tracking data
func (ids *IDS) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ids.mu.Lock()

		now := time.Now()
		cleanupAge := 10 * time.Minute

		// Clean port scan trackers
		for key, tracker := range ids.portScans {
			if now.Sub(tracker.LastSeen) > cleanupAge {
				delete(ids.portScans, key)
			}
		}

		// Clean auth trackers
		for key, tracker := range ids.failedAuths {
			if now.Sub(tracker.LastSeen) > cleanupAge {
				delete(ids.failedAuths, key)
			}
		}

		// Clean rate trackers
		for key, tracker := range ids.connectionRates {
			if now.Sub(tracker.LastSeen) > cleanupAge {
				delete(ids.connectionRates, key)
			}
		}

		// Clean blocked IPs
		for ip, expiry := range ids.stats.BlockedIPs {
			if now.After(expiry) {
				delete(ids.stats.BlockedIPs, ip)
			}
		}

		// Keep only last 1000 anomaly events
		if len(ids.anomalies) > 1000 {
			ids.anomalies = ids.anomalies[len(ids.anomalies)-1000:]
		}

		ids.mu.Unlock()
	}
}

// Helper functions
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		result[i] = c
	}
	return string(result)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && indexOfString(s, substr) >= 0
}

func indexOfString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
