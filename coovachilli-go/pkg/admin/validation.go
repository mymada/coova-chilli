package admin

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode"
)

// Input validation helpers to prevent injection attacks and malformed data

var (
	// Safe patterns for common inputs
	usernameRegex  = regexp.MustCompile(`^[a-zA-Z0-9_\-\.@]{1,64}$`)
	domainRegex    = regexp.MustCompile(`^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	idRegex        = regexp.MustCompile(`^[a-zA-Z0-9_\-]{1,128}$`)
	nameRegex      = regexp.MustCompile(`^[a-zA-Z0-9_\-\. ]{1,128}$`)
	descRegex      = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\, \n]{0,512}$`)
)

// ValidateUsername validates a username for security and format
func ValidateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	if len(username) > 64 {
		return fmt.Errorf("username exceeds maximum length of 64 characters")
	}

	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("username contains invalid characters (allowed: a-z, A-Z, 0-9, _, -, ., @)")
	}

	// Prevent common injection patterns
	lower := strings.ToLower(username)
	if strings.Contains(lower, "script") || strings.Contains(lower, "union") ||
	   strings.Contains(lower, "select") || strings.Contains(lower, "drop") {
		return fmt.Errorf("username contains forbidden patterns")
	}

	return nil
}

// ValidateDomain validates a domain name pattern (supports wildcards)
func ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}

	if len(domain) > 253 {
		return fmt.Errorf("domain exceeds maximum length of 253 characters")
	}

	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("domain has invalid format")
	}

	// Check each label length
	labels := strings.Split(strings.TrimPrefix(domain, "*."), ".")
	for _, label := range labels {
		if len(label) > 63 {
			return fmt.Errorf("domain label exceeds 63 characters")
		}
	}

	return nil
}

// ValidateIP validates an IP address (v4 or v6)
func ValidateIP(ipStr string) error {
	if ipStr == "" {
		return fmt.Errorf("IP address cannot be empty")
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address format")
	}

	return nil
}

// ValidateCIDR validates a CIDR notation (e.g., 192.168.1.0/24)
func ValidateCIDR(cidr string) error {
	if cidr == "" {
		return fmt.Errorf("CIDR cannot be empty")
	}

	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR notation: %w", err)
	}

	return nil
}

// ValidateIPOrCIDR validates either an IP address or CIDR
func ValidateIPOrCIDR(str string) error {
	if strings.Contains(str, "/") {
		return ValidateCIDR(str)
	}
	return ValidateIP(str)
}

// ValidateID validates an identifier (policy ID, group ID, etc.)
func ValidateID(id string) error {
	if id == "" {
		return fmt.Errorf("ID cannot be empty")
	}

	if len(id) > 128 {
		return fmt.Errorf("ID exceeds maximum length of 128 characters")
	}

	if !idRegex.MatchString(id) {
		return fmt.Errorf("ID contains invalid characters (allowed: a-z, A-Z, 0-9, _, -)")
	}

	return nil
}

// ValidateName validates a human-readable name
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("name cannot be empty")
	}

	if len(name) > 128 {
		return fmt.Errorf("name exceeds maximum length of 128 characters")
	}

	if !nameRegex.MatchString(name) {
		return fmt.Errorf("name contains invalid characters")
	}

	// Check for control characters
	for _, r := range name {
		if unicode.IsControl(r) && r != '\n' {
			return fmt.Errorf("name contains control characters")
		}
	}

	return nil
}

// ValidateDescription validates a description field
func ValidateDescription(desc string) error {
	if len(desc) > 512 {
		return fmt.Errorf("description exceeds maximum length of 512 characters")
	}

	if !descRegex.MatchString(desc) {
		return fmt.Errorf("description contains invalid characters")
	}

	// Check for control characters (except newline)
	for _, r := range desc {
		if unicode.IsControl(r) && r != '\n' {
			return fmt.Errorf("description contains control characters")
		}
	}

	return nil
}

// ValidatePriority validates a priority value
func ValidatePriority(priority int) error {
	if priority < 0 || priority > 1000 {
		return fmt.Errorf("priority must be between 0 and 1000")
	}
	return nil
}

// ValidatePort validates a port number
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

// ValidateBandwidth validates bandwidth limit (bytes/sec)
func ValidateBandwidth(bw uint64) error {
	// Max 100 Gbps = 12,500,000,000 bytes/sec
	if bw > 12500000000 {
		return fmt.Errorf("bandwidth exceeds maximum of 100 Gbps")
	}
	return nil
}

// SanitizeString removes potentially dangerous characters from strings
func SanitizeString(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Remove control characters except newline and tab
	var result strings.Builder
	for _, r := range input {
		if !unicode.IsControl(r) || r == '\n' || r == '\t' {
			result.WriteRune(r)
		}
	}

	return strings.TrimSpace(result.String())
}

// ValidateSessionID validates a session identifier
func ValidateSessionID(id string) error {
	if id == "" {
		return fmt.Errorf("session ID cannot be empty")
	}

	// Session IDs can be MAC addresses or IPs
	if err := ValidateIP(id); err != nil {
		// Try as MAC address
		if _, err := net.ParseMAC(id); err != nil {
			return fmt.Errorf("invalid session ID format (must be IP or MAC address)")
		}
	}

	return nil
}

// ValidateSnapshotName validates a snapshot name
func ValidateSnapshotName(name string) error {
	if name == "" {
		// Empty name is allowed, will be auto-generated
		return nil
	}

	return ValidateName(name)
}
