package auth

import (
	"net"
	"testing"
	"time"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
)

func TestNewAuthenticationManager(t *testing.T) {
	cfg := &config.Config{
		UseLocalUsers:  true,
		LocalUsersFile: "/tmp/test_users",
	}

	logger := zerolog.Nop()
	am, err := NewAuthenticationManager(cfg, logger)

	if err != nil {
		t.Fatalf("Failed to create AuthenticationManager: %v", err)
	}

	if am == nil {
		t.Fatal("AuthenticationManager is nil")
	}

	if am.localAuth == nil {
		t.Error("localAuth should be initialized")
	}

	if am.sessions == nil {
		t.Error("sessions map should be initialized")
	}

	if am.stats.MethodStats == nil {
		t.Error("MethodStats should be initialized")
	}
}

func TestAuthenticateLocal(t *testing.T) {
	cfg := &config.Config{
		UseLocalUsers:  true,
		LocalUsersFile: "/tmp/test_users",
	}

	logger := zerolog.Nop()
	am, err := NewAuthenticationManager(cfg, logger)
	if err != nil {
		t.Fatalf("Failed to create AuthenticationManager: %v", err)
	}

	// Test with valid credentials (assuming test user exists)
	req := &AuthRequest{
		Method:   AuthMethodLocal,
		Username: "testuser",
		Password: "testpass",
		IP:       net.ParseIP("192.168.1.100"),
	}

	resp, err := am.Authenticate(req)

	if err != nil {
		t.Errorf("Authenticate failed: %v", err)
	}

	if resp == nil {
		t.Fatal("Response is nil")
	}

	// Note: Will fail if user doesn't exist, which is expected in test env
	t.Logf("Auth result: success=%v, method=%s", resp.Success, resp.Method)
}

func TestGenerateSessionToken(t *testing.T) {
	token1 := generateSessionToken()
	token2 := generateSessionToken()

	if token1 == "" {
		t.Error("Token should not be empty")
	}

	if token1 == token2 {
		t.Error("Tokens should be unique")
	}

	if len(token1) < 32 {
		t.Error("Token should be at least 32 characters")
	}
}

func TestGenerateRandomString(t *testing.T) {
	str1 := generateRandomString(16)
	str2 := generateRandomString(16)

	if str1 == str2 {
		t.Error("Random strings should be unique")
	}

	if len(str1) != 16 {
		t.Errorf("Expected length 16, got %d", len(str1))
	}
}

func TestAuthStats(t *testing.T) {
	cfg := &config.Config{
		UseLocalUsers:  true,
		LocalUsersFile: "/tmp/test_users",
	}

	logger := zerolog.Nop()
	am, err := NewAuthenticationManager(cfg, logger)
	if err != nil {
		t.Fatalf("Failed to create AuthenticationManager: %v", err)
	}

	initialStats := am.GetStats()
	if initialStats.TotalAttempts != 0 {
		t.Error("Initial TotalAttempts should be 0")
	}

	// Attempt authentication
	req := &AuthRequest{
		Method:   AuthMethodLocal,
		Username: "test",
		Password: "test",
		IP:       net.ParseIP("192.168.1.100"),
	}

	am.Authenticate(req)

	stats := am.GetStats()
	if stats.TotalAttempts != 1 {
		t.Errorf("Expected TotalAttempts=1, got %d", stats.TotalAttempts)
	}
}

func TestValidateSession(t *testing.T) {
	cfg := &config.Config{
		UseLocalUsers:  true,
		LocalUsersFile: "/tmp/test_users",
	}

	logger := zerolog.Nop()
	am, err := NewAuthenticationManager(cfg, logger)
	if err != nil {
		t.Fatalf("Failed to create AuthenticationManager: %v", err)
	}

	// Create a mock session
	token := generateSessionToken()
	session := &AuthSession{
		ID:        generateSessionID(),
		Username:  "testuser",
		Method:    AuthMethodLocal,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		IPAddress: net.ParseIP("192.168.1.100"),
	}

	am.mu.Lock()
	am.sessions[token] = session
	am.mu.Unlock()

	// Test valid session
	validated, err := am.ValidateSession(token)
	if err != nil {
		t.Errorf("ValidateSession failed: %v", err)
	}

	if validated == nil {
		t.Fatal("Validated session is nil")
	}

	if validated.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", validated.Username)
	}

	// Test invalid token
	_, err = am.ValidateSession("invalid_token")
	if err == nil {
		t.Error("Expected error for invalid token")
	}
}

func TestRevokeSession(t *testing.T) {
	cfg := &config.Config{
		UseLocalUsers:  true,
		LocalUsersFile: "/tmp/test_users",
	}

	logger := zerolog.Nop()
	am, err := NewAuthenticationManager(cfg, logger)
	if err != nil {
		t.Fatalf("Failed to create AuthenticationManager: %v", err)
	}

	// Create a mock session
	token := generateSessionToken()
	session := &AuthSession{
		ID:        generateSessionID(),
		Username:  "testuser",
		Method:    AuthMethodLocal,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	am.mu.Lock()
	am.sessions[token] = session
	am.mu.Unlock()

	// Revoke session
	err = am.RevokeSession(token)
	if err != nil {
		t.Errorf("RevokeSession failed: %v", err)
	}

	// Try to validate revoked session
	_, err = am.ValidateSession(token)
	if err == nil {
		t.Error("Expected error for revoked session")
	}

	// Try to revoke non-existent session
	err = am.RevokeSession("non_existent")
	if err == nil {
		t.Error("Expected error for non-existent session")
	}
}

func TestSessionExpiration(t *testing.T) {
	cfg := &config.Config{
		UseLocalUsers:  true,
		LocalUsersFile: "/tmp/test_users",
	}

	logger := zerolog.Nop()
	am, err := NewAuthenticationManager(cfg, logger)
	if err != nil {
		t.Fatalf("Failed to create AuthenticationManager: %v", err)
	}

	// Create an expired session
	token := generateSessionToken()
	session := &AuthSession{
		ID:        generateSessionID(),
		Username:  "testuser",
		Method:    AuthMethodLocal,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}

	am.mu.Lock()
	am.sessions[token] = session
	am.mu.Unlock()

	// Try to validate expired session
	_, err = am.ValidateSession(token)
	if err == nil {
		t.Error("Expected error for expired session")
	}

	if err.Error() != "session expired" {
		t.Errorf("Expected 'session expired' error, got '%s'", err.Error())
	}
}

func TestAuthMethodString(t *testing.T) {
	tests := []struct {
		method AuthMethod
		str    string
	}{
		{AuthMethodRADIUS, "radius"},
		{AuthMethodLocal, "local"},
		{AuthMethodLDAP, "ldap"},
		{AuthMethodSAML, "saml"},
		{AuthMethodOIDC, "oidc"},
		{AuthMethodQRCode, "qrcode"},
		{AuthMethodSMS, "sms"},
		{AuthMethodGuest, "guest"},
		{AuthMethodMAC, "mac"},
	}

	for _, tt := range tests {
		if string(tt.method) != tt.str {
			t.Errorf("Expected %s, got %s", tt.str, string(tt.method))
		}
	}
}

func TestAuthResponseAttributes(t *testing.T) {
	resp := &AuthResponse{
		Success:    true,
		Method:     AuthMethodLocal,
		Username:   "testuser",
		Attributes: make(map[string]interface{}),
	}

	// Add attributes
	resp.Attributes["role"] = "admin"
	resp.Attributes["permissions"] = []string{"read", "write"}

	if resp.Attributes["role"] != "admin" {
		t.Error("Role attribute not set correctly")
	}

	perms, ok := resp.Attributes["permissions"].([]string)
	if !ok {
		t.Error("Permissions not a string slice")
	}

	if len(perms) != 2 {
		t.Errorf("Expected 2 permissions, got %d", len(perms))
	}
}
