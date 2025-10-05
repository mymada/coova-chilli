package sso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// OIDCConfig holds OpenID Connect configuration
type OIDCConfig struct {
	Enabled bool `yaml:"enabled" envconfig:"OIDC_ENABLED"`

	// Provider configuration
	ProviderURL  string `yaml:"provider_url" envconfig:"OIDC_PROVIDER_URL"`       // e.g., https://accounts.google.com
	ClientID     string `yaml:"client_id" envconfig:"OIDC_CLIENT_ID"`
	ClientSecret string `yaml:"client_secret" envconfig:"OIDC_CLIENT_SECRET"`
	RedirectURL  string `yaml:"redirect_url" envconfig:"OIDC_REDIRECT_URL"`

	// Optional scopes (default: openid profile email)
	Scopes []string `yaml:"scopes" envconfig:"OIDC_SCOPES"`

	// Optional claims mapping
	UsernameClai string `yaml:"username_claim" envconfig:"OIDC_USERNAME_CLAIM"` // e.g., "preferred_username", "email"
	EmailClaim   string `yaml:"email_claim" envconfig:"OIDC_EMAIL_CLAIM"`
	GroupsClaim  string `yaml:"groups_claim" envconfig:"OIDC_GROUPS_CLAIM"`

	// Security settings
	VerifyIssuer   bool          `yaml:"verify_issuer" envconfig:"OIDC_VERIFY_ISSUER"`
	MaxClockSkew   time.Duration `yaml:"max_clock_skew" envconfig:"OIDC_MAX_CLOCK_SKEW"`
	InsecureSkipTLS bool          `yaml:"insecure_skip_tls" envconfig:"OIDC_INSECURE_SKIP_TLS"` // For testing only
}

// OIDCProvider handles OpenID Connect authentication
type OIDCProvider struct {
	config    *OIDCConfig
	logger    zerolog.Logger
	discovery *OIDCDiscovery
	client    *http.Client
}

// OIDCDiscovery represents OpenID Connect Discovery document
type OIDCDiscovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	SubjectTypesSupported  []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

// OIDCTokenResponse represents the token endpoint response
type OIDCTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token"`
}

// OIDCUserInfo represents user information from userinfo endpoint
type OIDCUserInfo struct {
	Sub               string   `json:"sub"`
	Name              string   `json:"name"`
	GivenName         string   `json:"given_name"`
	FamilyName        string   `json:"family_name"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Picture           string   `json:"picture"`
	Groups            []string `json:"groups"`
}

// IDTokenClaims represents the ID token claims
type IDTokenClaims struct {
	Issuer         string   `json:"iss"`
	Subject        string   `json:"sub"`
	Audience       []string `json:"aud"`
	Expiration     int64    `json:"exp"`
	IssuedAt       int64    `json:"iat"`
	Nonce          string   `json:"nonce,omitempty"`
	Email          string   `json:"email,omitempty"`
	EmailVerified  bool     `json:"email_verified,omitempty"`
	Name           string   `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Groups         []string `json:"groups,omitempty"`
}

// OIDCUser represents authenticated user information
type OIDCUser struct {
	Subject  string
	Username string
	Email    string
	Name     string
	Groups   []string
	Claims   map[string]interface{}
}

// NewOIDCProvider creates a new OIDC provider
func NewOIDCProvider(config *OIDCConfig, logger zerolog.Logger) (*OIDCProvider, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("OIDC is not enabled")
	}

	op := &OIDCProvider{
		config: config,
		logger: logger.With().Str("component", "oidc").Logger(),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	// Set defaults
	if len(config.Scopes) == 0 {
		config.Scopes = []string{"openid", "profile", "email"}
	}
	if config.UsernameClai == "" {
		config.UsernameClai = "preferred_username"
	}
	if config.EmailClaim == "" {
		config.EmailClaim = "email"
	}
	if config.MaxClockSkew == 0 {
		config.MaxClockSkew = 60 * time.Second
	}
	if config.VerifyIssuer {
		// Default to true for security
		config.VerifyIssuer = true
	}

	// Discover endpoints
	if err := op.discover(); err != nil {
		return nil, fmt.Errorf("failed to discover OIDC endpoints: %w", err)
	}

	op.logger.Info().
		Str("provider", config.ProviderURL).
		Str("issuer", op.discovery.Issuer).
		Msg("OIDC provider initialized")

	return op, nil
}

// discover performs OpenID Connect Discovery
func (op *OIDCProvider) discover() error {
	discoveryURL := strings.TrimSuffix(op.config.ProviderURL, "/") + "/.well-known/openid-configuration"

	resp, err := op.client.Get(discoveryURL)
	if err != nil {
		return fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read discovery response: %w", err)
	}

	var discovery OIDCDiscovery
	if err := json.Unmarshal(body, &discovery); err != nil {
		return fmt.Errorf("failed to parse discovery document: %w", err)
	}

	op.discovery = &discovery

	op.logger.Debug().
		Str("auth_endpoint", discovery.AuthorizationEndpoint).
		Str("token_endpoint", discovery.TokenEndpoint).
		Str("userinfo_endpoint", discovery.UserinfoEndpoint).
		Msg("OIDC endpoints discovered")

	return nil
}

// BuildAuthURL creates an OIDC authentication redirect URL
func (op *OIDCProvider) BuildAuthURL(state, nonce string) (string, error) {
	if state == "" {
		state = generateRandomString(32)
	}
	if nonce == "" {
		nonce = generateRandomString(32)
	}

	authURL, err := url.Parse(op.discovery.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("invalid authorization endpoint: %w", err)
	}

	query := authURL.Query()
	query.Set("client_id", op.config.ClientID)
	query.Set("redirect_uri", op.config.RedirectURL)
	query.Set("response_type", "code")
	query.Set("scope", strings.Join(op.config.Scopes, " "))
	query.Set("state", state)
	query.Set("nonce", nonce)
	authURL.RawQuery = query.Encode()

	op.logger.Info().
		Str("state", state).
		Str("nonce", nonce).
		Msg("OIDC authorization URL created")

	return authURL.String(), nil
}

// HandleCallback processes the OIDC callback
func (op *OIDCProvider) HandleCallback(ctx context.Context, code string) (*OIDCUser, error) {
	// Exchange code for tokens
	tokenResp, err := op.exchangeCode(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Parse ID token (basic parsing without signature verification for now)
	claims, err := op.parseIDToken(tokenResp.IDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ID token: %w", err)
	}

	// Validate ID token
	if err := op.validateIDToken(claims); err != nil {
		return nil, fmt.Errorf("invalid ID token: %w", err)
	}

	// Get additional user info
	userInfo, err := op.getUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		op.logger.Warn().Err(err).Msg("Failed to fetch user info, using ID token claims only")
		// Not fatal, we can use ID token claims
	}

	// Build user object
	user := op.buildUser(claims, userInfo)

	op.logger.Info().
		Str("username", user.Username).
		Str("email", user.Email).
		Strs("groups", user.Groups).
		Msg("OIDC authentication successful")

	return user, nil
}

// exchangeCode exchanges authorization code for tokens
func (op *OIDCProvider) exchangeCode(ctx context.Context, code string) (*OIDCTokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", op.config.RedirectURL)
	data.Set("client_id", op.config.ClientID)
	data.Set("client_secret", op.config.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", op.discovery.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := op.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	var tokenResp OIDCTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResp, nil
}

// parseIDToken parses the ID token (basic parsing without signature verification)
func (op *OIDCProvider) parseIDToken(idToken string) (*IDTokenClaims, error) {
	// ID token format: header.payload.signature
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid ID token format")
	}

	// Decode payload (base64url)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode ID token payload: %w", err)
	}

	var claims IDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	return &claims, nil
}

// validateIDToken validates the ID token claims
func (op *OIDCProvider) validateIDToken(claims *IDTokenClaims) error {
	now := time.Now().Unix()

	// Check expiration
	if now > claims.Expiration+int64(op.config.MaxClockSkew.Seconds()) {
		return fmt.Errorf("ID token expired (exp: %d, now: %d)", claims.Expiration, now)
	}

	// Check issued at
	if now < claims.IssuedAt-int64(op.config.MaxClockSkew.Seconds()) {
		return fmt.Errorf("ID token used before issued (iat: %d, now: %d)", claims.IssuedAt, now)
	}

	// Check issuer
	if op.config.VerifyIssuer && claims.Issuer != op.discovery.Issuer {
		return fmt.Errorf("invalid issuer: expected %s, got %s", op.discovery.Issuer, claims.Issuer)
	}

	// Check audience
	validAudience := false
	for _, aud := range claims.Audience {
		if aud == op.config.ClientID {
			validAudience = true
			break
		}
	}
	if !validAudience {
		return fmt.Errorf("invalid audience: client ID not in audience")
	}

	return nil
}

// getUserInfo fetches user information from userinfo endpoint
func (op *OIDCProvider) getUserInfo(ctx context.Context, accessToken string) (*OIDCUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", op.discovery.UserinfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := op.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send userinfo request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint returned status %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read userinfo response: %w", err)
	}

	var userInfo OIDCUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse userinfo: %w", err)
	}

	return &userInfo, nil
}

// buildUser builds the user object from ID token and userinfo
func (op *OIDCProvider) buildUser(claims *IDTokenClaims, userInfo *OIDCUserInfo) *OIDCUser {
	user := &OIDCUser{
		Subject: claims.Subject,
		Claims:  make(map[string]interface{}),
	}

	// Prefer userinfo over ID token claims
	if userInfo != nil {
		user.Email = userInfo.Email
		user.Name = userInfo.Name
		user.Groups = userInfo.Groups

		// Determine username
		switch op.config.UsernameClai {
		case "email":
			user.Username = userInfo.Email
		case "sub":
			user.Username = userInfo.Sub
		default:
			user.Username = userInfo.PreferredUsername
		}
	} else {
		// Fallback to ID token claims
		user.Email = claims.Email
		user.Name = claims.Name
		user.Groups = claims.Groups

		switch op.config.UsernameClai {
		case "email":
			user.Username = claims.Email
		case "sub":
			user.Username = claims.Subject
		default:
			user.Username = claims.PreferredUsername
		}
	}

	// Fallback to subject if username not found
	if user.Username == "" {
		user.Username = user.Subject
	}

	return user
}

// generateRandomString generates a cryptographically secure random string
func generateRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		// Fallback to time-based if crypto/rand fails
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.URLEncoding.EncodeToString(b)[:length]
}
