package fas

import (
	"net"
	"testing"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func TestGenerateAndValidateToken(t *testing.T) {
	// 1. Setup
	secret := "a-very-secure-secret-key-for-testing"
	cfg := &config.FASConfig{
		Secret:        securestore.NewSecret(secret),
		TokenValidity: 1 * time.Minute,
	}

	mac, _ := net.ParseMAC("00-de-ad-be-ef-00")
	session := &core.Session{
		SessionID: "nas01-12345",
		HisMAC:    mac,
		HisIP:     net.ParseIP("10.1.0.100"),
		Redir: core.RedirState{
			UserURL: "http://example.com/page",
		},
	}

	// 2. Generate Token
	tokenString, err := GenerateToken(session, cfg)
	require.NoError(t, err, "Token generation should not fail")
	require.NotEmpty(t, tokenString, "Generated token string should not be empty")

	// 3. Validate Token
	claims, err := ValidateToken(tokenString, cfg)
	require.NoError(t, err, "Token validation should succeed for a valid token")
	require.NotNil(t, claims, "Claims should not be nil for a valid token")

	// 4. Assert Claims
	require.Equal(t, session.SessionID, claims.NASID)
	require.Equal(t, session.HisMAC.String(), claims.ClientMAC)
	require.Equal(t, session.HisIP.String(), claims.ClientIP)
	require.Equal(t, session.Redir.UserURL, claims.OriginalURL)
	require.Equal(t, session.HisMAC.String(), claims.Subject)
	require.InDelta(t, time.Now().Add(1*time.Minute).Unix(), claims.ExpiresAt.Unix(), 2, "Expiration time should be about 1 minute from now")
}

func TestValidateToken_InvalidSignature(t *testing.T) {
	// 1. Setup two different configs/secrets
	secret1 := "this-is-the-correct-secret"
	cfg1 := &config.FASConfig{
		Secret: securestore.NewSecret(secret1),
	}

	secret2 := "this-is-the-wrong-secret"
	cfg2 := &config.FASConfig{
		Secret: securestore.NewSecret(secret2),
	}

	mac, _ := net.ParseMAC("00-de-ad-be-ef-01")
	session := &core.Session{HisMAC: mac}

	// 2. Generate token with the first secret
	tokenString, err := GenerateToken(session, cfg1)
	require.NoError(t, err)

	// 3. Validate with the second (wrong) secret
	_, err = ValidateToken(tokenString, cfg2)
	require.Error(t, err, "Token validation should fail with an invalid signature")
	require.Contains(t, err.Error(), "signature is invalid")
}

func TestValidateToken_Expired(t *testing.T) {
	// 1. Setup
	secret := "a-very-secure-secret-key-for-testing"
	cfg := &config.FASConfig{
		Secret:        securestore.NewSecret(secret),
		TokenValidity: -1 * time.Minute, // Create a token that is already expired
	}

	mac, _ := net.ParseMAC("00-de-ad-be-ef-02")
	session := &core.Session{HisMAC: mac}

	// 2. Generate an expired token
	tokenString, err := GenerateToken(session, cfg)
	require.NoError(t, err)

	// 3. Validate the expired token
	_, err = ValidateToken(tokenString, cfg)
	require.Error(t, err, "Token validation should fail for an expired token")
	require.Contains(t, err.Error(), "token is expired")
}