package fas

import (
	"fmt"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"github.com/golang-jwt/jwt/v4"
)

// Claims defines the JWT claims for the FAS protocol.
type Claims struct {
	NASID       string `json:"nas"`
	ClientMAC   string `json:"cli"`
	ClientIP    string `json:"cip"`
	OriginalURL string `json:"url"`
	jwt.RegisteredClaims
}

// GenerateToken creates a new signed JWT for a given user session.
func GenerateToken(session *core.Session, cfg *config.FASConfig) (string, error) {
	// Get the shared secret from the secure store
	var secret []byte
	if err := cfg.Secret.Access(func(p []byte) error {
		secret = make([]byte, len(p))
		copy(secret, p)
		return nil
	}); err != nil {
		return "", fmt.Errorf("failed to access FAS secret: %w", err)
	}

	if len(secret) == 0 {
		return "", fmt.Errorf("FAS secret is not configured")
	}

	// Define the token validity duration
	validity := cfg.TokenValidity
	if validity == 0 {
		validity = 5 * time.Minute // Default to 5 minutes if not specified
	}
	expirationTime := time.Now().Add(validity)

	// Create the JWT claims
	claims := &Claims{
		NASID:       session.SessionID, // Using SessionID as a unique identifier for the NAS context
		ClientMAC:   session.HisMAC.String(),
		ClientIP:    session.HisIP.String(),
		OriginalURL: session.Redir.UserURL,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Subject:   session.HisMAC.String(), // The user's MAC is the subject
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign FAS token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken validates a token string and returns the claims if successful.
func ValidateToken(tokenString string, cfg *config.FASConfig) (*Claims, error) {
	var secret []byte
	if err := cfg.Secret.Access(func(p []byte) error {
		secret = make([]byte, len(p))
		copy(secret, p)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to access FAS secret: %w", err)
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}