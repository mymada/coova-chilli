package auth

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// LocalUser represents a user defined in the local user file.
type LocalUser struct {
	Username     string
	PasswordHash string // Now stores bcrypt hash instead of plaintext
}

// Default bcrypt cost (14 = ~500ms per hash on modern CPU)
const DefaultBcryptCost = 14

// AuthenticateLocalUser checks if the given username and password match a user in the local file.
// The file format is now: username:$2a$14$hashedpassword
// For backward compatibility, it still supports plaintext (but logs a warning)
func AuthenticateLocalUser(filePath, username, password string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue // Skip malformed lines
		}

		if parts[0] == username {
			// Check if it's a bcrypt hash (starts with $2a$, $2b$, or $2y$)
			if strings.HasPrefix(parts[1], "$2") {
				// Compare with bcrypt
				err := bcrypt.CompareHashAndPassword([]byte(parts[1]), []byte(password))
				if err == nil {
					return true, nil // Authentication successful
				}
				return false, nil // Wrong password
			} else {
				// WARNING: Plaintext password detected (backward compatibility)
				// This should be migrated to bcrypt
				if parts[1] == password {
					// Log warning about plaintext password
					fmt.Fprintf(os.Stderr, "WARNING: User %s has plaintext password. Please migrate to bcrypt!\n", username)
					return true, nil
				}
				return false, nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return false, err
	}

	return false, nil // User not found
}

// HashPassword generates a bcrypt hash for the given password.
// Use this to generate hashed passwords for the local users file.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), DefaultBcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

// ValidatePasswordStrength checks if a password meets minimum security requirements.
func ValidatePasswordStrength(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}
	if len(password) > 128 {
		return fmt.Errorf("password must not exceed 128 characters")
	}

	// Check for at least one digit, one letter
	hasDigit := false
	hasLetter := false

	for _, char := range password {
		if char >= '0' && char <= '9' {
			hasDigit = true
		}
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') {
			hasLetter = true
		}
	}

	if !hasDigit || !hasLetter {
		return fmt.Errorf("password must contain at least one letter and one digit")
	}

	return nil
}
