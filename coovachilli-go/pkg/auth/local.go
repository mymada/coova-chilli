package auth

import (
	"bufio"
	"os"
	"strings"
)

// LocalUser represents a user defined in the local user file.
type LocalUser struct {
	Username string
	Password string
}

// AuthenticateLocalUser checks if the given username and password match a user in the local file.
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

		if parts[0] == username && parts[1] == password {
			return true, nil // Authentication successful
		}
	}

	if err := scanner.Err(); err != nil {
		return false, err
	}

	return false, nil // User not found or password incorrect
}