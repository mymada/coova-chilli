package securestore

import (
	"github.com/awnumar/memguard"
)

// Secret holds a value securely in an encrypted enclave.
type Secret struct {
	enclave *memguard.Enclave
}

// NewSecret creates a new secret from a string.
// The original string should be cleared from memory after use.
func NewSecret(value string) *Secret {
	if value == "" {
		return &Secret{enclave: nil}
	}
	// NewEnclave will wipe the source buffer.
	return &Secret{enclave: memguard.NewEnclave([]byte(value))}
}

// IsSet returns true if the secret has been configured with a value.
func (s *Secret) IsSet() bool {
	return s != nil && s.enclave != nil
}

// Access securely opens the enclave and calls a function with the plaintext value.
// The plaintext is held in a LockedBuffer which is destroyed after the function returns.
func (s *Secret) Access(f func(plaintext []byte) error) error {
	if s == nil || s.enclave == nil {
		// Pass nil to the function if the secret is empty/not set.
		return f(nil)
	}

	// Open the enclave to get a LockedBuffer with the plaintext.
	lockedBuffer, err := s.enclave.Open()
	if err != nil {
		return err
	}
	defer lockedBuffer.Destroy() // Ensure the plaintext buffer is destroyed.

	// Pass the bytes from the locked buffer to the function.
	return f(lockedBuffer.Bytes())
}

// EqualToConstantTime compares the secret to a given byte slice in constant time.
func (s *Secret) EqualToConstantTime(value []byte) (bool, error) {
	if s == nil || s.enclave == nil {
		return len(value) == 0, nil
	}

	lockedBuffer, err := s.enclave.Open()
	if err != nil {
		return false, err
	}
	defer lockedBuffer.Destroy()

	return lockedBuffer.EqualTo(value), nil
}