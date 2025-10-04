package securestore

import (
	"github.com/awnumar/memguard"
)

// Secret holds a value securely in memory.
type Secret struct {
	buffer *memguard.LockedBuffer
}

// NewSecret creates a new secret from a string.
// The original string should be cleared from memory after use.
func NewSecret(value string) (*Secret, error) {
	buf, err := memguard.NewImmutableFromBytes([]byte(value))
	if err != nil {
		return nil, err
	}
	return &Secret{buffer: buf}, nil
}

// Access securely calls a function with the plaintext value of the secret.
// The provided byte slice is only valid for the duration of the function call.
func (s *Secret) Access(f func([]byte)) error {
	if s == nil || s.buffer == nil {
		// Treat as empty secret, call function with nil slice
		f(nil)
		return nil
	}

	b, err := s.buffer.Open()
	if err != nil {
		return err
	}
	defer b.Destroy()

	f(b.Bytes())
	return nil
}

// Destroy securely wipes the secret from memory.
func (s *Secret) Destroy() {
	if s != nil && s.buffer != nil {
		s.buffer.Destroy()
	}
}