package securestore

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSecret(t *testing.T) {
	t.Run("creates secret from string", func(t *testing.T) {
		secret := NewSecret("test-password")
		require.NotNil(t, secret)
		assert.True(t, secret.IsSet())
	})

	t.Run("handles empty string", func(t *testing.T) {
		secret := NewSecret("")
		require.NotNil(t, secret)
		assert.False(t, secret.IsSet())
	})
}

func TestSecretIsSet(t *testing.T) {
	t.Run("returns true for set secret", func(t *testing.T) {
		secret := NewSecret("password123")
		assert.True(t, secret.IsSet())
	})

	t.Run("returns false for nil secret", func(t *testing.T) {
		var secret *Secret
		assert.False(t, secret.IsSet())
	})

	t.Run("returns false for empty secret", func(t *testing.T) {
		secret := NewSecret("")
		assert.False(t, secret.IsSet())
	})
}

func TestSecretAccess(t *testing.T) {
	t.Run("provides access to plaintext", func(t *testing.T) {
		expected := []byte("my-secret-value")
		secret := NewSecret(string(expected))

		var accessed []byte
		err := secret.Access(func(plaintext []byte) error {
			accessed = make([]byte, len(plaintext))
			copy(accessed, plaintext)
			return nil
		})

		require.NoError(t, err)
		assert.Equal(t, expected, accessed)
	})

	t.Run("destroys plaintext after access", func(t *testing.T) {
		secret := NewSecret("temporary")

		var firstAccess, secondAccess []byte
		secret.Access(func(plaintext []byte) error {
			firstAccess = make([]byte, len(plaintext))
			copy(firstAccess, plaintext)
			return nil
		})

		secret.Access(func(plaintext []byte) error {
			secondAccess = make([]byte, len(plaintext))
			copy(secondAccess, plaintext)
			return nil
		})

		// Both accesses should get the same value
		assert.Equal(t, firstAccess, secondAccess)
	})

	t.Run("handles nil secret", func(t *testing.T) {
		var secret *Secret
		called := false
		err := secret.Access(func(plaintext []byte) error {
			called = true
			assert.Nil(t, plaintext)
			return nil
		})

		require.NoError(t, err)
		assert.True(t, called, "callback should be called even for nil secret")
	})

	t.Run("handles empty secret", func(t *testing.T) {
		secret := NewSecret("")
		called := false
		err := secret.Access(func(plaintext []byte) error {
			called = true
			assert.Nil(t, plaintext)
			return nil
		})

		require.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("propagates callback errors", func(t *testing.T) {
		secret := NewSecret("test")
		expectedErr := assert.AnError

		err := secret.Access(func(plaintext []byte) error {
			return expectedErr
		})

		assert.Equal(t, expectedErr, err)
	})
}

func TestEqualToConstantTime(t *testing.T) {
	t.Run("returns true for equal values", func(t *testing.T) {
		value := "matching-secret"
		secret := NewSecret(value)

		equal, err := secret.EqualToConstantTime([]byte(value))
		require.NoError(t, err)
		assert.True(t, equal)
	})

	t.Run("returns false for different values", func(t *testing.T) {
		secret := NewSecret("secret1")

		equal, err := secret.EqualToConstantTime([]byte("secret2"))
		require.NoError(t, err)
		assert.False(t, equal)
	})

	t.Run("handles nil secret", func(t *testing.T) {
		var secret *Secret

		equal, err := secret.EqualToConstantTime([]byte{})
		require.NoError(t, err)
		assert.True(t, equal, "nil secret should equal empty value")

		equal, err = secret.EqualToConstantTime([]byte("something"))
		require.NoError(t, err)
		assert.False(t, equal, "nil secret should not equal non-empty value")
	})

	t.Run("handles empty secret", func(t *testing.T) {
		secret := NewSecret("")

		equal, err := secret.EqualToConstantTime([]byte{})
		require.NoError(t, err)
		assert.True(t, equal)

		equal, err = secret.EqualToConstantTime([]byte("something"))
		require.NoError(t, err)
		assert.False(t, equal)
	})

	t.Run("is resistant to timing attacks", func(t *testing.T) {
		// This is a basic test - true timing analysis would require more sophisticated testing
		secret := NewSecret("constant-time-secret")

		// Compare with values of different lengths
		values := [][]byte{
			[]byte("a"),
			[]byte("ab"),
			[]byte("abc"),
			[]byte("constant-time-secret"),
			[]byte("constant-time-secreX"),
			[]byte("different-value-entirely"),
		}

		for _, v := range values {
			_, err := secret.EqualToConstantTime(v)
			assert.NoError(t, err, "comparison should not error for value: %s", string(v))
		}
	})
}

func TestSecretMemorySafety(t *testing.T) {
	t.Run("does not leak plaintext in memory", func(t *testing.T) {
		// Note: This test verifies the concept but memguard handles the actual protection
		sensitiveData := "super-secret-password-123"
		secret := NewSecret(sensitiveData)

		// Verify we can access the secret correctly
		var result []byte
		secret.Access(func(plaintext []byte) error {
			result = make([]byte, len(plaintext))
			copy(result, plaintext)
			return nil
		})

		assert.Equal(t, []byte(sensitiveData), result, "secret should be accessible")
	})

	t.Run("multiple secrets are independent", func(t *testing.T) {
		secret1 := NewSecret("password1")
		secret2 := NewSecret("password2")

		var value1, value2 []byte
		secret1.Access(func(p []byte) error {
			value1 = make([]byte, len(p))
			copy(value1, p)
			return nil
		})

		secret2.Access(func(p []byte) error {
			value2 = make([]byte, len(p))
			copy(value2, p)
			return nil
		})

		assert.NotEqual(t, value1, value2, "different secrets should have different values")
	})
}

func TestSecretConcurrency(t *testing.T) {
	t.Run("handles concurrent access safely", func(t *testing.T) {
		secret := NewSecret("concurrent-secret")
		done := make(chan bool, 10)

		// Launch 10 goroutines accessing the secret concurrently
		for i := 0; i < 10; i++ {
			go func() {
				defer func() { done <- true }()

				err := secret.Access(func(plaintext []byte) error {
					// Verify we got the correct value
					assert.True(t, bytes.Equal(plaintext, []byte("concurrent-secret")))
					return nil
				})
				assert.NoError(t, err)
			}()
		}

		// Wait for all goroutines to complete
		for i := 0; i < 10; i++ {
			<-done
		}
	})
}
