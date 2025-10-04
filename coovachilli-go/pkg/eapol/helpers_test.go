package eapol

import (
	"crypto/md5"
	"fmt"
)

// rfc2548Encrypt is a helper function to create test vectors for MS-MPPE-Key decryption testing.
// It implements the encryption process described in RFC 2548, Section 2.4.3.
func rfc2548Encrypt(secret, requestAuthenticator, plainKey []byte, salt byte) ([]byte, error) {
	if len(plainKey) > 254 {
		return nil, fmt.Errorf("key too long")
	}
	// Plaintext is prepended with its length.
	plainText := append([]byte{byte(len(plainKey))}, plainKey...)
	// The first byte of plaintext is XORed with the salt.
	plainText[0] ^= salt

	// Pad plaintext to a multiple of 16 bytes for encryption.
	paddedPlaintext := make([]byte, (len(plainText)+15)&^15)
	copy(paddedPlaintext, plainText)

	encryptedKey := make([]byte, len(paddedPlaintext))

	// First chunk uses the Request-Authenticator.
	b := md5.Sum(append(secret, requestAuthenticator...))
	for i := 0; i < 16; i++ {
		encryptedKey[i] = paddedPlaintext[i] ^ b[i]
	}

	// Subsequent chunks use the previous block of ciphertext.
	for i := 16; i < len(paddedPlaintext); i += 16 {
		b = md5.Sum(append(secret, encryptedKey[i-16:i]...))
		for j := 0; j < 16; j++ {
			if i+j < len(paddedPlaintext) {
				encryptedKey[i+j] = paddedPlaintext[i+j] ^ b[j]
			}
		}
	}

	return append([]byte{salt}, encryptedKey...), nil
}
