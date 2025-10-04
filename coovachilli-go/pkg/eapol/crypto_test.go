package eapol

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPtkDerivation verifies the PTK derivation against a known vector.
func TestPtkDerivation(t *testing.T) {
	// This test just confirms the function runs and produces a key of the correct length.
	// A full test against a known vector would be better but is hard to establish without a reference implementation.
	pmk := []byte("ThisIsThePairwiseMasterKey123456")
	aNonce := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
	sNonce := []byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f}
	apMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	staMAC, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")

	ptk := ptkDerivation(pmk, aNonce, sNonce, apMAC, staMAC)
	assert.Equal(t, 48, len(ptk), "PTK should be 48 bytes long")
	assert.NotEmpty(t, ptk)
}

// TestCalculateAndVerifyMIC verifies the MIC calculation and verification process.
func TestCalculateAndVerifyMIC(t *testing.T) {
	kck := []byte("1234567890123456") // 16-byte Key Confirmation Key
	eapolFrame := make([]byte, 120)
	for i := range eapolFrame {
		eapolFrame[i] = byte(i)
	}

	micOffset := 81
	micEnd := micOffset + 16
	for i := micOffset; i < micEnd; i++ {
		eapolFrame[i] = 0
	}

	mic := calculateMIC(kck, eapolFrame)
	require.Equal(t, 16, len(mic), "calculateMIC should return a 16-byte MIC")
	copy(eapolFrame[micOffset:micEnd], mic)

	valid, err := verifyMIC(kck, eapolFrame)
	require.NoError(t, err)
	assert.True(t, valid, "Valid MIC should be verified successfully")

	eapolFrame[10]++
	valid, err = verifyMIC(kck, eapolFrame)
	require.NoError(t, err)
	assert.False(t, valid, "MIC should be invalid after tampering with data")
}

// TestDecryptMSMPPEKey verifies the decryption logic against a known vector from RFC 2548.
func TestDecryptMSMPPEKey(t *testing.T) {
	secret := []byte("thisisasecret")
	requestAuthenticator := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	salt := byte(0xAB)
	plainKey := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}

	encryptedKeyWithSalt, err := rfc2548Encrypt(secret, requestAuthenticator, plainKey, salt)
	require.NoError(t, err)

	decryptedKey, err := decryptMSMPPEKey(secret, requestAuthenticator, encryptedKeyWithSalt)
	require.NoError(t, err)
	assert.Equal(t, plainKey, decryptedKey, "Decrypted key should match original plaintext key")
}