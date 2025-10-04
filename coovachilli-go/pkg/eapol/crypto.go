package eapol

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"fmt"
)

// ptkDerivation implements the PTK derivation function as defined in IEEE 802.11i.
// It generates a 48-byte (384-bit) key for WPA2-AES.
func ptkDerivation(pmk, aNonce, sNonce, apMAC, staMAC []byte) []byte {
	label := []byte("Pairwise key expansion")
	data := make([]byte, 0, 100)
	if bytes.Compare(apMAC, staMAC) < 0 {
		data = append(data, apMAC...)
		data = append(data, staMAC...)
	} else {
		data = append(data, staMAC...)
		data = append(data, apMAC...)
	}
	if bytes.Compare(aNonce, sNonce) < 0 {
		data = append(data, aNonce...)
		data = append(data, sNonce...)
	} else {
		data = append(data, sNonce...)
		data = append(data, aNonce...)
	}
	ptk := make([]byte, 0, 64)
	var i uint8
	for i = 0; i < 4; i++ {
		h := hmac.New(sha1.New, pmk)
		h.Write(label)
		h.Write([]byte{0x00})
		h.Write(data)
		h.Write([]byte{i})
		ptk = h.Sum(ptk)
	}
	return ptk[:48]
}

// calculateMIC calculates the Message Integrity Check using HMAC-SHA1 and returns the 16-byte MIC.
func calculateMIC(kck, eapolFrame []byte) []byte {
	h := hmac.New(sha1.New, kck)
	h.Write(eapolFrame)
	return h.Sum(nil)[:16]
}

// verifyMIC verifies the MIC of an EAPOL-Key frame.
func verifyMIC(kck, eapolFrame []byte) (bool, error) {
	// EAPOL-Key frame structure:
	// EAPOL header (4 bytes) + Key Descriptor (1) + Key Info (2) + Key Length (2) +
	// Replay Counter (8) + Key Nonce (32) + Key IV (16) + Key RSC (8) + Key ID (8) +
	// Key MIC (16 @ offset 81) + Key Data Length (2) + Key Data (variable)
	micOffset := 81
	micEnd := micOffset + 16
	if len(eapolFrame) < micEnd {
		return false, fmt.Errorf("EAPOL frame too short for MIC verification: got %d, need %d", len(eapolFrame), micEnd)
	}
	receivedMIC := make([]byte, 16)
	copy(receivedMIC, eapolFrame[micOffset:micEnd])
	tempFrame := make([]byte, len(eapolFrame))
	copy(tempFrame, eapolFrame)
	// Zero out the MIC field before calculating
	copy(tempFrame[micOffset:micEnd], make([]byte, 16))
	calculatedMIC := calculateMIC(kck, tempFrame)
	return hmac.Equal(receivedMIC, calculatedMIC), nil
}

// decryptMSMPPEKey decrypts the MS-MPPE-Recv-Key from a RADIUS Access-Accept.
// It follows the procedure outlined in RFC 2548, Section 2.4.3.1.
func decryptMSMPPEKey(radiusSecret, requestAuthenticator, encryptedKeyWithSalt []byte) ([]byte, error) {
	if len(encryptedKeyWithSalt) < 2 {
		return nil, fmt.Errorf("encrypted key is too short")
	}
	salt := encryptedKeyWithSalt[0]
	encryptedKey := encryptedKeyWithSalt[1:]
	if len(encryptedKey) == 0 || len(encryptedKey)%16 != 0 {
		return nil, fmt.Errorf("encrypted key length (%d) is not a multiple of 16", len(encryptedKey))
	}
	decryptedKey := make([]byte, len(encryptedKey))
	b := md5.Sum(append(radiusSecret, requestAuthenticator...))
	for i := 0; i < 16; i++ {
		decryptedKey[i] = encryptedKey[i] ^ b[i]
	}
	for i := 16; i < len(encryptedKey); i += 16 {
		b = md5.Sum(append(radiusSecret, encryptedKey[i-16:i]...))
		for j := 0; j < 16; j++ {
			decryptedKey[i+j] = encryptedKey[i+j] ^ b[j]
		}
	}
	decryptedKey[0] ^= salt
	keyLength := int(decryptedKey[0])
	if 1+keyLength > len(decryptedKey) {
		return nil, fmt.Errorf("invalid decrypted key length: %d", keyLength)
	}
	return decryptedKey[1 : 1+keyLength], nil
}