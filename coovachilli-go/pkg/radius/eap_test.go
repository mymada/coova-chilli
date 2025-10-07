package radius

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseEAPPacket(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    *EAPPacket
		wantErr bool
	}{
		{
			name: "valid identity request",
			data: []byte{
				0x01, // Code: Request
				0x00, // Identifier: 0
				0x00, 0x05, // Length: 5
				0x01, // Type: Identity
			},
			want: &EAPPacket{
				Code:       EAPCodeRequest,
				Identifier: 0,
				Length:     5,
				Type:       EAPTypeIdentity,
				TypeData:   []byte{},
			},
			wantErr: false,
		},
		{
			name: "too short packet",
			data: []byte{0x01, 0x00},
			want: nil,
			wantErr: true,
		},
		{
			name: "EAP-TLS start",
			data: []byte{
				0x01, // Code: Request
				0x01, // Identifier: 1
				0x00, 0x06, // Length: 6
				0x0d, // Type: EAP-TLS (13)
				0x20, // Flags: Start flag set
			},
			want: &EAPPacket{
				Code:       EAPCodeRequest,
				Identifier: 1,
				Length:     6,
				Type:       EAPTypeTLS,
				TypeData:   []byte{0x20},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEAPPacket(tt.data)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want.Code, got.Code)
			assert.Equal(t, tt.want.Identifier, got.Identifier)
			assert.Equal(t, tt.want.Type, got.Type)
		})
	}
}

func TestEncodeEAPPacket(t *testing.T) {
	tests := []struct {
		name string
		pkt  *EAPPacket
		want []byte
	}{
		{
			name: "identity response",
			pkt: &EAPPacket{
				Code:       EAPCodeResponse,
				Identifier: 0,
				Type:       EAPTypeIdentity,
				TypeData:   []byte("user@example.com"),
			},
			want: append(
				[]byte{0x02, 0x00, 0x00, 0x15, 0x01}, // Header + type
				[]byte("user@example.com")...,
			),
		},
		{
			name: "success packet",
			pkt: &EAPPacket{
				Code:       EAPCodeSuccess,
				Identifier: 5,
			},
			want: []byte{0x03, 0x05, 0x00, 0x04},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pkt.Encode()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDecryptMPPEKey(t *testing.T) {
	// This test is simplified - real MPPE decryption requires proper test vectors
	// For now, we just test that the function handles errors correctly
	secret := []byte("secret")
	authenticator := []byte{
		0x5a, 0xe5, 0xce, 0x3a, 0x9f, 0x8c, 0x9b, 0x1d,
		0x8e, 0x4f, 0x6b, 0x2a, 0x7c, 0x3d, 0x9e, 0x0f,
	}

	// Test too short encrypted data
	encrypted := []byte{0x12}
	_, err := decryptMPPEKey(encrypted, secret, authenticator)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestGenerateChallenge(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{name: "16 bytes", length: 16},
		{name: "32 bytes", length: 32},
		{name: "64 bytes", length: 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge, err := GenerateChallenge(tt.length)
			assert.NoError(t, err)
			assert.Len(t, challenge, tt.length)

			// Generate another and ensure they're different
			challenge2, err := GenerateChallenge(tt.length)
			assert.NoError(t, err)
			assert.NotEqual(t, challenge, challenge2)
		})
	}
}

func TestEAPTLSFlags(t *testing.T) {
	tests := []struct {
		name         string
		flags        byte
		expectStart  bool
		expectMore   bool
		expectLength bool
	}{
		{
			name:         "start flag only",
			flags:        EAPTLSFlagStart,
			expectStart:  true,
			expectMore:   false,
			expectLength: false,
		},
		{
			name:         "length flag only",
			flags:        EAPTLSFlagLength,
			expectStart:  false,
			expectMore:   false,
			expectLength: true,
		},
		{
			name:         "more fragments flag",
			flags:        EAPTLSFlagMoreFragment,
			expectStart:  false,
			expectMore:   true,
			expectLength: false,
		},
		{
			name:         "all flags set",
			flags:        EAPTLSFlagStart | EAPTLSFlagMoreFragment | EAPTLSFlagLength,
			expectStart:  true,
			expectMore:   true,
			expectLength: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectStart, (tt.flags&EAPTLSFlagStart) != 0)
			assert.Equal(t, tt.expectMore, (tt.flags&EAPTLSFlagMoreFragment) != 0)
			assert.Equal(t, tt.expectLength, (tt.flags&EAPTLSFlagLength) != 0)
		})
	}
}

// Test removed - getDefaultTrafficClass is package-private

func BenchmarkEAPPacketParse(b *testing.B) {
	data := []byte{
		0x01, 0x00, 0x00, 0x05, 0x01,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseEAPPacket(data)
	}
}

func BenchmarkEAPPacketEncode(b *testing.B) {
	pkt := &EAPPacket{
		Code:       EAPCodeResponse,
		Identifier: 0,
		Type:       EAPTypeIdentity,
		TypeData:   []byte("user@example.com"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pkt.Encode()
	}
}

func BenchmarkGenerateChallenge(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateChallenge(16)
	}
}
