package radius

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"fmt"

	"coovachilli-go/pkg/core"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

// EAP message codes
const (
	EAPCodeRequest  = 1
	EAPCodeResponse = 2
	EAPCodeSuccess  = 3
	EAPCodeFailure  = 4
)

// EAP types
const (
	EAPTypeIdentity = 1
	EAPTypeTLS      = 13
	EAPTypeTTLS     = 21
	EAPTypePEAP     = 25
)

// EAP-TLS flags
const (
	EAPTLSFlagLength       = 0x80
	EAPTLSFlagMoreFragment = 0x40
	EAPTLSFlagStart        = 0x20
)

// EAPPacket represents an EAP packet structure
type EAPPacket struct {
	Code       uint8
	Identifier uint8
	Length     uint16
	Type       uint8
	TypeData   []byte
}

// EAPSession holds the state for an ongoing EAP authentication
type EAPSession struct {
	Session      *core.Session
	EAPType      uint8
	Identifier   uint8
	State        []byte
	TLSConn      *tls.Conn
	TLSBuffer    []byte
	PMK          []byte // Pairwise Master Key
	MSK          []byte // Master Session Key
	EMSK         []byte // Extended Master Session Key
}

// ParseEAPPacket parses an EAP packet from raw bytes
func ParseEAPPacket(data []byte) (*EAPPacket, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("EAP packet too short: %d bytes", len(data))
	}

	pkt := &EAPPacket{
		Code:       data[0],
		Identifier: data[1],
		Length:     binary.BigEndian.Uint16(data[2:4]),
	}

	if len(data) < int(pkt.Length) {
		return nil, fmt.Errorf("EAP packet length mismatch: expected %d, got %d", pkt.Length, len(data))
	}

	if pkt.Length > 4 {
		pkt.Type = data[4]
		if pkt.Length > 5 {
			pkt.TypeData = data[5:pkt.Length]
		}
	}

	return pkt, nil
}

// EncodeEAPPacket encodes an EAP packet to raw bytes
func (p *EAPPacket) Encode() []byte {
	length := 4
	if p.Type != 0 {
		length++
		length += len(p.TypeData)
	}
	p.Length = uint16(length)

	buf := make([]byte, length)
	buf[0] = p.Code
	buf[1] = p.Identifier
	binary.BigEndian.PutUint16(buf[2:4], p.Length)

	if p.Type != 0 {
		buf[4] = p.Type
		if len(p.TypeData) > 0 {
			copy(buf[5:], p.TypeData)
		}
	}

	return buf
}

// HandleEAPRequest handles an incoming EAP request for a session
func (c *Client) HandleEAPRequest(session *core.Session, eapData []byte) (*radius.Packet, error) {
	eapPkt, err := ParseEAPPacket(eapData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EAP packet: %w", err)
	}

	c.logger.Debug().
		Uint8("code", eapPkt.Code).
		Uint8("type", eapPkt.Type).
		Uint8("id", eapPkt.Identifier).
		Msg("Processing EAP packet")

	// Get or create EAP session state
	var eapSession *EAPSession
	if session.EAPSession != nil {
		eapSession = session.EAPSession.(*EAPSession)
	} else {
		eapSession = &EAPSession{
			Session:    session,
			Identifier: 0,
		}
		session.EAPSession = eapSession
	}

	switch eapPkt.Code {
	case EAPCodeRequest:
		return c.handleEAPRequestType(eapSession, eapPkt)
	case EAPCodeResponse:
		return c.handleEAPResponse(eapSession, eapPkt)
	default:
		return nil, fmt.Errorf("unsupported EAP code: %d", eapPkt.Code)
	}
}

// handleEAPRequestType handles specific EAP request types
func (c *Client) handleEAPRequestType(eapSession *EAPSession, eapPkt *EAPPacket) (*radius.Packet, error) {
	switch eapPkt.Type {
	case EAPTypeIdentity:
		return c.handleEAPIdentity(eapSession, eapPkt)
	case EAPTypeTLS:
		return c.handleEAPTLS(eapSession, eapPkt)
	case EAPTypeTTLS:
		return c.handleEAPTTLS(eapSession, eapPkt)
	case EAPTypePEAP:
		return c.handleEAPPEAP(eapSession, eapPkt)
	default:
		c.logger.Warn().Uint8("type", eapPkt.Type).Msg("Unsupported EAP type")
		return nil, fmt.Errorf("unsupported EAP type: %d", eapPkt.Type)
	}
}

// handleEAPIdentity handles EAP-Identity requests
func (c *Client) handleEAPIdentity(eapSession *EAPSession, eapPkt *EAPPacket) (*radius.Packet, error) {
	// Respond with identity
	responseData := []byte(eapSession.Session.Redir.Username)

	response := &EAPPacket{
		Code:       EAPCodeResponse,
		Identifier: eapPkt.Identifier,
		Type:       EAPTypeIdentity,
		TypeData:   responseData,
	}

	encoded := response.Encode()
	radiusResp, authenticator, err := c.SendEAPAccessRequest(eapSession.Session, encoded, eapSession.State)
	if err != nil {
		return nil, fmt.Errorf("failed to send EAP identity response: %w", err)
	}

	// Update state from RADIUS response
	if state := radiusResp.Get(rfc2865.State_Type); state != nil {
		eapSession.State = state
	}

	// Store authenticator for potential key derivation
	if len(authenticator) > 0 {
		eapSession.Session.RequestAuthenticator = authenticator
	}

	return radiusResp, nil
}

// handleEAPTLS handles EAP-TLS authentication
func (c *Client) handleEAPTLS(eapSession *EAPSession, eapPkt *EAPPacket) (*radius.Packet, error) {
	if len(eapPkt.TypeData) < 1 {
		return nil, fmt.Errorf("EAP-TLS packet too short")
	}

	flags := eapPkt.TypeData[0]
	eapSession.EAPType = EAPTypeTLS

	c.logger.Debug().
		Uint8("flags", flags).
		Bool("start", (flags&EAPTLSFlagStart) != 0).
		Bool("more", (flags&EAPTLSFlagMoreFragment) != 0).
		Bool("length", (flags&EAPTLSFlagLength) != 0).
		Msg("EAP-TLS flags")

	// Handle TLS handshake start
	if (flags & EAPTLSFlagStart) != 0 {
		return c.startEAPTLSHandshake(eapSession, eapPkt)
	}

	// Continue TLS handshake
	return c.continueEAPTLSHandshake(eapSession, eapPkt)
}

// startEAPTLSHandshake initiates an EAP-TLS handshake
func (c *Client) startEAPTLSHandshake(eapSession *EAPSession, eapPkt *EAPPacket) (*radius.Packet, error) {
	// Initialize TLS connection state
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		// Add certificate configuration from config
	}

	if c.cfg.RadSecCertFile != "" {
		cert, err := tls.LoadX509KeyPair(c.cfg.RadSecCertFile, c.cfg.RadSecKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificates: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Generate ClientHello
	response := &EAPPacket{
		Code:       EAPCodeResponse,
		Identifier: eapPkt.Identifier,
		Type:       EAPTypeTLS,
		TypeData:   []byte{0x00}, // Flags: no special flags
	}

	// Add TLS ClientHello data (simplified)
	// In a real implementation, this would involve proper TLS handshake
	tlsData := make([]byte, 0)
	response.TypeData = append(response.TypeData, tlsData...)

	encoded := response.Encode()
	radiusResp, authenticator, err := c.SendEAPAccessRequest(eapSession.Session, encoded, eapSession.State)
	if err != nil {
		return nil, fmt.Errorf("failed to send EAP-TLS start response: %w", err)
	}

	// Update state
	if state := radiusResp.Get(rfc2865.State_Type); state != nil {
		eapSession.State = state
	}

	if len(authenticator) > 0 {
		eapSession.Session.RequestAuthenticator = authenticator
	}

	return radiusResp, nil
}

// continueEAPTLSHandshake continues an ongoing EAP-TLS handshake
func (c *Client) continueEAPTLSHandshake(eapSession *EAPSession, eapPkt *EAPPacket) (*radius.Packet, error) {
	// Parse TLS data from EAP packet
	flags := eapPkt.TypeData[0]
	offset := 1

	var tlsLength uint32
	if (flags & EAPTLSFlagLength) != 0 {
		if len(eapPkt.TypeData) < 5 {
			return nil, fmt.Errorf("EAP-TLS length flag set but no length present")
		}
		tlsLength = binary.BigEndian.Uint32(eapPkt.TypeData[1:5])
		offset = 5
		c.logger.Debug().Uint32("tls_length", tlsLength).Msg("EAP-TLS message length")
	}

	tlsData := eapPkt.TypeData[offset:]
	eapSession.TLSBuffer = append(eapSession.TLSBuffer, tlsData...)

	// If more fragments expected, send ACK
	if (flags & EAPTLSFlagMoreFragment) != 0 {
		response := &EAPPacket{
			Code:       EAPCodeResponse,
			Identifier: eapPkt.Identifier,
			Type:       EAPTypeTLS,
			TypeData:   []byte{0x00}, // ACK
		}

		encoded := response.Encode()
		radiusResp, _, err := c.SendEAPAccessRequest(eapSession.Session, encoded, eapSession.State)
		return radiusResp, err
	}

	// Complete TLS handshake processing
	// In a full implementation, this would process the TLS messages
	response := &EAPPacket{
		Code:       EAPCodeResponse,
		Identifier: eapPkt.Identifier,
		Type:       EAPTypeTLS,
		TypeData:   []byte{0x00},
	}

	encoded := response.Encode()
	radiusResp, authenticator, err := c.SendEAPAccessRequest(eapSession.Session, encoded, eapSession.State)
	if err != nil {
		return nil, err
	}

	// Extract keys if authentication succeeded
	if radiusResp.Code == radius.CodeAccessAccept {
		if err := c.extractEAPKeys(eapSession, radiusResp, authenticator); err != nil {
			c.logger.Warn().Err(err).Msg("Failed to extract EAP keys")
		}
	}

	return radiusResp, nil
}

// handleEAPTTLS handles EAP-TTLS authentication
func (c *Client) handleEAPTTLS(eapSession *EAPSession, eapPkt *EAPPacket) (*radius.Packet, error) {
	eapSession.EAPType = EAPTypeTTLS

	// EAP-TTLS is similar to EAP-TLS but allows tunneling other authentication methods
	// For now, delegate to TLS handling with TTLS-specific modifications
	c.logger.Debug().Msg("Processing EAP-TTLS request")

	return c.handleEAPTLS(eapSession, eapPkt)
}

// handleEAPPEAP handles PEAP authentication
func (c *Client) handleEAPPEAP(eapSession *EAPSession, eapPkt *EAPPacket) (*radius.Packet, error) {
	eapSession.EAPType = EAPTypePEAP

	c.logger.Debug().Msg("Processing PEAP request")

	// PEAP is also TLS-based, similar to TTLS
	return c.handleEAPTLS(eapSession, eapPkt)
}

// handleEAPResponse handles EAP response packets
func (c *Client) handleEAPResponse(eapSession *EAPSession, eapPkt *EAPPacket) (*radius.Packet, error) {
	// Forward the response to RADIUS server
	encoded := eapPkt.Encode()
	radiusResp, authenticator, err := c.SendEAPAccessRequest(eapSession.Session, encoded, eapSession.State)
	if err != nil {
		return nil, err
	}

	// Update state
	if state := radiusResp.Get(rfc2865.State_Type); state != nil {
		eapSession.State = state
	}

	if len(authenticator) > 0 {
		eapSession.Session.RequestAuthenticator = authenticator
	}

	return radiusResp, nil
}

// extractEAPKeys extracts encryption keys from successful EAP authentication
func (c *Client) extractEAPKeys(eapSession *EAPSession, radiusResp *radius.Packet, authenticator []byte) error {
	// Extract MS-MPPE-Recv-Key which contains the PMK
	pmkEncrypted := GetMSMPPERecvKey(radiusResp)
	if len(pmkEncrypted) == 0 {
		return fmt.Errorf("no MS-MPPE-Recv-Key in RADIUS response")
	}

	// Decrypt the PMK using RADIUS secret and authenticator
	var pmk []byte
	err := c.cfg.RadiusSecret.Access(func(secret []byte) error {
		var decryptErr error
		pmk, decryptErr = decryptMPPEKey(pmkEncrypted, secret, authenticator)
		return decryptErr
	})
	if err != nil {
		return fmt.Errorf("failed to decrypt PMK: %w", err)
	}

	eapSession.PMK = pmk

	// Derive MSK and EMSK from PMK for different EAP types
	switch eapSession.EAPType {
	case EAPTypeTLS, EAPTypeTTLS, EAPTypePEAP:
		// For TLS-based EAP methods, the PMK is directly usable as MSK
		eapSession.MSK = pmk
		// EMSK would be derived separately in full implementation
	}

	c.logger.Info().
		Uint8("eap_type", eapSession.EAPType).
		Int("pmk_len", len(pmk)).
		Msg("Successfully extracted EAP keys")

	return nil
}

// decryptMPPEKey decrypts an MS-MPPE key attribute
func decryptMPPEKey(encrypted, secret, authenticator []byte) ([]byte, error) {
	if len(encrypted) < 2 {
		return nil, fmt.Errorf("encrypted key too short")
	}

	// MS-MPPE-Key format: Salt (2 bytes) + Encrypted data
	salt := encrypted[0:2]
	encryptedData := encrypted[2:]

	if len(encryptedData)%16 != 0 {
		return nil, fmt.Errorf("encrypted data length not multiple of 16")
	}

	// First hash: MD5(secret + authenticator + salt)
	hash := md5.New()
	hash.Write(secret)
	hash.Write(authenticator)
	hash.Write(salt)
	b := hash.Sum(nil)

	decrypted := make([]byte, len(encryptedData))

	// XOR first block
	for i := 0; i < 16 && i < len(encryptedData); i++ {
		decrypted[i] = encryptedData[i] ^ b[i]
	}

	// Process remaining blocks
	for offset := 16; offset < len(encryptedData); offset += 16 {
		hash.Reset()
		hash.Write(secret)
		hash.Write(encryptedData[offset-16 : offset])
		b = hash.Sum(nil)

		for i := 0; i < 16 && offset+i < len(encryptedData); i++ {
			decrypted[offset+i] = encryptedData[offset+i] ^ b[i]
		}
	}

	// First byte is the key length
	if len(decrypted) == 0 {
		return nil, fmt.Errorf("decrypted data is empty")
	}

	keyLen := int(decrypted[0])
	if keyLen > len(decrypted)-1 {
		return nil, fmt.Errorf("invalid key length: %d", keyLen)
	}

	return decrypted[1 : keyLen+1], nil
}

// PRF generates pseudorandom data for key derivation (simplified)
func PRF(secret, label, seed []byte, length int) []byte {
	// Simplified PRF using SHA1 (TLS PRF)
	result := make([]byte, 0, length)
	a := append(label, seed...)

	for len(result) < length {
		h := sha1.New()
		h.Write(secret)
		h.Write(a)
		result = append(result, h.Sum(nil)...)

		h.Reset()
		h.Write(secret)
		h.Write(a)
		a = h.Sum(nil)
	}

	return result[:length]
}

// GenerateChallenge generates a random challenge for EAP
func GenerateChallenge(length int) ([]byte, error) {
	challenge := make([]byte, length)
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random challenge: %w", err)
	}
	return challenge, nil
}
