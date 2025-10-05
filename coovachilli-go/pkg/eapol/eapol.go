package eapol

import (
	"bytes"
	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/radius"
	"crypto/rand"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rs/zerolog"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

const EAPOLTypeKey layers.EAPOLType = 3

type EAPOLSender interface {
	SendEAPOL(dstMAC net.HardwareAddr, eapolPayload []byte) error
}

type Handler struct {
	cfg          *config.Config
	sm           *core.SessionManager
	radiusClient radius.EAPOLAuthenticator
	sender       EAPOLSender
	logger       zerolog.Logger
	ifaceMAC     net.HardwareAddr
}

type pcapSender struct {
	handle   *pcap.Handle
	ifaceMAC net.HardwareAddr
}

func (s *pcapSender) SendEAPOL(dstMAC net.HardwareAddr, eapolPayload []byte) error {
	ethLayer := &layers.Ethernet{
		SrcMAC:       s.ifaceMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeEAPOL,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ethLayer, gopacket.Payload(eapolPayload)); err != nil {
		return fmt.Errorf("failed to serialize EAPOL response: %w", err)
	}
	return s.handle.WritePacketData(buf.Bytes())
}

func NewHandler(cfg *config.Config, sm *core.SessionManager, rc radius.EAPOLAuthenticator, handle *pcap.Handle, iface net.Interface, logger zerolog.Logger) *Handler {
	sender := &pcapSender{handle: handle, ifaceMAC: iface.HardwareAddr}
	return &Handler{
		cfg:          cfg,
		sm:           sm,
		radiusClient: rc,
		sender:       sender,
		logger:       logger.With().Str("component", "eapol").Logger(),
		ifaceMAC:     iface.HardwareAddr,
	}
}

func (h *Handler) HandlePacket(packet gopacket.Packet) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}
	eth, _ := ethLayer.(*layers.Ethernet)

	eapolLayer := packet.Layer(layers.LayerTypeEAPOL)
	if eapolLayer == nil {
		return
	}
	eapol, _ := eapolLayer.(*layers.EAPOL)

	session, ok := h.sm.GetSessionByMAC(eth.SrcMAC)
	if !ok {
		session = h.sm.CreateSession(nil, eth.SrcMAC, 0)
	}

	switch eapol.Type {
	case layers.EAPOLTypeStart:
		h.logger.Debug().Str("mac", eth.SrcMAC.String()).Msg("Received EAPOL-Start")
		h.sendEAPRequestIdentity(session)
	case layers.EAPOLTypeEAP:
		h.handleEAP(session, packet)
	case EAPOLTypeKey:
		h.logger.Debug().Str("mac", eth.SrcMAC.String()).Msg("Received EAPOL-Key")
		keyLayer := packet.Layer(layers.LayerTypeEAPOLKey)
		if keyLayer != nil {
			key, _ := keyLayer.(*layers.EAPOLKey)
			// Serialize the EAPOL and Key layers to get the full frame for MIC verification
			eapolMsg := eapolLayer.(*layers.EAPOL)
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{FixLengths: true}
			err := gopacket.SerializeLayers(buf, opts, eapolMsg, key)
			if err != nil {
				h.logger.Error().Err(err).Msg("Failed to serialize EAPOL frame for MIC verification")
				return
			}
			fullFrame := buf.Bytes()
			h.handleEAPOLKey(session, eth.SrcMAC, key, fullFrame)
		} else {
			h.logger.Warn().Msg("EAPOL-Key layer not found in packet")
		}
	}
}

func (h *Handler) sendEAPRequestIdentity(session *core.Session) {
	session.Lock()
	session.EAPOL.EapID++
	currentID := session.EAPOL.EapID
	session.Unlock()

	eapReq := &layers.EAP{
		Code:     layers.EAPCodeRequest,
		Id:       currentID,
		Type:     layers.EAPTypeIdentity,
		TypeData: []byte{}, // Empty for Identity request
	}
	h.sendEAP(session.HisMAC, eapReq)
}

func (h *Handler) handleEAP(session *core.Session, packet gopacket.Packet) {
	eapLayer := packet.Layer(layers.LayerTypeEAP)
	if eapLayer == nil {
		return
	}
	eap, _ := eapLayer.(*layers.EAP)
	eapPayload := eapLayer.LayerContents()

	session.Lock()
	session.EAPOL.EapID = eap.Id
	if eap.Type == layers.EAPTypeIdentity {
		username := string(bytes.TrimRight(eap.TypeData, "\x00"))
		session.Redir.Username = username
	}
	session.Unlock()

	radiusResp, requestAuthenticator, err := h.radiusClient.SendEAPAccessRequest(session, eapPayload, session.SessionParams.State)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to send EAP Access-Request")
		return
	}

	switch radiusResp.Code {
	case layehradius.CodeAccessChallenge:
		h.handleRadiusChallenge(session, radiusResp)
	case layehradius.CodeAccessAccept:
		h.handleRadiusAccept(session, radiusResp, requestAuthenticator)
	case layehradius.CodeAccessReject:
		h.handleRadiusReject(session, radiusResp)
	}
}

func (h *Handler) handleRadiusChallenge(session *core.Session, radiusResp *layehradius.Packet) {
	eapPayload := rfc2869.EAPMessage_Get(radiusResp)
	if eapPayload == nil {
		return
	}
	if state := rfc2865.State_Get(radiusResp); state != nil {
		session.Lock()
		session.SessionParams.State = state
		session.Unlock()
	}
	h.sendEAPPayload(session.HisMAC, eapPayload)
}

func (h *Handler) handleRadiusAccept(session *core.Session, radiusResp *layehradius.Packet, requestAuthenticator []byte) {
	session.Lock()
	session.Authenticated = true

	var pmk []byte
	if encryptedKey := radius.GetMSMPPERecvKey(radiusResp); encryptedKey != nil {
		h.cfg.RadiusSecret.Access(func(secret []byte) error {
			decryptedKey, err := decryptMSMPPEKey(secret, requestAuthenticator, encryptedKey)
			if err == nil {
				pmk = decryptedKey
			} else {
				h.logger.Error().Err(err).Msg("Failed to decrypt MS-MPPE-Recv-Key")
			}
			return nil
		})
	}
	if pmk != nil {
		session.EAPOL.PMK = pmk
	}
	session.Unlock()

	if eapPayload := rfc2869.EAPMessage_Get(radiusResp); eapPayload != nil {
		h.sendEAPPayload(session.HisMAC, eapPayload)
	} else {
		h.sendEAP(session.HisMAC, &layers.EAP{Code: layers.EAPCodeSuccess, Id: session.EAPOL.EapID})
	}

	if pmk != nil {
		h.startHandshake(session)
	}
}

func (h *Handler) handleRadiusReject(session *core.Session, radiusResp *layehradius.Packet) {
	if eapPayload := rfc2869.EAPMessage_Get(radiusResp); eapPayload != nil {
		h.sendEAPPayload(session.HisMAC, eapPayload)
	} else {
		h.sendEAP(session.HisMAC, &layers.EAP{Code: layers.EAPCodeFailure, Id: session.EAPOL.EapID})
	}
	h.sm.DeleteSession(session)
}

func (h *Handler) startHandshake(session *core.Session) {
	session.Lock()
	defer session.Unlock()

	aNonce := make([]byte, 32)
	rand.Read(aNonce)
	session.EAPOL.ANonce = aNonce
	session.EAPOL.ReplayCounter++

	key := &layers.EAPOLKey{
		KeyDescriptorType:    layers.EAPOLKeyDescriptorTypeWPA,
		KeyDescriptorVersion: layers.EAPOLKeyDescriptorVersionAESHMACSHA1,
		KeyType:              layers.EAPOLKeyTypePairwise,
		Nonce:                aNonce,
		ReplayCounter:        session.EAPOL.ReplayCounter,
	}
	h.sendEAPOLKey(session.HisMAC, key)
	session.EAPOL.HandshakeState = HandshakeStateSentMsg1
}

const (
	HandshakeStateNone     = ""
	HandshakeStateSentMsg1 = "SENT_MSG1"
	HandshakeStateSentMsg3 = "SENT_MSG3"
	HandshakeStateComplete = "COMPLETE"
)

func (h *Handler) handleEAPOLKey(session *core.Session, clientMAC net.HardwareAddr, key *layers.EAPOLKey, eapolFrame []byte) {
	session.Lock()

	if key.ReplayCounter < session.EAPOL.ReplayCounter {
		session.Unlock()
		h.logger.Warn().Msg("Replay counter check failed")
		return
	}

	switch session.EAPOL.HandshakeState {
	case HandshakeStateSentMsg1: // Received Message 2
		session.EAPOL.SNonce = key.Nonce
		ptk := ptkDerivation(session.EAPOL.PMK, session.EAPOL.ANonce, session.EAPOL.SNonce, h.ifaceMAC, clientMAC)
		kck := ptk[0:16]

		if valid, _ := verifyMIC(kck, eapolFrame); !valid {
			session.Unlock()
			h.logger.Warn().Str("mac", clientMAC.String()).Msg("Handshake Message 2 MIC verification failed")
			return
		}

		session.EAPOL.PTK = ptk
		session.EAPOL.ReplayCounter = key.ReplayCounter

		msg3 := &layers.EAPOLKey{
			KeyDescriptorType:    layers.EAPOLKeyDescriptorTypeWPA,
			KeyDescriptorVersion: layers.EAPOLKeyDescriptorVersionAESHMACSHA1,
			KeyType:              layers.EAPOLKeyTypePairwise,
			KeyMIC:               true,
			Secure:               true,
			Install:              true,
			Nonce:                session.EAPOL.ANonce,
			ReplayCounter:        session.EAPOL.ReplayCounter,
		}

		mic, err := h.calculateEAPOLKeyMIC(kck, msg3)
		if err != nil {
			session.Unlock()
			h.logger.Error().Err(err).Msg("Failed to calculate MIC for Message 3")
			return
		}
		msg3.MIC = mic

		session.EAPOL.HandshakeState = HandshakeStateSentMsg3
		session.Unlock()
		h.sendEAPOLKey(clientMAC, msg3)

	case HandshakeStateSentMsg3: // Received Message 4
		kck := session.EAPOL.PTK[0:16]
		if valid, _ := verifyMIC(kck, eapolFrame); !valid {
			session.Unlock()
			h.logger.Warn().Str("mac", clientMAC.String()).Msg("Handshake Message 4 MIC verification failed")
			return
		}
		h.logger.Info().Str("mac", clientMAC.String()).Msg("4-way handshake complete")
		session.EAPOL.HandshakeState = HandshakeStateComplete
		session.Unlock()
	default:
		session.Unlock()
	}
}

func (h *Handler) calculateEAPOLKeyMIC(kck []byte, key *layers.EAPOLKey) ([]byte, error) {
	tempKey := *key
	tempKey.MIC = make([]byte, 16)

	eapol := &layers.EAPOL{Version: 1, Type: EAPOLTypeKey}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buf, opts, eapol, &tempKey)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize EAPOL-Key for MIC calc: %w", err)
	}
	return calculateMIC(kck, buf.Bytes()), nil
}

func (h *Handler) sendEAPOLKey(dstMAC net.HardwareAddr, key *layers.EAPOLKey) {
	eapol := &layers.EAPOL{Version: 1, Type: EAPOLTypeKey}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts, eapol, key)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to serialize EAPOL-Key")
		return
	}
	if err := h.sender.SendEAPOL(dstMAC, buf.Bytes()); err != nil {
		h.logger.Error().Err(err).Msg("Failed to send EAPOL-Key")
	}
}

func (h *Handler) sendEAP(dstMAC net.HardwareAddr, eap *layers.EAP) {
	// Manually serialize EAP packet
	// EAP structure: Code(1) + Id(1) + Length(2) + Type(1) + TypeData(n)
	eapLength := 4 + 1 + len(eap.TypeData) // Total length including Type field
	eapPacket := make([]byte, eapLength)
	eapPacket[0] = byte(eap.Code)
	eapPacket[1] = eap.Id
	eapPacket[2] = byte(eapLength >> 8)
	eapPacket[3] = byte(eapLength)
	eapPacket[4] = byte(eap.Type)
	copy(eapPacket[5:], eap.TypeData)

	eapol := &layers.EAPOL{Version: 1, Type: layers.EAPOLTypeEAP}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts, eapol, gopacket.Payload(eapPacket))
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to serialize EAP")
		return
	}
	if err := h.sender.SendEAPOL(dstMAC, buf.Bytes()); err != nil {
		h.logger.Error().Err(err).Msg("Failed to send EAP")
	}
}

func (h *Handler) sendEAPPayload(dstMAC net.HardwareAddr, eapPayload []byte) {
	eapol := &layers.EAPOL{Version: 1, Type: layers.EAPOLTypeEAP}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts, eapol, gopacket.Payload(eapPayload))
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to serialize EAP payload")
		return
	}
	if err := h.sender.SendEAPOL(dstMAC, buf.Bytes()); err != nil {
		h.logger.Error().Err(err).Msg("Failed to send EAP payload")
	}
}

func parseEAPOLKey(data []byte) (*layers.EAPOLKey, error) {
	p := gopacket.NewPacket(data, layers.LayerTypeEAPOLKey, gopacket.Default)
	if err := p.ErrorLayer(); err != nil {
		return nil, err.Error()
	}
	if keyLayer := p.Layer(layers.LayerTypeEAPOLKey); keyLayer != nil {
		return keyLayer.(*layers.EAPOLKey), nil
	}
	return nil, fmt.Errorf("packet does not contain an EAPOL-Key layer")
}