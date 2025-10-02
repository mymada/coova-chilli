package eapol

import (
	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/radius"
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/rs/zerolog"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

type EAPOLSender interface {
	SendEAPOL(dstMAC net.HardwareAddr, eapolPayload []byte) error
}

type Handler struct {
	cfg          *config.Config
	sm           *core.SessionManager
	radiusClient radius.EAPOLAuthenticator
	sender       EAPOLSender
	logger       zerolog.Logger
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
	opts := gopacket.SerializeOptions{}
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
		h.logger.Info().Str("mac", eth.SrcMAC.String()).Msg("Received EAPOL-Start, sending EAP-Request/Identity")
		h.sendEAPRequestIdentity(session)
	case layers.EAPOLTypeEAP:
		h.handleEAP(session, eapol.LayerPayload())
	}
}

func (h *Handler) sendEAPRequestIdentity(session *core.Session) {
	session.Lock()
	session.EapID++
	currentID := session.EapID
	session.Unlock()
	eapReq := &layers.EAP{Code: layers.EAPCodeRequest, Id: currentID, Type: layers.EAPTypeIdentity, Length: 5}
	h.sendEAP(session.HisMAC, eapReq)
}

func (h *Handler) handleEAP(session *core.Session, eapPayload []byte) {
	eap, err := parseEAP(eapPayload)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to parse EAP payload")
		return
	}

	session.Lock()
	session.EapID = eap.Id // Store the ID of the client's response
	if eap.Type == layers.EAPTypeIdentity {
		username := string(eap.TypeData)
		session.Redir.Username = username
		h.logger.Info().Str("mac", session.HisMAC.String()).Str("user", username).Msg("Received EAP-Response/Identity")
	}
	session.Unlock()

	radiusResp, err := h.radiusClient.SendEAPAccessRequest(session, eapPayload, session.SessionParams.State)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to send EAP Access-Request to RADIUS server")
		return
	}

	switch radiusResp.Code {
	case layehradius.CodeAccessChallenge:
		h.handleRadiusChallenge(session, radiusResp)
	case layehradius.CodeAccessAccept:
		h.handleRadiusAccept(session, radiusResp)
	case layehradius.CodeAccessReject:
		h.handleRadiusReject(session, radiusResp)
	}
}

func (h *Handler) handleRadiusChallenge(session *core.Session, radiusResp *layehradius.Packet) {
	eapPayload := rfc2869.EAPMessage_Get(radiusResp)
	if eapPayload == nil {
		h.logger.Warn().Msg("RADIUS Access-Challenge missing EAP-Message")
		return
	}
	state := rfc2865.State_Get(radiusResp)
	if state != nil {
		session.Lock()
		session.SessionParams.State = state
		session.Unlock()
	}
	h.logger.Debug().Str("mac", session.HisMAC.String()).Msg("Relaying RADIUS Access-Challenge to client")
	h.sendEAPPayload(session.HisMAC, eapPayload)
}

func (h *Handler) handleRadiusAccept(session *core.Session, radiusResp *layehradius.Packet) {
	session.Lock()
	session.Authenticated = true
	session.Unlock()

	eapPayload := rfc2869.EAPMessage_Get(radiusResp)
	if eapPayload == nil {
		h.logger.Error().Msg("RADIUS Access-Accept missing EAP-Message, sending generic EAP-Success")
		eapSuccess := &layers.EAP{Code: layers.EAPCodeSuccess, Id: session.EapID, Length: 4}
		h.sendEAP(session.HisMAC, eapSuccess)
		return
	}
	h.logger.Info().Str("mac", session.HisMAC.String()).Msg("EAP authentication successful, relaying EAP-Success")
	h.sendEAPPayload(session.HisMAC, eapPayload)
}

func (h *Handler) handleRadiusReject(session *core.Session, radiusResp *layehradius.Packet) {
	eapPayload := rfc2869.EAPMessage_Get(radiusResp)
	if eapPayload == nil {
		h.logger.Error().Msg("RADIUS Access-Reject missing EAP-Message, sending generic EAP-Failure")
		eapFailure := &layers.EAP{Code: layers.EAPCodeFailure, Id: session.EapID, Length: 4}
		h.sendEAP(session.HisMAC, eapFailure)
	} else {
		h.logger.Info().Str("mac", session.HisMAC.String()).Msg("EAP authentication failed, relaying EAP-Failure")
		h.sendEAPPayload(session.HisMAC, eapPayload)
	}
	h.sm.DeleteSession(session)
}

func (h *Handler) sendEAP(dstMAC net.HardwareAddr, eap gopacket.SerializableLayer) {
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eap)
	h.sendEAPPayload(dstMAC, buf.Bytes())
}

func (h *Handler) sendEAPPayload(dstMAC net.HardwareAddr, eapPayload []byte) {
	eapol := &layers.EAPOL{Version: 2, Type: layers.EAPOLTypeEAP, Length: uint16(len(eapPayload))}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eapol, gopacket.Payload(eapPayload))
	h.sender.SendEAPOL(dstMAC, buf.Bytes())
}

// parseEAP uses gopacket to robustly decode an EAP layer from a byte slice.
func parseEAP(data []byte) (*layers.EAP, error) {
	packet := gopacket.NewPacket(data, layers.LayerTypeEAP, gopacket.Default)
	if err := packet.ErrorLayer(); err != nil {
		return nil, err.Error()
	}
	eapLayer := packet.Layer(layers.LayerTypeEAP)
	if eapLayer == nil {
		return nil, fmt.Errorf("packet does not contain an EAP layer")
	}
	return eapLayer.(*layers.EAP), nil
}