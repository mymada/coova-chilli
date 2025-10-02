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
	eapReq := &layers.EAP{Code: layers.EAPCodeRequest, Id: 1, Type: layers.EAPTypeIdentity, Length: 5}
	h.sendEAP(session.HisMAC, eapReq)
}

func (h *Handler) handleEAP(session *core.Session, eapPayload []byte) {
	eap, err := parseEAP(eapPayload)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to parse EAP payload")
		return
	}

	if eap.Type == layers.EAPTypeIdentity {
		username := string(eap.TypeData)
		session.Lock()
		session.Redir.Username = username
		session.Unlock()
		h.logger.Info().Str("mac", session.HisMAC.String()).Str("user", username).Msg("Received EAP-Response/Identity")
	}

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
		h.handleRadiusReject(session)
	}
}

func (h *Handler) handleRadiusChallenge(session *core.Session, radiusResp *layehradius.Packet) {
	eapPayload := rfc2869.EAPMessage_Get(radiusResp)
	if eapPayload == nil {
		return
	}
	state := rfc2865.State_Get(radiusResp)
	if state != nil {
		session.Lock()
		session.SessionParams.State = state
		session.Unlock()
	}
	h.sendEAPPayload(session.HisMAC, eapPayload)
}

func (h *Handler) handleRadiusAccept(session *core.Session, radiusResp *layehradius.Packet) {
	session.Lock()
	session.Authenticated = true
	session.Unlock()
	eapSuccess := &layers.EAP{Code: layers.EAPCodeSuccess, Id: 1, Length: 4}
	h.sendEAP(session.HisMAC, eapSuccess)
}

func (h *Handler) handleRadiusReject(session *core.Session) {
	eapFailure := &layers.EAP{Code: layers.EAPCodeFailure, Id: 1, Length: 4}
	h.sendEAP(session.HisMAC, eapFailure)
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

func parseEAP(data []byte) (*layers.EAP, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("EAP packet too short")
	}
	eap := &layers.EAP{
		Code:   layers.EAPCode(data[0]),
		Id:     data[1],
		Length: uint16(data[2])<<8 | uint16(data[3]),
	}
	if len(data) >= 5 {
		eap.Type = layers.EAPType(data[4])
		if len(data) > 5 {
			eap.TypeData = data[5:]
		}
	}
	return eap, nil
}