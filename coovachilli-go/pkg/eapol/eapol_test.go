package eapol

import (
	"bytes"
	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

var eapolMulticastMAC, _ = net.ParseMAC("01:80:c2:00:00:03")

// mockEAPOLSender is a mock implementation of the EAPOLSender interface for testing.
type mockEAPOLSender struct {
	SentPacket []byte
	DstMAC     net.HardwareAddr
}

func (m *mockEAPOLSender) SendEAPOL(dstMAC net.HardwareAddr, eapolPayload []byte) error {
	m.DstMAC = dstMAC
	m.SentPacket = eapolPayload
	return nil
}

// mockRadiusClient is a mock implementation of the EAPOLAuthenticator interface for testing.
type mockRadiusClient struct {
	ReceivedEAP   []byte
	ReceivedState []byte
	Response      *radius.Packet
	ResponseErr   error
}

func (m *mockRadiusClient) SendEAPAccessRequest(session *core.Session, eapPayload []byte, state []byte) (*radius.Packet, error) {
	m.ReceivedEAP = eapPayload
	m.ReceivedState = state
	return m.Response, m.ResponseErr
}

// setupTestHandler creates a new EAPOL Handler with mock dependencies.
func setupTestHandler(t *testing.T) (*Handler, *core.SessionManager, *mockRadiusClient, *mockEAPOLSender) {
	cfg := &config.Config{}
	sm := core.NewSessionManager(cfg, nil)
	rc := &mockRadiusClient{}
	sender := &mockEAPOLSender{}
	logger := zerolog.Nop()
	handler := &Handler{
		cfg:          cfg,
		sm:           sm,
		radiusClient: rc,
		sender:       sender,
		logger:       logger,
	}
	return handler, sm, rc, sender
}

// createTestPacket is a helper to build a gopacket.Packet for testing.
func createTestPacket(eth *layers.Ethernet, payload ...gopacket.SerializableLayer) gopacket.Packet {
	eth.EthernetType = layers.EthernetTypeEAPOL
	if eth.DstMAC == nil {
		eth.DstMAC = eapolMulticastMAC
	}
	opts := gopacket.SerializeOptions{FixLengths: true}
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts, append([]gopacket.SerializableLayer{eth}, payload...)...)
	if err != nil {
		panic(err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestHandleEAPOLStart(t *testing.T) {
	handler, _, _, sender := setupTestHandler(t)
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:01")
	eapolStart := &layers.EAPOL{Type: layers.EAPOLTypeStart, Version: 1}
	packet := createTestPacket(&layers.Ethernet{SrcMAC: clientMAC}, eapolStart)

	handler.HandlePacket(packet)

	require.NotNil(t, sender.SentPacket, "Handler should have sent a packet")
	p := gopacket.NewPacket(sender.SentPacket, layers.LayerTypeEAPOL, gopacket.Default)
	eapolLayer := p.Layer(layers.LayerTypeEAPOL).(*layers.EAPOL)
	require.NotNil(t, eapolLayer, "Sent packet should contain an EAPOL layer")
	eap, err := parseEAP(eapolLayer.LayerPayload())
	require.NoError(t, err)
	require.Equal(t, layers.EAPCodeRequest, eap.Code)
	require.Equal(t, layers.EAPTypeIdentity, eap.Type)
}

func TestHandleEAPResponseIdentity(t *testing.T) {
	handler, sm, rc, _ := setupTestHandler(t)
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:02")
	session := sm.CreateSession(nil, clientMAC, 0)

	eapResp := &layers.EAP{
		Code:     layers.EAPCodeResponse,
		Id:       1,
		Type:     layers.EAPTypeIdentity,
		TypeData: []byte("testuser"),
	}
	eapResp.Length = uint16(5 + len(eapResp.TypeData))
	eapBuf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(eapBuf, gopacket.SerializeOptions{}, eapResp)
	eapol := &layers.EAPOL{Type: layers.EAPOLTypeEAP, Version: 1, Length: uint16(len(eapBuf.Bytes()))}
	packet := createTestPacket(&layers.Ethernet{SrcMAC: clientMAC}, eapol, gopacket.Payload(eapBuf.Bytes()))

	rc.Response = radius.New(radius.CodeAccessChallenge, []byte("secret"))
	handler.HandlePacket(packet)

	require.Equal(t, "testuser", session.Redir.Username)
	require.NotNil(t, rc.ReceivedEAP, "RADIUS client should have received an EAP message")
	parsedEAP, err := parseEAP(rc.ReceivedEAP)
	require.NoError(t, err)
	require.Equal(t, "testuser", string(bytes.Trim(parsedEAP.TypeData, "\x00")))
}

func TestHandleRadiusChallenge(t *testing.T) {
	handler, _, _, sender := setupTestHandler(t)
	session := handler.sm.CreateSession(nil, net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, 0)

	eapBuf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(eapBuf, gopacket.SerializeOptions{}, &layers.EAP{Code: layers.EAPCodeRequest, Id: 2, Type: 4, TypeData: []byte("challenge-data"), Length: 22})
	radiusResp := radius.New(radius.CodeAccessChallenge, []byte("secret"))
	rfc2869.EAPMessage_Set(radiusResp, eapBuf.Bytes())
	rfc2865.State_Set(radiusResp, []byte("radius-state"))

	handler.handleRadiusChallenge(session, radiusResp)

	require.NotNil(t, sender.SentPacket, "Handler should have sent a challenge packet to the client")
	p := gopacket.NewPacket(sender.SentPacket, layers.LayerTypeEAPOL, gopacket.Default)
	eapLayer := p.Layer(layers.LayerTypeEAP)
	require.NotNil(t, eapLayer)
	sentEAP, err := parseEAP(eapLayer.LayerContents())
	require.NoError(t, err)
	require.Equal(t, layers.EAPCodeRequest, sentEAP.Code)
	require.Equal(t, layers.EAPType(4), sentEAP.Type)
	require.Equal(t, []byte("radius-state"), session.SessionParams.State)
}

func TestHandleRadiusAccept(t *testing.T) {
	handler, _, _, sender := setupTestHandler(t)
	session := handler.sm.CreateSession(nil, net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x07}, 0)

	handler.handleRadiusAccept(session, radius.New(radius.CodeAccessAccept, []byte{}))

	require.True(t, session.Authenticated)
	require.NotNil(t, sender.SentPacket)
	p := gopacket.NewPacket(sender.SentPacket, layers.LayerTypeEAPOL, gopacket.Default)
	eapLayer := p.Layer(layers.LayerTypeEAP)
	require.NotNil(t, eapLayer)
	parsedEAP, err := parseEAP(eapLayer.LayerContents())
	require.NoError(t, err)
	require.Equal(t, layers.EAPCodeSuccess, parsedEAP.Code)
}

func TestHandleRadiusReject(t *testing.T) {
	handler, sm, _, sender := setupTestHandler(t)
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:05")
	session := sm.CreateSession(nil, clientMAC, 0)

	handler.handleRadiusReject(session)

	require.NotNil(t, sender.SentPacket)
	p := gopacket.NewPacket(sender.SentPacket, layers.LayerTypeEAPOL, gopacket.Default)
	eapLayer := p.Layer(layers.LayerTypeEAP)
	require.NotNil(t, eapLayer)
	parsedEAP, err := parseEAP(eapLayer.LayerContents())
	require.NoError(t, err)
	require.Equal(t, layers.EAPCodeFailure, parsedEAP.Code)
	_, ok := sm.GetSessionByMAC(clientMAC)
	require.False(t, ok, "Session should be deleted on reject")
}