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

// createTestEthPacket creates a gopacket.Packet with a correctly formed Ethernet layer.
func createTestEthPacket(eth *layers.Ethernet, payload gopacket.SerializableLayer) gopacket.Packet {
	eth.EthernetType = layers.EthernetTypeEAPOL
	if eth.DstMAC == nil {
		eth.DstMAC = eapolMulticastMAC
	}
	opts := gopacket.SerializeOptions{FixLengths: true}
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts, eth, payload)
	if err != nil {
		panic(err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestHandleEAPOLStart(t *testing.T) {
	handler, _, _, sender := setupTestHandler(t)
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:01")
	eapolStart := &layers.EAPOL{Type: layers.EAPOLTypeStart, Version: 1}
	packet := createTestEthPacket(&layers.Ethernet{SrcMAC: clientMAC}, eapolStart)

	handler.HandlePacket(packet)

	require.NotNil(t, sender.SentPacket, "Handler should have sent a packet")
	p := gopacket.NewPacket(sender.SentPacket, layers.LayerTypeEAPOL, gopacket.Default)
	eapolLayer := p.Layer(layers.LayerTypeEAPOL).(*layers.EAPOL)
	require.NotNil(t, eapolLayer, "Sent packet should contain an EAPOL layer")
	eap, err := parseEAP(eapolLayer.LayerPayload())
	require.NoError(t, err)
	require.Equal(t, layers.EAPCodeRequest, eap.Code)
	require.Equal(t, layers.EAPTypeIdentity, eap.Type)
	require.Equal(t, uint8(1), eap.Id)
}

func TestHandleEAPResponseIdentity(t *testing.T) {
	handler, sm, rc, sender := setupTestHandler(t)
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:02")
	session := sm.CreateSession(nil, clientMAC, 0)

	// NOTE(Correction): The EAP layer must be serialized first and then passed as a
	// generic payload to the EAPOL layer. This removes ambiguity for gopacket.
	eapResp := &layers.EAP{
		Code:     layers.EAPCodeResponse,
		Id:       1, // Responding to the initial Identity Request
		Type:     layers.EAPTypeIdentity,
		TypeData: []byte("testuser"),
	}
	eapResp.Length = uint16(5 + len(eapResp.TypeData))
	eapBuf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(eapBuf, gopacket.SerializeOptions{}, eapResp)
	eapol := &layers.EAPOL{Type: layers.EAPOLTypeEAP, Version: 1, Length: uint16(len(eapBuf.Bytes()))}
	packet := createTestEthPacket(&layers.Ethernet{SrcMAC: clientMAC}, eapol, gopacket.Payload(eapBuf.Bytes()))

	// Mock a RADIUS challenge in response to ensure the full flow is tested
	radiusChallengeEAPBuf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(radiusChallengeEAPBuf, gopacket.SerializeOptions{}, &layers.EAP{Code: layers.EAPCodeRequest, Id: 2, Type: 4, TypeData: []byte("challenge-data"), Length: 22})
	radiusResp := radius.New(radius.CodeAccessChallenge, []byte("secret"))
	rfc2869.EAPMessage_Set(radiusResp, radiusChallengeEAPBuf.Bytes())
	rc.Response = radiusResp

	handler.HandlePacket(packet)

	require.Equal(t, "testuser", session.Redir.Username)
	require.NotNil(t, rc.ReceivedEAP)
	parsedEAP, err := parseEAP(rc.ReceivedEAP)
	require.NoError(t, err)
	require.Equal(t, "testuser", string(bytes.Trim(parsedEAP.TypeData, "\x00")))
	require.NotNil(t, sender.SentPacket, "Handler should have relayed the RADIUS challenge")
}

func TestHandleRadiusAccept(t *testing.T) {
	handler, _, _, sender := setupTestHandler(t)
	session := handler.sm.CreateSession(nil, net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x07}, 0)
	session.EapID = 5 // Simulate that the last client response had ID 5

	// Create a mock RADIUS Access-Accept that CONTAINS an EAP-Success message
	radiusResp := radius.New(radius.CodeAccessAccept, []byte("secret"))
	eapSuccessBuf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(eapSuccessBuf, gopacket.SerializeOptions{}, &layers.EAP{Code: layers.EAPCodeSuccess, Id: 5, Length: 4})
	rfc2869.EAPMessage_Set(radiusResp, eapSuccessBuf.Bytes())

	handler.handleRadiusAccept(session, radiusResp)

	require.True(t, session.Authenticated)
	require.NotNil(t, sender.SentPacket)
	p := gopacket.NewPacket(sender.SentPacket, layers.LayerTypeEAPOL, gopacket.Default)
	eapLayer := p.Layer(layers.LayerTypeEAP)
	require.NotNil(t, eapLayer)
	parsedEAP, err := parseEAP(eapLayer.LayerContents())
	require.NoError(t, err)
	require.Equal(t, layers.EAPCodeSuccess, parsedEAP.Code)
	require.Equal(t, uint8(5), parsedEAP.Id) // Verify the ID was relayed correctly
}

func TestHandleRadiusReject(t *testing.T) {
	handler, sm, _, sender := setupTestHandler(t)
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:05")
	session := sm.CreateSession(nil, clientMAC, 0)
	session.EapID = 6

	// Create a mock RADIUS Access-Reject that CONTAINS an EAP-Failure message
	radiusResp := radius.New(radius.CodeAccessReject, []byte("secret"))
	eapFailureBuf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(eapFailureBuf, gopacket.SerializeOptions{}, &layers.EAP{Code: layers.EAPCodeFailure, Id: 6, Length: 4})
	rfc2869.EAPMessage_Set(radiusResp, eapFailureBuf.Bytes())

	handler.handleRadiusReject(session, radiusResp)

	require.NotNil(t, sender.SentPacket)
	p := gopacket.NewPacket(sender.SentPacket, layers.LayerTypeEAPOL, gopacket.Default)
	eapLayer := p.Layer(layers.LayerTypeEAP)
	require.NotNil(t, eapLayer)
	parsedEAP, err := parseEAP(eapLayer.LayerContents())
	require.NoError(t, err)
	require.Equal(t, layers.EAPCodeFailure, parsedEAP.Code)
	require.Equal(t, uint8(6), parsedEAP.Id)
	_, ok := sm.GetSessionByMAC(clientMAC)
	require.False(t, ok, "Session should be deleted on reject")
}