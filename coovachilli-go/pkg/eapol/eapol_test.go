package eapol

import (
	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	cr "coovachilli-go/pkg/radius"
	"coovachilli-go/pkg/securestore"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"layeh.com/radius"
)

var (
	testAPMAC, _  = net.ParseMAC("00:11:22:33:44:55")
	testStaMAC, _ = net.ParseMAC("AA:BB:CC:DD:EE:FF")
	testPMK       = []byte("ThisIsThePairwiseMasterKey123456") // 32 bytes
)

type mockEAPOLSender struct {
	SentPacket []byte
	DstMAC     net.HardwareAddr
}

func (m *mockEAPOLSender) SendEAPOL(dstMAC net.HardwareAddr, eapolPayload []byte) error {
	m.DstMAC = dstMAC
	m.SentPacket = eapolPayload
	return nil
}

func (m *mockEAPOLSender) GetSentPacketAs(t *testing.T, layerType gopacket.LayerType) gopacket.Packet {
	if m.SentPacket == nil {
		return nil
	}
	p := gopacket.NewPacket(m.SentPacket, layerType, gopacket.Default)
	require.NotNil(t, p, "Failed to parse sent packet")
	return p
}

type mockRadiusClient struct {
	ReceivedEAP          []byte
	ReceivedState        []byte
	Response             *radius.Packet
	ResponseErr          error
	RequestAuthenticator []byte
}

func (m *mockRadiusClient) SendEAPAccessRequest(session *core.Session, eapPayload []byte, state []byte) (*radius.Packet, []byte, error) {
	m.ReceivedEAP = eapPayload
	m.ReceivedState = state
	if m.RequestAuthenticator == nil {
		m.RequestAuthenticator = make([]byte, 16)
	}
	return m.Response, m.RequestAuthenticator, m.ResponseErr
}

func setupTestHandler(t *testing.T) (*Handler, *core.SessionManager, *mockRadiusClient, *mockEAPOLSender) {
	cfg := &config.Config{RadiusSecret: securestore.NewSecret("testing123")}
	logger := zerolog.Nop()
	sm := core.NewSessionManager(cfg, nil, logger)
	rc := &mockRadiusClient{}
	sender := &mockEAPOLSender{}
	iface := net.Interface{HardwareAddr: testAPMAC}

	handler := NewHandler(cfg, sm, rc, nil, iface, logger)
	handler.sender = sender
	return handler, sm, rc, sender
}

func createPacket(t *testing.T, srcMAC net.HardwareAddr, payload ...gopacket.SerializableLayer) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       layers.EthernetBroadcast,
		EthernetType: layers.EthernetTypeEAPOL,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts, append([]gopacket.SerializableLayer{eth}, payload...)...)
	require.NoError(t, err)
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestHandleEAPOLStart(t *testing.T) {
	handler, _, _, sender := setupTestHandler(t)
	packet := createPacket(t, testStaMAC, &layers.EAPOL{Type: layers.EAPOLTypeStart, Version: 1})

	handler.HandlePacket(packet)

	require.NotNil(t, sender.SentPacket, "Handler should have sent a packet")
	p := sender.GetSentPacketAs(t, layers.LayerTypeEAPOL)
	eapLayer := p.Layer(layers.LayerTypeEAP)
	require.NotNil(t, eapLayer, "Sent packet should contain an EAP layer")
	eap, _ := eapLayer.(*layers.EAP)
	assert.Equal(t, layers.EAPCodeRequest, eap.Code)
	assert.Equal(t, layers.EAPTypeIdentity, eap.Type)
}

func TestHandleRadiusAccept_StartsHandshake(t *testing.T) {
	handler, _, rc, sender := setupTestHandler(t)
	session := handler.sm.CreateSession(nil, testStaMAC, 0)
	session.EAPOL.EapID = 5

	handler.cfg.RadiusSecret.Access(func(secret []byte) error {
		rc.Response = radius.New(radius.CodeAccessAccept, secret)
		_, requestAuthenticator, _ := rc.SendEAPAccessRequest(session, nil, nil)
		encryptedPMK, err := rfc2548Encrypt(secret, requestAuthenticator, testPMK, 0xAB)
		require.NoError(t, err)
		cr.SetMSMPPERecvKey(rc.Response, encryptedPMK)
		return nil
	})

	handler.handleRadiusAccept(session, rc.Response, rc.RequestAuthenticator)

	assert.True(t, session.Authenticated)
	assert.Equal(t, testPMK, session.EAPOL.PMK)
	require.NotNil(t, sender.SentPacket)
	p := sender.GetSentPacketAs(t, layers.LayerTypeEAPOL)
	keyLayer := p.Layer(layers.LayerTypeEAPOLKey)
	require.NotNil(t, keyLayer)
	key, _ := keyLayer.(*layers.EAPOLKey)
	assert.Equal(t, HandshakeStateSentMsg1, session.EAPOL.HandshakeState)
	assert.NotNil(t, key.Nonce)
}

func TestFullHandshake(t *testing.T) {
	handler, _, _, sender := setupTestHandler(t)
	session := handler.sm.CreateSession(nil, testStaMAC, 0)
	session.EAPOL.PMK = testPMK

	// 1. AP sends Message 1
	handler.startHandshake(session)
	require.NotNil(t, sender.SentPacket, "Message 1 was not sent")
	p1 := sender.GetSentPacketAs(t, layers.LayerTypeEAPOL)
	msg1, _ := p1.Layer(layers.LayerTypeEAPOLKey).(*layers.EAPOLKey)
	aNonce := msg1.Nonce

	// 2. Client sends Message 2
	sNonce := []byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f}
	ptk := ptkDerivation(testPMK, aNonce, sNonce, testAPMAC, testStaMAC)
	kck := ptk[0:16]

	eapolMsg2 := &layers.EAPOL{Version: 1, Type: EAPOLTypeKey}
	msg2Key := &layers.EAPOLKey{
		KeyDescriptorType:    layers.EAPOLKeyDescriptorTypeWPA,
		KeyDescriptorVersion: layers.EAPOLKeyDescriptorVersionAESHMACSHA1,
		KeyType:              layers.EAPOLKeyTypePairwise,
		Nonce:                sNonce,
		ReplayCounter:        msg1.ReplayCounter,
	}

	// Calculate MIC for message 2
	mic, err := handler.calculateEAPOLKeyMIC(kck, msg2Key)
	require.NoError(t, err)
	msg2Key.MIC = mic

	packet2 := createPacket(t, testStaMAC, eapolMsg2, msg2Key)
	handler.HandlePacket(packet2)

	// 3. AP verifies Msg2, sends Message 3
	assert.Equal(t, HandshakeStateSentMsg3, session.EAPOL.HandshakeState, "State should be SENT_MSG3 after receiving message 2")
	require.NotNil(t, sender.SentPacket, "Message 3 was not sent")
	p3 := sender.GetSentPacketAs(t, layers.LayerTypeEAPOL)
	msg3, _ := p3.Layer(layers.LayerTypeEAPOLKey).(*layers.EAPOLKey)
	assert.True(t, msg3.Install, "Message 3 should have Install flag set")
	assert.True(t, msg3.KeyMIC, "Message 3 should have KeyMIC flag set")

	// 4. Client sends Message 4
	msg4Key := &layers.EAPOLKey{
		KeyDescriptorType:    layers.EAPOLKeyDescriptorTypeWPA,
		KeyDescriptorVersion: layers.EAPOLKeyDescriptorVersionAESHMACSHA1,
		KeyType:              layers.EAPOLKeyTypePairwise,
		KeyMIC:               true,
		Secure:               true,
		ReplayCounter:        msg3.ReplayCounter,
	}
	mic4, err := handler.calculateEAPOLKeyMIC(kck, msg4Key)
	require.NoError(t, err)
	msg4Key.MIC = mic4
	packet4 := createPacket(t, testStaMAC, &layers.EAPOL{Version: 1, Type: EAPOLTypeKey}, msg4Key)
	handler.HandlePacket(packet4)

	// 5. AP verifies Msg4, completes handshake
	assert.Equal(t, HandshakeStateComplete, session.EAPOL.HandshakeState, "State should be COMPLETE after receiving message 4")
	assert.Equal(t, ptk, session.EAPOL.PTK, "PTK should be stored in the session")
}