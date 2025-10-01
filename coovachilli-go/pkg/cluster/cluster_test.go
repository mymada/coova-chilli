package cluster

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPeerStateStringer(t *testing.T) {
	assert.Equal(t, "Active", PeerStateActive.String())
	assert.Equal(t, "Standby", PeerStateStandby.String())
	assert.Equal(t, "Offline", PeerStateOffline.String())
	assert.Equal(t, "Unknown", PeerState(99).String())
}

func TestChilliHeaderSerialization(t *testing.T) {
	mac, _ := net.ParseMAC("01:02:03:04:05:06")
	ip := net.ParseIP("192.168.1.1").To4()

	h := &ChilliHeader{
		From:  1,
		Type:  MsgTypeHello,
		State: uint8(PeerStateActive),
	}
	copy(h.MAC[:], mac)
	copy(h.Addr[:], ip)

	serialized, err := h.Serialize()
	require.NoError(t, err)
	// Sizeof ChilliHeader is 16 bytes
	require.Len(t, serialized, 16)

	deserialized, err := DeserializeChilliHeader(serialized)
	require.NoError(t, err)

	assert.Equal(t, h.From, deserialized.From)
	assert.Equal(t, h.Type, deserialized.Type)
	assert.Equal(t, h.State, deserialized.State)
	assert.Equal(t, h.Addr, deserialized.Addr)
	assert.True(t, bytes.Equal(h.MAC[:], deserialized.MAC[:]))
}

func TestBlowfishEncryptionDecryption(t *testing.T) {
	key := []byte("a-secret-key-that-is-long-enough")
	originalData := []byte("this is a test of the blowfish encryption")

	encrypted, err := Encrypt(originalData, key)
	require.NoError(t, err)
	assert.NotEqual(t, originalData, encrypted)

	decrypted, err := Decrypt(encrypted, key)
	require.NoError(t, err)
	assert.Equal(t, originalData, decrypted)
}

func TestInvalidKey(t *testing.T) {
	key := []byte("short") // Invalid key size
	_, err := Encrypt([]byte("test"), key)
	assert.Error(t, err)
}

func TestInvalidPadding(t *testing.T) {
	key := []byte("a-valid-key-for-testing-blowfish")
	// Corrupt the last byte to simulate invalid padding
	badData := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 99}
	_, err := Decrypt(badData, key)
	assert.Error(t, err, "should fail due to invalid padding")
}

// newTestManager creates a PeerManager with a dummy interface for testing.
func newTestManager(t *testing.T, peerID int, initialState PeerState) *PeerManager {
	iface := &net.Interface{
		Index:        1,
		MTU:          1500,
		Name:         "test0",
		HardwareAddr: net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, byte(peerID)},
	}

	m := &PeerManager{
		peers:      make(map[int]*Peer),
		localID:    peerID,
		localMAC:   iface.HardwareAddr,
		localAddr:  net.ParseIP("192.168.10.1").To4(),
		peerKey:    []byte("test-key"),
		iface:      iface,
		currentState: initialState,
	}

	m.peers[m.localID] = &Peer{
		ID:         m.localID,
		MAC:        m.localMAC,
		Addr:       m.localAddr,
		State:      m.currentState,
		LastUpdate: time.Now(),
	}
	return m
}

func TestPeerManagerInitialization(t *testing.T) {
	m := newTestManager(t, 0, PeerStateActive)
	require.NotNil(t, m)
	assert.Equal(t, 0, m.localID)
	assert.Equal(t, PeerStateActive, m.GetCurrentState())
	assert.Len(t, m.peers, 1)

	m2 := newTestManager(t, 1, PeerStateStandby)
	require.NotNil(t, m2)
	assert.Equal(t, 1, m2.localID)
	assert.Equal(t, PeerStateStandby, m2.GetCurrentState())
}

func TestPeerManagerUpdateAndFailover(t *testing.T) {
	m := newTestManager(t, 1, PeerStateActive)

	remoteMAC, _ := net.ParseMAC("00:00:00:11:22:33")
	remoteIP := net.ParseIP("192.168.10.100")
	m.UpdatePeerState(0, PeerStateActive, remoteMAC, remoteIP)

	assert.Equal(t, PeerStateStandby, m.GetCurrentState(), "Local peer should failover to Standby")

	m.RLock()
	remotePeer, exists := m.peers[0]
	m.RUnlock()
	require.True(t, exists)
	assert.Equal(t, PeerStateActive, remotePeer.State)
}

func TestPeerLivenessCheck(t *testing.T) {
	m := newTestManager(t, 0, PeerStateActive)

	remoteMAC, _ := net.ParseMAC("00:00:00:11:22:33")
	remoteIP := net.ParseIP("192.168.10.100")
	m.UpdatePeerState(1, PeerStateStandby, remoteMAC, remoteIP)

	m.Lock()
	m.peers[1].LastUpdate = time.Now().Add(-40 * time.Second)
	m.Unlock()

	m.checkPeerLiveness()

	m.RLock()
	peer1state := m.peers[1].State
	m.RUnlock()
	assert.Equal(t, PeerStateOffline, peer1state, "Peer 1 should be marked as offline")
}

func TestElectionLogic(t *testing.T) {
	m := newTestManager(t, 1, PeerStateStandby)

	activeMAC, _ := net.ParseMAC("00:00:00:11:22:00")
	activeIP := net.ParseIP("192.168.10.100")
	m.UpdatePeerState(0, PeerStateActive, activeMAC, activeIP)

	standbyMAC, _ := net.ParseMAC("00:00:00:11:22:02")
	standbyIP := net.ParseIP("192.168.10.102")
	m.UpdatePeerState(2, PeerStateStandby, standbyMAC, standbyIP)

	m.Lock()
	m.peers[0].State = PeerStateOffline
	m.electNewActivePeer()
	m.Unlock()

	assert.Equal(t, PeerStateActive, m.GetCurrentState(), "Peer 1 should be elected as the new Active peer")

	m2 := newTestManager(t, 2, PeerStateStandby)
	m2.UpdatePeerState(0, PeerStateActive, activeMAC, activeIP)
	m2.UpdatePeerState(1, PeerStateStandby, standbyMAC, standbyIP)

	m2.Lock()
	m2.peers[0].State = PeerStateOffline
	m2.electNewActivePeer()
	m2.Unlock()

	assert.Equal(t, PeerStateStandby, m2.GetCurrentState(), "Peer 2 should remain Standby as a lower ID peer exists")
}