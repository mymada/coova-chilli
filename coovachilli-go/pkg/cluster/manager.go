package cluster

import (
	"log"
	"net"
	"sync"
	"time"

	"coovachilli-go/pkg/config"
)

// PeerManager manages the state of all peers in the cluster.
type PeerManager struct {
	sync.RWMutex
	peers      map[int]*Peer
	localID    int
	localMAC   net.HardwareAddr
	localAddr  net.IP
	peerKey    []byte
	iface      *net.Interface
	currentState PeerState
}

// NewManager creates and initializes a new PeerManager.
func NewManager(cfg config.ClusterConfig, dhcpIfName string, uamListen net.IP) (*PeerManager, error) {
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, err
	}

	// In the C code, the initial state is Active for peer 0, Standby otherwise.
	initialState := PeerStateStandby
	if cfg.PeerID == 0 {
		initialState = PeerStateActive
	}

	m := &PeerManager{
		peers:      make(map[int]*Peer),
		localID:    cfg.PeerID,
		localMAC:   iface.HardwareAddr,
		localAddr:  uamListen, // Using UAM listen address as the peer's address
		peerKey:    []byte(cfg.PeerKey),
		iface:      iface,
		currentState: initialState,
	}

	// Initialize self
	m.peers[m.localID] = &Peer{
		ID:         m.localID,
		MAC:        m.localMAC,
		Addr:       m.localAddr,
		State:      m.currentState,
		LastUpdate: time.Now(),
	}

	log.Printf("Cluster Manager initialized for Peer %d on %s with state %s", m.localID, m.iface.Name, m.currentState)
	return m, nil
}

// GetCurrentState returns the current state of the local peer.
func (m *PeerManager) GetCurrentState() PeerState {
	m.RLock()
	defer m.RUnlock()
	return m.currentState
}

// UpdatePeerState updates the state of a given peer.
func (m *PeerManager) UpdatePeerState(peerID int, newState PeerState, mac net.HardwareAddr, addr net.IP) {
	m.Lock()
	defer m.Unlock()

	peer, exists := m.peers[peerID]
	if !exists {
		peer = &Peer{ID: peerID}
		m.peers[peerID] = peer
	}

	peer.State = newState
	peer.MAC = mac
	peer.Addr = addr
	peer.LastUpdate = time.Now()

	log.Printf("Updated peer %d to state %s", peerID, newState)

	// Failover logic from C code: if another peer becomes active, we go into standby.
	if peerID != m.localID && newState == PeerStateActive && m.currentState == PeerStateActive {
		log.Printf("Peer %d became active, transitioning to Standby", peerID)
		m.currentState = PeerStateStandby
		m.peers[m.localID].State = PeerStateStandby
	}
}

// checkPeerLiveness iterates through peers and marks them as offline if they are stale.
func (m *PeerManager) checkPeerLiveness() {
	m.Lock()
	defer m.Unlock()

	activePeerIsOffline := false
	for id, peer := range m.peers {
		if id == m.localID {
			continue
		}

		// Consider a peer offline if no update for 35 seconds.
		if time.Since(peer.LastUpdate) > 35*time.Second && peer.State != PeerStateOffline {
			log.Printf("Peer %d timed out. Marking as Offline.", id)
			if peer.State == PeerStateActive {
				activePeerIsOffline = true
			}
			peer.State = PeerStateOffline
		}
	}

	// If the active peer went offline, and we are in standby, try to become active.
	if activePeerIsOffline && m.currentState == PeerStateStandby {
		m.electNewActivePeer()
	}
}

// electNewActivePeer handles the logic for a standby node to become active.
// The peer with the lowest ID becomes the new active node.
func (m *PeerManager) electNewActivePeer() {
	// This function assumes it's called within a write lock.
	lowestID := m.localID
	canBecomeActive := true

	for id, peer := range m.peers {
		if id == m.localID {
			continue
		}
		// If there's another online standby peer with a lower ID, we can't become active.
		if peer.State == PeerStateStandby && id < lowestID {
			canBecomeActive = false
			break
		}
	}

	if canBecomeActive {
		log.Println("Active peer is offline. Transitioning this node to Active.")
		m.currentState = PeerStateActive
		m.peers[m.localID].State = PeerStateActive
		// Immediately send a HELLO to notify others of the state change.
		// Guard against nil interface for testing purposes.
		if m.iface != nil {
			if err := m.SendClusterMessage(MsgTypeHello); err != nil {
				log.Printf("Failed to send state change notification: %v", err)
			}
		}
	}
}


// Start begins the cluster management tasks (heartbeat, monitoring).
func (m *PeerManager) Start() {
	log.Println("Cluster manager started.")

	// Start listening for cluster messages in a separate goroutine.
	go m.ListenForClusterMessages()

	// Send an initial HELLO message to announce presence.
	if err := m.SendClusterMessage(MsgTypeHello); err != nil {
		log.Printf("Failed to send initial HELLO message: %v", err)
	}

	// Ticker for periodic tasks (heartbeat and liveness checks).
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Send a heartbeat message.
		if err := m.SendClusterMessage(MsgTypeHello); err != nil {
			log.Printf("Failed to send cluster heartbeat: %v", err)
		}

		// Check for stale peers.
		m.checkPeerLiveness()
	}
}