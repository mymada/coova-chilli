package cluster

import (
	"net"
	"time"
)

// PeerState represents the state of a cluster peer.
type PeerState int

const (
	// PeerStateOffline means the peer is not reachable.
	PeerStateOffline PeerState = iota
	// PeerStateStandby means the peer is ready to take over.
	PeerStateStandby
	// PeerStateActive means the peer is currently handling traffic.
	PeerStateActive
)

func (s PeerState) String() string {
	switch s {
	case PeerStateActive:
		return "Active"
	case PeerStateStandby:
		return "Standby"
	case PeerStateOffline:
		return "Offline"
	default:
		return "Unknown"
	}
}

// Peer represents a node in the cluster.
type Peer struct {
	ID         int
	MAC        net.HardwareAddr
	Addr       net.IP
	State      PeerState
	LastUpdate time.Time
}