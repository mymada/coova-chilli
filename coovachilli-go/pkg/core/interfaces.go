package core

import (
	"net"
	"net/http"

	"coovachilli-go/pkg/config"
	"layeh.com/radius"
	"layeh.com/radius/rfc2866"
)

// CoAContext defines an interface for incoming CoA/Disconnect requests to avoid package cycles.
type CoAContext interface {
	Packet() *radius.Packet
	Peer() *net.UDPAddr
}

// RadiusClient defines the interface for RADIUS client operations.
type RadiusClient interface {
	SendAccessRequest(session *Session, username, password string) (*radius.Packet, error)
	SendAccountingRequest(session *Session, statusType rfc2866.AcctStatusType) (*radius.Packet, error)
	StartCoAListener(coaReqChan chan<- CoAContext)
	SendCoAResponse(response *radius.Packet, peer *net.UDPAddr) error
}

// HttpServer defines the interface for the main HTTP/UAM server.
type HttpServer interface {
	Start()
}

// AdminServer defines the interface for the admin API server.
type AdminServer interface {
	Start()
}

// FirewallManager defines the interface for managing firewall rules.
type FirewallManager interface {
	config.Reconfigurable
	Initialize() error
	AddAuthenticatedUser(ip net.IP) error
	RemoveAuthenticatedUser(ip net.IP) error
	Cleanup()
}

// Disconnector defines the interface for session disconnection logic.
type Disconnector interface {
	Disconnect(session *Session, reason string)
}

// Reaper defines the interface for the session reaper.
type Reaper interface {
	Start()
	Stop()
}

// ScriptRunner defines the interface for executing external scripts.
type ScriptRunner interface {
	RunScript(scriptPath string, session *Session, acctStatusType int)
}

// PeerManager defines the interface for cluster peer management.
type PeerManager interface {
	Start()
	GetCurrentState() int // Using basic types to avoid package cycles
}

// MetricsRecorder defines the interface for recording metrics.
type MetricsRecorder interface {
	IncCounter(name string, labels map[string]string)
	ObserveHistogram(name string, labels map[string]string, value float64)
	Handler() http.Handler
}