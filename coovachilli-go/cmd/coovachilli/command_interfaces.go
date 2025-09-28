package main

import (
	"net"

	"coovachilli-go/pkg/core"
	"layeh.com/radius/rfc2866"
)

// sessionManagerInterface defines the methods we need from a session manager.
type sessionManagerInterface interface {
	GetSessionByMAC(mac net.HardwareAddr) (*core.Session, bool)
	GetSessionByIP(ip net.IP) (*core.Session, bool)
	GetAllSessions() []*core.Session
}

// disconnectManagerInterface defines the methods we need from a disconnect manager.
type disconnectManagerInterface interface {
	Disconnect(session *core.Session, reason string)
}

// accountingSenderInterface defines the methods we need from an accounting sender.
type accountingSenderInterface interface {
	SendAccountingRequest(session *core.Session, statusType rfc2866.AcctStatusType, reason string)
}