package radius

import (
	"context"
	"fmt"
	"net"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"github.com/rs/zerolog"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc3162"
)

// AccountingSender defines the interface for sending RADIUS accounting packets.
type AccountingSender interface {
	SendAccountingRequest(session *core.Session, statusType rfc2866.AcctStatusType, reason string)
}

// A map to convert string reasons to RADIUS Acct-Terminate-Cause codes
// Using integer values as the library version does not export these constants.
var terminateCauseMap = map[string]rfc2866.AcctTerminateCause{
	"User-Request":         rfc2866.AcctTerminateCause(1),
	"Lost-Carrier":         rfc2866.AcctTerminateCause(2),
	"Lost-Service":         rfc2866.AcctTerminateCause(3),
	"Idle-Timeout":         rfc2866.AcctTerminateCause(4),
	"Session-Timeout":      rfc2866.AcctTerminateCause(5),
	"Admin-Reset":          rfc2866.AcctTerminateCause(6),
	"Admin-Reboot":         rfc2866.AcctTerminateCause(7),
	"Port-Error":           rfc2866.AcctTerminateCause(8),
	"NAS-Error":            rfc2866.AcctTerminateCause(9),
	"NAS-Request":          rfc2866.AcctTerminateCause(10),
	"Port-Unneeded":        rfc2866.AcctTerminateCause(11),
	"Port-Preempted":       rfc2866.AcctTerminateCause(12),
	"Port-Suspended":       rfc2866.AcctTerminateCause(13),
	"Service-Unavailable":  rfc2866.AcctTerminateCause(14),
	"Callback":             rfc2866.AcctTerminateCause(15),
	"User-Error":           rfc2866.AcctTerminateCause(16),
	"Host-Request":         rfc2866.AcctTerminateCause(17),
	"Data-Limit-Reached":   rfc2866.AcctTerminateCause(5), // Using SessionTimeout as a proxy
}

// CoAIncomingRequest holds a parsed CoA/Disconnect packet and the sender's address.
type CoAIncomingRequest struct {
	Packet *radius.Packet
	Peer   *net.UDPAddr
}

// Client holds the state for the RADIUS client.
type Client struct {
	cfg    *config.Config
	logger zerolog.Logger
}

// NewClient creates a new RADIUS client.
func NewClient(cfg *config.Config, logger zerolog.Logger) *Client {
	return &Client{
		cfg:    cfg,
		logger: logger.With().Str("component", "radius").Logger(),
	}
}

// SendAccessRequest sends a RADIUS Access-Request packet.
func (c *Client) SendAccessRequest(session *core.Session, username, password string) (*radius.Packet, error) {
	packet := radius.New(radius.CodeAccessRequest, []byte(c.cfg.RadiusSecret))

	// Add standard attributes
	rfc2865.UserName_SetString(packet, username)
	rfc2865.UserPassword_SetString(packet, password)
	rfc2865.NASIdentifier_SetString(packet, c.cfg.RadiusNASID)
	rfc2865.NASIPAddress_Set(packet, c.cfg.RadiusListen)

	// Add Framed-IP-Address or Framed-IPv6-Prefix attribute
	if session.HisIP != nil {
		if session.HisIP.To4() != nil {
			rfc2865.FramedIPAddress_Set(packet, session.HisIP)
		} else if c.cfg.IPv6Enable { // Only add IPv6 attributes if enabled
			prefix := &net.IPNet{
				IP:   session.HisIP,
				Mask: net.CIDRMask(128, 128), // /128 for a single host address
			}
			rfc3162.FramedIPv6Prefix_Add(packet, prefix)
		}
	}

	// Add MAC address
	rfc2865.CallingStationID_SetString(packet, session.HisMAC.String())

	// Add Port Type and VLAN ID if available
	rfc2865.NASPortType_Set(packet, rfc2865.NASPortType(19)) // 19 for Wireless-Other, matches C version
	if session.VLANID > 0 {
		rfc2865.NASPortID_SetString(packet, fmt.Sprintf("vlan-%d", session.VLANID))
	}

	// Send the packet
	server := fmt.Sprintf("%s:%d", c.cfg.RadiusServer1, c.cfg.RadiusAuthPort)
	response, err := radius.Exchange(context.Background(), packet, server)
	if err != nil {
		return nil, fmt.Errorf("failed to send RADIUS Access-Request: %w", err)
	}

	c.logger.Debug().Str("code", response.Code.String()).Str("user", username).Msg("Received RADIUS response")
	return response, nil
}

// SendAccountingRequest sends a RADIUS Accounting-Request packet asynchronously.
func (c *Client) SendAccountingRequest(session *core.Session, statusType rfc2866.AcctStatusType, reason string) {
	go func() {
		packet := radius.New(radius.CodeAccountingRequest, []byte(c.cfg.RadiusSecret))

		// Add standard attributes
		rfc2866.AcctStatusType_Set(packet, statusType)
		rfc2866.AcctSessionID_SetString(packet, session.SessionID)
		rfc2865.UserName_SetString(packet, session.Redir.Username)
		rfc2865.NASIdentifier_SetString(packet, c.cfg.RadiusNASID)
		rfc2865.NASIPAddress_Set(packet, c.cfg.RadiusListen)

		// Add accounting data
		rfc2866.AcctInputOctets_Set(packet, rfc2866.AcctInputOctets(session.InputOctets))
		rfc2866.AcctOutputOctets_Set(packet, rfc2866.AcctOutputOctets(session.OutputOctets))
		rfc2866.AcctInputPackets_Set(packet, rfc2866.AcctInputPackets(session.InputPackets))
		rfc2866.AcctOutputPackets_Set(packet, rfc2866.AcctOutputPackets(session.OutputPackets))
		rfc2866.AcctSessionTime_Set(packet, rfc2866.AcctSessionTime(session.LastSeen.Sub(session.StartTime).Seconds()))

		// Add Framed-IP-Address or Framed-IPv6-Prefix attribute
		if session.HisIP != nil {
			if session.HisIP.To4() != nil {
				rfc2865.FramedIPAddress_Set(packet, session.HisIP)
			} else if c.cfg.IPv6Enable {
				prefix := &net.IPNet{IP: session.HisIP, Mask: net.CIDRMask(128, 128)}
				rfc3162.FramedIPv6Prefix_Add(packet, prefix)
			}
		}

		// Add MAC address
		rfc2865.CallingStationID_SetString(packet, session.HisMAC.String())

	// Add Port Type and VLAN ID if available
	rfc2865.NASPortType_Set(packet, rfc2865.NASPortType(19)) // 19 for Wireless-Other
	if session.VLANID > 0 {
		rfc2865.NASPortID_SetString(packet, fmt.Sprintf("vlan-%d", session.VLANID))
	}

		// Add terminate cause if this is a stop packet
		if statusType == rfc2866.AcctStatusType(2) { // 2 = Stop
			if cause, ok := terminateCauseMap[reason]; ok {
				rfc2866.AcctTerminateCause_Set(packet, cause)
			} else {
				// 9 = NAS-Error
				rfc2866.AcctTerminateCause_Set(packet, rfc2866.AcctTerminateCause(9))
				c.logger.Warn().Str("reason", reason).Msg("Unknown terminate cause reason")
			}
		}


		// Send the packet
		server := fmt.Sprintf("%s:%d", c.cfg.RadiusServer1, c.cfg.RadiusAcctPort)
		response, err := radius.Exchange(context.Background(), packet, server)
		if err != nil {
			c.logger.Error().Err(err).Str("type", statusType.String()).Msg("Failed to send RADIUS Accounting-Request")
			return
		}

		c.logger.Debug().Str("code", response.Code.String()).Str("user", session.Redir.Username).Msg("Received RADIUS accounting response")
	}()
}

// StartCoAListener starts listeners for incoming CoA and Disconnect requests.
func (c *Client) StartCoAListener(coaReqChan chan<- CoAIncomingRequest) {
	// Listener for IPv4. If no specific address is configured, listen on all interfaces.
	ipv4Addr := "0.0.0.0"
	if c.cfg.RadiusListen != nil {
		// Ensure it's an IPv4 address
		if c.cfg.RadiusListen.To4() != nil {
			ipv4Addr = c.cfg.RadiusListen.String()
		}
	}
	go c.listen("udp4", fmt.Sprintf("%s:%d", ipv4Addr, c.cfg.CoaPort), coaReqChan)

	// Listener for IPv6, if enabled. If no specific address is configured, listen on all interfaces.
	if c.cfg.IPv6Enable {
		ipv6Addr := "::"
		if c.cfg.RadiusListenV6 != nil {
			// Ensure it's an IPv6 address
			if c.cfg.RadiusListenV6.To4() == nil {
				ipv6Addr = c.cfg.RadiusListenV6.String()
			}
		}
		go c.listen("udp6", fmt.Sprintf("%s:%d", ipv6Addr, c.cfg.CoaPort), coaReqChan)
	}
}

// listen is a helper function to listen on a specific address and protocol.
func (c *Client) listen(network, addr string, coaReqChan chan<- CoAIncomingRequest) {
	conn, err := net.ListenPacket(network, addr)
	if err != nil {
		// Log as an error instead of fatal, as one of the listeners might fail (e.g., no IPv6 on host)
		// while the other succeeds.
		c.logger.Error().Err(err).Str("addr", addr).Msg("Failed to start CoA listener")
		return
	}
	defer conn.Close()

	c.logger.Info().Str("addr", conn.LocalAddr().String()).Msg("CoA listener started")

	for {
		buf := make([]byte, 4096)
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			c.logger.Error().Err(err).Msg("Error reading from CoA socket")
			continue
		}

		packet, err := radius.Parse(buf[:n], []byte(c.cfg.RadiusSecret))
		if err != nil {
			c.logger.Error().Err(err).Msg("Failed to parse incoming CoA packet")
			continue
		}


		c.logger.Info().Str("code", packet.Code.String()).Str("peer", peer.String()).Msg("Received CoA/Disconnect request")
		coaReqChan <- CoAIncomingRequest{
			Packet: packet,
			Peer:   peer.(*net.UDPAddr),
		}
	}
}

// SendCoAResponse sends a CoA or Disconnect ACK/NAK.
func (c *Client) SendCoAResponse(response *radius.Packet, peer *net.UDPAddr) error {
	conn, err := net.DialUDP("udp", nil, peer)
	if err != nil {
		return fmt.Errorf("failed to dial peer for CoA response: %w", err)
	}
	defer conn.Close()

	encoded, err := response.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode CoA response: %w", err)
	}

	_, err = conn.Write(encoded)
	if err != nil {
		return fmt.Errorf("failed to write CoA response: %w", err)
	}

	c.logger.Info().Str("code", response.Code.String()).Str("peer", peer.String()).Msg("Sent CoA/Disconnect response")
	return nil
}
