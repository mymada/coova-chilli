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

	// Add IPv4 and IPv6 attributes if available
	if session.HisIP != nil && session.HisIP.To4() != nil {
		rfc2865.FramedIPAddress_Set(packet, session.HisIP)
	}
	if session.HisIPv6 != nil {
		rfc3162.FramedIP6Prefix_Set(packet, 128, session.HisIPv6)
	}

	// Add MAC address
	rfc2865.CallingStationID_SetString(packet, session.HisMAC.String())

	// Send the packet
	server := fmt.Sprintf("%s:%d", c.cfg.RadiusServer1, c.cfg.RadiusAuthPort)
	response, err := radius.Exchange(context.Background(), packet, server)
	if err != nil {
		return nil, fmt.Errorf("failed to send RADIUS Access-Request: %w", err)
	}

	c.logger.Debug().Str("code", response.Code.String()).Str("user", username).Msg("Received RADIUS response")
	return response, nil
}

// SendAccountingRequest sends a RADIUS Accounting-Request packet.
func (c *Client) SendAccountingRequest(session *core.Session, statusType rfc2866.AcctStatusType) (*radius.Packet, error) {
	packet := radius.New(radius.CodeAccountingRequest, []byte(c.cfg.RadiusSecret))

	// Add standard attributes
	rfc2866.AcctStatusType_Set(packet, statusType)
	rfc2866.AcctSessionID_SetString(packet, session.SessionID)
	rfc2865.UserName_SetString(packet, session.Redir.Username)
	rfc2865.NASIdentifier_SetString(packet, c.cfg.RadiusNASID)
	rfc2865.NASIPAddress_Set(packet, c.cfg.RadiusListen)

	// Add accounting data
	rfc2866.AcctInputOctets_Set(packet, uint32(session.InputOctets))
	rfc2866.AcctOutputOctets_Set(packet, uint32(session.OutputOctets))
	rfc2866.AcctInputPackets_Set(packet, uint32(session.InputPackets))
	rfc2866.AcctOutputPackets_Set(packet, uint32(session.OutputPackets))
	rfc2866.AcctSessionTime_Set(packet, uint32(session.LastSeen.Sub(session.StartTime).Seconds()))

	// Add IPv4 and IPv6 attributes if available
	if session.HisIP != nil && session.HisIP.To4() != nil {
		rfc2865.FramedIPAddress_Set(packet, session.HisIP)
	}
	if session.HisIPv6 != nil {
		rfc3162.FramedIP6Prefix_Set(packet, 128, session.HisIPv6)
	}

	// Add MAC address
	rfc2865.CallingStationID_SetString(packet, session.HisMAC.String())

	// Send the packet
	server := fmt.Sprintf("%s:%d", c.cfg.RadiusServer1, c.cfg.RadiusAcctPort)
	response, err := radius.Exchange(context.Background(), packet, server)
	if err != nil {
		return nil, fmt.Errorf("failed to send RADIUS Accounting-Request: %w", err)
	}

	c.logger.Debug().Str("code", response.Code.String()).Str("user", session.Redir.Username).Msg("Received RADIUS accounting response")
	return response, nil
}
