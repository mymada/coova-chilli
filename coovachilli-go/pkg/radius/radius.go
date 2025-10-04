package radius

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/metrics"
	"github.com/rs/zerolog"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/rfc3162"
)

// AccountingSender defines the interface for sending RADIUS accounting packets.
type AccountingSender interface {
	SendAccountingRequest(session *core.Session, statusType rfc2866.AcctStatusType) (*radius.Packet, error)
}

// EAPOLAuthenticator defines the interface for handling EAP authentication via RADIUS.
type EAPOLAuthenticator interface {
	SendEAPAccessRequest(session *core.Session, eapPayload []byte, state []byte) (*radius.Packet, []byte, error)
}

// CoAIncomingRequest holds a parsed CoA/Disconnect packet and the sender's address.
type CoAIncomingRequest struct {
	Packet *radius.Packet
	Peer   *net.UDPAddr
}

// Client holds the state for the RADIUS client.
type Client struct {
	cfg            *config.Config
	logger         zerolog.Logger
	radsecConns    map[string]net.Conn
	radsecMutex    sync.Mutex
	lastGoodServer int // 0 for server1, 1 for server2
	recorder       metrics.Recorder
}

// NewClient creates a new RADIUS client.
func NewClient(cfg *config.Config, logger zerolog.Logger, recorder metrics.Recorder) *Client {
	if recorder == nil {
		recorder = metrics.NewNoopRecorder()
	}
	return &Client{
		cfg:         cfg,
		logger:      logger.With().Str("component", "radius").Logger(),
		radsecConns: make(map[string]net.Conn),
		recorder:    recorder,
	}
}

func (c *Client) dialRadSec(serverAddr string) (net.Conn, error) {
	cert, err := tls.LoadX509KeyPair(c.cfg.RadSecCertFile, c.cfg.RadSecKeyFile)
	if err != nil {
		return nil, fmt.Errorf("could not load radsec key pair: %w", err)
	}

	caCert, err := os.ReadFile(c.cfg.RadSecCAFile)
	if err != nil {
		return nil, fmt.Errorf("could not load radsec ca file: %w", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	server := fmt.Sprintf("%s:%d", serverAddr, c.cfg.RadSecPort)
	conn, err := tls.Dial("tcp", server, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial radsec server: %w", err)
	}
	c.logger.Info().Str("server", server).Msg("Successfully connected to RadSec server")
	return conn, nil
}

func (c *Client) radsecExchange(packet *radius.Packet, serverAddr string) (*radius.Packet, error) {
	c.radsecMutex.Lock()
	conn := c.radsecConns[serverAddr]
	c.radsecMutex.Unlock()

	if conn == nil {
		var err error
		conn, err = c.dialRadSec(serverAddr)
		if err != nil {
			return nil, err
		}
		c.radsecMutex.Lock()
		c.radsecConns[serverAddr] = conn
		c.radsecMutex.Unlock()
	}

	encoded, err := packet.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode radius packet for radsec: %w", err)
	}

	_, err = conn.Write(encoded)
	if err != nil {
		c.logger.Warn().Err(err).Msg("Failed to write to RadSec connection, will close and attempt redial on next request")
		conn.Close()
		c.radsecMutex.Lock()
		delete(c.radsecConns, serverAddr)
		c.radsecMutex.Unlock()
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		c.logger.Warn().Err(err).Msg("Failed to read from RadSec connection, closing")
		conn.Close()
		c.radsecMutex.Lock()
		delete(c.radsecConns, serverAddr)
		c.radsecMutex.Unlock()
		return nil, fmt.Errorf("failed to read from radsec connection: %w", err)
	}

	response, err := radius.Parse(buf[:n], []byte(c.cfg.RadiusSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to parse radsec response: %w", err)
	}

	return response, nil
}

func (c *Client) exchangeWithFailover(packet *radius.Packet, auth bool) (*radius.Packet, error) {
	servers := []string{c.cfg.RadiusServer1, c.cfg.RadiusServer2}

	// Order of preference: start with the last known good server
	serverOrder := []int{c.lastGoodServer, 1 - c.lastGoodServer}

	// If no secondary server is configured, just try the primary
	if servers[1] == "" {
		serverOrder = []int{0}
	}

	requestType := "acct"
	if auth {
		requestType = "auth"
	}

	var lastErr error
	for _, serverIndex := range serverOrder {
		serverAddr := servers[serverIndex]
		if serverAddr == "" {
			continue // Skip if server is not configured
		}

		now := time.Now()
		labels := metrics.Labels{
			"server": serverAddr,
			"type":   requestType,
		}

		var response *radius.Packet
		var err error

		if c.cfg.RadSecEnable {
			response, err = c.radsecExchange(packet, serverAddr)
		} else {
			port := c.cfg.RadiusAcctPort
			if auth {
				port = c.cfg.RadiusAuthPort
			}
			target := fmt.Sprintf("%s:%d", serverAddr, port)
			c.logger.Debug().Str("server", target).Msg("Sending RADIUS request")
			response, err = radius.Exchange(context.Background(), packet, target)
		}

		c.recorder.ObserveHistogram("chilli_radius_request_duration_seconds", labels, time.Since(now).Seconds())

		if err == nil {
			c.logger.Info().Str("server", serverAddr).Msg("RADIUS request successful")
			c.lastGoodServer = serverIndex // Update last good server
			labels["status"] = "success"
			c.recorder.IncCounter("chilli_radius_requests_total", labels)
			return response, nil
		}

		c.logger.Warn().Err(err).Str("server", serverAddr).Msg("RADIUS request failed")
		labels["status"] = "failure"
		c.recorder.IncCounter("chilli_radius_requests_total", labels)
		lastErr = err
	}

	return nil, fmt.Errorf("all RADIUS servers failed: %w", lastErr)
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

	// Send the packet
	response, err := c.exchangeWithFailover(packet, true)
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
	rfc2866.AcctInputOctets_Set(packet, rfc2866.AcctInputOctets(session.InputOctets))
	rfc2866.AcctOutputOctets_Set(packet, rfc2866.AcctOutputOctets(session.OutputOctets))
	rfc2866.AcctInputPackets_Set(packet, rfc2866.AcctInputPackets(session.InputPackets))
	rfc2866.AcctOutputPackets_Set(packet, rfc2866.AcctOutputPackets(session.OutputPackets))
	rfc2866.AcctSessionTime_Set(packet, rfc2866.AcctSessionTime(session.LastSeen.Sub(session.StartTime).Seconds()))

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

	// Send the packet
	response, err := c.exchangeWithFailover(packet, false)
	if err != nil {
		return nil, fmt.Errorf("failed to send RADIUS Accounting-Request: %w", err)
	}

	c.logger.Debug().Str("code", response.Code.String()).Str("user", session.Redir.Username).Msg("Received RADIUS accounting response")
	return response, nil
}

// SendEAPAccessRequest sends a RADIUS Access-Request with an EAP payload.
// It returns the response packet, the original request's authenticator, and any error.
func (c *Client) SendEAPAccessRequest(session *core.Session, eapPayload []byte, state []byte) (*radius.Packet, []byte, error) {
	packet := radius.New(radius.CodeAccessRequest, []byte(c.cfg.RadiusSecret))

	// Add standard attributes
	rfc2865.UserName_SetString(packet, session.Redir.Username)
	rfc2865.NASIdentifier_SetString(packet, c.cfg.RadiusNASID)
	rfc2865.NASIPAddress_Set(packet, c.cfg.RadiusListen)
	rfc2865.CallingStationID_SetString(packet, session.HisMAC.String())

	// Add EAP and State attributes
	rfc2869.EAPMessage_Set(packet, eapPayload)
	if len(state) > 0 {
		rfc2865.State_Set(packet, state)
	}

	// Store the authenticator before sending, as it's needed for key decryption
	requestAuthenticator := make([]byte, 16)
	copy(requestAuthenticator, packet.Authenticator[:])

	// Send the packet
	response, err := c.exchangeWithFailover(packet, true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to send RADIUS EAP Access-Request: %w", err)
	}

	c.logger.Debug().Str("code", response.Code.String()).Str("user", session.Redir.Username).Msg("Received RADIUS EAP response")
	return response, requestAuthenticator, nil
}

// Vendor-specific attribute constants for Microsoft
const (
	msVendorID      = 311
	msMPPERecvKeyID = 17
)

// GetMSMPPERecvKey extracts the MS-MPPE-Recv-Key from a RADIUS packet.
// This key is often used to carry the Pairwise Master Key (PMK) in 802.1X authentications.
func GetMSMPPERecvKey(p *radius.Packet) []byte {
	for _, avp := range p.Attributes {
		if avp.Type != rfc2865.VendorSpecific_Type {
			continue
		}

		vendorID, value, err := radius.VendorSpecific(avp.Attribute)
		if err != nil || vendorID != msVendorID {
			continue
		}

		// The 'value' is the payload of the VSA, which contains sub-attributes.
		subAttrs := radius.Bytes(value)
		for len(subAttrs) >= 2 {
			subAttrType := subAttrs[0]
			subAttrLen := int(subAttrs[1])
			if subAttrLen < 2 || subAttrLen > len(subAttrs) {
				break // Malformed sub-attribute
			}
			if subAttrType == msMPPERecvKeyID {
				// The key is the value part of the sub-attribute.
				return subAttrs[2:subAttrLen]
			}
			subAttrs = subAttrs[subAttrLen:]
		}
	}
	return nil
}

// SetMSMPPERecvKey adds the MS-MPPE-Recv-Key to a RADIUS packet.
// This is primarily used for testing.
func SetMSMPPERecvKey(p *radius.Packet, key []byte) {
	// Sub-attribute format: Type (1) + Length (1) + Value
	subAttrPayload := make([]byte, 2+len(key))
	subAttrPayload[0] = msMPPERecvKeyID
	subAttrPayload[1] = byte(len(subAttrPayload))
	copy(subAttrPayload[2:], key)

	// NewVendorSpecific wraps the payload with the Vendor ID.
	vsa, err := radius.NewVendorSpecific(msVendorID, radius.Attribute(subAttrPayload))
	if err != nil {
		// For a test helper, panicking is acceptable if something goes wrong.
		panic(err)
	}

	// Add the VSA to the packet's attributes.
	p.Add(rfc2865.VendorSpecific_Type, vsa)
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