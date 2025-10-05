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
	"github.com/sony/gobreaker"
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
	packet *radius.Packet
	peer   *net.UDPAddr
}

// Packet returns the underlying RADIUS packet to satisfy the core.CoAContext interface.
func (r *CoAIncomingRequest) Packet() *radius.Packet {
	return r.packet
}

// Peer returns the sender's network address to satisfy the core.CoAContext interface.
func (r *CoAIncomingRequest) Peer() *net.UDPAddr {
	return r.peer
}

// Client holds the state for the RADIUS client.
type Client struct {
	cfg         *config.Config
	logger      zerolog.Logger
	radsecConns map[string]net.Conn
	radsecMutex sync.Mutex
	recorder    metrics.Recorder
	cb          []*gobreaker.CircuitBreaker
}

// NewClient creates a new RADIUS client.
func NewClient(cfg *config.Config, logger zerolog.Logger, recorder metrics.Recorder) *Client {
	if recorder == nil {
		recorder = metrics.NewNoopRecorder()
	}
	client := &Client{
		cfg:         cfg,
		logger:      logger.With().Str("component", "radius").Logger(),
		radsecConns: make(map[string]net.Conn),
		recorder:    recorder,
		cb:          make([]*gobreaker.CircuitBreaker, 2),
	}

	// TODO: Circuit breaker configuration not yet in config.yaml
	// Enable with default settings for now
	_ = cfg // prevent unused variable warning
	st := gobreaker.Settings{
		Name:        "RADIUS Server 1",
		MaxRequests: 100,
		Interval:    60 * time.Second,
		Timeout:     30 * time.Second,
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			logger.Info().Str("name", name).Str("from", from.String()).Str("to", to.String()).Msg("Circuit breaker state changed")
		},
	}
	client.cb[0] = gobreaker.NewCircuitBreaker(st)

	st.Name = "RADIUS Server 2"
	client.cb[1] = gobreaker.NewCircuitBreaker(st)

	return client
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
	dialer := &net.Dialer{Timeout: c.cfg.RadiusTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", server, tlsConfig)
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

	// Set a deadline for the entire request/response exchange.
	if c.cfg.RadiusTimeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(c.cfg.RadiusTimeout)); err != nil {
			c.logger.Error().Err(err).Msg("Failed to set deadline on RadSec connection")
			// Not fatal, we can still try
		}
		defer conn.SetDeadline(time.Time{}) // Clear the deadline
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

	var response *radius.Packet
	parseErr := c.cfg.RadiusSecret.Access(func(secret []byte) (err error) {
		// Create a copy of the secret that will persist after this closure
		secretCopy := make([]byte, len(secret))
		copy(secretCopy, secret)
		response, err = radius.Parse(buf[:n], secretCopy)
		return
	})
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse radsec response: %w", parseErr)
	}

	return response, nil
}

func (c *Client) exchangeWithFailover(packet *radius.Packet, auth bool) (*radius.Packet, error) {
	var servers []string
	requestType := "acct"
	if auth {
		requestType = "auth"
		servers = []string{c.cfg.RadiusServer1, c.cfg.RadiusServer2}
	} else {
		// For accounting, prefer accounting-specific servers if configured
		if c.cfg.RadiusAcctServer1 != "" {
			servers = []string{c.cfg.RadiusAcctServer1, c.cfg.RadiusAcctServer2}
		} else {
			// Fallback to primary servers
			servers = []string{c.cfg.RadiusServer1, c.cfg.RadiusServer2}
		}
	}

	var lastErr error
	for i, serverAddr := range servers {
		if serverAddr == "" {
			continue // Skip if server is not configured
		}

		// If circuit breaker is nil (disabled), execute directly
		if c.cb[i] == nil {
			resp, err := c.executeRequest(packet, serverAddr, auth, requestType)
			if err == nil {
				return resp, nil
			}
			lastErr = err
			continue // Try next server
		}

		// Execute with circuit breaker protection
		resp, err := c.cb[i].Execute(func() (interface{}, error) {
			return c.executeRequest(packet, serverAddr, auth, requestType)
		})

		if err == nil {
			return resp.(*radius.Packet), nil
		}
		lastErr = err
		c.logger.Warn().Err(err).Str("server", serverAddr).Str("state", c.cb[i].State().String()).Msg("Circuit breaker protected RADIUS request failed")
	}

	return nil, fmt.Errorf("all RADIUS servers failed or circuit breakers open: %w", lastErr)
}

// executeRequest performs the actual RADIUS request and is wrapped by the circuit breaker.
func (c *Client) executeRequest(packet *radius.Packet, serverAddr string, auth bool, requestType string) (*radius.Packet, error) {
	now := time.Now()
	labels := map[string]string{
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

		ctx := context.Background()
		if c.cfg.RadiusTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, c.cfg.RadiusTimeout)
			defer cancel()
		}
		response, err = radius.Exchange(ctx, packet, target)
	}

	c.recorder.ObserveHistogram("chilli_radius_request_duration_seconds", labels, time.Since(now).Seconds())

	if err != nil {
		c.logger.Warn().Err(err).Str("server", serverAddr).Msg("RADIUS request failed")
		labels["status"] = "failure"
		c.recorder.IncCounter("chilli_radius_requests_total", labels)
		return nil, err
	}

	c.logger.Info().Str("server", serverAddr).Msg("RADIUS request successful")
	labels["status"] = "success"
	c.recorder.IncCounter("chilli_radius_requests_total", labels)
	return response, nil
}

// SendAccessRequest sends a RADIUS Access-Request packet.
func (c *Client) SendAccessRequest(session *core.Session, username, password string) (*radius.Packet, error) {
	var packet *radius.Packet
	err := c.cfg.RadiusSecret.Access(func(secret []byte) error {
		// Create a copy of the secret that will persist after this closure
		secretCopy := make([]byte, len(secret))
		copy(secretCopy, secret)
		packet = radius.New(radius.CodeAccessRequest, secretCopy)

		// Add standard attributes while the secret is still valid
		rfc2865.UserName_SetString(packet, username)
		rfc2865.UserPassword_SetString(packet, password)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to access RADIUS secret for Access-Request: %w", err)
	}
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
	var packet *radius.Packet
	secretToUse := c.cfg.RadiusSecret
	if c.cfg.RadiusAcctSecret != nil {
		secretToUse = c.cfg.RadiusAcctSecret
	}

	err := secretToUse.Access(func(secret []byte) error {
		// Create a copy of the secret that will persist after this closure
		secretCopy := make([]byte, len(secret))
		copy(secretCopy, secret)
		packet = radius.New(radius.CodeAccountingRequest, secretCopy)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to access RADIUS secret for Accounting-Request: %w", err)
	}

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
	var packet *radius.Packet
	err := c.cfg.RadiusSecret.Access(func(secret []byte) error {
		// Create a copy of the secret that will persist after this closure
		secretCopy := make([]byte, len(secret))
		copy(secretCopy, secret)
		packet = radius.New(radius.CodeAccessRequest, secretCopy)
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to access RADIUS secret for EAP-Request: %w", err)
	}

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
func (c *Client) StartCoAListener(coaReqChan chan<- core.CoAContext) {
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
func (c *Client) listen(network, addr string, coaReqChan chan<- core.CoAContext) {
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

		var packet *radius.Packet
		parseErr := c.cfg.RadiusSecret.Access(func(secret []byte) (err error) {
			// Create a copy of the secret that will persist after this closure
			secretCopy := make([]byte, len(secret))
			copy(secretCopy, secret)
			packet, err = radius.Parse(buf[:n], secretCopy)
			return
		})
		if parseErr != nil {
			c.logger.Error().Err(parseErr).Msg("Failed to parse incoming CoA packet")
			continue
		}

		c.logger.Info().Str("code", packet.Code.String()).Str("peer", peer.String()).Msg("Received CoA/Disconnect request")
		coaReqChan <- &CoAIncomingRequest{
			packet: packet,
			peer:   peer.(*net.UDPAddr),
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