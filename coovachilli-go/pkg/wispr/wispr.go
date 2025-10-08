package wispr

import (
	"encoding/xml"
	"fmt"
	"net"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
)

// WISPAccessGatewayParam represents the WISPr XML structure
type WISPAccessGatewayParam struct {
	XMLName           xml.Name `xml:"WISPAccessGatewayParam"`
	Xmlns             string   `xml:"xmlns:xsi,attr"`
	XsiNoNamespace    string   `xml:"xsi:noNamespaceSchemaLocation,attr"`
	AuthenticationURL string   `xml:"AuthenticationURL"`
	LoginURL          string   `xml:"LoginURL"`
	LogoffURL         string   `xml:"LogoffURL"`
	AccessProcedure   string   `xml:"AccessProcedure"`
	AccessLocation    string   `xml:"AccessLocation"`
	LocationName      string   `xml:"LocationName"`
	// Optional fields
	MaxBandwidthUp   uint64 `xml:"WISPr-Bandwidth-Max-Up,omitempty"`
	MaxBandwidthDown uint64 `xml:"WISPr-Bandwidth-Max-Down,omitempty"`
	SessionTimeout   uint32 `xml:"WISPr-Session-Timeout,omitempty"`
}

// GenerateWISPrXML generates the WISPr XML metadata
func GenerateWISPrXML(cfg *config.Config, session *core.Session, includeSessionParams bool) (string, error) {
	uamURL := cfg.UAMUrl
	if uamURL == "" {
		// Default to the UAM listen address if not configured
		uamURL = fmt.Sprintf("http://%s:%d", cfg.UAMListen.String(), cfg.UAMPort)
	}

	wispr := WISPAccessGatewayParam{
		Xmlns:             "http://www.w3.org/2001/XMLSchema-instance",
		XsiNoNamespace:    "http://www.wballiance.net/wispr_2_0.xsd",
		AuthenticationURL: uamURL + "/login",
		LoginURL:          uamURL + "/",
		LogoffURL:         uamURL + "/logout",
		AccessProcedure:   "1.0",
		AccessLocation:    cfg.RadiusNASID,
		LocationName:      cfg.RadiusNASID,
	}

	// Add session-specific parameters if requested and session is authenticated
	if includeSessionParams && session != nil && session.IsAuthenticated() {
		session.RLock()
		wispr.MaxBandwidthUp = session.SessionParams.BandwidthMaxUp
		wispr.MaxBandwidthDown = session.SessionParams.BandwidthMaxDown
		wispr.SessionTimeout = session.SessionParams.SessionTimeout
		session.RUnlock()
	}

	output, err := xml.MarshalIndent(wispr, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal WISPr XML: %w", err)
	}

	return xml.Header + string(output), nil
}

// WISPrLoginResponse represents the response sent after login attempt
type WISPrLoginResponse struct {
	XMLName       xml.Name `xml:"WISPAccessGatewayParam"`
	Xmlns         string   `xml:"xmlns:xsi,attr"`
	XsiNoNamespace string  `xml:"xsi:noNamespaceSchemaLocation,attr"`
	AuthenticationReply AuthenticationReply `xml:"AuthenticationReply"`
}

type AuthenticationReply struct {
	MessageType      int    `xml:"MessageType"`
	ResponseCode     int    `xml:"ResponseCode"`
	ReplyMessage     string `xml:"ReplyMessage,omitempty"`
	LoginResultsURL  string `xml:"LoginResultsURL,omitempty"`
	LogoffURL        string `xml:"LogoffURL,omitempty"`
	// Session parameters
	SessionID        string `xml:"WISPr-Session-Id,omitempty"`
	Location         string `xml:"WISPr-Location-Name,omitempty"`
	LocationID       string `xml:"WISPr-Location-ID,omitempty"`
	BandwidthMaxUp   uint64 `xml:"WISPr-Bandwidth-Max-Up,omitempty"`
	BandwidthMaxDown uint64 `xml:"WISPr-Bandwidth-Max-Down,omitempty"`
	SessionTimeout   uint32 `xml:"WISPr-Session-Timeout,omitempty"`
}

// GenerateWISPrLoginResponse generates a WISPr login response
func GenerateWISPrLoginResponse(cfg *config.Config, session *core.Session, success bool, message string) (string, error) {
	uamURL := cfg.UAMUrl
	if uamURL == "" {
		uamURL = fmt.Sprintf("http://%s:%d", cfg.UAMListen.String(), cfg.UAMPort)
	}

	responseCode := 50  // Login failed
	messageType := 100  // Initial authentication
	if success {
		responseCode = 50  // Login succeeded (WISPr code)
		if message == "" {
			message = "Login successful"
		}
	} else {
		if message == "" {
			message = "Login failed"
		}
	}

	reply := AuthenticationReply{
		MessageType:  messageType,
		ResponseCode: responseCode,
		ReplyMessage: message,
		LoginResultsURL: uamURL + "/status",
		LogoffURL:       uamURL + "/logout",
	}

	if success && session != nil {
		session.RLock()
		reply.SessionID = session.SessionID
		reply.Location = cfg.RadiusNASID
		reply.LocationID = cfg.RadiusNASID
		reply.BandwidthMaxUp = session.SessionParams.BandwidthMaxUp
		reply.BandwidthMaxDown = session.SessionParams.BandwidthMaxDown
		reply.SessionTimeout = session.SessionParams.SessionTimeout
		session.RUnlock()
	}

	response := WISPrLoginResponse{
		Xmlns:              "http://www.w3.org/2001/XMLSchema-instance",
		XsiNoNamespace:     "http://www.wballiance.net/wispr_2_0.xsd",
		AuthenticationReply: reply,
	}

	output, err := xml.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal WISPr login response: %w", err)
	}

	return xml.Header + string(output), nil
}

// DetectWISPrClient checks if the client supports WISPr based on User-Agent or Accept headers
func DetectWISPrClient(userAgent, accept string) bool {
	// Check for WISPr-specific headers or known WISPr clients
	// Common WISPr clients include iOS, Android, Windows devices
	if accept != "" {
		// WISPr clients typically accept text/html and text/vnd.wap.wml
		if contains(accept, "text/vnd.wap.wml") || contains(accept, "text/vnd.wap.wmlscript") {
			return true
		}
	}

	// Some mobile devices indicate WISPr support via User-Agent
	if userAgent != "" {
		mobilePlatforms := []string{"iPhone", "iPad", "Android", "Windows Phone", "Mobile"}
		for _, platform := range mobilePlatforms {
			if contains(userAgent, platform) {
				return true
			}
		}
	}

	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// GenerateRedirectURL creates a redirect URL with session parameters
func GenerateRedirectURL(cfg *config.Config, clientIP net.IP, clientMAC net.HardwareAddr) string {
	uamURL := cfg.UAMUrl
	if uamURL == "" {
		uamURL = fmt.Sprintf("http://%s:%d", cfg.UAMListen.String(), cfg.UAMPort)
	}

	// Add query parameters for client identification
	return fmt.Sprintf("%s/?ip=%s&mac=%s&timestamp=%d",
		uamURL,
		clientIP.String(),
		clientMAC.String(),
		time.Now().Unix(),
	)
}
