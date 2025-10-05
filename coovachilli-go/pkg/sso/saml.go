package sso

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog"
)

// SAMLConfig holds SAML 2.0 configuration
type SAMLConfig struct {
	Enabled bool `yaml:"enabled" envconfig:"SAML_ENABLED"`

	// Identity Provider (IdP) configuration
	IDPEntityID       string `yaml:"idp_entity_id" envconfig:"SAML_IDP_ENTITY_ID"`
	IDPSSOURL         string `yaml:"idp_sso_url" envconfig:"SAML_IDP_SSO_URL"`
	IDPCertificate    string `yaml:"idp_certificate" envconfig:"SAML_IDP_CERTIFICATE"`     // Path to cert file
	IDPCertificateRaw string `yaml:"idp_certificate_raw" envconfig:"SAML_IDP_CERT_RAW"` // Or PEM string

	// Service Provider (SP) configuration - this server
	SPEntityID              string `yaml:"sp_entity_id" envconfig:"SAML_SP_ENTITY_ID"`
	SPAssertionConsumerURL  string `yaml:"sp_assertion_consumer_url" envconfig:"SAML_SP_ACS_URL"`
	SPPrivateKey            string `yaml:"sp_private_key" envconfig:"SAML_SP_PRIVATE_KEY"` // Path to key file
	SPCertificate           string `yaml:"sp_certificate" envconfig:"SAML_SP_CERTIFICATE"` // Path to cert file

	// Optional settings
	NameIDFormat          string        `yaml:"name_id_format" envconfig:"SAML_NAME_ID_FORMAT"`
	SignRequests          bool          `yaml:"sign_requests" envconfig:"SAML_SIGN_REQUESTS"`
	RequireSignedResponse bool          `yaml:"require_signed_response" envconfig:"SAML_REQUIRE_SIGNED_RESPONSE"`
	MaxClockSkew          time.Duration `yaml:"max_clock_skew" envconfig:"SAML_MAX_CLOCK_SKEW"`

	// Attribute mapping
	UsernameAttribute string `yaml:"username_attribute" envconfig:"SAML_USERNAME_ATTR"` // e.g., "uid", "email"
	EmailAttribute    string `yaml:"email_attribute" envconfig:"SAML_EMAIL_ATTR"`
	GroupsAttribute   string `yaml:"groups_attribute" envconfig:"SAML_GROUPS_ATTR"`
}

// SAMLProvider handles SAML 2.0 authentication
type SAMLProvider struct {
	config     *SAMLConfig
	logger     zerolog.Logger
	idpCert    *x509.Certificate
	spKey      *rsa.PrivateKey
	spCert     *x509.Certificate
}

// SAMLRequest represents a SAML AuthnRequest
type SAMLRequest struct {
	XMLName                     xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                          string    `xml:"ID,attr"`
	Version                     string    `xml:"Version,attr"`
	IssueInstant                time.Time `xml:"IssueInstant,attr"`
	Destination                 string    `xml:"Destination,attr"`
	AssertionConsumerServiceURL string    `xml:"AssertionConsumerServiceURL,attr"`
	ProtocolBinding             string    `xml:"ProtocolBinding,attr"`
	Issuer                      Issuer    `xml:"Issuer"`
	NameIDPolicy                NameIDPolicy `xml:"NameIDPolicy"`
}

type Issuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Value   string   `xml:",chardata"`
}

type NameIDPolicy struct {
	XMLName     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	Format      string   `xml:"Format,attr"`
	AllowCreate bool     `xml:"AllowCreate,attr"`
}

// SAMLResponse represents a SAML Response from IdP
type SAMLResponse struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID           string    `xml:"ID,attr"`
	Version      string    `xml:"Version,attr"`
	IssueInstant time.Time `xml:"IssueInstant,attr"`
	Destination  string    `xml:"Destination,attr"`
	InResponseTo string    `xml:"InResponseTo,attr"`
	Issuer       Issuer    `xml:"Issuer"`
	Status       Status    `xml:"Status"`
	Assertion    Assertion `xml:"Assertion"`
}

type Status struct {
	XMLName    xml.Name   `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	StatusCode StatusCode `xml:"StatusCode"`
}

type StatusCode struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
	Value   string   `xml:"Value,attr"`
}

type Assertion struct {
	XMLName            xml.Name           `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID                 string             `xml:"ID,attr"`
	Version            string             `xml:"Version,attr"`
	IssueInstant       time.Time          `xml:"IssueInstant,attr"`
	Issuer             Issuer             `xml:"Issuer"`
	Subject            Subject            `xml:"Subject"`
	Conditions         Conditions         `xml:"Conditions"`
	AttributeStatement AttributeStatement `xml:"AttributeStatement"`
}

type Subject struct {
	XMLName             xml.Name            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	NameID              NameID              `xml:"NameID"`
	SubjectConfirmation SubjectConfirmation `xml:"SubjectConfirmation"`
}

type NameID struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	Format  string   `xml:"Format,attr"`
	Value   string   `xml:",chardata"`
}

type SubjectConfirmation struct {
	XMLName                 xml.Name                `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
	Method                  string                  `xml:"Method,attr"`
	SubjectConfirmationData SubjectConfirmationData `xml:"SubjectConfirmationData"`
}

type SubjectConfirmationData struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
	NotOnOrAfter time.Time `xml:"NotOnOrAfter,attr"`
	Recipient    string    `xml:"Recipient,attr"`
	InResponseTo string    `xml:"InResponseTo,attr"`
}

type Conditions struct {
	XMLName              xml.Name             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	NotBefore            time.Time            `xml:"NotBefore,attr"`
	NotOnOrAfter         time.Time            `xml:"NotOnOrAfter,attr"`
	AudienceRestriction  AudienceRestriction  `xml:"AudienceRestriction"`
}

type AudienceRestriction struct {
	XMLName  xml.Name   `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
	Audience []Audience `xml:"Audience"`
}

type Audience struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
	Value   string   `xml:",chardata"`
}

type AttributeStatement struct {
	XMLName    xml.Name    `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
	Attributes []Attribute `xml:"Attribute"`
}

type Attribute struct {
	XMLName         xml.Name         `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
	Name            string           `xml:"Name,attr"`
	AttributeValues []AttributeValue `xml:"AttributeValue"`
}

type AttributeValue struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
	Type    string   `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	Value   string   `xml:",chardata"`
}

// SAMLUser represents authenticated user information
type SAMLUser struct {
	NameID     string
	Username   string
	Email      string
	Groups     []string
	Attributes map[string][]string
}

// NewSAMLProvider creates a new SAML provider
func NewSAMLProvider(config *SAMLConfig, logger zerolog.Logger) (*SAMLProvider, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("SAML is not enabled")
	}

	sp := &SAMLProvider{
		config: config,
		logger: logger.With().Str("component", "saml").Logger(),
	}

	// Load IdP certificate
	if err := sp.loadIDPCertificate(); err != nil {
		return nil, fmt.Errorf("failed to load IdP certificate: %w", err)
	}

	// Load SP private key and certificate (if signing is enabled)
	if config.SignRequests {
		if err := sp.loadSPCredentials(); err != nil {
			return nil, fmt.Errorf("failed to load SP credentials: %w", err)
		}
	}

	// Set defaults
	if config.NameIDFormat == "" {
		config.NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	}
	if config.MaxClockSkew == 0 {
		config.MaxClockSkew = 90 * time.Second
	}
	if config.UsernameAttribute == "" {
		config.UsernameAttribute = "uid"
	}

	sp.logger.Info().
		Str("idp_entity_id", config.IDPEntityID).
		Str("sp_entity_id", config.SPEntityID).
		Msg("SAML provider initialized")

	return sp, nil
}

// loadIDPCertificate loads the Identity Provider's certificate
func (sp *SAMLProvider) loadIDPCertificate() error {
	var certPEM []byte
	var err error

	if sp.config.IDPCertificateRaw != "" {
		certPEM = []byte(sp.config.IDPCertificateRaw)
	} else if sp.config.IDPCertificate != "" {
		certPEM, err = ioutil.ReadFile(sp.config.IDPCertificate)
		if err != nil {
			return fmt.Errorf("failed to read certificate file: %w", err)
		}
	} else {
		return fmt.Errorf("no IdP certificate configured")
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	sp.idpCert = cert
	return nil
}

// loadSPCredentials loads the Service Provider's private key and certificate
func (sp *SAMLProvider) loadSPCredentials() error {
	// Load private key
	keyPEM, err := ioutil.ReadFile(sp.config.SPPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to parse private key PEM")
	}

	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS1
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is not RSA")
	}
	sp.spKey = rsaKey

	// Load certificate
	certPEM, err := ioutil.ReadFile(sp.config.SPCertificate)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	sp.spCert = cert
	return nil
}

// BuildAuthURL creates a SAML authentication redirect URL
func (sp *SAMLProvider) BuildAuthURL(relayState string) (string, error) {
	requestID := generateID()

	request := SAMLRequest{
		ID:                          requestID,
		Version:                     "2.0",
		IssueInstant:                time.Now().UTC(),
		Destination:                 sp.config.IDPSSOURL,
		AssertionConsumerServiceURL: sp.config.SPAssertionConsumerURL,
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		Issuer: Issuer{
			Value: sp.config.SPEntityID,
		},
		NameIDPolicy: NameIDPolicy{
			Format:      sp.config.NameIDFormat,
			AllowCreate: true,
		},
	}

	// Marshal to XML
	xmlBytes, err := xml.MarshalIndent(request, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SAML request: %w", err)
	}

	// Base64 encode
	encoded := base64.StdEncoding.EncodeToString(xmlBytes)

	// Build redirect URL
	redirectURL, err := url.Parse(sp.config.IDPSSOURL)
	if err != nil {
		return "", fmt.Errorf("invalid IdP SSO URL: %w", err)
	}

	query := redirectURL.Query()
	query.Set("SAMLRequest", encoded)
	if relayState != "" {
		query.Set("RelayState", relayState)
	}
	redirectURL.RawQuery = query.Encode()

	sp.logger.Info().
		Str("request_id", requestID).
		Str("relay_state", relayState).
		Msg("SAML AuthnRequest created")

	return redirectURL.String(), nil
}

// HandleCallback processes the SAML response from IdP
func (sp *SAMLProvider) HandleCallback(r *http.Request) (*SAMLUser, error) {
	// Get SAMLResponse from POST
	samlResponse := r.FormValue("SAMLResponse")
	if samlResponse == "" {
		return nil, fmt.Errorf("no SAMLResponse in request")
	}

	// Base64 decode
	xmlBytes, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SAMLResponse: %w", err)
	}

	// Parse XML
	var response SAMLResponse
	if err := xml.Unmarshal(xmlBytes, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal SAMLResponse: %w", err)
	}

	// Validate response
	if err := sp.validateResponse(&response); err != nil {
		return nil, fmt.Errorf("invalid SAML response: %w", err)
	}

	// Extract user information
	user := sp.extractUserInfo(&response)

	sp.logger.Info().
		Str("username", user.Username).
		Str("email", user.Email).
		Strs("groups", user.Groups).
		Msg("SAML authentication successful")

	return user, nil
}

// validateResponse validates the SAML response
func (sp *SAMLProvider) validateResponse(response *SAMLResponse) error {
	// Check status
	if response.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return fmt.Errorf("authentication failed: %s", response.Status.StatusCode.Value)
	}

	// Check issuer
	if response.Issuer.Value != sp.config.IDPEntityID {
		return fmt.Errorf("invalid issuer: expected %s, got %s", sp.config.IDPEntityID, response.Issuer.Value)
	}

	// Check destination
	if response.Destination != sp.config.SPAssertionConsumerURL {
		return fmt.Errorf("invalid destination: expected %s, got %s", sp.config.SPAssertionConsumerURL, response.Destination)
	}

	// Check assertion conditions
	assertion := &response.Assertion
	now := time.Now().UTC()

	// Check time validity with clock skew
	notBefore := assertion.Conditions.NotBefore.Add(-sp.config.MaxClockSkew)
	notOnOrAfter := assertion.Conditions.NotOnOrAfter.Add(sp.config.MaxClockSkew)

	if now.Before(notBefore) {
		return fmt.Errorf("assertion not yet valid (NotBefore: %s, now: %s)", notBefore, now)
	}

	if now.After(notOnOrAfter) {
		return fmt.Errorf("assertion expired (NotOnOrAfter: %s, now: %s)", notOnOrAfter, now)
	}

	// Check audience
	validAudience := false
	for _, audience := range assertion.Conditions.AudienceRestriction.Audience {
		if audience.Value == sp.config.SPEntityID {
			validAudience = true
			break
		}
	}
	if !validAudience {
		return fmt.Errorf("invalid audience: SP entity ID not in audience restriction")
	}

	// TODO: Verify signature if RequireSignedResponse is true
	// This requires implementing XML signature verification

	return nil
}

// extractUserInfo extracts user information from SAML assertion
func (sp *SAMLProvider) extractUserInfo(response *SAMLResponse) *SAMLUser {
	user := &SAMLUser{
		NameID:     response.Assertion.Subject.NameID.Value,
		Attributes: make(map[string][]string),
	}

	// Extract attributes
	for _, attr := range response.Assertion.AttributeStatement.Attributes {
		values := make([]string, 0, len(attr.AttributeValues))
		for _, val := range attr.AttributeValues {
			values = append(values, val.Value)
		}
		user.Attributes[attr.Name] = values

		// Map to standard fields
		switch attr.Name {
		case sp.config.UsernameAttribute:
			if len(values) > 0 {
				user.Username = values[0]
			}
		case sp.config.EmailAttribute:
			if len(values) > 0 {
				user.Email = values[0]
			}
		case sp.config.GroupsAttribute:
			user.Groups = values
		}
	}

	// Fallback to NameID if username not found
	if user.Username == "" {
		user.Username = user.NameID
	}

	return user
}

// generateID generates a unique SAML request ID
func generateID() string {
	return fmt.Sprintf("__%d", time.Now().UnixNano())
}
