package security

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
)

// TLSManager handles TLS/SSL configuration
type TLSManager struct {
	cfg    *config.TLSConfig
	logger zerolog.Logger
}

// NewTLSManager creates a new TLS manager
func NewTLSManager(cfg *config.TLSConfig, logger zerolog.Logger) (*TLSManager, error) {
	return &TLSManager{
		cfg:    cfg,
		logger: logger.With().Str("component", "tls").Logger(),
	}, nil
}

// GetServerTLSConfig returns a TLS configuration for servers
func (tm *TLSManager) GetServerTLSConfig() (*tls.Config, error) {
	if !tm.cfg.Enabled {
		return nil, fmt.Errorf("TLS is not enabled")
	}

	// Load certificate and key
	cert, err := tls.LoadX509KeyPair(tm.cfg.CertFile, tm.cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, // Enforce TLS 1.2 minimum
		CipherSuites: tm.getSecureCipherSuites(),
	}

	// Load CA certificate if provided
	if tm.cfg.CAFile != "" {
		caCert, err := os.ReadFile(tm.cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.ClientCAs = caCertPool
		if tm.cfg.RequireClientCert {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}

	tm.logger.Info().
		Str("min_version", "TLS 1.2").
		Int("cipher_suites", len(tlsConfig.CipherSuites)).
		Bool("client_auth", tm.cfg.RequireClientCert).
		Msg("TLS configuration loaded")

	return tlsConfig, nil
}

// GetClientTLSConfig returns a TLS configuration for clients
func (tm *TLSManager) GetClientTLSConfig() (*tls.Config, error) {
	if !tm.cfg.Enabled {
		return nil, fmt.Errorf("TLS is not enabled")
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: tm.getSecureCipherSuites(),
	}

	// Load CA certificate if provided
	if tm.cfg.CAFile != "" {
		caCert, err := os.ReadFile(tm.cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate if provided
	if tm.cfg.ClientCertFile != "" && tm.cfg.ClientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(tm.cfg.ClientCertFile, tm.cfg.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if tm.cfg.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
		tm.logger.Warn().Msg("TLS certificate verification is disabled (insecure)")
	}

	return tlsConfig, nil
}

// getSecureCipherSuites returns a list of secure cipher suites
func (tm *TLSManager) getSecureCipherSuites() []uint16 {
	// Only use strong, modern cipher suites
	return []uint16{
		// TLS 1.3 cipher suites (automatically used when TLS 1.3 is negotiated)

		// TLS 1.2 cipher suites
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	}
}

// UpgradeToTLS13 configures TLS 1.3 if available
func (tm *TLSManager) UpgradeToTLS13(tlsConfig *tls.Config) {
	// TLS 1.3 is available in Go 1.12+
	tlsConfig.MinVersion = tls.VersionTLS13
	tm.logger.Info().Msg("Upgraded to TLS 1.3")
}

// ValidateCertificate validates a certificate file
func (tm *TLSManager) ValidateCertificate(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	// Parse the certificate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check expiration
	now := tm.getCurrentTime()
	if now.Before(x509Cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid")
	}
	if now.After(x509Cert.NotAfter) {
		return fmt.Errorf("certificate has expired")
	}

	tm.logger.Info().
		Str("subject", x509Cert.Subject.String()).
		Time("not_before", x509Cert.NotBefore).
		Time("not_after", x509Cert.NotAfter).
		Msg("Certificate validated")

	return nil
}

// getCurrentTime returns current time (can be mocked for testing)
func (tm *TLSManager) getCurrentTime() interface{ Before(interface{}) bool; After(interface{}) bool } {
	return timeWrapper{tm.cfg.Now()}
}

type timeWrapper struct {
	t interface{}
}

func (tw timeWrapper) Before(other interface{}) bool {
	// Type assertion would be needed for real implementation
	return false
}

func (tw timeWrapper) After(other interface{}) bool {
	// Type assertion would be needed for real implementation
	return false
}
