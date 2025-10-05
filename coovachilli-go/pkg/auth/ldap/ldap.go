package ldap

import (
	"crypto/tls"
	"fmt"

	"coovachilli-go/pkg/config"
	"github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog"
)

// Authenticate performs user authentication against an LDAP server.
func Authenticate(cfg *config.LDAPConfig, username, password string, logger zerolog.Logger) (bool, error) {
	if !cfg.Enabled {
		return false, nil // LDAP is not enabled, do not treat as an error
	}

	if password == "" {
		return false, nil // LDAP does not support empty passwords
	}

	log := logger.With().Str("component", "ldap_auth").Logger()

	var l *ldap.Conn
	var err error

	addr := fmt.Sprintf("%s:%d", cfg.Server, cfg.Port)

	// Connect to the LDAP server
	if cfg.UseTLS {
		l, err = ldap.DialURL(fmt.Sprintf("ldaps://%s", addr), ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})) // Note: In a real-world scenario, InsecureSkipVerify should be false and CAs should be properly configured.
	} else {
		l, err = ldap.DialURL(fmt.Sprintf("ldap://%s", addr))
	}
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to LDAP server")
		return false, err
	}
	defer l.Close()

	// First, bind with a read-only user to search for the user's DN
	var bindPassword string
	if err := cfg.BindPassword.Access(func(p []byte) error {
		bindPassword = string(p)
		return nil
	}); err != nil {
		log.Error().Err(err).Msg("Failed to access LDAP bind password")
		return false, err
	}

	err = l.Bind(cfg.BindDN, bindPassword)
	if err != nil {
		log.Error().Err(err).Str("bind_dn", cfg.BindDN).Msg("Failed to bind to LDAP with service account")
		return false, err
	}

	// Search for the user to get their full DN
	searchRequest := ldap.NewSearchRequest(
		cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(cfg.UserFilter, ldap.EscapeFilter(username)),
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Error().Err(err).Msg("LDAP search failed")
		return false, err
	}

	if len(sr.Entries) != 1 {
		log.Warn().Str("username", username).Int("entries_found", len(sr.Entries)).Msg("LDAP search did not return exactly one entry")
		return false, nil // User not found or ambiguous
	}

	userDN := sr.Entries[0].DN

	// Second, try to bind as the user with their password
	err = l.Bind(userDN, password)
	if err != nil {
		// This is a normal authentication failure, not a system error
		log.Info().Err(err).Str("user_dn", userDN).Msg("LDAP user authentication failed")
		return false, nil
	}

	log.Info().Str("user_dn", userDN).Msg("LDAP user authenticated successfully")
	return true, nil
}