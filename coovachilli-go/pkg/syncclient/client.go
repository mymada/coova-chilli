package syncclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"coovachilli-go/pkg/config"
	"github.com/rs/zerolog"
)

// SyncClient is responsible for fetching configuration from a remote management server.
type SyncClient struct {
	cfg        *config.ManagementConfig
	logger     zerolog.Logger
	httpClient *http.Client
}

// New creates a new SyncClient.
func New(cfg *config.ManagementConfig, logger zerolog.Logger) *SyncClient {
	return &SyncClient{
		cfg:    cfg,
		logger: logger.With().Str("component", "sync_client").Logger(),
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// FetchConfig fetches the latest configuration from the remote management server.
func (c *SyncClient) FetchConfig(ctx context.Context) (*config.Config, error) {
	if !c.cfg.Enabled {
		return nil, fmt.Errorf("remote management is not enabled")
	}

	// Construct the request URL, e.g., http://host/api/v1/instances/instance-id/config
	url := fmt.Sprintf("%s/api/v1/instances/%s/config", c.cfg.ServerURL, c.cfg.InstanceID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication token to the header
	var authToken string
	if err := c.cfg.AuthToken.Access(func(p []byte) error {
		authToken = string(p)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to access management auth token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Accept", "application/json")

	c.logger.Info().Str("url", url).Msg("Fetching configuration from remote server")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request to management server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("management server returned non-200 status: %d", resp.StatusCode)
	}

	var newConfig config.Config
	if err := json.NewDecoder(resp.Body).Decode(&newConfig); err != nil {
		return nil, fmt.Errorf("failed to decode configuration response: %w", err)
	}

	c.logger.Info().Msg("Successfully fetched new configuration")
	return &newConfig, nil
}