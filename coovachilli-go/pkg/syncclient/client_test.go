package syncclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/securestore"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestFetchConfig_Success(t *testing.T) {
	// 1. Setup a mock server
	expectedToken := "test-token"
	expectedInstanceID := "test-instance"
	expectedConfig := &config.Config{
		UAMPort: 9999, // A value to check
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Assert that the request is correct
		expectedURL := "/api/v1/instances/" + expectedInstanceID + "/config"
		require.Equal(t, expectedURL, r.URL.Path)
		require.Equal(t, "GET", r.Method)

		authHeader := r.Header.Get("Authorization")
		require.Equal(t, "Bearer "+expectedToken, authHeader, "Authorization header is missing or incorrect")

		// Send back the mock config
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expectedConfig)
	}))
	defer mockServer.Close()

	// 2. Setup the SyncClient
	mgmtConfig := &config.ManagementConfig{
		Enabled:      true,
		ServerURL:    mockServer.URL,
		InstanceID:   expectedInstanceID,
		AuthToken:    securestore.NewSecret(expectedToken),
	}
	client := New(mgmtConfig, zerolog.Nop())

	// 3. Perform the fetch
	newConfig, err := client.FetchConfig(context.Background())

	// 4. Assert the results
	require.NoError(t, err, "FetchConfig should not return an error on success")
	require.NotNil(t, newConfig, "Returned config should not be nil")
	require.Equal(t, expectedConfig.UAMPort, newConfig.UAMPort, "The fetched config does not match the expected config")
}

func TestFetchConfig_ServerError(t *testing.T) {
	// 1. Setup a mock server that returns an error
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mockServer.Close()

	// 2. Setup the SyncClient
	mgmtConfig := &config.ManagementConfig{
		Enabled:      true,
		ServerURL:    mockServer.URL,
		InstanceID:   "any-instance",
		AuthToken:    securestore.NewSecret("any-token"),
	}
	client := New(mgmtConfig, zerolog.Nop())

	// 3. Perform the fetch
	_, err := client.FetchConfig(context.Background())

	// 4. Assert that an error was returned
	require.Error(t, err, "FetchConfig should return an error when the server returns a non-200 status")
	require.Contains(t, err.Error(), "non-200 status: 500", "Error message should indicate a server error")
}