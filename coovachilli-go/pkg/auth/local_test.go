package auth

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthenticateLocalUser(t *testing.T) {
	// Create a temporary user file
	content := []byte("testuser:testpass\nadmin:secret")
	tmpfile, err := ioutil.TempFile("", "localusers")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name()) // clean up

	_, err = tmpfile.Write(content)
	require.NoError(t, err)
	err = tmpfile.Close()
	require.NoError(t, err)

	// Test successful authentication
	ok, err := AuthenticateLocalUser(tmpfile.Name(), "testuser", "testpass")
	require.NoError(t, err)
	require.True(t, ok, "Should have authenticated successfully")

	// Test incorrect password
	ok, err = AuthenticateLocalUser(tmpfile.Name(), "testuser", "wrongpass")
	require.NoError(t, err)
	require.False(t, ok, "Should have failed with incorrect password")

	// Test non-existent user
	ok, err = AuthenticateLocalUser(tmpfile.Name(), "nosuchuser", "somepass")
	require.NoError(t, err)
	require.False(t, ok, "Should have failed for non-existent user")

	// Test with non-existent file
	_, err = AuthenticateLocalUser("nonexistentfile", "user", "pass")
	require.Error(t, err, "Should have failed for non-existent file")
}