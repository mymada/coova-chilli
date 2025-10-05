#!/bin/sh

# Exit immediately if a command exits with a non-zero status.
set -e
# Print commands and their arguments as they are executed.
set -x

echo "--- Running Integration Tests ---"

# The client container should get a DHCP lease automatically from chilli.
# We'll wait a few seconds to ensure the network is up.
sleep 5

echo "1. Testing access to walled garden (should succeed)..."
# Use curl to check if we can access the webserver in the walled garden.
# --fail: Fail silently (no output) on HTTP errors
# --silent: Don't show progress meter
# --show-error: If --fail is used, show the error on stderr
if curl --fail --silent --show-error http://10.1.0.254 | grep -q "Success!"; then
    echo "Walled garden access successful."
else
    echo "ERROR: Failed to access the walled garden."
    exit 1
fi

echo ""
echo "2. Testing access to external site (should fail)..."
# We expect this curl command to fail (either by timeout or redirection).
# The '!' inverts the exit code, so the script succeeds if curl fails.
if ! curl --fail --silent --max-time 5 http://www.google.com; then
    echo "External site access correctly blocked."
else
    echo "ERROR: External site was accessible, but should have been blocked."
    exit 1
fi

echo ""
echo "--- Integration Tests Passed ---"
exit 0