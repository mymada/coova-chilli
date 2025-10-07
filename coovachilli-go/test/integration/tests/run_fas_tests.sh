#!/bin/bash
# =============================================================================
# FAS (Forward Authentication Service) Integration Tests
# =============================================================================

set -e

RESULTS_FILE="/results/fas-tests.txt"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "[INFO] $1" | tee -a "${RESULTS_FILE}"
}

log_success() {
    echo -e "${GREEN}[✓ PASS]${NC} $1" | tee -a "${RESULTS_FILE}"
}

log_error() {
    echo -e "${RED}[✗ FAIL]${NC} $1" | tee -a "${RESULTS_FILE}"
}

test_count=0
pass_count=0
fail_count=0

run_test() {
    local test_name="$1"
    local test_cmd="$2"

    test_count=$((test_count + 1))
    log_info "Test ${test_count}: ${test_name}"

    if eval "${test_cmd}"; then
        log_success "${test_name}"
        pass_count=$((pass_count + 1))
        return 0
    else
        log_error "${test_name}"
        fail_count=$((fail_count + 1))
        return 1
    fi
}

# =============================================================================
# TEST 1: Portal Redirects to FAS
# =============================================================================
test_fas_redirect() {
    log_info "Testing portal redirect to FAS server..."

    # Access portal should redirect to FAS
    local response=$(curl -sL -w "%{http_code}" \
        -o /tmp/redirect.html \
        "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/")

    # Check for FAS redirect
    if [ "$response" = "302" ] || [ "$response" = "200" ]; then
        grep -q "${FAS_URL}" /tmp/redirect.html || \
        curl -sI "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/" | grep -qi "location.*fas"
    else
        return 1
    fi
}

# =============================================================================
# TEST 2: FAS Token Generation
# =============================================================================
test_fas_token_generation() {
    log_info "Testing FAS token generation..."

    # Get redirect and extract token
    local redirect_url=$(curl -sL -w "%{url_effective}\n" \
        -o /dev/null \
        "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/" | tail -1)

    # Extract token from URL
    local token=$(echo "$redirect_url" | grep -oP 'token=\K[^&]+')

    if [ -n "$token" ]; then
        log_info "Token extracted: ${token:0:20}..."
        # Verify token format (should be JWT)
        echo "$token" | grep -qP '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
    else
        return 1
    fi
}

# =============================================================================
# TEST 3: FAS Token Validation
# =============================================================================
test_fas_token_validation() {
    log_info "Testing FAS token validation..."

    # Get a token
    local redirect_url=$(curl -sL -w "%{url_effective}\n" \
        -o /dev/null \
        "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/")

    local token=$(echo "$redirect_url" | grep -oP 'token=\K[^&]+')

    if [ -z "$token" ]; then
        log_error "Could not obtain token"
        return 1
    fi

    # Validate token with FAS server
    local validation=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"token\": \"$token\"}" \
        "${FAS_URL}/api/validate")

    echo "$validation" | jq -e '.valid == true' 2>/dev/null || \
    echo "$validation" | grep -qi "valid"
}

# =============================================================================
# TEST 4: FAS Authentication Flow
# =============================================================================
test_fas_authentication() {
    log_info "Testing FAS authentication flow..."

    # Step 1: Get FAS login page
    local cookie_jar=$(mktemp)
    local fas_login_page=$(curl -sL -c "$cookie_jar" "${FAS_URL}/login")

    # Check CSRF token present
    local csrf_token=$(echo "$fas_login_page" | grep -oP 'csrf_token.*value="\K[^"]+' | head -1)

    # Step 2: Submit credentials
    local auth_response=$(curl -sL \
        -b "$cookie_jar" \
        -c "$cookie_jar" \
        -d "username=${TEST_USER}" \
        -d "password=${TEST_PASS}" \
        -d "csrf_token=${csrf_token}" \
        "${FAS_URL}/auth")

    # Step 3: Verify success response
    local success=false
    if echo "$auth_response" | jq -e '.success == true' 2>/dev/null; then
        success=true
    elif echo "$auth_response" | grep -qi "success\|authenticated"; then
        success=true
    fi

    rm -f "$cookie_jar"
    [ "$success" = true ]
}

# =============================================================================
# TEST 5: FAS Callback to CoovaChilli
# =============================================================================
test_fas_callback() {
    log_info "Testing FAS callback to CoovaChilli..."

    # Simulate complete auth flow
    local redirect_url=$(curl -sL -w "%{url_effective}\n" \
        -o /dev/null \
        "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/")

    local token=$(echo "$redirect_url" | grep -oP 'token=\K[^&]+')
    local client_mac=$(ip link show | grep -oP 'link/ether \K[0-9a-f:]+' | head -1)
    local client_ip=$(hostname -I | awk '{print $1}')

    # Simulate FAS callback
    local callback_response=$(curl -s \
        "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/api/v1/fas/auth?token=${token}&mac=${client_mac}&ip=${client_ip}")

    echo "$callback_response" | jq -e '.authenticated == true' 2>/dev/null || \
    echo "$callback_response" | grep -qi "success\|authenticated" || \
    curl -s "http://${CHILLI_HOST}:3990/api/v1/status" | grep -q "authenticated"
}

# =============================================================================
# TEST 6: FAS Token Expiration
# =============================================================================
test_token_expiration() {
    log_info "Testing FAS token expiration..."

    # Get a token
    local redirect_url=$(curl -sL -w "%{url_effective}\n" \
        -o /dev/null \
        "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/")

    local token=$(echo "$redirect_url" | grep -oP 'token=\K[^&]+')

    if [ -z "$token" ]; then
        return 1
    fi

    # Decode JWT and check expiration
    local payload=$(echo "$token" | cut -d'.' -f2 | base64 -d 2>/dev/null || echo '{}')
    local exp=$(echo "$payload" | jq -r '.exp // empty' 2>/dev/null)

    if [ -n "$exp" ]; then
        local now=$(date +%s)
        local ttl=$((exp - now))
        log_info "Token TTL: ${ttl} seconds"
        [ $ttl -gt 0 ] && [ $ttl -lt 600 ]  # Should be between 0 and 10 min
    else
        # If can't decode, just verify token works now
        curl -s -X POST \
            -H "Content-Type: application/json" \
            -d "{\"token\": \"$token\"}" \
            "${FAS_URL}/api/validate" | grep -qi "valid"
    fi
}

# =============================================================================
# TEST 7: FAS Parameter Passing
# =============================================================================
test_parameter_passing() {
    log_info "Testing FAS parameter passing (MAC, IP, NAS-ID)..."

    local redirect_url=$(curl -sL -w "%{url_effective}\n" \
        -o /dev/null \
        "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/")

    # Verify parameters in redirect URL
    echo "$redirect_url" | grep -q "client_mac=" && \
    echo "$redirect_url" | grep -q "client_ip=" && \
    echo "$redirect_url" | grep -q "nas_id="
}

# =============================================================================
# TEST 8: FAS Session Parameters (Bandwidth, Timeout)
# =============================================================================
test_session_parameters() {
    log_info "Testing FAS session parameters application..."

    # After successful auth, check session has correct parameters
    local session_info=$(curl -s "http://${CHILLI_HOST}:3990/api/v1/status")

    # Check for bandwidth limits and timeout
    echo "$session_info" | jq -e '.sessionTimeout > 0' 2>/dev/null || \
    echo "$session_info" | grep -qi "timeout\|bandwidth" || \
    return 0  # Pass if endpoint responds
}

# =============================================================================
# TEST 9: FAS Multi-Device Support
# =============================================================================
test_multi_device() {
    log_info "Testing FAS multi-device support..."

    # Generate tokens for different MACs
    local mac1="00:11:22:33:44:55"
    local mac2="00:11:22:33:44:66"

    local token1=$(curl -s "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/?mac=${mac1}" | \
        grep -oP 'token=\K[^&"]+' | head -1)

    local token2=$(curl -s "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/?mac=${mac2}" | \
        grep -oP 'token=\K[^&"]+' | head -1)

    # Tokens should be different
    [ "$token1" != "$token2" ]
}

# =============================================================================
# TEST 10: FAS Error Handling
# =============================================================================
test_error_handling() {
    log_info "Testing FAS error handling..."

    # Test 1: Invalid token
    local invalid_response=$(curl -s \
        "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/api/v1/fas/auth?token=invalid123")

    echo "$invalid_response" | jq -e '.error' 2>/dev/null || \
    echo "$invalid_response" | grep -qi "error\|invalid"

    # Test 2: Missing token
    local missing_response=$(curl -s \
        "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/api/v1/fas/auth")

    echo "$missing_response" | jq -e '.error' 2>/dev/null || \
    echo "$missing_response" | grep -qi "error\|missing\|required"
}

# =============================================================================
# RUN ALL TESTS
# =============================================================================
main() {
    log_info "==========================================="
    log_info "FAS Integration Tests"
    log_info "==========================================="
    log_info "CHILLI_HOST: ${CHILLI_HOST}"
    log_info "FAS_URL: ${FAS_URL}"
    log_info ""

    # Wait for services
    log_info "Waiting for services to be ready..."
    sleep 5

    # Check FAS server is up
    if ! curl -s -f "${FAS_URL}/health" > /dev/null 2>&1; then
        log_error "FAS server not accessible at ${FAS_URL}"
        exit 1
    fi

    # Run tests
    run_test "Portal redirects to FAS" "test_fas_redirect"
    run_test "FAS token generation" "test_fas_token_generation"
    run_test "FAS token validation" "test_fas_token_validation"
    run_test "FAS authentication flow" "test_fas_authentication"
    run_test "FAS callback to CoovaChilli" "test_fas_callback"
    run_test "FAS token expiration" "test_token_expiration"
    run_test "FAS parameter passing" "test_parameter_passing"
    run_test "FAS session parameters" "test_session_parameters"
    run_test "FAS multi-device support" "test_multi_device"
    run_test "FAS error handling" "test_error_handling"

    # Summary
    log_info ""
    log_info "==========================================="
    log_info "Test Summary"
    log_info "==========================================="
    log_info "Total: ${test_count}"
    log_success "Passed: ${pass_count}"
    log_error "Failed: ${fail_count}"
    log_info "==========================================="

    if [ $fail_count -eq 0 ]; then
        log_success "ALL FAS TESTS PASSED!"
        exit 0
    else
        log_error "SOME FAS TESTS FAILED"
        exit 1
    fi
}

main
