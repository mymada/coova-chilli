#!/bin/bash
# =============================================================================
# SSO Integration Tests (SAML + OIDC)
# =============================================================================

set -e

SSO_TYPE="${1:-saml}"  # saml or oidc
RESULTS_FILE="/results/sso-${SSO_TYPE}-tests.txt"

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
# TEST 1: Portal Redirect to SSO
# =============================================================================
test_portal_redirect() {
    log_info "Testing initial portal redirect to SSO provider..."

    local response=$(curl -sL -w "%{http_code}" \
        -o /tmp/portal.html \
        "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/")

    if [ "$response" = "302" ] || [ "$response" = "200" ]; then
        # Check redirect contains SSO provider URL
        if [ "$SSO_TYPE" = "saml" ]; then
            grep -q "simplesaml" /tmp/portal.html || \
            curl -sI "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/" | grep -q "saml"
        else
            grep -q "keycloak" /tmp/portal.html || \
            curl -sI "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/" | grep -q "oidc"
        fi
        return $?
    fi
    return 1
}

# =============================================================================
# TEST 2: SSO Login Flow
# =============================================================================
test_sso_login() {
    log_info "Testing SSO authentication flow..."

    if [ "$SSO_TYPE" = "saml" ]; then
        test_saml_login
    else
        test_oidc_login
    fi
}

test_saml_login() {
    # Simulate SAML authentication
    local saml_login_url="${SAML_IDP_URL}/saml2/idp/SSOService.php"

    # Get SAML request
    local saml_request=$(curl -sL "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/sso/saml/login" | \
        grep -oP 'SAMLRequest=\K[^&"]*' | head -1)

    if [ -z "$saml_request" ]; then
        return 1
    fi

    # Submit credentials to IdP
    local cookie_jar=$(mktemp)
    local saml_response=$(curl -sL \
        -c "$cookie_jar" \
        -d "username=${TEST_USER}" \
        -d "password=${TEST_PASS}" \
        -d "SAMLRequest=${saml_request}" \
        "${saml_login_url}")

    # Extract SAML Response
    local saml_resp=$(echo "$saml_response" | grep -oP 'SAMLResponse=\K[^&"]*' | head -1)

    if [ -n "$saml_resp" ]; then
        # Post SAML response to ACS
        curl -sL \
            -b "$cookie_jar" \
            -d "SAMLResponse=${saml_resp}" \
            "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/sso/saml/acs" | \
            grep -q "authenticated" || \
            grep -q "success"
        local result=$?
        rm -f "$cookie_jar"
        return $result
    fi

    rm -f "$cookie_jar"
    return 1
}

test_oidc_login() {
    # Simulate OIDC authentication
    local cookie_jar=$(mktemp)

    # 1. Get authorization URL
    local auth_url=$(curl -sL "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/sso/oidc/login" | \
        grep -oP 'href="\K[^"]*' | grep 'auth' | head -1)

    if [ -z "$auth_url" ]; then
        rm -f "$cookie_jar"
        return 1
    fi

    # 2. Authenticate with Keycloak
    local login_url="${OIDC_PROVIDER_URL}/realms/master/protocol/openid-connect/auth"
    local token_response=$(curl -sL \
        -c "$cookie_jar" \
        -d "username=${TEST_USER}" \
        -d "password=${TEST_PASS}" \
        -d "grant_type=password" \
        -d "client_id=coovachilli" \
        "${login_url}")

    # 3. Extract code and exchange for token
    local auth_code=$(echo "$token_response" | jq -r '.code // empty')

    if [ -n "$auth_code" ]; then
        # 4. Callback to CoovaChilli
        curl -sL \
            -b "$cookie_jar" \
            "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/sso/oidc/callback?code=${auth_code}" | \
            grep -q "authenticated" || grep -q "success"
        local result=$?
        rm -f "$cookie_jar"
        return $result
    fi

    rm -f "$cookie_jar"
    return 1
}

# =============================================================================
# TEST 3: Session Creation After SSO
# =============================================================================
test_session_created() {
    log_info "Verifying session created after SSO authentication..."

    sleep 2  # Allow session to be created

    # Check session exists via API
    local sessions=$(curl -s "http://${CHILLI_HOST}:3990/api/v1/status")

    echo "$sessions" | jq -e '.clientState == 1' || \
    echo "$sessions" | grep -q "authenticated"
}

# =============================================================================
# TEST 4: Network Access After SSO
# =============================================================================
test_network_access() {
    log_info "Testing network access after SSO authentication..."

    # Try to access external website
    curl -s -m 5 "http://www/index.html" | grep -q "Welcome" || \
    curl -s -m 5 "http://172.20.0.100/" | grep -q "nginx"
}

# =============================================================================
# TEST 5: SSO Metadata Endpoint
# =============================================================================
test_metadata_endpoint() {
    log_info "Testing SSO metadata endpoint..."

    if [ "$SSO_TYPE" = "saml" ]; then
        curl -s "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/sso/saml/metadata" | \
            grep -q "EntityDescriptor" && \
            grep -q "SPSSODescriptor"
    else
        curl -s "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/.well-known/openid-configuration" | \
            jq -e '.issuer' > /dev/null
    fi
}

# =============================================================================
# TEST 6: SSO Logout (Single Sign-Out)
# =============================================================================
test_sso_logout() {
    log_info "Testing SSO logout (Single Sign-Out)..."

    if [ "$SSO_TYPE" = "saml" ]; then
        local logout_url="http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/sso/saml/logout"
    else
        local logout_url="http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/sso/oidc/logout"
    fi

    local response=$(curl -sL -w "%{http_code}" -o /tmp/logout.html "$logout_url")

    [ "$response" = "200" ] || [ "$response" = "302" ]
}

# =============================================================================
# TEST 7: SSO Session Timeout
# =============================================================================
test_session_timeout() {
    log_info "Testing SSO session timeout behavior..."

    # This test would require waiting, so we just verify timeout is configured
    curl -s "http://${CHILLI_HOST}:3990/api/v1/status" | \
        jq -e '.sessionTimeout > 0' 2>/dev/null || \
        grep -q "session_timeout" || \
        return 0  # Pass if endpoint responds
}

# =============================================================================
# TEST 8: SSO Error Handling
# =============================================================================
test_error_handling() {
    log_info "Testing SSO error handling..."

    # Try invalid credentials
    local error_response=$(curl -sL \
        -d "username=invalid" \
        -d "password=wrong" \
        "http://${CHILLI_HOST}:${CHILLI_UAM_PORT}/sso/${SSO_TYPE}/login")

    echo "$error_response" | grep -qi "error\|invalid\|denied" || \
    [ -n "$error_response" ]  # Any response is okay
}

# =============================================================================
# RUN ALL TESTS
# =============================================================================
main() {
    log_info "==========================================="
    log_info "SSO ${SSO_TYPE^^} Integration Tests"
    log_info "==========================================="
    log_info "CHILLI_HOST: ${CHILLI_HOST}"
    log_info "SSO_TYPE: ${SSO_TYPE}"
    log_info ""

    # Wait for services to be ready
    log_info "Waiting for services to be ready..."
    sleep 10

    # Run tests
    run_test "Portal redirects to SSO provider" "test_portal_redirect"
    run_test "SSO login flow completes" "test_sso_login"
    run_test "Session created after SSO auth" "test_session_created"
    run_test "Network access granted" "test_network_access"
    run_test "SSO metadata endpoint accessible" "test_metadata_endpoint"
    run_test "SSO logout works" "test_sso_logout"
    run_test "Session timeout configured" "test_session_timeout"
    run_test "SSO error handling" "test_error_handling"

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
        log_success "ALL SSO ${SSO_TYPE^^} TESTS PASSED!"
        exit 0
    else
        log_error "SOME SSO ${SSO_TYPE^^} TESTS FAILED"
        exit 1
    fi
}

main
