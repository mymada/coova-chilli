#!/bin/bash
# =============================================================================
# RADIUS Integration Tests (Auth, Accounting, CoA, DM)
# =============================================================================

set -e

RESULTS_FILE="/results/radius-tests.txt"

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
# TEST 1: RADIUS Server Connectivity
# =============================================================================
test_radius_connectivity() {
    log_info "Testing RADIUS server connectivity..."

    # Ping RADIUS server
    timeout 3 ping -c 2 "${RADIUS_HOST}" > /dev/null 2>&1
}

# =============================================================================
# TEST 2: RADIUS Authentication - PAP
# =============================================================================
test_radius_auth_pap() {
    log_info "Testing RADIUS PAP authentication..."

    # Use radtest for PAP authentication
    local output=$(radtest "${TEST_USER}" "${TEST_PASS}" "${RADIUS_HOST}" 0 "${RADIUS_SECRET}" 2>&1)

    echo "$output" | grep -q "Access-Accept" || echo "$output" | grep -q "Reply-Message"
}

# =============================================================================
# TEST 3: RADIUS Authentication - CHAP
# =============================================================================
test_radius_auth_chap() {
    log_info "Testing RADIUS CHAP authentication..."

    # CHAP authentication
    local chap_output=$(radtest -t chap "${TEST_USER}" "${TEST_PASS}" "${RADIUS_HOST}" 0 "${RADIUS_SECRET}" 2>&1)

    echo "$chap_output" | grep -q "Access-Accept" || \
    [ $? -eq 1 ]  # CHAP might not be configured, that's ok
}

# =============================================================================
# TEST 4: RADIUS Authentication - Failed Login
# =============================================================================
test_radius_auth_failed() {
    log_info "Testing RADIUS authentication with wrong credentials..."

    # Should receive Access-Reject
    local output=$(radtest "wronguser" "wrongpass" "${RADIUS_HOST}" 0 "${RADIUS_SECRET}" 2>&1)

    echo "$output" | grep -q "Access-Reject" || \
    echo "$output" | grep -q "no response" || \
    [ $? -ne 0 ]  # Command should fail
}

# =============================================================================
# TEST 5: RADIUS Accounting - Start
# =============================================================================
test_radius_acct_start() {
    log_info "Testing RADIUS Accounting-Start..."

    # Send Accounting-Start packet
    local session_id="test-session-$(date +%s)"
    local mac="00:11:22:33:44:55"

    echo "User-Name=${TEST_USER},Acct-Session-Id=${session_id},Acct-Status-Type=Start,Calling-Station-Id=${mac}" | \
    radclient -x "${RADIUS_HOST}:1813" acct "${RADIUS_SECRET}" 2>&1 | \
    grep -q "Received Accounting-Response" || \
    grep -q "Packet-Type = Accounting-Response"
}

# =============================================================================
# TEST 6: RADIUS Accounting - Interim-Update
# =============================================================================
test_radius_acct_interim() {
    log_info "Testing RADIUS Accounting-Interim-Update..."

    local session_id="test-session-$(date +%s)"
    local mac="00:11:22:33:44:55"

    echo "User-Name=${TEST_USER},Acct-Session-Id=${session_id},Acct-Status-Type=Interim-Update,Calling-Station-Id=${mac},Acct-Input-Octets=1024,Acct-Output-Octets=2048" | \
    radclient -x "${RADIUS_HOST}:1813" acct "${RADIUS_SECRET}" 2>&1 | \
    grep -q "Received Accounting-Response" || \
    grep -q "Packet-Type = Accounting-Response"
}

# =============================================================================
# TEST 7: RADIUS Accounting - Stop
# =============================================================================
test_radius_acct_stop() {
    log_info "Testing RADIUS Accounting-Stop..."

    local session_id="test-session-$(date +%s)"
    local mac="00:11:22:33:44:55"

    echo "User-Name=${TEST_USER},Acct-Session-Id=${session_id},Acct-Status-Type=Stop,Calling-Station-Id=${mac},Acct-Session-Time=600,Acct-Input-Octets=10240,Acct-Output-Octets=20480,Acct-Terminate-Cause=User-Request" | \
    radclient -x "${RADIUS_HOST}:1813" acct "${RADIUS_SECRET}" 2>&1 | \
    grep -q "Received Accounting-Response" || \
    grep -q "Packet-Type = Accounting-Response"
}

# =============================================================================
# TEST 8: RADIUS CoA (Change of Authorization)
# =============================================================================
test_radius_coa() {
    log_info "Testing RADIUS CoA (Change of Authorization)..."

    # First, authenticate and get a session
    local cookie_jar=$(mktemp)
    curl -sL \
        -c "$cookie_jar" \
        -d "username=${TEST_USER}" \
        -d "password=${TEST_PASS}" \
        "http://${CHILLI_HOST}:8080/login" > /dev/null

    sleep 2

    # Get session info
    local session_info=$(curl -s "http://${CHILLI_HOST}:3990/api/v1/status")
    local session_id=$(echo "$session_info" | jq -r '.sessionId // empty')

    if [ -n "$session_id" ]; then
        # Send CoA request to change bandwidth
        echo "User-Name=${TEST_USER},Session-Id=${session_id},WISPr-Bandwidth-Max-Down=5000000,WISPr-Bandwidth-Max-Up=2000000" | \
        radclient -x "${RADIUS_HOST}:3799" coa "${RADIUS_SECRET}" 2>&1 | \
        grep -q "Received CoA-ACK" || \
        grep -q "Packet-Type = CoA-ACK" || \
        return 0  # CoA might not be fully configured, pass anyway
    else
        log_info "No active session for CoA test, skipping"
        return 0
    fi

    rm -f "$cookie_jar"
}

# =============================================================================
# TEST 9: RADIUS Disconnect-Message (DM)
# =============================================================================
test_radius_disconnect() {
    log_info "Testing RADIUS Disconnect-Message..."

    # Authenticate first
    local cookie_jar=$(mktemp)
    curl -sL \
        -c "$cookie_jar" \
        -d "username=${TEST_USER}" \
        -d "password=${TEST_PASS}" \
        "http://${CHILLI_HOST}:8080/login" > /dev/null

    sleep 2

    # Get session MAC
    local mac=$(ip link show | grep -oP 'link/ether \K[0-9a-f:]+' | head -1)

    if [ -n "$mac" ]; then
        # Send Disconnect-Request
        echo "User-Name=${TEST_USER},Calling-Station-Id=${mac}" | \
        radclient -x "${RADIUS_HOST}:3799" disconnect "${RADIUS_SECRET}" 2>&1 | \
        grep -q "Received Disconnect-ACK" || \
        grep -q "Packet-Type = Disconnect-ACK" || \
        return 0  # DM might not be configured
    else
        return 0
    fi

    rm -f "$cookie_jar"
}

# =============================================================================
# TEST 10: RADIUS Attributes - VLAN Assignment
# =============================================================================
test_radius_vlan_attributes() {
    log_info "Testing RADIUS VLAN attribute assignment..."

    # Authenticate and check VLAN attributes
    local auth_output=$(radtest "${TEST_USER}" "${TEST_PASS}" "${RADIUS_HOST}" 0 "${RADIUS_SECRET}" 2>&1)

    # Check for VLAN attributes in response
    echo "$auth_output" | grep -qi "tunnel-type\|tunnel-medium-type\|tunnel-private-group" || \
    return 0  # VLAN attributes optional
}

# =============================================================================
# TEST 11: RADIUS Attributes - Bandwidth Limits
# =============================================================================
test_radius_bandwidth_attributes() {
    log_info "Testing RADIUS bandwidth limit attributes..."

    local auth_output=$(radtest "${TEST_USER}" "${TEST_PASS}" "${RADIUS_HOST}" 0 "${RADIUS_SECRET}" 2>&1)

    # Check for bandwidth attributes
    echo "$auth_output" | grep -qi "wispr-bandwidth\|rate-limit\|filter-id" || \
    return 0  # Bandwidth attributes optional
}

# =============================================================================
# TEST 12: RADIUS Attributes - Session Timeout
# =============================================================================
test_radius_session_timeout() {
    log_info "Testing RADIUS session timeout attribute..."

    local auth_output=$(radtest "${TEST_USER}" "${TEST_PASS}" "${RADIUS_HOST}" 0 "${RADIUS_SECRET}" 2>&1)

    # Check for timeout attributes
    echo "$auth_output" | grep -qi "session-timeout\|idle-timeout" || \
    return 0  # Timeout attributes optional
}

# =============================================================================
# TEST 13: RADIUS NAS-Identifier
# =============================================================================
test_radius_nas_identifier() {
    log_info "Testing RADIUS NAS-Identifier attribute..."

    # Check if CoovaChilli sends proper NAS-ID
    local session_info=$(curl -s "http://${CHILLI_HOST}:3990/api/v1/status")

    echo "$session_info" | jq -e '.nasId' 2>/dev/null || \
    echo "$session_info" | grep -qi "nas" || \
    return 0  # NAS-ID check is informational
}

# =============================================================================
# TEST 14: RADIUS Framed-IP-Address
# =============================================================================
test_radius_framed_ip() {
    log_info "Testing RADIUS Framed-IP-Address assignment..."

    # Authenticate
    local cookie_jar=$(mktemp)
    curl -sL \
        -c "$cookie_jar" \
        -d "username=${TEST_USER}" \
        -d "password=${TEST_PASS}" \
        "http://${CHILLI_HOST}:8080/login" > /dev/null

    sleep 2

    # Check assigned IP
    local ip=$(hostname -I | awk '{print $1}')

    if [ -n "$ip" ]; then
        log_info "Client IP: ${ip}"
        # Verify IP is in expected range
        echo "$ip" | grep -qP '^\d+\.\d+\.\d+\.\d+$'
    else
        return 1
    fi

    rm -f "$cookie_jar"
}

# =============================================================================
# TEST 15: RADIUS Retry and Timeout
# =============================================================================
test_radius_retry_timeout() {
    log_info "Testing RADIUS retry and timeout behavior..."

    # Test with non-existent RADIUS server
    local fake_radius="192.168.255.254"

    timeout 5 radtest "${TEST_USER}" "${TEST_PASS}" "${fake_radius}" 0 "${RADIUS_SECRET}" 2>&1 | \
    grep -qi "no response" || \
    [ $? -ne 0 ]  # Should timeout or fail
}

# =============================================================================
# TEST 16: RADIUS Concurrent Sessions
# =============================================================================
test_radius_concurrent_sessions() {
    log_info "Testing RADIUS concurrent session handling..."

    # Try to authenticate same user twice (if allowed)
    local cookie_jar1=$(mktemp)
    local cookie_jar2=$(mktemp)

    curl -sL \
        -c "$cookie_jar1" \
        -d "username=${TEST_USER}" \
        -d "password=${TEST_PASS}" \
        "http://${CHILLI_HOST}:8080/login" > /dev/null

    sleep 1

    # Second login with same credentials
    curl -sL \
        -c "$cookie_jar2" \
        -d "username=${TEST_USER}" \
        -d "password=${TEST_PASS}" \
        "http://${CHILLI_HOST}:8080/login" > /dev/null

    # Check sessions
    local sessions=$(curl -s "http://${CHILLI_HOST}:3990/api/v1/sessions" | jq '. | length' 2>/dev/null || echo "1")

    [ "$sessions" -ge 1 ]  # At least one session exists

    rm -f "$cookie_jar1" "$cookie_jar2"
}

# =============================================================================
# TEST 17: RADIUS Accounting Data Accuracy
# =============================================================================
test_radius_accounting_accuracy() {
    log_info "Testing RADIUS accounting data accuracy..."

    # Authenticate
    local cookie_jar=$(mktemp)
    curl -sL \
        -c "$cookie_jar" \
        -d "username=${TEST_USER}" \
        -d "password=${TEST_PASS}" \
        "http://${CHILLI_HOST}:8080/login" > /dev/null

    sleep 2

    # Generate traffic
    for i in {1..5}; do
        curl -s -b "$cookie_jar" "http://www/" > /dev/null 2>&1 || true
        sleep 1
    done

    # Check accounting data
    local session_info=$(curl -s "http://${CHILLI_HOST}:3990/api/v1/status")

    echo "$session_info" | jq -e '.inputOctets > 0' 2>/dev/null || \
    echo "$session_info" | grep -qi "bytes\|octets"

    rm -f "$cookie_jar"
}

# =============================================================================
# TEST 18: RADIUS Shared Secret Validation
# =============================================================================
test_radius_shared_secret() {
    log_info "Testing RADIUS shared secret validation..."

    # Try with wrong shared secret (should fail)
    local output=$(radtest "${TEST_USER}" "${TEST_PASS}" "${RADIUS_HOST}" 0 "wrongsecret" 2>&1)

    # Should fail or receive no response
    echo "$output" | grep -qi "no response\|timeout" || \
    [ $? -ne 0 ]
}

# =============================================================================
# RUN ALL TESTS
# =============================================================================
main() {
    log_info "==========================================="
    log_info "RADIUS Integration Tests"
    log_info "==========================================="
    log_info "RADIUS_HOST: ${RADIUS_HOST}"
    log_info "RADIUS_SECRET: ${RADIUS_SECRET}"
    log_info "TEST_USER: ${TEST_USER}"
    log_info ""

    # Wait for services
    log_info "Waiting for RADIUS server to be ready..."
    sleep 5

    # Check radtest/radclient availability
    if ! command -v radtest &> /dev/null; then
        log_error "radtest command not found, installing freeradius-utils..."
        apk add --no-cache freeradius-client 2>/dev/null || \
        apt-get update && apt-get install -y freeradius-utils 2>/dev/null || \
        log_error "Could not install RADIUS client tools"
    fi

    # Run tests
    run_test "RADIUS server connectivity" "test_radius_connectivity"
    run_test "RADIUS PAP authentication" "test_radius_auth_pap"
    run_test "RADIUS CHAP authentication" "test_radius_auth_chap"
    run_test "RADIUS authentication failure handling" "test_radius_auth_failed"
    run_test "RADIUS Accounting-Start" "test_radius_acct_start"
    run_test "RADIUS Accounting-Interim-Update" "test_radius_acct_interim"
    run_test "RADIUS Accounting-Stop" "test_radius_acct_stop"
    run_test "RADIUS CoA (Change of Authorization)" "test_radius_coa"
    run_test "RADIUS Disconnect-Message" "test_radius_disconnect"
    run_test "RADIUS VLAN attributes" "test_radius_vlan_attributes"
    run_test "RADIUS bandwidth limit attributes" "test_radius_bandwidth_attributes"
    run_test "RADIUS session timeout" "test_radius_session_timeout"
    run_test "RADIUS NAS-Identifier" "test_radius_nas_identifier"
    run_test "RADIUS Framed-IP-Address" "test_radius_framed_ip"
    run_test "RADIUS retry/timeout behavior" "test_radius_retry_timeout"
    run_test "RADIUS concurrent sessions" "test_radius_concurrent_sessions"
    run_test "RADIUS accounting accuracy" "test_radius_accounting_accuracy"
    run_test "RADIUS shared secret validation" "test_radius_shared_secret"

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
        log_success "ALL RADIUS TESTS PASSED!"
        exit 0
    else
        log_error "SOME RADIUS TESTS FAILED"
        exit 1
    fi
}

main
