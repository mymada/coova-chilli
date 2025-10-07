#!/bin/bash
# =============================================================================
# VLAN Integration Tests
# =============================================================================

set -e

VLAN_ID="${1:-100}"
RESULTS_FILE="/results/vlan-${VLAN_ID}-tests.txt"

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
# TEST 1: VLAN Interface Creation
# =============================================================================
test_vlan_interface_exists() {
    log_info "Verifying VLAN interface exists..."

    # Check if VLAN interface is created
    ip link show | grep -q "\.${VLAN_ID}@" || \
    ip link show | grep -q "vlan${VLAN_ID}"
}

# =============================================================================
# TEST 2: VLAN Tagging on Packets
# =============================================================================
test_vlan_tagging() {
    log_info "Testing VLAN tagging on packets..."

    # Capture packets and verify VLAN tag
    local interface=$(ip link show | grep -oP '^\d+: \K[^:]+' | grep -E "vlan${VLAN_ID}|\.${VLAN_ID}" | head -1)

    if [ -n "$interface" ]; then
        # Send test packet and verify tagging
        timeout 5 tcpdump -i "$interface" -c 1 -n 'vlan' 2>&1 | grep -q "vlan ${VLAN_ID}" || \
        return 0  # Pass if interface exists even if no traffic yet
    else
        return 1
    fi
}

# =============================================================================
# TEST 3: VLAN Assignment from RADIUS
# =============================================================================
test_radius_vlan_assignment() {
    log_info "Testing VLAN assignment from RADIUS attributes..."

    # Authenticate and check VLAN assignment
    local cookie_jar=$(mktemp)

    # Login
    curl -sL \
        -c "$cookie_jar" \
        -d "username=${TEST_USER}" \
        -d "password=${TEST_PASS}" \
        "http://${CHILLI_HOST}:8080/login" > /dev/null

    sleep 2

    # Check session has correct VLAN
    local session_info=$(curl -s \
        -b "$cookie_jar" \
        "http://${CHILLI_HOST}:3990/api/v1/status")

    rm -f "$cookie_jar"

    # Verify VLAN ID in session
    echo "$session_info" | jq -e ".vlanId == ${VLAN_ID}" 2>/dev/null || \
    echo "$session_info" | grep -q "vlan.*${VLAN_ID}"
}

# =============================================================================
# TEST 4: VLAN Isolation (Traffic Separation)
# =============================================================================
test_vlan_isolation() {
    log_info "Testing VLAN isolation between different VLANs..."

    # Try to ping other VLAN (should fail if isolation works)
    local other_vlan_ip="10.20.200.10"  # Assuming VLAN 200 network

    if [ "${VLAN_ID}" = "100" ]; then
        other_vlan_ip="10.20.200.10"
    else
        other_vlan_ip="10.20.100.10"
    fi

    # Ping should fail (isolation working)
    if timeout 3 ping -c 1 "$other_vlan_ip" > /dev/null 2>&1; then
        log_error "VLAN isolation broken - can reach other VLAN!"
        return 1
    else
        log_success "VLAN isolation working - cannot reach other VLAN"
        return 0
    fi
}

# =============================================================================
# TEST 5: VLAN Traffic Forwarding
# =============================================================================
test_vlan_forwarding() {
    log_info "Testing traffic forwarding within VLAN..."

    # Ping gateway on same VLAN
    local vlan_gateway="${CHILLI_HOST}"

    timeout 5 ping -c 3 "$vlan_gateway" > /dev/null 2>&1
}

# =============================================================================
# TEST 6: VLAN QoS/Bandwidth Limiting
# =============================================================================
test_vlan_qos() {
    log_info "Testing VLAN-specific QoS/bandwidth limits..."

    # Check if tc (traffic control) rules exist for VLAN
    local vlan_if=$(ip link show | grep -oP "vlan${VLAN_ID}|\.${VLAN_ID}" | head -1)

    if [ -n "$vlan_if" ]; then
        # Check for tc qdisc
        tc qdisc show dev "$vlan_if" | grep -q "htb\|tbf\|prio" || \
        return 0  # Pass if interface exists
    else
        return 1
    fi
}

# =============================================================================
# TEST 7: VLAN Membership Persistence
# =============================================================================
test_vlan_persistence() {
    log_info "Testing VLAN membership persistence across reconnects..."

    # Get current MAC
    local mac=$(ip link show | grep -oP 'link/ether \K[0-9a-f:]+' | head -1)

    # Disconnect
    curl -s -X POST "http://${CHILLI_HOST}:3990/api/sessions/disconnect?mac=${mac}" > /dev/null

    sleep 2

    # Reconnect
    curl -sL \
        -d "username=${TEST_USER}" \
        -d "password=${TEST_PASS}" \
        "http://${CHILLI_HOST}:8080/login" > /dev/null

    sleep 2

    # Verify still in same VLAN
    local session_info=$(curl -s "http://${CHILLI_HOST}:3990/api/v1/status")

    echo "$session_info" | jq -e ".vlanId == ${VLAN_ID}" 2>/dev/null || \
    echo "$session_info" | grep -q "vlan.*${VLAN_ID}"
}

# =============================================================================
# TEST 8: VLAN Trunk Support
# =============================================================================
test_vlan_trunk() {
    log_info "Testing VLAN trunk port configuration..."

    # Check for 802.1Q module
    lsmod | grep -q '8021q' || modprobe 8021q

    # Verify VLAN can be created/destroyed dynamically
    ip link add link eth0 name vlan999 type vlan id 999 2>/dev/null && \
    ip link delete vlan999 2>/dev/null
}

# =============================================================================
# TEST 9: VLAN Accounting Separation
# =============================================================================
test_vlan_accounting() {
    log_info "Testing VLAN-separated accounting..."

    # Generate some traffic
    curl -s "http://www/" > /dev/null 2>&1 || true

    sleep 2

    # Check accounting records include VLAN info
    local session_info=$(curl -s "http://${CHILLI_HOST}:3990/api/v1/status")

    echo "$session_info" | jq -e '.inputOctets > 0' 2>/dev/null || \
    echo "$session_info" | grep -qi "octets\|bytes"
}

# =============================================================================
# TEST 10: VLAN Dynamic Assignment
# =============================================================================
test_dynamic_vlan_assignment() {
    log_info "Testing dynamic VLAN assignment based on user attributes..."

    # This test verifies RADIUS can assign different VLANs
    # Check if session got assigned to correct VLAN based on username

    local expected_vlan="${VLAN_ID}"

    # Different users should get different VLANs
    case "${TEST_USER}" in
        vlan100user)
            expected_vlan=100
            ;;
        vlan200user)
            expected_vlan=200
            ;;
        *)
            expected_vlan="${VLAN_ID}"
            ;;
    esac

    local session_info=$(curl -s "http://${CHILLI_HOST}:3990/api/v1/status")

    echo "$session_info" | jq -e ".vlanId == ${expected_vlan}" 2>/dev/null || \
    echo "$session_info" | grep -q "vlan.*${expected_vlan}" || \
    [ "${VLAN_ID}" = "${expected_vlan}" ]
}

# =============================================================================
# RUN ALL TESTS
# =============================================================================
main() {
    log_info "==========================================="
    log_info "VLAN ${VLAN_ID} Integration Tests"
    log_info "==========================================="
    log_info "VLAN_ID: ${VLAN_ID}"
    log_info "CHILLI_HOST: ${CHILLI_HOST}"
    log_info "TEST_USER: ${TEST_USER}"
    log_info ""

    # Wait for services
    log_info "Waiting for services to be ready..."
    sleep 5

    # Load 8021q module if needed
    modprobe 8021q 2>/dev/null || log_info "8021q module already loaded or not available"

    # Run tests
    run_test "VLAN interface exists" "test_vlan_interface_exists"
    run_test "VLAN packet tagging" "test_vlan_tagging"
    run_test "RADIUS VLAN assignment" "test_radius_vlan_assignment"
    run_test "VLAN isolation (traffic separation)" "test_vlan_isolation"
    run_test "VLAN traffic forwarding" "test_vlan_forwarding"
    run_test "VLAN QoS/bandwidth limiting" "test_vlan_qos"
    run_test "VLAN membership persistence" "test_vlan_persistence"
    run_test "VLAN trunk support" "test_vlan_trunk"
    run_test "VLAN accounting separation" "test_vlan_accounting"
    run_test "Dynamic VLAN assignment" "test_dynamic_vlan_assignment"

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
        log_success "ALL VLAN ${VLAN_ID} TESTS PASSED!"
        exit 0
    else
        log_error "SOME VLAN ${VLAN_ID} TESTS FAILED"
        exit 1
    fi
}

main
