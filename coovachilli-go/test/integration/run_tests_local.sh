#!/bin/bash
# =============================================================================
# Local Integration Test Runner
# =============================================================================
# This script runs the complete integration test suite locally using Docker
# =============================================================================

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.e2e.yml"
RESULTS_DIR="${SCRIPT_DIR}/results"

# Parse arguments
TEST_SUITE="${1:-all}"  # all, ipv4, ipv6, iptables, ufw
CLEANUP="${2:-yes}"     # yes, no

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

usage() {
    cat <<EOF
Usage: $0 [TEST_SUITE] [CLEANUP]

TEST_SUITE:
  all       - Run all tests (default)
  ipv4      - Run IPv4 tests only
  ipv6      - Run IPv6 tests only
  iptables  - Run iptables tests only
  ufw       - Run ufw tests only
  ipv4-iptables - Run IPv4 with iptables
  ipv6-iptables - Run IPv6 with iptables
  ipv4-ufw      - Run IPv4 with ufw
  ipv6-ufw      - Run IPv6 with ufw

CLEANUP:
  yes - Clean up containers after tests (default)
  no  - Leave containers running for debugging

Examples:
  $0                    # Run all tests with cleanup
  $0 ipv4               # Run IPv4 tests only
  $0 iptables no        # Run iptables tests, leave containers running
  $0 ipv4-iptables yes  # Run IPv4 iptables tests with cleanup
EOF
    exit 1
}

cleanup() {
    if [ "${CLEANUP}" = "yes" ]; then
        log_info "Cleaning up containers..."
        docker compose -f "${COMPOSE_FILE}" down -v
        log_success "Cleanup complete"
    else
        log_warning "Containers left running. Clean up with: docker compose -f ${COMPOSE_FILE} down -v"
    fi
}

run_test() {
    local test_name="$1"
    local services="$2"

    log_info "========================================"
    log_info "Running: ${test_name}"
    log_info "========================================"

    # Start required services
    log_info "Starting services: ${services}"
    docker compose -f "${COMPOSE_FILE}" up -d ${services}

    # Wait for services to be ready
    log_info "Waiting for services to be ready..."
    sleep 15

    # Show service status
    docker compose -f "${COMPOSE_FILE}" ps

    # Run the test
    local test_service=$(echo "${services}" | grep -o 'client-[^ ]*' | head -n1)
    log_info "Running test service: ${test_service}"

    if docker compose -f "${COMPOSE_FILE}" run --rm ${test_service}; then
        log_success "${test_name} PASSED"
        return 0
    else
        log_error "${test_name} FAILED"

        # Show logs on failure
        log_error "=== Service Logs ==="
        for service in ${services}; do
            if [[ ! ${service} =~ ^client- ]]; then
                log_info "--- ${service} logs ---"
                docker compose -f "${COMPOSE_FILE}" logs --tail=50 ${service}
            fi
        done

        return 1
    fi
}

# Main execution
main() {
    log_info "CoovaChilli-Go Integration Test Suite"
    log_info "Test Suite: ${TEST_SUITE}"
    log_info "Cleanup: ${CLEANUP}"
    log_info ""

    # Create results directory
    mkdir -p "${RESULTS_DIR}"

    # Enable IPv6 in Docker if needed
    if [[ "${TEST_SUITE}" =~ ipv6 ]] || [ "${TEST_SUITE}" = "all" ]; then
        log_info "Checking Docker IPv6 configuration..."
        if ! docker network inspect bridge | grep -q "EnableIPv6.*true"; then
            log_warning "IPv6 may not be enabled in Docker. Some tests might fail."
            log_warning "To enable IPv6, edit /etc/docker/daemon.json and add:"
            log_warning '  {"ipv6": true, "fixed-cidr-v6": "2001:db8:1::/64"}'
        fi
    fi

    # Build images first
    log_info "Building Docker images..."
    docker compose -f "${COMPOSE_FILE}" build

    local all_passed=true

    # Run tests based on test suite selection
    case "${TEST_SUITE}" in
        all)
            run_test "IPv4 + iptables" "radius webserver chilli-iptables client-iptables-ipv4" || all_passed=false
            cleanup
            run_test "IPv6 + iptables" "radius webserver chilli-iptables client-iptables-ipv6" || all_passed=false
            cleanup
            run_test "IPv4 + ufw" "radius webserver chilli-ufw client-ufw-ipv4" || all_passed=false
            cleanup
            run_test "IPv6 + ufw" "radius webserver chilli-ufw client-ufw-ipv6" || all_passed=false
            ;;

        ipv4)
            run_test "IPv4 + iptables" "radius webserver chilli-iptables client-iptables-ipv4" || all_passed=false
            cleanup
            run_test "IPv4 + ufw" "radius webserver chilli-ufw client-ufw-ipv4" || all_passed=false
            ;;

        ipv6)
            run_test "IPv6 + iptables" "radius webserver chilli-iptables client-iptables-ipv6" || all_passed=false
            cleanup
            run_test "IPv6 + ufw" "radius webserver chilli-ufw client-ufw-ipv6" || all_passed=false
            ;;

        iptables)
            run_test "IPv4 + iptables" "radius webserver chilli-iptables client-iptables-ipv4" || all_passed=false
            cleanup
            run_test "IPv6 + iptables" "radius webserver chilli-iptables client-iptables-ipv6" || all_passed=false
            ;;

        ufw)
            run_test "IPv4 + ufw" "radius webserver chilli-ufw client-ufw-ipv4" || all_passed=false
            cleanup
            run_test "IPv6 + ufw" "radius webserver chilli-ufw client-ufw-ipv6" || all_passed=false
            ;;

        ipv4-iptables)
            run_test "IPv4 + iptables" "radius webserver chilli-iptables client-iptables-ipv4" || all_passed=false
            ;;

        ipv6-iptables)
            run_test "IPv6 + iptables" "radius webserver chilli-iptables client-iptables-ipv6" || all_passed=false
            ;;

        ipv4-ufw)
            run_test "IPv4 + ufw" "radius webserver chilli-ufw client-ufw-ipv4" || all_passed=false
            ;;

        ipv6-ufw)
            run_test "IPv6 + ufw" "radius webserver chilli-ufw client-ufw-ipv6" || all_passed=false
            ;;

        help|--help|-h)
            usage
            ;;

        *)
            log_error "Unknown test suite: ${TEST_SUITE}"
            usage
            ;;
    esac

    # Final cleanup
    cleanup

    # Print summary
    log_info "========================================"
    if [ "${all_passed}" = true ]; then
        log_success "All tests PASSED ✓"
        log_info "Results available in: ${RESULTS_DIR}"
        exit 0
    else
        log_error "Some tests FAILED ✗"
        log_info "Results available in: ${RESULTS_DIR}"
        exit 1
    fi
}

# Handle Ctrl+C
trap cleanup EXIT INT TERM

# Check if help is requested
if [ "$1" = "-h" ] || [ "$1" = "--help" ] || [ "$1" = "help" ]; then
    usage
fi

# Run main
main
