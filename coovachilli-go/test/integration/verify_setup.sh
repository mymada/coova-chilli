#!/bin/bash
# =============================================================================
# Verification script for integration test infrastructure
# =============================================================================
# This script verifies that all required files and dependencies are in place
# for running the integration tests.
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ERRORS=0
WARNINGS=0
CHECKS=0

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    CHECKS=$((CHECKS + 1))
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
    ERRORS=$((ERRORS + 1))
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    WARNINGS=$((WARNINGS + 1))
}

check_command() {
    local cmd="$1"
    local name="$2"

    if command -v "$cmd" >/dev/null 2>&1; then
        local version=$(eval "$cmd --version 2>&1 | head -n1" || echo "unknown")
        log_success "$name installed: $version"
        return 0
    else
        log_error "$name not found. Install: $3"
        return 1
    fi
}

check_file() {
    local file="$1"
    local name="$2"

    if [ -f "$file" ]; then
        log_success "$name exists: $file"
        return 0
    else
        log_error "$name not found: $file"
        return 1
    fi
}

check_executable() {
    local file="$1"
    local name="$2"

    if [ -f "$file" ] && [ -x "$file" ]; then
        log_success "$name is executable: $file"
        return 0
    elif [ -f "$file" ]; then
        log_warning "$name exists but is not executable: $file"
        return 1
    else
        log_error "$name not found: $file"
        return 1
    fi
}

echo "=========================================="
echo "Integration Test Setup Verification"
echo "=========================================="
echo ""

# Check required commands
log_info "Checking required commands..."
check_command "docker" "Docker" "https://docs.docker.com/get-docker/"
check_command "docker compose" "Docker Compose" "https://docs.docker.com/compose/install/" || \
    check_command "docker-compose" "Docker Compose (standalone)" "https://docs.docker.com/compose/install/"
check_command "bash" "Bash" "Should be pre-installed"
check_command "jq" "jq (JSON processor)" "apt-get install jq / brew install jq"

echo ""

# Check optional commands
log_info "Checking optional commands..."
check_command "make" "Make" "apt-get install build-essential / xcode-select --install" || log_warning "Make not found (optional)"
check_command "curl" "curl" "apt-get install curl / brew install curl" || log_warning "curl not found (recommended)"
check_command "wget" "wget" "apt-get install wget / brew install wget" || log_warning "wget not found (optional)"

echo ""

# Check infrastructure files
log_info "Checking infrastructure files..."
check_file "${SCRIPT_DIR}/docker-compose.e2e.yml" "Docker Compose config"
check_file "${SCRIPT_DIR}/Dockerfile.chilli" "CoovaChilli Dockerfile"
check_file "${SCRIPT_DIR}/Dockerfile.client" "Client Dockerfile"
check_file "${SCRIPT_DIR}/entrypoint.sh" "Entrypoint script"

echo ""

# Check configuration files
log_info "Checking configuration files..."
check_file "${SCRIPT_DIR}/config.iptables.yaml" "iptables config"
check_file "${SCRIPT_DIR}/config.ufw.yaml" "ufw config"
check_file "${SCRIPT_DIR}/nginx.conf" "Nginx config"

echo ""

# Check RADIUS files
log_info "Checking RADIUS configuration..."
check_file "${SCRIPT_DIR}/radius/clients.conf" "RADIUS clients"
check_file "${SCRIPT_DIR}/radius/users" "RADIUS users"

echo ""

# Check test scripts
log_info "Checking test scripts..."
check_executable "${SCRIPT_DIR}/run_tests_local.sh" "Local test runner"
check_executable "${SCRIPT_DIR}/tests/run_e2e_tests.sh" "E2E test script"
check_executable "${SCRIPT_DIR}/entrypoint.sh" "Entrypoint script"

echo ""

# Check web files
log_info "Checking web files..."
check_file "${SCRIPT_DIR}/www/index.html" "Test web page"

echo ""

# Check Docker daemon
log_info "Checking Docker daemon..."
if docker info >/dev/null 2>&1; then
    log_success "Docker daemon is running"
else
    log_error "Docker daemon is not running. Start with: sudo systemctl start docker"
fi

echo ""

# Check Docker IPv6 support
log_info "Checking Docker IPv6 support..."
if docker network inspect bridge 2>/dev/null | grep -q '"EnableIPv6": true'; then
    log_success "Docker IPv6 is enabled"
elif docker network inspect bridge 2>/dev/null | grep -q "EnableIPv6"; then
    log_warning "Docker IPv6 may not be enabled. Some IPv6 tests might fail."
    log_warning "To enable, edit /etc/docker/daemon.json and add:"
    log_warning '  {"ipv6": true, "fixed-cidr-v6": "2001:db8:1::/64"}'
else
    log_warning "Could not determine Docker IPv6 status"
fi

echo ""

# Check results directory
log_info "Checking results directory..."
if [ -d "${SCRIPT_DIR}/results" ]; then
    log_success "Results directory exists"
else
    log_info "Creating results directory..."
    mkdir -p "${SCRIPT_DIR}/results"
    log_success "Results directory created"
fi

echo ""

# Check Go workspace (optional)
log_info "Checking Go workspace..."
if [ -f "${SCRIPT_DIR}/../../go.mod" ]; then
    log_success "go.mod found in project root"

    # Check if dependencies are downloaded
    if [ -d "${SCRIPT_DIR}/../../vendor" ] || [ -d "$HOME/go/pkg/mod" ]; then
        log_success "Go dependencies appear to be downloaded"
    else
        log_warning "Go dependencies may not be downloaded. Run: go mod download"
    fi
else
    log_error "go.mod not found in project root"
fi

echo ""

# Check documentation
log_info "Checking documentation..."
check_file "${SCRIPT_DIR}/../../docs/INTEGRATION_TESTING.md" "Integration testing guide"
check_file "${SCRIPT_DIR}/../../docs/CI_CD_TESTING_SUMMARY.md" "CI/CD summary"
check_file "${SCRIPT_DIR}/README.md" "Integration tests README"
check_file "${SCRIPT_DIR}/../../TESTING.md" "Testing guide"

echo ""

# Print summary
echo "=========================================="
echo "Summary"
echo "=========================================="
log_info "Checks passed: ${CHECKS}"
if [ ${WARNINGS} -gt 0 ]; then
    log_warning "Warnings: ${WARNINGS}"
fi
if [ ${ERRORS} -gt 0 ]; then
    log_error "Errors: ${ERRORS}"
fi
echo ""

if [ ${ERRORS} -eq 0 ]; then
    log_success "All critical checks passed! Ready to run tests."
    echo ""
    log_info "To run tests:"
    echo "  1. All tests:         ./run_tests_local.sh"
    echo "  2. Specific test:     ./run_tests_local.sh ipv4-iptables"
    echo "  3. Debug mode:        ./run_tests_local.sh ipv4-iptables no"
    echo ""
    log_info "For more information:"
    echo "  - Integration guide: docs/INTEGRATION_TESTING.md"
    echo "  - Quick start:       test/integration/README.md"
    echo "  - Testing guide:     TESTING.md"
    echo ""
    exit 0
else
    log_error "Some critical checks failed. Please fix the errors above."
    echo ""
    log_info "Common fixes:"
    echo "  - Install Docker: https://docs.docker.com/get-docker/"
    echo "  - Install Docker Compose: https://docs.docker.com/compose/install/"
    echo "  - Start Docker daemon: sudo systemctl start docker"
    echo "  - Install jq: sudo apt-get install jq (or brew install jq)"
    echo ""
    exit 1
fi
