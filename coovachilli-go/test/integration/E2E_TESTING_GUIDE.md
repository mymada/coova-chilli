# E2E Testing Guide - CoovaChilli-Go

Complete End-to-End testing infrastructure for CoovaChilli-Go, simulating production environments with SSO, FAS, VLAN, and RADIUS authentication.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Test Scenarios](#test-scenarios)
- [Running Tests](#running-tests)
- [CI/CD Integration](#cicd-integration)
- [Test Components](#test-components)
- [Troubleshooting](#troubleshooting)

---

## Overview

The E2E testing stack provides comprehensive validation of CoovaChilli-Go functionality across multiple authentication methods and network configurations.

### Key Features

- ✅ **SSO Authentication** - SAML 2.0 and OIDC (OpenID Connect)
- ✅ **FAS Integration** - Forward Authentication Service with JWT tokens
- ✅ **VLAN Support** - Dynamic VLAN assignment and isolation testing
- ✅ **RADIUS Protocol** - Auth, Accounting, CoA, and Disconnect-Message
- ✅ **IPv4/IPv6** - Dual-stack network testing
- ✅ **Firewall Backends** - iptables and ufw support
- ✅ **Performance Testing** - Load tests with concurrent sessions
- ✅ **Security Scanning** - Gosec and Trivy integration

### Test Coverage

| Component | Tests | Coverage |
|-----------|-------|----------|
| SSO (SAML) | 8 | Login flow, metadata, logout, session |
| SSO (OIDC) | 8 | Authorization, tokens, callback, error handling |
| FAS | 10 | Token lifecycle, validation, callbacks, multi-device |
| VLAN | 10 | Tagging, isolation, QoS, persistence, trunk |
| RADIUS | 18 | Auth (PAP/CHAP), Accounting, CoA, DM, attributes |
| **Total** | **54** | **Comprehensive E2E coverage** |

---

## Architecture

### Network Topology

```
┌─────────────────────────────────────────────────────────────┐
│                    Backend Network (172.20.0.0/16)          │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ RADIUS   │  │   FAS    │  │Keycloak  │  │  SAML    │   │
│  │  Server  │  │  Server  │  │  (OIDC)  │  │   IdP    │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
│                                                              │
│  ┌──────────┐  ┌──────────┐                                │
│  │PostgreSQL│  │Prometheus│                                │
│  └──────────┘  └──────────┘                                │
└─────────────────────────────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
┌───────▼─────┐   ┌────────▼────┐   ┌────────▼────┐
│  CoovaChilli│   │ CoovaChilli │   │ CoovaChilli │
│    (SAML)   │   │   (OIDC)    │   │    (FAS)    │
└───────┬─────┘   └─────────────┘   └─────────────┘
        │
┌───────▼─────────────────────────────────────────────┐
│          Hotspot Networks (10.x.x.x/24)             │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐         │
│  │  Client  │  │  Client  │  │  Client  │         │
│  │  (SAML)  │  │  (OIDC)  │  │  (VLAN)  │         │
│  └──────────┘  └──────────┘  └──────────┘         │
└──────────────────────────────────────────────────────┘
```

### Docker Services

#### Backend Services

1. **RADIUS Server** (FreeRADIUS)
   - Authentication: Port 1812/udp
   - Accounting: Port 1813/udp
   - CoA/DM: Port 3799/udp
   - Users: testuser/testpass, vlan100user, vlan200user

2. **FAS Server** (Python/Flask)
   - Port: 8081
   - JWT token generation and validation
   - Session management

3. **Keycloak** (OIDC Provider)
   - Port: 8090
   - Realm: master
   - Client: coovachilli

4. **SimpleSAMLphp** (SAML IdP)
   - Port: 8091
   - Test users configured

5. **PostgreSQL**
   - Port: 5432
   - Database: coovachilli
   - Session persistence testing

6. **Prometheus**
   - Port: 9090
   - Metrics collection

#### CoovaChilli Instances

Multiple instances for different test scenarios:

| Instance | Port (Admin) | Port (Portal) | Auth Method | Network |
|----------|--------------|---------------|-------------|---------|
| chilli-saml | 3990 | 8080 | SAML | 10.10.0.0/24 |
| chilli-oidc | 3991 | 8081 | OIDC | 10.11.0.0/24 |
| chilli-fas | 3992 | 8082 | FAS | 10.12.0.0/24 |
| chilli-vlan | 3993 | 8083 | VLAN | 10.20.0.0/16 |

#### Test Clients

Automated test runners for each scenario:
- `client-saml` - Tests SAML authentication flow
- `client-oidc` - Tests OIDC authentication flow
- `client-fas` - Tests FAS integration
- `client-vlan-100` - Tests VLAN 100 assignment
- `client-vlan-200` - Tests VLAN 200 assignment

---

## Test Scenarios

### 1. SSO Tests (SAML + OIDC)

**Location:** `test/integration/tests/run_sso_tests.sh`

**Tests:**
1. Portal redirect to SSO provider
2. SSO login flow (SAML/OIDC)
3. Session creation after authentication
4. Network access granted
5. SSO metadata endpoint
6. SSO logout (Single Sign-Out)
7. Session timeout configuration
8. Error handling

**SAML Flow:**
```
Client → CoovaChilli Portal → SAML IdP Login
         ↓
SimpleSAMLphp Authentication
         ↓
SAML Response → CoovaChilli ACS → Session Created
```

**OIDC Flow:**
```
Client → CoovaChilli Portal → OIDC Authorization
         ↓
Keycloak Authentication
         ↓
Authorization Code → Token Exchange → Session Created
```

### 2. FAS Tests

**Location:** `test/integration/tests/run_fas_tests.sh`

**Tests:**
1. Portal redirects to FAS server
2. FAS token generation (JWT)
3. FAS token validation
4. FAS authentication flow
5. FAS callback to CoovaChilli
6. Token expiration handling
7. Parameter passing (MAC, IP, NAS-ID)
8. Session parameter application
9. Multi-device support
10. Error handling

**FAS Flow:**
```
Client → CoovaChilli → FAS Server (with JWT token)
         ↓
User authenticates on FAS portal
         ↓
FAS validates → Callback to CoovaChilli → Session Created
```

### 3. VLAN Tests

**Location:** `test/integration/tests/run_vlan_tests.sh`

**Tests:**
1. VLAN interface creation
2. VLAN packet tagging (802.1Q)
3. RADIUS VLAN assignment
4. VLAN isolation (traffic separation)
5. VLAN traffic forwarding
6. VLAN QoS/bandwidth limiting
7. VLAN membership persistence
8. VLAN trunk support
9. VLAN accounting separation
10. Dynamic VLAN assignment

**VLAN Assignment:**
```
Client Auth → RADIUS Response with VLAN attributes
         ↓
Tunnel-Type = VLAN (13)
Tunnel-Medium-Type = 802 (6)
Tunnel-Private-Group-Id = 100
         ↓
Client assigned to VLAN 100 network
```

### 4. RADIUS Tests

**Location:** `test/integration/tests/run_radius_tests.sh`

**Tests:**
1. RADIUS server connectivity
2. PAP authentication
3. CHAP authentication
4. Authentication failure handling
5. Accounting-Start
6. Accounting-Interim-Update
7. Accounting-Stop
8. CoA (Change of Authorization)
9. Disconnect-Message
10. VLAN attributes
11. Bandwidth limit attributes
12. Session timeout attributes
13. NAS-Identifier
14. Framed-IP-Address assignment
15. Retry and timeout behavior
16. Concurrent sessions
17. Accounting data accuracy
18. Shared secret validation

**RADIUS Protocols:**

```
┌──────────────────────────────────────────────────┐
│ Authentication (Port 1812)                       │
│ Access-Request → Access-Accept/Reject            │
└──────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────┐
│ Accounting (Port 1813)                           │
│ Start → Interim-Update → Stop                    │
└──────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────┐
│ CoA/DM (Port 3799)                               │
│ CoA-Request → CoA-ACK/NAK                        │
│ Disconnect-Request → Disconnect-ACK/NAK          │
└──────────────────────────────────────────────────┘
```

---

## Running Tests

### Prerequisites

```bash
# Docker and Docker Compose
docker --version  # >= 20.10
docker compose version  # >= 2.0

# Required for local testing
go version  # >= 1.21
make --version
```

### Quick Start

```bash
# 1. Build the application
cd /IdeaProjects/coovachilli-go
make build

# 2. Navigate to test directory
cd test/integration

# 3. Run all tests
docker compose -f docker-compose.full-e2e.yml up --abort-on-container-exit

# 4. View results
ls -lh results/
```

### Running Specific Test Suites

```bash
# SSO SAML tests only
docker compose -f docker-compose.full-e2e.yml run --rm client-saml

# SSO OIDC tests only
docker compose -f docker-compose.full-e2e.yml run --rm client-oidc

# FAS tests only
docker compose -f docker-compose.full-e2e.yml run --rm client-fas

# VLAN tests (VLAN 100)
docker compose -f docker-compose.full-e2e.yml run --rm client-vlan-100

# VLAN tests (VLAN 200)
docker compose -f docker-compose.full-e2e.yml run --rm client-vlan-200
```

### Manual Testing

```bash
# Start services
docker compose -f docker-compose.full-e2e.yml up -d

# Check service health
docker compose -f docker-compose.full-e2e.yml ps

# Access portals
# SAML: http://localhost:8080
# OIDC: http://localhost:8081
# FAS:  http://localhost:8082

# View logs
docker compose -f docker-compose.full-e2e.yml logs -f chilli-saml

# Stop services
docker compose -f docker-compose.full-e2e.yml down -v
```

### Local Testing (Without Docker)

```bash
cd test/integration

# Basic tests (IPv4, iptables)
./run_tests_local.sh ipv4-iptables yes

# IPv6 tests
./run_tests_local.sh ipv6-iptables yes

# UFW firewall tests
./run_tests_local.sh ipv4-ufw yes
```

---

## CI/CD Integration

### GitHub Actions Workflow

**Location:** `.github/workflows/e2e-tests.yml`

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop`
- Daily schedule (2 AM UTC)
- Manual workflow dispatch

**Jobs:**

1. **Basic Tests** (Matrix: IPv4/IPv6 × iptables/ufw)
   - Duration: ~10 minutes
   - Tests fundamental network functionality

2. **SSO Tests** (Matrix: SAML, OIDC)
   - Duration: ~15 minutes
   - Tests enterprise SSO integration

3. **FAS Tests**
   - Duration: ~10 minutes
   - Tests forward authentication

4. **VLAN Tests** (Matrix: VLAN 100, 200)
   - Duration: ~12 minutes
   - Tests VLAN isolation and assignment

5. **RADIUS Tests**
   - Duration: ~15 minutes
   - Comprehensive RADIUS protocol testing

6. **Performance Tests**
   - Duration: ~20 minutes
   - Load testing with 1000 concurrent sessions
   - Benchmarking

7. **Security Tests**
   - Gosec (Go security scanner)
   - Trivy (container vulnerability scanner)
   - SARIF report upload to GitHub

8. **Report Generation**
   - Aggregates all test results
   - Generates markdown report
   - Comments on pull requests

### Running Specific Test Suites in CI

```yaml
# Trigger via workflow_dispatch
gh workflow run e2e-tests.yml --field test_suite=sso

# Available options:
# - all (default)
# - basic
# - sso
# - fas
# - vlan
# - radius
```

### Test Results

Results are uploaded as artifacts:
- **Retention:** 30 days (test results), 90 days (reports)
- **Artifacts:**
  - `basic-test-results-{type}`
  - `sso-test-results-{type}`
  - `fas-test-results`
  - `vlan-test-results-{id}`
  - `radius-test-results`
  - `performance-results`
  - `complete-test-report`

---

## Test Components

### Configuration Files

Each test scenario has a dedicated configuration:

```
test/integration/
├── config.saml.yaml    # SAML SSO configuration
├── config.oidc.yaml    # OIDC SSO configuration
├── config.fas.yaml     # FAS configuration
└── config.vlan.yaml    # VLAN configuration
```

**Key Configuration Sections:**

```yaml
# Server configuration
server:
  http:
    host: "0.0.0.0"
    port: 3990
  portal:
    port: 8080
    uam_secret: "ChangeMe"

# Network configuration
network:
  interface: "eth0"
  dhcp:
    subnet: "10.10.0.0/24"
    gateway: "10.10.0.1"

# RADIUS configuration
radius:
  auth:
    host: "radius"
    port: 1812
    secret: "testing123"

# SSO configuration (SAML/OIDC)
sso:
  enabled: true
  type: "saml"  # or "oidc"

# FAS configuration
fas:
  enabled: true
  url: "http://fas:8081"
  secret: "supersecretfaskey123456789"

# VLAN configuration
network:
  vlan:
    enabled: true
    vlans:
      - id: 100
        subnet: "10.20.100.0/24"
```

### Test Scripts

All test scripts follow a common pattern:

```bash
#!/bin/bash
set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Test tracking
test_count=0
pass_count=0
fail_count=0

# Run test function
run_test() {
    local test_name="$1"
    local test_cmd="$2"

    test_count=$((test_count + 1))

    if eval "${test_cmd}"; then
        echo -e "${GREEN}[✓ PASS]${NC} ${test_name}"
        pass_count=$((pass_count + 1))
    else
        echo -e "${RED}[✗ FAIL]${NC} ${test_name}"
        fail_count=$((fail_count + 1))
    fi
}

# Test implementations
test_example() {
    # Test logic here
    return 0  # Success
}

# Main
main() {
    run_test "Example test" "test_example"

    # Summary
    echo "Total: ${test_count}"
    echo "Passed: ${pass_count}"
    echo "Failed: ${fail_count}"

    [ $fail_count -eq 0 ] && exit 0 || exit 1
}

main
```

### FAS Mock Server

**Location:** `test/integration/fas/`

The FAS server is a Python Flask application that simulates a Forward Authentication Service:

**Features:**
- JWT token generation and validation
- Session management
- Beautiful login portal
- RADIUS integration (optional)
- Health check endpoint
- REST API for testing

**Endpoints:**
- `GET /health` - Health check
- `GET /login` - Display login page
- `POST /auth` - Process authentication
- `POST /api/validate` - Validate JWT token
- `POST /api/callback` - Callback from CoovaChilli
- `GET /api/sessions` - List active sessions

**Test Credentials:**
- Username: `testuser`, Password: `testpass`
- Username: `user1`, Password: `user1pass`
- Username: `vlan100user`, Password: `testpass`
- Username: `vlan200user`, Password: `testpass`

---

## Troubleshooting

### Common Issues

#### 1. Docker Network Issues

**Problem:** Containers can't communicate

**Solution:**
```bash
# Restart Docker daemon
sudo systemctl restart docker

# Recreate networks
docker compose -f docker-compose.full-e2e.yml down -v
docker compose -f docker-compose.full-e2e.yml up -d
```

#### 2. RADIUS Authentication Fails

**Problem:** Access-Reject responses

**Solution:**
```bash
# Check RADIUS server logs
docker compose -f docker-compose.full-e2e.yml logs radius

# Test RADIUS manually
docker compose -f docker-compose.full-e2e.yml exec radius \
    radtest testuser testpass localhost 0 testing123

# Verify shared secret in config files
grep -r "testing123" test/integration/
```

#### 3. VLAN Tests Fail

**Problem:** VLAN interfaces not created

**Solution:**
```bash
# Load 8021q kernel module
sudo modprobe 8021q
lsmod | grep 8021q

# Check if running in privileged mode
docker inspect chilli-vlan | jq '.[].HostConfig.Privileged'

# Verify VLAN configuration
docker compose -f docker-compose.full-e2e.yml exec chilli-vlan \
    ip link show | grep vlan
```

#### 4. SSO Redirect Loops

**Problem:** Infinite redirects between portal and IdP

**Solution:**
```bash
# Check callback URLs in config
cat test/integration/config.saml.yaml | grep -A5 "sp:"

# Verify IdP metadata
curl http://localhost:8091/simplesaml/saml2/idp/metadata.php

# Check CoovaChilli logs for SAML errors
docker compose -f docker-compose.full-e2e.yml logs chilli-saml | grep -i saml
```

#### 5. Test Container Exits Immediately

**Problem:** Client containers exit before tests complete

**Solution:**
```bash
# Check exit code
docker compose -f docker-compose.full-e2e.yml ps -a

# View test logs
docker compose -f docker-compose.full-e2e.yml logs client-saml

# Run interactively for debugging
docker compose -f docker-compose.full-e2e.yml run --rm client-saml /bin/sh
```

### Debug Commands

```bash
# Full stack status
docker compose -f docker-compose.full-e2e.yml ps

# View all logs
docker compose -f docker-compose.full-e2e.yml logs -f

# Check service health
docker compose -f docker-compose.full-e2e.yml exec radius radtest testuser testpass localhost 0 testing123
docker compose -f docker-compose.full-e2e.yml exec fas-server curl -f http://localhost:8081/health
docker compose -f docker-compose.full-e2e.yml exec keycloak curl -f http://localhost:8080/health/ready

# Network debugging
docker network ls
docker network inspect integration_backend

# Container inspection
docker compose -f docker-compose.full-e2e.yml exec chilli-saml ip addr
docker compose -f docker-compose.full-e2e.yml exec chilli-saml iptables -L -n -v

# Database queries (PostgreSQL)
docker compose -f docker-compose.full-e2e.yml exec postgres \
    psql -U chilli -d coovachilli -c "SELECT * FROM sessions;"
```

### Performance Optimization

If tests are slow:

```bash
# Use build cache
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

# Build images in parallel
docker compose -f docker-compose.full-e2e.yml build --parallel

# Limit resource usage
docker compose -f docker-compose.full-e2e.yml up --scale client-saml=0

# Clean up old images/volumes
docker system prune -af --volumes
```

---

## Advanced Testing

### Load Testing

Simulate 1000 concurrent sessions:

```bash
cd test/integration

# Start services
docker compose -f docker-compose.full-e2e.yml up -d

# Run load test
bash tests/run_load_tests.sh 1000

# Monitor metrics
open http://localhost:9090  # Prometheus
```

### Custom Test Scenarios

Create a custom test:

```bash
# 1. Create test script
cat > test/integration/tests/run_custom_tests.sh << 'EOF'
#!/bin/bash
# Your custom tests here
EOF

chmod +x test/integration/tests/run_custom_tests.sh

# 2. Add to docker-compose.full-e2e.yml
# (Add new service under test clients)

# 3. Run custom test
docker compose -f docker-compose.full-e2e.yml run --rm custom-client
```

### Integration with External RADIUS

Test with your own RADIUS server:

```yaml
# Modify docker-compose.full-e2e.yml
radius:
  image: freeradius/freeradius-server:latest
  # Comment out to use external RADIUS
  # ...

# Update CoovaChilli config
radius:
  auth:
    host: "your-radius-server.example.com"
    secret: "your-shared-secret"
```

---

## Test Metrics and KPIs

### Success Criteria

- ✅ **Pass Rate:** ≥ 95% of tests must pass
- ✅ **Response Time:** Portal < 500ms, Auth < 2s
- ✅ **Concurrent Sessions:** Handle 1000+ simultaneous users
- ✅ **Memory Usage:** < 500MB per CoovaChilli instance
- ✅ **CPU Usage:** < 50% under normal load

### Performance Benchmarks

```bash
# Run benchmarks
cd /IdeaProjects/coovachilli-go
go test -bench=. -benchmem -run=^$ ./pkg/...

# Example output:
BenchmarkSessionCreate-8       100000    10234 ns/op    256 B/op    3 allocs/op
BenchmarkRADIUSAuth-8           50000    35678 ns/op    512 B/op    8 allocs/op
BenchmarkPortalHandler-8       200000     5432 ns/op    128 B/op    2 allocs/op
```

---

## Contributing

### Adding New Tests

1. Create test script in `test/integration/tests/`
2. Add Docker client service in `docker-compose.full-e2e.yml`
3. Add GitHub Actions job in `.github/workflows/e2e-tests.yml`
4. Update this documentation

### Test Standards

- Use bash for test scripts
- Include colored output (RED/GREEN)
- Track pass/fail counts
- Write results to `/results/`
- Exit with proper status code (0=pass, 1=fail)
- Include descriptive test names
- Log important events

---

## Resources

### Documentation
- [CoovaChilli Documentation](../docs/)
- [RADIUS RFC 2865](https://tools.ietf.org/html/rfc2865)
- [SAML 2.0 Specification](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)

### Tools
- [FreeRADIUS](https://freeradius.org/)
- [Keycloak](https://www.keycloak.org/)
- [SimpleSAMLphp](https://simplesamlphp.org/)
- [Docker Compose](https://docs.docker.com/compose/)

### Support
- GitHub Issues: https://github.com/your-org/coovachilli-go/issues
- Discussions: https://github.com/your-org/coovachilli-go/discussions

---

**Last Updated:** 2025-01-10
**Version:** 1.0.0
**Maintainer:** CoovaChilli-Go Team
