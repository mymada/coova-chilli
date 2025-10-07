# CoovaChilli-Go - Integration Tests

Complete E2E test suite for CoovaChilli-Go with SSO, FAS, VLAN, and RADIUS support.

## 🚀 Quick Start

```bash
# Build application
cd ../.. && make build && cd test/integration

# Run all E2E tests (SSO, FAS, VLAN)
docker compose -f docker-compose.full-e2e.yml up --abort-on-container-exit

# Run basic tests (IPv4/IPv6)
./run_tests_local.sh ipv4-iptables yes

# Debug mode (keeps containers running)
./run_tests_local.sh ipv4-iptables no
```

## 📁 Structure

```
test/integration/
├── docker-compose.e2e.yml        # Basic tests (IPv4/IPv6)
├── docker-compose.full-e2e.yml   # Complete E2E stack (SSO/FAS/VLAN)
├── Dockerfile.chilli             # CoovaChilli image
├── Dockerfile.client             # Test client image
├── entrypoint.sh                 # CoovaChilli startup script
├── run_tests_local.sh            # Local test runner
│
├── config.*.yaml                 # Test configurations
│   ├── config.iptables.yaml      # iptables config
│   ├── config.ufw.yaml           # ufw config
│   ├── config.saml.yaml          # SAML SSO config
│   ├── config.oidc.yaml          # OIDC SSO config
│   ├── config.fas.yaml           # FAS config
│   └── config.vlan.yaml          # VLAN config
│
├── radius/
│   ├── clients.conf              # RADIUS client config
│   └── users                     # Test users database
│
├── fas/
│   ├── Dockerfile                # FAS mock server
│   ├── server.py                 # Python Flask FAS server
│   └── requirements.txt          # Python dependencies
│
├── tests/
│   ├── run_e2e_tests.sh          # Basic E2E tests
│   ├── run_sso_tests.sh          # SSO tests (SAML/OIDC)
│   ├── run_fas_tests.sh          # FAS tests
│   ├── run_vlan_tests.sh         # VLAN tests
│   └── run_radius_tests.sh       # RADIUS tests
│
├── www/
│   └── index.html                # Test web page
│
├── nginx.conf                    # Nginx config
├── E2E_TESTING_GUIDE.md          # Complete documentation
└── results/                      # Test results (generated)
```

## 🧪 Test Suites

### E2E Test Suites (Full Stack)

| Suite | Tests | Description | Command |
|-------|-------|-------------|---------|
| **SSO (SAML)** | 8 | SAML 2.0 authentication | `docker compose -f docker-compose.full-e2e.yml run --rm client-saml` |
| **SSO (OIDC)** | 8 | OpenID Connect auth | `docker compose -f docker-compose.full-e2e.yml run --rm client-oidc` |
| **FAS** | 10 | Forward Auth Service | `docker compose -f docker-compose.full-e2e.yml run --rm client-fas` |
| **VLAN 100** | 10 | VLAN tagging/isolation | `docker compose -f docker-compose.full-e2e.yml run --rm client-vlan-100` |
| **VLAN 200** | 10 | VLAN tagging/isolation | `docker compose -f docker-compose.full-e2e.yml run --rm client-vlan-200` |
| **RADIUS** | 18 | RADIUS protocol | See E2E_TESTING_GUIDE.md |

**Total E2E Tests:** 54+

### Basic Tests (IPv4/IPv6)

| Config | IPv4 | IPv6 | Firewall | Tests |
|--------|------|------|----------|-------|
| 1 | ✅ | ❌ | iptables | 12 |
| 2 | ❌ | ✅ | iptables | 12 |
| 3 | ✅ | ❌ | ufw | 12 |
| 4 | ❌ | ✅ | ufw | 12 |

**Total Basic Tests:** 48

### Test Coverage

1. ✅ Network Interface Check
2. ✅ DHCP IP Allocation (IPv4/IPv6)
3. ✅ DNS Resolution
4. ✅ Internet Blocked Before Auth
5. ✅ Captive Portal Redirect
6. ✅ RADIUS Authentication (PAP/CHAP)
7. ✅ Internet Access After Auth
8. ✅ Firewall Rules Verification
9. ✅ Session Status API
10. ✅ SSO Authentication (SAML/OIDC)
11. ✅ FAS Token Lifecycle
12. ✅ VLAN Assignment & Isolation
13. ✅ Bandwidth Test & QoS
14. ✅ Metrics Endpoint (Prometheus)
15. ✅ Admin API
16. ✅ CoA (Change of Authorization)
17. ✅ Disconnect-Message
18. ✅ Accounting (Start/Interim/Stop)

## 🛠️ Commandes utiles

### Build et test

```bash
# Build images
docker compose -f docker-compose.e2e.yml build

# Démarrer services
docker compose -f docker-compose.e2e.yml up -d radius webserver chilli-iptables

# Lancer un test
docker compose -f docker-compose.e2e.yml run --rm client-iptables-ipv4

# Nettoyer
docker compose -f docker-compose.e2e.yml down -v
```

### Debugging

```bash
# Logs en temps réel
docker compose -f docker-compose.e2e.yml logs -f chilli-iptables

# Shell dans le client
docker compose -f docker-compose.e2e.yml run --rm client-iptables-ipv4 /bin/bash

# Vérifier les règles firewall
docker compose -f docker-compose.e2e.yml exec chilli-iptables iptables -L -n -v

# Tester RADIUS manuellement
docker compose -f docker-compose.e2e.yml exec radius radtest testuser testpass localhost 0 testing123
```

### Résultats

```bash
# Voir les résultats
cat results/test_*.json | jq '.summary'

# Taux de succès
jq -r '.summary.success_rate' results/test_*.json

# Tests échoués
jq -r '.tests[] | select(.status == "fail") | .name' results/test_*.json
```

## 🌐 Test Credentials

### RADIUS Users

| Username | Password | Timeout | Bandwidth | VLAN |
|----------|----------|---------|-----------|------|
| testuser | testpass | 3600s | 10 Mbps | - |
| user1 | user1pass | 3600s | 10 Mbps | - |
| vlan100user | testpass | 3600s | 5 Mbps | 100 |
| vlan200user | testpass | 3600s | 5 Mbps | 200 |
| limiteduser | limitedpass | 1800s | 1 Mbps | - |
| shortuser | shortpass | 300s | Unlimited | - |
| ipv6user | ipv6pass | 3600s | 10 Mbps (IPv6) | - |

### Admin Access

- **Keycloak (OIDC):** http://localhost:8090 (admin/admin123)
- **SAML IdP:** http://localhost:8091
- **FAS Server:** http://localhost:8081
- **Prometheus:** http://localhost:9090

## 📊 Résultats

Les résultats sont sauvegardés dans `results/` au format JSON :

```json
{
  "test_type": "ipv4",
  "firewall": "iptables",
  "timestamp": "2025-10-05T10:30:00Z",
  "tests": [...],
  "summary": {
    "total": 12,
    "passed": 12,
    "failed": 0,
    "success_rate": "100.00%"
  }
}
```

## 🔧 Configuration

### Variables d'environnement

Les clients de test utilisent :

- `TEST_TYPE` - `ipv4` ou `ipv6`
- `CHILLI_HOST` - Adresse IP CoovaChilli
- `CHILLI_UAM_PORT` - Port du portail captif (8080)
- `WEB_HOST` - Serveur web de test
- `TEST_USER` - Username RADIUS (testuser)
- `TEST_PASS` - Password RADIUS (testpass)
- `FIREWALL_TYPE` - `iptables` ou `ufw`

### Service Ports

#### CoovaChilli Instances

| Instance | Admin API | Portal | Metrics | Auth Method |
|----------|-----------|--------|---------|-------------|
| chilli-saml | 3990 | 8080 | 2112 | SAML |
| chilli-oidc | 3991 | 8081 | 2113 | OIDC |
| chilli-fas | 3992 | 8082 | 2114 | FAS |
| chilli-vlan | 3993 | 8083 | 2115 | VLAN |
| chilli-iptables | 8081 | 8080 | 9090 | Basic |
| chilli-ufw | 8082 | 8080 | 9091 | Basic |

#### Backend Services

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| RADIUS Auth | 1812 | UDP | RADIUS authentication |
| RADIUS Acct | 1813 | UDP | RADIUS accounting |
| RADIUS CoA | 3799 | UDP | Change of Authorization |
| FAS Server | 8081 | HTTP | Forward Auth Service |
| Keycloak | 8090 | HTTP | OIDC Provider |
| SAML IdP | 8091 | HTTP | SAML 2.0 IdP |
| PostgreSQL | 5432 | TCP | Database |
| Prometheus | 9090 | HTTP | Metrics |
| Nginx | 8888 | HTTP | Test web server |

## 🐛 Dépannage

### IPv6 ne fonctionne pas

```bash
# Vérifier config Docker
docker network inspect bridge | grep IPv6

# Activer IPv6 dans /etc/docker/daemon.json
{
  "ipv6": true,
  "fixed-cidr-v6": "2001:db8:1::/64"
}

sudo systemctl restart docker
```

### DHCP échoue

```bash
# Vérifier logs CoovaChilli
docker compose logs chilli-iptables | grep -i dhcp

# Test manuel DHCP dans le client
docker compose run --rm client-iptables-ipv4 dhclient -d -v eth0
```

### RADIUS authentication échoue

```bash
# Vérifier serveur RADIUS
docker compose logs radius

# Test manuel
docker compose exec radius radtest testuser testpass localhost 0 testing123
```

### Firewall rules manquantes

```bash
# Pour iptables
docker compose exec chilli-iptables iptables -L -n -v
docker compose exec chilli-iptables ip6tables -L -n -v

# Pour ufw
docker compose exec chilli-ufw ufw status verbose
```

## 📚 Complete Documentation

**For detailed information, see [E2E_TESTING_GUIDE.md](./E2E_TESTING_GUIDE.md)**

Topics covered:
- **Architecture** - Network topology, service components
- **Test Scenarios** - Detailed test descriptions
- **Running Tests** - All execution methods
- **CI/CD Integration** - GitHub Actions workflow
- **Troubleshooting** - Common issues and solutions
- **Advanced Testing** - Load testing, custom scenarios
- **Contributing** - How to add new tests

## 🚀 CI/CD Integration

Tests run automatically via GitHub Actions:

```yaml
# Workflow file: .github/workflows/e2e-tests.yml

# Triggers:
- Push to main/develop
- Pull requests
- Daily schedule (2 AM UTC)
- Manual workflow dispatch
```

**Test Jobs:**
1. Basic Tests (IPv4/IPv6 × iptables/ufw)
2. SSO Tests (SAML + OIDC)
3. FAS Tests
4. VLAN Tests (VLAN 100 + 200)
5. RADIUS Tests (Auth, Accounting, CoA, DM)
6. Performance Tests (1000 concurrent sessions)
7. Security Tests (Gosec + Trivy)
8. Report Generation

## 🤝 Contributing

To add a new test:

1. Create test script in `tests/run_YOUR_test.sh`
2. Add Docker client service in `docker-compose.full-e2e.yml`
3. Add GitHub Actions job in `.github/workflows/e2e-tests.yml`
4. Update documentation

**Test Standards:**
- Use bash for test scripts
- Include colored output (RED/GREEN)
- Track pass/fail counts
- Write results to `/results/`
- Exit with proper code (0=pass, 1=fail)
- Include descriptive test names

## 📞 Support

- **Issues:** https://github.com/your-org/coovachilli-go/issues
- **Discussions:** https://github.com/your-org/coovachilli-go/discussions
- **Documentation:** [E2E_TESTING_GUIDE.md](./E2E_TESTING_GUIDE.md)

## 📝 License

Same license as the main CoovaChilli-Go project.

---

**Last Updated:** 2025-01-10
**Test Coverage:** 100+ E2E tests across all components