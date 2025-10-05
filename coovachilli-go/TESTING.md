# Guide de Tests - CoovaChilli-Go

Guide rapide pour exécuter les tests unitaires et d'intégration.

---

## 🚀 Quick Start

### Tests unitaires

```bash
# Méthode 1 : Make (recommandé)
make test

# Méthode 2 : Go directement
go test ./pkg/...

# Avec race detector
make test-race
```

### Tests d'intégration

```bash
# Tous les tests (IPv4/IPv6 + iptables/ufw)
make test-integration

# Tests spécifiques
make test-integration-ipv4      # IPv4 seulement
make test-integration-ipv6      # IPv6 seulement
make test-integration-iptables  # iptables seulement
make test-integration-ufw       # ufw seulement

# Méthode manuelle
cd test/integration
./run_tests_local.sh ipv4-iptables
```

### Couverture de code

```bash
# Générer rapport
make coverage

# Ouvrir rapport HTML
make coverage-html
```

### Benchmarks

```bash
# Tous les benchmarks
make bench

# Benchmarks session uniquement
make bench-session
```

---

## 📊 Types de tests

### 1. Tests unitaires (pkg/)

**Couverture actuelle : 36%**

```bash
# Lancer tous les tests
go test ./pkg/...

# Test d'un package spécifique
go test ./pkg/core
go test ./pkg/http
go test ./pkg/securestore

# Avec verbosité
go test -v ./pkg/core

# Avec couverture
go test -cover ./pkg/...
```

**Packages testés :**
- ✅ pkg/admin (83.9%)
- ✅ pkg/auth (86.7%)
- ✅ pkg/cluster (49.3%)
- ✅ pkg/cmdsock (33.3%)
- ✅ pkg/core (47.9%)
- ✅ pkg/dhcp (41.9%)
- ✅ pkg/eapol (64.2%)
- ✅ pkg/firewall (24.1%)
- ✅ pkg/garden (66.1%)
- ✅ pkg/http (20.8%)
- ✅ pkg/securestore (88.9%)

### 2. Tests d'intégration (test/integration/)

**Total : 48 tests (12 par configuration)**

```bash
# Via Make
make test-integration

# Via script
cd test/integration
./run_tests_local.sh all

# Configurations disponibles :
# - all              : Tous les tests
# - ipv4             : IPv4 seulement (iptables + ufw)
# - ipv6             : IPv6 seulement (iptables + ufw)
# - iptables         : iptables seulement (IPv4 + IPv6)
# - ufw              : ufw seulement (IPv4 + IPv6)
# - ipv4-iptables    : IPv4 avec iptables
# - ipv6-iptables    : IPv6 avec iptables
# - ipv4-ufw         : IPv4 avec ufw
# - ipv6-ufw         : IPv6 avec ufw
```

**Scénarios testés :**
1. Network Interface Check
2. DHCP IP Allocation (IPv4/IPv6)
3. DNS Resolution
4. Internet Blocked Before Auth
5. Captive Portal Redirect
6. RADIUS Authentication
7. Internet Access After Auth
8. Firewall Rules Verification
9. Session Status API
10. Bandwidth Test
11. Metrics Endpoint
12. Admin API

### 3. Tests de race conditions

```bash
# Via Make
make test-race

# Via Go
go test -race ./pkg/...
```

### 4. Benchmarks

```bash
# Tous les benchmarks
make bench

# Benchmarks spécifiques
go test -bench=BenchmarkCreateSession ./pkg/core
go test -bench=BenchmarkGetSessionByIP ./pkg/core
go test -bench=. -benchmem ./pkg/core
```

---

## 🔧 Commandes Make disponibles

```bash
make help                       # Afficher toutes les commandes
make build                      # Build le binaire
make test                       # Tests unitaires
make test-race                  # Tests avec race detector
make test-integration           # Tests d'intégration complets
make test-all                   # Tous les tests
make coverage                   # Rapport de couverture
make coverage-html              # Rapport HTML + ouverture navigateur
make bench                      # Benchmarks
make lint                       # Linters (golangci-lint)
make fmt                        # Formater le code
make vet                        # Go vet
make clean                      # Nettoyer artifacts
make docker-build               # Build images Docker
make docker-test                # Tests dans Docker
make ci-test                    # Tests CI (unit + race + coverage)
make ci-integration             # Tests intégration CI
```

---

## 🐛 Debugging des tests

### Tests unitaires qui échouent

```bash
# Avec verbosité maximale
go test -v ./pkg/http

# Test spécifique
go test -v -run TestHandleJsonpStatus ./pkg/http

# Avec race detector
go test -v -race -run TestSecretConcurrency ./pkg/securestore
```

### Tests d'intégration qui échouent

```bash
# Lancer sans cleanup pour inspecter
cd test/integration
./run_tests_local.sh ipv4-iptables no

# Inspecter les conteneurs
docker compose -f docker-compose.e2e.yml ps
docker compose -f docker-compose.e2e.yml logs chilli-iptables
docker compose -f docker-compose.e2e.yml logs radius

# Ouvrir shell dans un conteneur
docker compose -f docker-compose.e2e.yml exec chilli-iptables bash
docker compose -f docker-compose.e2e.yml run --rm client-iptables-ipv4 bash

# Vérifier règles firewall
docker compose -f docker-compose.e2e.yml exec chilli-iptables iptables -L -n -v

# Nettoyer manuellement
docker compose -f docker-compose.e2e.yml down -v
```

### Résultats des tests

```bash
# Voir résultats JSON
cat test/integration/results/test_*.json | jq

# Résumé
jq '.summary' test/integration/results/test_*.json

# Tests échoués seulement
jq -r '.tests[] | select(.status == "fail") | .name' test/integration/results/test_*.json
```

---

## 📈 Couverture de code

### Générer rapport

```bash
# Rapport texte
go test -cover ./pkg/...

# Rapport détaillé
go test -coverprofile=coverage.out ./pkg/...
go tool cover -func=coverage.out

# Rapport HTML
go tool cover -html=coverage.out -o coverage.html
```

### Objectifs de couverture

- **Actuel :** 36%
- **Objectif court terme :** 50%
- **Objectif long terme :** 70%

### Priorités de couverture

1. **P0 (critique)** : pkg/http, pkg/firewall
2. **P1 (haute)** : pkg/dhcp, pkg/dns
3. **P2 (moyenne)** : pkg/config, pkg/metrics, pkg/tun

---

## 🚦 CI/CD

### GitHub Actions

Les tests s'exécutent automatiquement sur :
- Push vers master/develop
- Pull request vers master/develop
- Quotidiennement à 2h UTC
- Manuellement via workflow_dispatch

### Jobs CI/CD

1. **unit-tests** : Tests unitaires + race + couverture
2. **integration-ipv4-iptables** : Tests IPv4 avec iptables
3. **integration-ipv6-iptables** : Tests IPv6 avec iptables
4. **integration-ipv4-ufw** : Tests IPv4 avec ufw
5. **integration-ipv6-ufw** : Tests IPv6 avec ufw
6. **aggregate-results** : Agrégation et rapport

### Critères de succès

Pour merger une PR :
- ✅ 100% des tests unitaires passent
- ✅ ≥90% des tests d'intégration IPv4 passent
- ✅ ≥80% des tests d'intégration IPv6 passent
- ✅ Pas de race conditions
- ✅ Pas de régression de couverture

---

## 📚 Documentation complète

Pour plus de détails, voir :
- [docs/INTEGRATION_TESTING.md](docs/INTEGRATION_TESTING.md) - Guide complet des tests d'intégration
- [docs/CI_CD_TESTING_SUMMARY.md](docs/CI_CD_TESTING_SUMMARY.md) - Résumé infrastructure CI/CD
- [docs/TEST_COVERAGE_REPORT.md](docs/TEST_COVERAGE_REPORT.md) - Rapport de couverture détaillé
- [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md) - Audit de sécurité
- [test/integration/README.md](test/integration/README.md) - Quick start tests d'intégration

---

## 🤝 Contribution

### Ajouter un test unitaire

```go
// Dans pkg/monpackage/monpackage_test.go
func TestMaNouvelleFonction(t *testing.T) {
    // Arrange
    input := "test"
    expected := "expected"

    // Act
    result := MaNouvelleFonction(input)

    // Assert
    if result != expected {
        t.Errorf("Expected %s, got %s", expected, result)
    }
}
```

### Ajouter un test d'intégration

Éditer `test/integration/tests/run_e2e_tests.sh` :

```bash
test_ma_nouvelle_feature() {
    log_info "Testing ma nouvelle feature..."

    # Test logic here
    if mon_test_reussit; then
        log_success "Feature working"
        return 0
    fi

    log_error "Feature failed"
    return 1
}

# Dans main :
run_test "Ma Nouvelle Feature" test_ma_nouvelle_feature
```

---

## 🔍 Commandes utiles

```bash
# Lister tous les tests
go test -list . ./pkg/...

# Tester avec timeout
go test -timeout 30s ./pkg/core

# Exécuter tests en parallèle
go test -parallel 4 ./pkg/...

# Afficher temps d'exécution
go test -v -count=1 ./pkg/core

# Désactiver cache de test
go test -count=1 ./pkg/...

# Benchmarks avec profiling mémoire
go test -bench=. -benchmem -memprofile=mem.out ./pkg/core

# Benchmarks avec profiling CPU
go test -bench=. -cpuprofile=cpu.out ./pkg/core
```

---

**Dernière mise à jour :** 2025-10-05
**Version :** 1.0.0
