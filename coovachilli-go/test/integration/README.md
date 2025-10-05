# Tests d'Intégration CoovaChilli-Go

Suite de tests end-to-end pour CoovaChilli-Go avec DHCP, RADIUS, IPv4/IPv6, iptables/ufw.

## 🚀 Quick Start

```bash
# Lancer tous les tests
./run_tests_local.sh

# Tests spécifiques
./run_tests_local.sh ipv4-iptables

# Déboguer (laisse les conteneurs actifs)
./run_tests_local.sh ipv4-iptables no
```

## 📁 Structure

```
test/integration/
├── docker-compose.e2e.yml      # Configuration Docker Compose principale
├── Dockerfile.chilli           # Image CoovaChilli pour tests
├── Dockerfile.client           # Image client de test
├── entrypoint.sh               # Script de démarrage CoovaChilli
├── run_tests_local.sh          # Script pour exécution locale
│
├── config.iptables.yaml        # Config CoovaChilli pour iptables
├── config.ufw.yaml             # Config CoovaChilli pour ufw
│
├── radius/
│   ├── clients.conf            # Configuration clients RADIUS
│   └── users                   # Base utilisateurs de test
│
├── tests/
│   └── run_e2e_tests.sh        # Script de test principal
│
├── www/
│   └── index.html              # Page web de test
│
├── nginx.conf                  # Configuration nginx
└── results/                    # Résultats des tests (généré)
```

## 🧪 Tests exécutés

### Configuration testée

| Config | IPv4 | IPv6 | Firewall | Tests |
|--------|------|------|----------|-------|
| 1 | ✅ | ❌ | iptables | 12 |
| 2 | ❌ | ✅ | iptables | 12 |
| 3 | ✅ | ❌ | ufw | 12 |
| 4 | ❌ | ✅ | ufw | 12 |

**Total : 48 tests**

### Scénarios

1. ✅ Network Interface Check
2. ✅ DHCP IP Allocation (IPv4/IPv6)
3. ✅ DNS Resolution
4. ✅ Internet Blocked Before Auth
5. ✅ Captive Portal Redirect
6. ✅ RADIUS Authentication
7. ✅ Internet Access After Auth
8. ✅ Firewall Rules Verification
9. ✅ Session Status API
10. ✅ Bandwidth Test
11. ✅ Metrics Endpoint (Prometheus)
12. ✅ Admin API

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

## 🌐 Utilisateurs de test

| Username | Password | Timeout | Bandwidth |
|----------|----------|---------|-----------|
| testuser | testpass | 3600s | 10 Mbps |
| limiteduser | limitedpass | 1800s | 1 Mbps |
| shortuser | shortpass | 300s | Unlimited |
| ipv6user | ipv6pass | 3600s | 10 Mbps (IPv6) |

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

### Ports exposés

| Service | Port | Description |
|---------|------|-------------|
| CoovaChilli UAM | 8080 | Portail captif HTTP |
| CoovaChilli Metrics | 9090 | Prometheus metrics |
| CoovaChilli Admin | 8081 | API d'administration |
| FreeRADIUS Auth | 1812 | RADIUS authentication |
| FreeRADIUS Acct | 1813 | RADIUS accounting |
| Nginx | 80 | Serveur web de test |

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

## 📚 Documentation complète

Voir [docs/INTEGRATION_TESTING.md](../../docs/INTEGRATION_TESTING.md) pour :

- Architecture détaillée
- Guide CI/CD
- Contribution
- Métriques de qualité
- Références

## 🤝 Contribution

Pour ajouter un nouveau test :

1. Éditer `tests/run_e2e_tests.sh`
2. Ajouter fonction `test_nouvelle_feature()`
3. Appeler via `run_test "Nom" test_nouvelle_feature`

## 📝 License

Même licence que le projet principal CoovaChilli-Go.