# Guide de Tests d'Intégration - CoovaChilli-Go

**Date:** 2025-10-05
**Version:** 1.0.0

---

## 📋 Table des Matières

- [Vue d'ensemble](#vue-densemble)
- [Architecture des tests](#architecture-des-tests)
- [Prérequis](#prérequis)
- [Exécution locale](#exécution-locale)
- [CI/CD Pipeline](#cicd-pipeline)
- [Scénarios de test](#scénarios-de-test)
- [Dépannage](#dépannage)
- [Contribution](#contribution)

---

## 📖 Vue d'ensemble

Cette suite de tests d'intégration valide le fonctionnement complet de CoovaChilli-Go en simulant un environnement de production réel avec :

- **Clients réels** obtenant des adresses IP via DHCP
- **Authentification RADIUS** via FreeRADIUS
- **Portail captif** avec redirection HTTP
- **Firewall** iptables et ufw
- **Dual-stack** IPv4 et IPv6
- **Métriques** Prometheus
- **API d'administration**

### Matrice de tests

| Test Suite | IPv4 | IPv6 | iptables | ufw | Status |
|------------|------|------|----------|-----|--------|
| IPv4 + iptables | ✅ | ❌ | ✅ | ❌ | Production |
| IPv6 + iptables | ❌ | ✅ | ✅ | ❌ | Production |
| IPv4 + ufw | ✅ | ❌ | ❌ | ✅ | Production |
| IPv6 + ufw | ❌ | ✅ | ❌ | ✅ | Production |

**Total : 4 configurations testées automatiquement**

---

## 🏗️ Architecture des tests

### Composants Docker

```
┌─────────────────────────────────────────────────────────────┐
│                     Integration Test Suite                   │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐      ┌──────────────┐      ┌───────────┐ │
│  │  FreeRADIUS  │◄─────┤ CoovaChilli  │◄─────┤  Client   │ │
│  │   (Auth)     │      │   Gateway    │      │  (DHCP)   │ │
│  └──────────────┘      └──────────────┘      └───────────┘ │
│         │                      │                     │       │
│         │                      │                     │       │
│         ▼                      ▼                     ▼       │
│  ┌──────────────┐      ┌──────────────┐      ┌───────────┐ │
│  │  Test Users  │      │  Firewall    │      │  Test Web │ │
│  │  Database    │      │(iptables/ufw)│      │  Server   │ │
│  └──────────────┘      └──────────────┘      └───────────┘ │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Flux de test complet

1. **Démarrage des services**
   - FreeRADIUS démarre avec base d'utilisateurs de test
   - Serveur web nginx démarre pour simuler internet
   - CoovaChilli démarre avec iptables ou ufw

2. **Client obtient une IP**
   - Client envoie DHCP DISCOVER
   - CoovaChilli répond avec DHCP OFFER
   - Client configure son interface réseau

3. **Redirection portail captif**
   - Client tente d'accéder à internet
   - Firewall redirige vers le portail captif
   - Client reçoit page de login

4. **Authentification RADIUS**
   - Client soumet credentials au portail
   - CoovaChilli envoie Access-Request à RADIUS
   - RADIUS valide et renvoie Access-Accept
   - Session créée avec attributs RADIUS

5. **Accès internet**
   - Firewall autorise le trafic du client
   - Client peut accéder au web
   - Accounting RADIUS commence

6. **Vérifications**
   - Session status API
   - Métriques Prometheus
   - Règles firewall
   - Bande passante

---

## 🔧 Prérequis

### Logiciels requis

```bash
# Docker et Docker Compose
docker --version  # >= 24.0.0
docker compose version  # >= 2.20.0

# Pour les tests locaux
bash >= 4.0
jq >= 1.6
curl
```

### Configuration Docker pour IPv6

Éditer `/etc/docker/daemon.json` :

```json
{
  "ipv6": true,
  "fixed-cidr-v6": "2001:db8:1::/64",
  "experimental": true,
  "ip6tables": true
}
```

Redémarrer Docker :

```bash
sudo systemctl restart docker
```

### Permissions

Les tests nécessitent des privilèges pour :
- Créer des interfaces TUN/TAP
- Modifier les règles iptables/ufw
- Gérer le routage réseau

Les conteneurs utilisent `privileged: true` et `cap_add: [NET_ADMIN, NET_RAW]`.

---

## 🚀 Exécution locale

### Méthode rapide

```bash
cd test/integration
./run_tests_local.sh
```

Cette commande exécute tous les tests (IPv4, IPv6, iptables, ufw).

### Tests sélectifs

```bash
# Tests IPv4 uniquement
./run_tests_local.sh ipv4

# Tests IPv6 uniquement
./run_tests_local.sh ipv6

# Tests iptables uniquement
./run_tests_local.sh iptables

# Tests ufw uniquement
./run_tests_local.sh ufw

# Test spécifique
./run_tests_local.sh ipv4-iptables

# Sans cleanup (pour debugging)
./run_tests_local.sh ipv4-iptables no
```

### Utilisation manuelle de Docker Compose

```bash
cd test/integration

# Build des images
docker compose -f docker-compose.e2e.yml build

# Démarrer les services
docker compose -f docker-compose.e2e.yml up -d radius webserver chilli-iptables

# Vérifier les logs
docker compose -f docker-compose.e2e.yml logs -f chilli-iptables

# Lancer le client de test
docker compose -f docker-compose.e2e.yml run --rm client-iptables-ipv4

# Récupérer les résultats
docker compose -f docker-compose.e2e.yml cp client-iptables-ipv4:/results/. ./results/

# Nettoyer
docker compose -f docker-compose.e2e.yml down -v
```

### Debugging interactif

```bash
# Démarrer les services
docker compose -f docker-compose.e2e.yml up -d radius webserver chilli-iptables

# Ouvrir un shell dans le client
docker compose -f docker-compose.e2e.yml run --rm client-iptables-ipv4 /bin/bash

# Dans le conteneur client :
root@client:/tests# dhclient -v eth0
root@client:/tests# ip addr show
root@client:/tests# curl http://192.168.100.200/test
root@client:/tests# /tests/run_e2e_tests.sh
```

---

## ⚙️ CI/CD Pipeline

### GitHub Actions

Le workflow `.github/workflows/integration-tests.yml` s'exécute automatiquement sur :

- **Push** sur `master` ou `develop`
- **Pull Request** vers `master` ou `develop`
- **Schedule** quotidien à 2h UTC
- **Manuel** via workflow_dispatch

### Jobs du pipeline

1. **unit-tests** (requis)
   - Tests unitaires avec race detector
   - Couverture de code uploadée à Codecov

2. **integration-ipv4-iptables**
   - Tests IPv4 avec firewall iptables
   - 12 tests de bout en bout

3. **integration-ipv6-iptables**
   - Tests IPv6 avec firewall iptables
   - Validation dual-stack

4. **integration-ipv4-ufw**
   - Tests IPv4 avec firewall ufw
   - Compatibilité ufw

5. **integration-ipv6-ufw**
   - Tests IPv6 avec firewall ufw
   - Validation complète ufw + IPv6

6. **aggregate-results**
   - Agrège tous les résultats
   - Génère rapport markdown
   - Commente automatiquement les PR

### Artefacts générés

- `integration-results-ipv4-iptables` - Résultats JSON IPv4 iptables
- `integration-results-ipv6-iptables` - Résultats JSON IPv6 iptables
- `integration-results-ipv4-ufw` - Résultats JSON IPv4 ufw
- `integration-results-ipv6-ufw` - Résultats JSON IPv6 ufw
- `test-summary` - Rapport agrégé markdown

### Temps d'exécution

| Job | Durée moyenne |
|-----|---------------|
| unit-tests | 2-3 min |
| integration-ipv4-iptables | 3-4 min |
| integration-ipv6-iptables | 3-4 min |
| integration-ipv4-ufw | 3-4 min |
| integration-ipv6-ufw | 3-4 min |
| aggregate-results | 1 min |
| **TOTAL** | **~15-20 min** |

---

## 🧪 Scénarios de test

### Tests exécutés pour chaque configuration

#### 1. Network Interface Check
- Vérifie la présence d'interface réseau
- IPv4 : interface avec adresse `inet`
- IPv6 : interface avec adresse `inet6`

#### 2. DHCP IP Allocation
- **IPv4** : `dhclient` obtient une adresse dans 10.x.0.100-200
- **IPv6** : `dhclient -6` obtient une adresse dans fd01:x::100-200
- Validation du lease DHCP
- Vérification DNS serveurs assignés

#### 3. DNS Resolution
- Résolution de `google.com`
- Vérification serveurs DNS CoovaChilli
- Validation walled garden DNS

#### 4. Internet Blocked Before Auth
- Tentative d'accès au serveur web
- Doit échouer ou rediriger
- Validation de l'isolation firewall

#### 5. Captive Portal Redirect
- Requête HTTP vers internet
- Redirection vers portail captif
- Vérification page de login

#### 6. RADIUS Authentication
- Soumission credentials `testuser/testpass`
- Validation Access-Accept RADIUS
- Création de session
- Réception attributs RADIUS (timeout, bande passante)

#### 7. Internet Access After Auth
- Accès au serveur web de test
- Vérification HTTP 200
- Validation bande passante

#### 8. Firewall Rules
- Vérification isolation client
- Validation règles NAT
- Test forwarding IPv4/IPv6

#### 9. Session Status API
- GET `/json/status?callback=getStatus`
- Validation JSONP response
- Vérification données session

#### 10. Bandwidth Test
- Download fichier 10MB
- Mesure vitesse
- Validation limites RADIUS

#### 11. Metrics Endpoint
- GET `/metrics` Prometheus
- Validation métriques `chilli_*`
- Vérification compteurs

#### 12. Admin API
- GET `/api/v1/sessions`
- Validation authentification token
- Vérification liste sessions

### Utilisateurs de test RADIUS

| Username | Password | Session Timeout | Bandwidth Down | Bandwidth Up |
|----------|----------|-----------------|----------------|--------------|
| testuser | testpass | 3600s | 10 Mbps | 10 Mbps |
| limiteduser | limitedpass | 1800s | 1 Mbps | 512 Kbps |
| shortuser | shortpass | 300s | Unlimited | Unlimited |
| ipv6user | ipv6pass | 3600s | 10 Mbps | 10 Mbps |
| rejectuser | rejectpass | - | REJECT | REJECT |

---

## 🐛 Dépannage

### Problème : Tests échouent avec "Network unreachable"

**Cause :** IPv6 non configuré dans Docker

**Solution :**
```bash
# Vérifier config Docker
docker network inspect bridge | grep IPv6

# Si false, éditer /etc/docker/daemon.json
sudo nano /etc/docker/daemon.json

# Ajouter :
{
  "ipv6": true,
  "fixed-cidr-v6": "2001:db8:1::/64"
}

# Redémarrer
sudo systemctl restart docker
```

### Problème : "Cannot create TUN device"

**Cause :** Privilèges insuffisants ou module kernel manquant

**Solution :**
```bash
# Charger module TUN
sudo modprobe tun

# Vérifier
lsmod | grep tun

# Dans docker-compose, vérifier :
privileged: true
cap_add:
  - NET_ADMIN
  - NET_RAW
```

### Problème : RADIUS authentication fails

**Cause :** Secret RADIUS incorrect ou serveur RADIUS non disponible

**Solution :**
```bash
# Vérifier logs RADIUS
docker compose -f test/integration/docker-compose.e2e.yml logs radius

# Tester RADIUS manuellement
docker compose exec radius radtest testuser testpass localhost 0 testing123

# Vérifier config client RADIUS
docker compose exec radius cat /etc/raddb/clients.conf
```

### Problème : Firewall rules not applied

**Cause :** Backend firewall non disponible ou permissions insuffisantes

**Solution :**
```bash
# Vérifier logs CoovaChilli
docker compose logs chilli-iptables | grep -i firewall

# Vérifier règles iptables dans le conteneur
docker compose exec chilli-iptables iptables -L -n -v
docker compose exec chilli-iptables ip6tables -L -n -v

# Pour ufw
docker compose exec chilli-ufw ufw status verbose
```

### Problème : DHCP lease fails

**Cause :** Conflit d'adresse IP ou serveur DHCP non écoutant

**Solution :**
```bash
# Vérifier logs DHCP dans CoovaChilli
docker compose logs chilli-iptables | grep -i dhcp

# Dans le client, activer debug DHCP
docker compose run --rm client-iptables-ipv4 dhclient -d -v eth0

# Vérifier interface réseau
docker compose exec chilli-iptables ip addr show
```

### Problème : Tests passent localement mais échouent en CI

**Cause :** Timing différent, ressources limitées, ou IPv6 non configuré

**Solution :**
```bash
# Augmenter les timeouts dans run_e2e_tests.sh
# Actuellement : timeout 30

# Ajouter plus de waits
sleep 15  # Augmenter à 30

# Vérifier logs GitHub Actions
# Onglet Actions > Workflow run > Job logs
```

### Logs utiles pour debugging

```bash
# Tous les logs
docker compose -f test/integration/docker-compose.e2e.yml logs

# Logs d'un service spécifique
docker compose logs chilli-iptables
docker compose logs radius
docker compose logs client-iptables-ipv4

# Logs en temps réel
docker compose logs -f chilli-iptables

# Dernières 100 lignes
docker compose logs --tail=100 chilli-iptables

# Sauvegarder tous les logs
docker compose logs > full-logs.txt
```

---

## 🔍 Analyse des résultats

### Format JSON des résultats

Les résultats sont sauvegardés dans `/results/` avec le format :

```json
{
  "test_type": "ipv4",
  "firewall": "iptables",
  "timestamp": "2025-10-05T10:30:00Z",
  "tests": [
    {
      "name": "DHCP IP Allocation",
      "status": "pass",
      "duration_ms": 1234,
      "message": "Test passed successfully"
    }
  ],
  "summary": {
    "total": 12,
    "passed": 12,
    "failed": 0,
    "success_rate": "100.00%"
  }
}
```

### Extraction des métriques

```bash
# Taux de succès global
jq '.summary.success_rate' results/*.json

# Nombre de tests échoués
jq '.summary.failed' results/*.json | awk '{s+=$1} END {print s}'

# Tests les plus lents
jq -r '.tests[] | "\(.duration_ms) ms - \(.name)"' results/*.json | sort -rn | head -5

# Tests échoués seulement
jq -r '.tests[] | select(.status == "fail") | .name' results/*.json
```

---

## 📊 Métriques de qualité

### Critères de succès

Pour qu'une PR soit mergeable :

- ✅ **100%** des tests unitaires passent
- ✅ **≥ 90%** des tests d'intégration IPv4 passent
- ✅ **≥ 80%** des tests d'intégration IPv6 passent
- ✅ **Pas de régression** de couverture de code
- ✅ **Pas de race conditions** détectées

### Couverture de code

La couverture globale doit être ≥ 36% (objectif : 50%).

```bash
# Générer rapport de couverture
go test ./pkg/... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
```

### Performance

Les benchmarks doivent rester dans les limites :

| Opération | Max Time | Max Allocs |
|-----------|----------|------------|
| CreateSession | 10 µs | 5 allocs |
| GetSessionByIP | 1 µs | 0 allocs |
| DHCP Request | 100 ms | - |
| RADIUS Auth | 500 ms | - |

---

## 🤝 Contribution

### Ajouter un nouveau test

1. Éditer `test/integration/tests/run_e2e_tests.sh`
2. Ajouter une fonction `test_nouvelle_feature()`
3. Appeler via `run_test "Nom du test" test_nouvelle_feature`

Exemple :

```bash
test_session_timeout() {
    log_info "Testing session timeout..."

    # Attendre timeout + 10s
    sleep 610

    # Vérifier que la session est expirée
    if ! curl -s "http://${WEB_HOST}/test" | grep -q "Test successful"; then
        log_success "Session correctly expired"
        return 0
    fi

    log_error "Session did not expire"
    return 1
}

# Dans main :
run_test "Session Timeout" test_session_timeout
```

### Ajouter une configuration de test

1. Créer nouveau fichier `config.nouvelle.yaml`
2. Ajouter service dans `docker-compose.e2e.yml`
3. Créer client de test correspondant
4. Ajouter job dans `.github/workflows/integration-tests.yml`

### Guidelines de test

- ✅ Tests doivent être **idempotents** (répétables)
- ✅ Tests doivent être **isolés** (pas de dépendances entre tests)
- ✅ Tests doivent **nettoyer** leurs ressources
- ✅ Timeouts doivent être **raisonnables** (max 60s par test)
- ✅ Messages de log doivent être **clairs** et **actionnables**
- ✅ Tests doivent gérer les **edge cases**

---

## 📚 Références

- [Docker Compose Reference](https://docs.docker.com/compose/)
- [FreeRADIUS Documentation](https://freeradius.org/documentation/)
- [GitHub Actions Workflow Syntax](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions)
- [CoovaChilli Configuration](../README.md)
- [RADIUS Protocol RFC 2865](https://tools.ietf.org/html/rfc2865)

---

## 📝 Changelog

### Version 1.0.0 (2025-10-05)

- ✅ Suite complète de tests d'intégration
- ✅ Support IPv4 et IPv6
- ✅ Support iptables et ufw
- ✅ Pipeline CI/CD GitHub Actions
- ✅ Documentation complète
- ✅ 12 scénarios de test par configuration
- ✅ 4 configurations testées (IPv4/IPv6 × iptables/ufw)
- ✅ Résultats JSON structurés
- ✅ Rapport agrégé automatique

---

**Maintenu par :** CoovaChilli-Go Team
**Licence :** Même que le projet principal
**Dernière mise à jour :** 2025-10-05
