# CoovaChilli-Go - Administration API Documentation

## Table des matières

1. [Introduction](#introduction)
2. [Configuration](#configuration)
3. [Authentification](#authentification)
4. [Endpoints API](#endpoints-api)
5. [Dashboard & Métriques](#dashboard--métriques)
6. [Gestion des sessions](#gestion-des-sessions)
7. [Gestion des utilisateurs](#gestion-des-utilisateurs)
8. [Gestion multi-site](#gestion-multi-site)
9. [Groupes et politiques](#groupes-et-politiques)
10. [Snapshots de configuration](#snapshots-de-configuration)
11. [Intégration sécurité](#intégration-sécurité)
12. [Exemples d'utilisation](#exemples-dutilisation)

---

## Introduction

L'API d'administration CoovaChilli-Go fournit une interface REST complète pour gérer et surveiller votre infrastructure de portail captif WiFi. Elle permet de :

- **Surveiller** en temps réel les sessions, utilisateurs et métriques
- **Gérer** les utilisateurs, groupes et politiques d'accès
- **Administrer** plusieurs sites depuis une console centralisée
- **Automatiser** les tâches avec des snapshots de configuration
- **Intégrer** avec des systèmes tiers (SIEM, CRM, ERP)

---

## Configuration

### Activer l'API

```yaml
# config.yaml
admin_api:
  enabled: true
  listen: "0.0.0.0:8080"
  auth_token: "YOUR_SECURE_TOKEN_HERE"

  # Timeouts
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 120s

  # Rate limiting
  rate_limit_enabled: true
  rate_limit: 10.0        # 10 requêtes par seconde
  rate_limit_burst: 20    # Burst de 20 requêtes
```

### Variables d'environnement

```bash
export ADMIN_API_ENABLED=true
export ADMIN_API_LISTEN=:8080
export ADMIN_API_AUTH_TOKEN=your-secret-token
export COOVACHILLI_SNAPSHOT_DIR=/var/lib/coovachilli/snapshots
```

---

## Authentification

Toutes les requêtes API nécessitent un token d'authentification Bearer.

### Format

```http
Authorization: Bearer YOUR_AUTH_TOKEN
```

### Exemple

```bash
curl -H "Authorization: Bearer your-token" \
  http://localhost:8080/api/v1/status
```

---

## Endpoints API

### Base URL

```
http://your-server:8080/api/v1
```

### Liste complète

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/status` | GET | État du serveur |
| `/health` | GET | Health check |
| `/dashboard` | GET | Statistiques complètes |
| `/dashboard/stats` | GET | Statistiques simplifiées |
| `/sessions` | GET | Liste des sessions |
| `/sessions/{id}` | GET | Détails d'une session |
| `/sessions/{id}/logout` | POST | Déconnecter une session |
| `/sessions/{id}/authorize` | POST | Autoriser une session |
| `/users` | GET | Liste des utilisateurs |
| `/users/{username}` | GET | Détails utilisateur |
| `/users/{username}/sessions` | GET | Sessions d'un utilisateur |
| `/config` | GET | Configuration (sanitisée) |
| `/config/reload` | POST | Recharger la config |
| `/snapshots` | GET | Liste des snapshots |
| `/snapshots` | POST | Créer un snapshot |
| `/snapshots/{id}` | GET | Détails d'un snapshot |
| `/snapshots/{id}/restore` | POST | Restaurer un snapshot |
| `/snapshots/{id}` | DELETE | Supprimer un snapshot |
| `/security/ids/events` | GET | Événements IDS |
| `/security/ids/block` | POST | Bloquer une IP |
| `/security/ids/unblock` | POST | Débloquer une IP |
| `/security/threats` | GET | Menaces détectées |
| `/filter/domains` | GET | Domaines bloqués |
| `/filter/domains` | POST | Bloquer un domaine |
| `/filter/domains/{domain}` | DELETE | Débloquer un domaine |
| `/sites` | GET | Liste des sites |
| `/sites/{id}` | GET | Détails d'un site |
| `/sites/{id}/stats` | GET | Statistiques d'un site |

---

## Dashboard & Métriques

### GET /dashboard

Retourne les statistiques complètes du serveur.

**Réponse:**

```json
{
  "uptime": "24h30m15s",
  "start_time": "2024-01-15T10:00:00Z",
  "version": "1.0.0",
  "active_sessions": 145,
  "total_sessions": 1523,
  "authenticated_sessions": 132,
  "total_input_octets": 15234567890,
  "total_output_octets": 45678901234,
  "current_input_rate": 1024000.0,
  "current_output_rate": 2048000.0,
  "unique_users": 98,
  "top_users": [
    {
      "username": "john.doe",
      "session_count": 3,
      "input_octets": 523456789,
      "output_octets": 1234567890,
      "last_seen": "2024-01-15T14:30:00Z"
    }
  ],
  "vlan_distribution": {
    "10": 45,
    "20": 87,
    "30": 13
  },
  "blocked_threats": 12,
  "ids_events": 34,
  "filtered_domains": 156,
  "successful_auths": 1489,
  "failed_auths": 34
}
```

### GET /dashboard/stats

Version simplifiée des statistiques.

**Exemple:**

```bash
curl -H "Authorization: Bearer token" \
  http://localhost:8080/api/v1/dashboard/stats
```

**Réponse:**

```json
{
  "uptime": "24h30m15s",
  "active_sessions": 145,
  "authenticated": 132,
  "total_sessions": 1523,
  "unique_users": 98,
  "input_octets": 15234567890,
  "output_octets": 45678901234,
  "blocked_threats": 12,
  "ids_events": 34
}
```

---

## Gestion des sessions

### GET /sessions

Liste toutes les sessions actives.

**Exemple:**

```bash
curl -H "Authorization: Bearer token" \
  http://localhost:8080/api/v1/sessions
```

**Réponse:**

```json
[
  {
    "id": "00:11:22:33:44:55",
    "username": "john.doe",
    "ip": "10.10.0.100",
    "mac": "00:11:22:33:44:55",
    "vlan_id": 20,
    "authenticated": true,
    "start_time": "2024-01-15T14:00:00Z",
    "last_seen": "2024-01-15T14:30:00Z",
    "input_octets": 12345678,
    "output_octets": 87654321
  }
]
```

### GET /sessions/{id}

Obtenir les détails d'une session (par IP ou MAC).

**Exemple:**

```bash
curl -H "Authorization: Bearer token" \
  http://localhost:8080/api/v1/sessions/10.10.0.100
```

### POST /sessions/{id}/logout

Déconnecter une session.

**Exemple:**

```bash
curl -X POST \
  -H "Authorization: Bearer token" \
  http://localhost:8080/api/v1/sessions/10.10.0.100/logout
```

**Réponse:**

```json
{
  "status": "ok",
  "message": "session disconnected"
}
```

### POST /sessions/{id}/authorize

Autoriser une session (bypass portail).

**Body:**

```json
{
  "username": "john.doe",
  "duration": 3600
}
```

**Exemple:**

```bash
curl -X POST \
  -H "Authorization: Bearer token" \
  -H "Content-Type: application/json" \
  -d '{"username":"john.doe","duration":3600}' \
  http://localhost:8080/api/v1/sessions/10.10.0.100/authorize
```

---

## Gestion des utilisateurs

### GET /users

Liste tous les utilisateurs actifs.

**Réponse:**

```json
[
  {
    "username": "john.doe",
    "active_sessions": 2,
    "total_octets": 123456789,
    "last_seen": "2024-01-15T14:30:00Z"
  }
]
```

### GET /users/{username}

Obtenir les détails d'un utilisateur.

**Exemple:**

```bash
curl -H "Authorization: Bearer token" \
  http://localhost:8080/api/v1/users/john.doe
```

### GET /users/{username}/sessions

Obtenir toutes les sessions d'un utilisateur.

---

## Gestion multi-site

### GET /sites

Liste tous les sites gérés.

**Réponse:**

```json
[
  {
    "id": "site-paris-1234567890",
    "name": "Paris HQ",
    "description": "Siège social Paris",
    "endpoint": "https://paris.example.com:8080",
    "location": {
      "address": "123 Avenue des Champs-Élysées",
      "city": "Paris",
      "country": "France"
    },
    "status": {
      "online": true,
      "last_checked": "2024-01-15T14:30:00Z",
      "response_time_ms": 45,
      "version": "1.0.0"
    },
    "stats": {
      "active_sessions": 234,
      "total_sessions": 5678,
      "unique_users": 189
    }
  }
]
```

### GET /sites/{id}/stats

Obtenir les statistiques d'un site spécifique.

---

## Groupes et politiques

### Créer un groupe d'utilisateurs

```bash
curl -X POST \
  -H "Authorization: Bearer token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Employees",
    "description": "Company employees",
    "members": ["john.doe", "jane.smith"]
  }' \
  http://localhost:8080/api/v1/groups
```

### Créer une politique

```bash
curl -X POST \
  -H "Authorization: Bearer token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Standard Access",
    "description": "Standard employee access policy",
    "rules": {
      "max_bandwidth_down": 10485760,
      "max_bandwidth_up": 5242880,
      "max_session_duration": "8h",
      "vlan_id": 20,
      "qos_class": "medium"
    },
    "priority": 100
  }' \
  http://localhost:8080/api/v1/policies
```

---

## Snapshots de configuration

### POST /snapshots

Créer un snapshot de la configuration actuelle.

**Body:**

```json
{
  "name": "Pre-upgrade backup",
  "description": "Configuration backup before v2.0 upgrade"
}
```

**Exemple:**

```bash
curl -X POST \
  -H "Authorization: Bearer token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Pre-upgrade backup",
    "description": "Before v2.0 upgrade"
  }' \
  http://localhost:8080/api/v1/snapshots
```

**Réponse:**

```json
{
  "id": "snapshot-1705324800",
  "name": "Pre-upgrade backup",
  "description": "Before v2.0 upgrade",
  "created_at": "2024-01-15T14:00:00Z",
  "checksum": "a1b2c3d4..."
}
```

### GET /snapshots

Liste tous les snapshots.

### POST /snapshots/{id}/restore

Restaurer un snapshot.

**Exemple:**

```bash
curl -X POST \
  -H "Authorization: Bearer token" \
  http://localhost:8080/api/v1/snapshots/snapshot-1705324800/restore
```

**⚠️ Important:** Un redémarrage est requis après la restauration.

### DELETE /snapshots/{id}

Supprimer un snapshot.

---

## Intégration sécurité

### GET /security/ids/events

Obtenir les événements IDS récents.

### POST /security/ids/block

Bloquer une IP manuellement.

**Body:**

```json
{
  "ip": "192.0.2.100",
  "duration": "1h",
  "reason": "Manual block - suspicious activity"
}
```

### GET /security/threats

Liste des menaces détectées.

---

## Exemples d'utilisation

### Script de monitoring

```bash
#!/bin/bash

API_URL="http://localhost:8080/api/v1"
TOKEN="your-token"

# Obtenir les stats
stats=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "$API_URL/dashboard/stats")

active=$(echo $stats | jq -r '.active_sessions')
threats=$(echo $stats | jq -r '.blocked_threats')

echo "Sessions actives: $active"
echo "Menaces bloquées: $threats"

# Alerter si trop de sessions
if [ $active -gt 500 ]; then
  echo "ALERTE: Trop de sessions actives!"
fi
```

### Script Python

```python
import requests

API_URL = "http://localhost:8080/api/v1"
TOKEN = "your-token"
headers = {"Authorization": f"Bearer {TOKEN}"}

# Obtenir les sessions
response = requests.get(f"{API_URL}/sessions", headers=headers)
sessions = response.json()

print(f"Sessions actives: {len(sessions)}")

# Déconnecter les sessions inactives
for session in sessions:
    if not session['authenticated']:
        requests.post(
            f"{API_URL}/sessions/{session['id']}/logout",
            headers=headers
        )
        print(f"Déconnecté: {session['id']}")
```

### Intégration Prometheus

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'coovachilli'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/api/v1/dashboard/stats'
    bearer_token: 'your-token'
```

### Webhook pour alertes

```bash
# Créer un webhook pour les événements IDS
curl -X POST \
  -H "Authorization: Bearer token" \
  -H "Content-Type: application/json" \
  -d '{
    "webhook_url": "https://your-siem.example.com/webhook",
    "events": ["ids_event", "threat_detected"]
  }' \
  http://localhost:8080/api/v1/webhooks
```

---

## Codes de statut HTTP

| Code | Signification |
|------|---------------|
| 200 | Succès |
| 201 | Créé |
| 400 | Requête invalide |
| 401 | Non authentifié |
| 404 | Non trouvé |
| 500 | Erreur serveur |
| 501 | Non implémenté |
| 503 | Service indisponible |

---

## Limites et quotas

Par défaut, l'API applique :

- **Rate limiting**: 10 requêtes/seconde (burst de 20)
- **Timeout lecture**: 30 secondes
- **Timeout écriture**: 30 secondes
- **Taille max body**: 1 MB

---

## Sécurité

### Bonnes pratiques

1. ✅ **Toujours utiliser HTTPS** en production
2. ✅ **Générer un token fort** (min 32 caractères)
3. ✅ **Restreindre l'accès** par IP si possible
4. ✅ **Activer le rate limiting**
5. ✅ **Logger toutes les requêtes**
6. ✅ **Renouveler les tokens** régulièrement

### Générer un token sécurisé

```bash
# Générer un token de 64 caractères
openssl rand -hex 32
```

---

## Support

Pour toute question ou problème:

- 📖 Documentation: [docs.coovachilli.example](https://docs.coovachilli.example)
- 🐛 Issues: [GitHub Issues](https://github.com/your-org/coovachilli-go/issues)
- 💬 Discord: [discord.gg/coovachilli](https://discord.gg/coovachilli)

---

**Dernière mise à jour:** 2024-01-15
**Version API:** v1.0.0
