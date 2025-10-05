# Filtrage Avancé et Export de Logs

Ce document décrit les nouvelles fonctionnalités de filtrage URL/DNS et d'export de logs de CoovaChilli-Go.

## Filtrage URL et DNS

Le filtrage URL/DNS permet de contrôler l'accès à certains domaines et IPs selon des règles configurables.

### Configuration

```yaml
urlfilter:
  enabled: true
  domain_blocklist_path: "/etc/coovachilli/blocklist_domains.txt"
  ip_blocklist_path: "/etc/coovachilli/blocklist_ips.txt"
  category_rules_path: "/etc/coovachilli/category_rules.txt"
  default_action: "allow"  # "allow" ou "block"
```

### Types de Filtrage

#### 1. Blocage de Domaines (Blocklist)

Fichier: `blocklist_domains.txt`

```
# Format: un domaine par ligne
example.com
*.malicious.com
*.ads.network.com
```

- Supporte les domaines exacts (`example.com`)
- Supporte les wildcards (`*.malicious.com` bloque `sub.malicious.com`)
- Les lignes commençant par `#` sont des commentaires

#### 2. Blocage d'IPs

Fichier: `blocklist_ips.txt`

```
# Format: une IP par ligne
192.0.2.1
198.51.100.5
203.0.113.88
```

#### 3. Règles de Catégories

Fichier: `category_rules.txt`

Format: `category:action:regex_pattern`

```
# Bloquer le contenu adulte
adult:block:.*porn.*
adult:block:.*xxx.*

# Logger les publicités (pour monitoring)
advertising:log:.*ads.*

# Autoriser les réseaux sociaux
social:allow:.*facebook.*

# Bloquer le partage de fichiers
filesharing:block:.*torrent.*
```

**Actions disponibles:**
- `block` - Bloque le domaine
- `allow` - Autorise explicitement le domaine
- `log` - Autorise mais enregistre dans les logs

**Catégories suggérées:**
- `adult` - Contenu pour adultes
- `advertising` - Publicités
- `social` - Réseaux sociaux
- `streaming` - Services de streaming
- `filesharing` - Partage de fichiers
- `gambling` - Jeux d'argent
- `security` - Malware/Phishing
- `mining` - Crypto-mining
- `proxy` - VPN/Proxy services

### Gestion Dynamique

Les règles peuvent être modifiées dynamiquement via l'API:

```go
// Ajouter un domaine à la blocklist
filter.AddBlockedDomain("newbad.com")

// Retirer un domaine de la blocklist
filter.RemoveBlockedDomain("newbad.com")

// Recharger toutes les règles depuis les fichiers
filter.ReloadRules()
```

### Statistiques

Obtenez des statistiques de filtrage:

```go
stats := filter.GetStats()
fmt.Printf("Total queries: %d\n", stats.TotalQueries)
fmt.Printf("Blocked: %d\n", stats.BlockedQueries)
fmt.Printf("Allowed: %d\n", stats.AllowedQueries)
fmt.Printf("Logged: %d\n", stats.LoggedQueries)
```

## Export de Logs

Le système d'export de logs permet d'envoyer les événements de CoovaChilli vers différents backends pour l'analyse et l'archivage.

### Configuration

```yaml
logexport:
  enabled: true
  exporters:
    - file
    - syslog
    - elasticsearch

  # Configuration Syslog
  syslog_addr: "192.0.2.10:514"
  syslog_proto: "udp"  # tcp ou udp

  # Configuration fichier
  file_path: "/var/log/coovachilli/export.jsonl"

  # Configuration Elasticsearch
  es_endpoint: "http://elasticsearch:9200"
  es_index: "coovachilli-logs"

  # Configuration S3 (non implémenté)
  # s3_bucket: "my-log-bucket"
  # s3_region: "us-east-1"
```

### Exporters Disponibles

#### 1. File Exporter

Exporte les logs au format JSON Lines (JSONL) dans un fichier.

**Format:**
```json
{
  "timestamp": "2025-01-05T10:30:00Z",
  "level": "info",
  "component": "auth",
  "event": "user_login",
  "message": "User authenticated successfully",
  "session_id": "abc123",
  "username": "john.doe",
  "ip": "10.0.0.5",
  "mac": "00:11:22:33:44:55"
}
```

#### 2. Syslog Exporter

Envoie les logs vers un serveur syslog au format RFC3164.

**Protocoles supportés:** UDP, TCP

**Format de message:**
```
<134>Jan 05 10:30:00 hostname coovachilli[auth]: User authenticated successfully session=abc123 user=john.doe
```

#### 3. Elasticsearch Exporter

Envoie les logs vers un cluster Elasticsearch pour l'indexation et la recherche.

**Note:** Actuellement implémenté comme stub. Nécessite le client Elasticsearch Go.

#### 4. S3 Exporter (Planifié)

Archivage des logs dans Amazon S3. Non encore implémenté.

### Structure des Événements de Log

```go
type LogEvent struct {
    Timestamp  time.Time              // Horodatage de l'événement
    Level      string                 // debug, info, warn, error
    Component  string                 // dhcp, auth, radius, etc.
    Event      string                 // Type d'événement spécifique
    Message    string                 // Message descriptif
    SessionID  string                 // ID de session (optionnel)
    Username   string                 // Nom d'utilisateur (optionnel)
    IP         string                 // Adresse IP (optionnel)
    MAC        string                 // Adresse MAC (optionnel)
    Attributes map[string]interface{} // Attributs additionnels
}
```

### Événements Exportés

Le système exporte automatiquement les événements suivants:

- **Authentification:**
  - `user_login` - Connexion utilisateur
  - `user_logout` - Déconnexion utilisateur
  - `auth_failed` - Échec d'authentification
  - `session_timeout` - Expiration de session

- **DHCP:**
  - `dhcp_discover` - Découverte DHCP
  - `dhcp_offer` - Offre DHCP
  - `dhcp_request` - Requête DHCP
  - `dhcp_ack` - Accusé DHCP

- **RADIUS:**
  - `radius_request` - Requête RADIUS
  - `radius_accept` - Acceptation RADIUS
  - `radius_reject` - Rejet RADIUS
  - `accounting_start` - Début de comptabilité
  - `accounting_stop` - Fin de comptabilité

- **Filtrage:**
  - `domain_blocked` - Domaine bloqué
  - `ip_blocked` - IP bloquée
  - `category_match` - Correspondance de catégorie

### Intégration avec Zerolog

Le système s'intègre avec zerolog via un writer personnalisé:

```go
// Créer le manager d'export
manager, _ := logexport.NewManager(cfg, logger)
defer manager.Close()

// Créer un writer qui exporte les logs
exportWriter := logexport.NewLogEventWriter(manager)

// Utiliser avec zerolog
logger := zerolog.New(io.MultiWriter(os.Stderr, exportWriter))
```

### Performance

- **Buffer de 1000 événements** pour éviter le blocage
- **Worker asynchrone** pour l'export
- **Gestion d'erreurs** avec retry automatique
- **Gestion de la pression** avec abandon des événements si le buffer est plein

### Exemples d'Utilisation

#### Export Manuel d'Événements

```go
manager.Export(logexport.LogEvent{
    Timestamp: time.Now(),
    Level:     "info",
    Component: "custom",
    Event:     "custom_event",
    Message:   "Something happened",
    Username:  "admin",
    IP:        "10.0.0.1",
})
```

#### Analyse avec ELK Stack

1. Exporter vers Elasticsearch
2. Visualiser avec Kibana
3. Créer des dashboards pour:
   - Authentifications par heure
   - Top des utilisateurs actifs
   - Domaines bloqués
   - Tentatives d'authentification échouées

#### Archivage Long Terme

1. Exporter vers fichier JSONL
2. Rotation avec logrotate
3. Compression et archivage
4. Ou export direct vers S3

## Meilleures Pratiques

### Filtrage

1. **Commencez avec `default_action: allow`** et ajoutez des règles de blocage progressivement
2. **Utilisez `log` action** pour tester avant de bloquer
3. **Maintenez vos listes à jour** régulièrement
4. **Catégorisez vos règles** pour une meilleure organisation
5. **Testez vos regex** avant de les mettre en production

### Export de Logs

1. **Choisissez les exporters adaptés** à votre infrastructure
2. **Configurez la rotation des logs** pour éviter de remplir le disque
3. **Surveillez les performances** du système d'export
4. **Sécurisez les endpoints** (TLS pour syslog, authentification pour ES)
5. **Sauvegardez régulièrement** vos logs exportés

## Dépannage

### Le filtrage ne fonctionne pas

1. Vérifiez que `enabled: true` dans la configuration
2. Vérifiez les chemins des fichiers de règles
3. Consultez les logs pour les erreurs de parsing
4. Vérifiez les permissions des fichiers

### Les logs ne sont pas exportés

1. Vérifiez que `enabled: true` dans la configuration
2. Vérifiez la connectivité réseau (syslog, ES)
3. Vérifiez les permissions d'écriture (file exporter)
4. Consultez les logs d'erreurs du manager

### Performance dégradée

1. Réduisez le nombre de règles regex complexes
2. Augmentez la taille du buffer d'export
3. Utilisez des exporters asynchrones
4. Surveillez l'utilisation CPU/mémoire

## TODO / Améliorations Futures

- [ ] Implémenter S3 exporter
- [ ] Ajouter support pour Kafka
- [ ] Interface web pour gérer les règles
- [ ] Import/Export de configurations
- [ ] Métriques Prometheus pour le filtrage
- [ ] Whitelisting par utilisateur/groupe
- [ ] Scheduling de règles (horaires)
- [ ] Quotas par catégorie
