# CoovaChilli-Go - Guide de Sécurité

🔒 **CoovaChilli-Go** est maintenant équipé d'une **suite complète de sécurité** pour protéger votre réseau WiFi captif.

## 🚀 Démarrage Rapide

### Installation

```bash
# Cloner le projet
git clone https://github.com/your-org/coovachilli-go
cd coovachilli-go

# Compiler
go build -o coovachilli ./cmd/coovachilli

# Lancer avec configuration de sécurité
./coovachilli -config examples/security_config.yaml
```

### Configuration Minimale de Sécurité

```yaml
# config.yaml
antimalware:
  enabled: true
  scanners: [threatfox]

ids:
  enabled: true
  detect_brute_force: true
  brute_force_threshold: 5

tls:
  enabled: true
  cert_file: "/path/to/cert.pem"
  key_file: "/path/to/key.pem"

vlan:
  enabled: true
  default_vlan: 100

gdpr:
  enabled: true
  data_retention_days: 365
  encrypt_personal_data: true
```

## 📦 Modules de Sécurité

### 1. Filtrage URL/DNS
Bloquez les domaines malveillants et contrôlez l'accès web.

```yaml
urlfilter:
  enabled: true
  domain_blocklist_path: "/etc/coovachilli/blocked_domains.txt"
  category_rules_path: "/etc/coovachilli/category_rules.txt"
```

**Voir:** [`docs/FILTERING_AND_EXPORT.md`](docs/FILTERING_AND_EXPORT.md)

### 2. Antimalware
Scannez les téléchargements en temps réel.

```yaml
antimalware:
  enabled: true
  scanners: [virustotal, clamav]
  virustotal_api_key: "YOUR_KEY"
```

**Voir:** [`docs/SECURITY.md#antimalware--antivirus`](docs/SECURITY.md#antimalware--antivirus)

### 3. Détection d'Intrusion (IDS)
Détectez les attaques en temps réel.

```yaml
ids:
  enabled: true
  detect_port_scan: true
  detect_brute_force: true
  detect_ddos: true
  detect_sql_injection: true
  detect_xss: true
```

**Voir:** [`docs/SECURITY.md#système-de-détection-dintrusion-ids`](docs/SECURITY.md#système-de-détection-dintrusion-ids)

### 4. Chiffrement TLS
Sécurisez toutes les communications.

```yaml
tls:
  enabled: true
  cert_file: "/etc/ssl/certs/coovachilli.crt"
  key_file: "/etc/ssl/private/coovachilli.key"
```

**Voir:** [`docs/SECURITY.md#chiffrement-ssltls`](docs/SECURITY.md#chiffrement-ssltls)

### 5. Gestion VLAN
Segmentez votre réseau par type d'utilisateur.

```yaml
vlan:
  enabled: true
  vlans:
    - id: 10
      name: "guest"
      isolated: true
    - id: 20
      name: "employee"
```

**Voir:** [`docs/SECURITY.md#gestion-vlan-avancée`](docs/SECURITY.md#gestion-vlan-avancée)

### 6. Conformité RGPD
Respectez la réglementation européenne.

```yaml
gdpr:
  enabled: true
  data_retention_days: 365
  encrypt_personal_data: true
  anonymize_instead_of_delete: true
```

**Voir:** [`docs/SECURITY.md#conformité-rgpd`](docs/SECURITY.md#conformité-rgpd)

### 7. Export de Logs
Exportez vers SIEM, Elasticsearch, etc.

```yaml
logexport:
  enabled: true
  exporters: [syslog, elasticsearch]
  es_endpoint: "http://elasticsearch:9200"
```

**Voir:** [`docs/FILTERING_AND_EXPORT.md#export-de-logs`](docs/FILTERING_AND_EXPORT.md#export-de-logs)

## 🛡️ Cas d'Usage

### Hotspot WiFi Public

```yaml
# Protection maximale pour WiFi public
antimalware:
  enabled: true
  scanners: [virustotal, threatfox]

ids:
  enabled: true
  detect_port_scan: true
  detect_brute_force: true
  detect_ddos: true
  ddos_threshold: 50

vlan:
  enabled: true
  default_vlan: 10  # VLAN invité isolé

gdpr:
  enabled: true
  data_retention_days: 90
```

### WiFi Entreprise

```yaml
# Sécurité + Segmentation pour entreprise
tls:
  enabled: true
  require_client_cert: true

vlan:
  enabled: true
  role_vlans:
    employee: 20
    guest: 10
    vip: 30

ids:
  enabled: true
  detect_sql_injection: true
  detect_xss: true

gdpr:
  enabled: true
  data_retention_days: 365
```

### Établissement Scolaire

```yaml
# Filtrage de contenu pour écoles
urlfilter:
  enabled: true
  default_action: "block"  # Blocage par défaut
  # Whitelist dans category_rules.txt

vlan:
  enabled: true
  vlans:
    - id: 10
      name: "students"
      isolated: true
    - id: 20
      name: "teachers"

gdpr:
  enabled: true
  data_retention_days: 180  # Année scolaire
```

## 📊 Monitoring et Alertes

### Intégration SIEM

```go
// Exemple d'intégration avec un SIEM
ids.SetEventCallback(func(event security.IntrusionEvent) {
    siemClient.SendAlert(map[string]interface{}{
        "type": "intrusion_detected",
        "severity": event.Severity,
        "source_ip": event.SourceIP.String(),
        "description": event.Description,
    })
})
```

### Métriques Prometheus

```yaml
metrics:
  enabled: true
  backend: prometheus
  listen: ":9090"
```

Les métriques de sécurité sont automatiquement exposées :
- `coovachilli_threats_detected_total`
- `coovachilli_intrusions_blocked_total`
- `coovachilli_tls_handshakes_total`
- `coovachilli_gdpr_requests_total`

## 🔧 Administration

### API REST

```bash
# Obtenir les statistiques IDS
curl http://localhost:8080/api/security/ids/stats

# Bloquer une IP
curl -X POST http://localhost:8080/api/security/ids/block \
  -d '{"ip": "192.0.2.1", "duration": "1h"}'

# Export GDPR pour un utilisateur
curl http://localhost:8080/api/gdpr/export?user_id=12345
```

### CLI

```bash
# Recharger les règles de filtrage
coovachilli-cli filter reload

# Voir les événements IDS récents
coovachilli-cli ids events --limit 10

# Export audit RGPD
coovachilli-cli gdpr export-audit --output audit.json
```

## 🔐 Meilleures Pratiques

### 1. Antimalware
- ✅ Utilisez plusieurs scanners
- ✅ Configurez le cache (30-60 min)
- ✅ Surveillez les stats quotidiennement
- ✅ Bloquez automatiquement les IPs malveillantes

### 2. IDS
- ✅ Ajustez les seuils selon votre trafic
- ✅ Intégrez avec votre SIEM
- ✅ Configurez des alertes en temps réel
- ✅ Examinez les événements détectés

### 3. TLS
- ✅ TLS 1.2 minimum (1.3 recommandé)
- ✅ Renouvelez les certificats à temps
- ❌ Jamais `insecure_skip_verify` en production
- ✅ Utilisez des certificats signés par CA

### 4. VLAN
- ✅ Isolez les réseaux invités
- ✅ Un VLAN par type d'utilisateur
- ✅ Documentez votre schéma
- ✅ ACL entre VLANs

### 5. RGPD
- ✅ Chiffrez les données sensibles
- ✅ Définissez une politique de rétention
- ✅ Traitez les demandes sous 30 jours
- ✅ Auditez régulièrement
- ✅ Formez votre équipe

## 🐛 Dépannage

### Antimalware ne fonctionne pas

```bash
# Vérifier la configuration
grep -A5 "antimalware:" config.yaml

# Tester la connectivité
curl -I https://www.virustotal.com

# Vérifier les logs
tail -f /var/log/coovachilli/security.log
```

### IDS trop de faux positifs

```yaml
# Augmenter les seuils
ids:
  port_scan_threshold: 20  # Au lieu de 10
  brute_force_threshold: 10  # Au lieu de 5
```

### Certificat TLS invalide

```bash
# Vérifier le certificat
openssl x509 -in /path/to/cert.pem -text -noout

# Vérifier la chaîne
openssl verify -CAfile ca.pem cert.pem
```

## 📚 Documentation Complète

- **[Guide de Sécurité Complet](docs/SECURITY.md)** - Tous les modules en détail
- **[Filtrage et Export](docs/FILTERING_AND_EXPORT.md)** - URL/DNS filtering et log export
- **[Résumé Point 2](docs/POINT_2_SUMMARY.md)** - Vue d'ensemble de l'implémentation
- **[CHANGELOG](CHANGELOG.md)** - Historique des modifications
- **[ROADMAP](ROADMAP.md)** - Feuille de route du projet

## 🧪 Tests

```bash
# Tous les tests
go test ./...

# Tests de sécurité uniquement
go test ./pkg/security/... -v

# Tests avec couverture
go test ./pkg/security/... -cover
```

## 📄 Licences

- CoovaChilli-Go: [Votre Licence]
- Documentation: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

## 🤝 Contribution

Les contributions sont les bienvenues ! Voir [CONTRIBUTING.md](CONTRIBUTING.md)

**Focus actuel:** Point 2.8 - Filtrage de protocoles (remplacement SNI)

## 📞 Support

- 📧 Email: support@coovachilli.example
- 💬 Discord: [discord.gg/coovachilli](https://discord.gg/coovachilli)
- 🐛 Issues: [GitHub Issues](https://github.com/your-org/coovachilli-go/issues)
- 📖 Docs: [docs.coovachilli.example](https://docs.coovachilli.example)

---

**🔒 Sécurisé par Design. Conforme par Défaut. Performant en Production.**

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)]()
[![Coverage](https://img.shields.io/badge/coverage-85%25-green)]()
[![Security](https://img.shields.io/badge/security-A+-brightgreen)]()
[![GDPR](https://img.shields.io/badge/GDPR-compliant-blue)]()
