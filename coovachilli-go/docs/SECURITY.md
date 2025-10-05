
# Fonctionnalités de Sécurité CoovaChilli-Go

Ce document décrit les fonctionnalités de sécurité avancées de CoovaChilli-Go.

## Table des Matières

1. [Antimalware / Antivirus](#antimalware--antivirus)
2. [Système de Détection d'Intrusion (IDS)](#système-de-détection-dintrusion-ids)
3. [Chiffrement SSL/TLS](#chiffrement-ssltls)
4. [Gestion VLAN Avancée](#gestion-vlan-avancée)
5. [Conformité RGPD](#conformité-rgpd)

---

## Antimalware / Antivirus

### Vue d'ensemble

Le système antimalware intègre plusieurs moteurs de scan pour détecter les menaces en temps réel.

### Scanners Supportés

- **VirusTotal** : API de scan de fichiers et d'IPs
- **ClamAV** : Antivirus open-source
- **ThreatFox** : Base de données d'indicateurs de compromission (IOC)

### Configuration

```yaml
antimalware:
  enabled: true
  scanners:
    - virustotal
    - clamav
    - threatfox
  virustotal_api_key: "votre_cle_api"
  clamav_host: "localhost:3310"
  cache_ttl: 60  # minutes
```

### Niveaux de Menace

- `clean` : Aucune menace détectée
- `low` : Menace mineure
- `medium` : Menace modérée
- `high` : Menace élevée
- `critical` : Menace critique

### Utilisation

```go
// Scanner un hash de fichier
result, err := am.ScanHash("abc123def456...")
if result.ThreatLevel != ThreatLevelClean {
    log.Warn().Str("threat", result.ThreatName).Msg("Threat detected")
}

// Scanner une IP
result, err := am.ScanIP(net.ParseIP("192.0.2.1"))

// Obtenir les statistiques
stats := am.GetStats()
```

---

## Système de Détection d'Intrusion (IDS)

### Vue d'ensemble

L'IDS surveille le trafic réseau et détecte les activités suspectes en temps réel.

### Types de Détection

1. **Port Scanning** : Détecte les tentatives de scan de ports
2. **Brute Force** : Détecte les attaques par force brute
3. **DDoS** : Détecte les attaques par déni de service
4. **SQL Injection** : Détecte les tentatives d'injection SQL
5. **XSS (Cross-Site Scripting)** : Détecte les attaques XSS

### Configuration

```yaml
ids:
  enabled: true
  detect_port_scan: true
  detect_brute_force: true
  detect_ddos: true
  detect_sql_injection: true
  detect_xss: true

  # Seuils
  port_scan_threshold: 10      # Nombre de ports différents
  brute_force_threshold: 5     # Nombre de tentatives échouées
  ddos_threshold: 100          # Connexions par fenêtre de temps
  ddos_time_window: 10         # Fenêtre en secondes
```

### Événements d'Intrusion

```go
// Configurer un callback pour les événements
ids.SetEventCallback(func(event IntrusionEvent) {
    log.Warn().
        Str("type", string(event.Type)).
        Str("severity", event.Severity).
        Str("source_ip", event.SourceIP.String()).
        Msg("Intrusion detected")
})

// Vérifier une connexion
event := ids.CheckConnection(srcIP, dstIP, dstPort, "tcp")

// Vérifier un échec d'authentification
event := ids.CheckAuthFailure(srcIP, username)

// Vérifier une requête HTTP
event := ids.CheckHTTPRequest(srcIP, "GET", "/path", "query")
```

### Blocage Automatique

```go
// Bloquer une IP pour 30 minutes
ids.BlockIP(ip, 30*time.Minute)

// Vérifier si une IP est bloquée
if ids.IsBlocked(ip) {
    // Refuser la connexion
}
```

### Statistiques

```go
stats := ids.GetStats()
fmt.Printf("Total events: %d\n", stats.TotalEvents)
fmt.Printf("Port scans: %d\n", stats.PortScans)
fmt.Printf("Brute force: %d\n", stats.BruteForceAttempts)
fmt.Printf("DDoS: %d\n", stats.DDoSAttempts)
```

---

## Chiffrement SSL/TLS

### Vue d'ensemble

Gestion complète du chiffrement TLS 1.2/1.3 pour toutes les communications.

### Configuration

```yaml
tls:
  enabled: true
  cert_file: "/etc/coovachilli/server.crt"
  key_file: "/etc/coovachilli/server.key"
  ca_file: "/etc/coovachilli/ca.crt"
  require_client_cert: false
  insecure_skip_verify: false  # NE PAS utiliser en production
```

### Utilisation Serveur

```go
tlsManager, _ := security.NewTLSManager(cfg, logger)

// Configuration TLS pour serveur
tlsConfig, err := tlsManager.GetServerTLSConfig()

// Utiliser avec HTTP
server := &http.Server{
    TLSConfig: tlsConfig,
    // ...
}
server.ListenAndServeTLS("", "")
```

### Utilisation Client

```go
// Configuration TLS pour client
tlsConfig, err := tlsManager.GetClientTLSConfig()

// Utiliser avec HTTP client
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: tlsConfig,
    },
}
```

### Suites de Chiffrement

Le système utilise uniquement des suites de chiffrement modernes et sécurisées :

- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305

### Validation des Certificats

```go
err := tlsManager.ValidateCertificate(certFile, keyFile)
if err != nil {
    log.Error().Err(err).Msg("Certificate validation failed")
}
```

---

## Gestion VLAN Avancée

### Vue d'ensemble

Système de gestion VLAN avec affectation dynamique basée sur les rôles et les utilisateurs.

### Configuration

```yaml
vlan:
  enabled: true
  default_vlan: 100

  vlans:
    - id: 10
      name: "guest"
      description: "Guest Network"
      network: "10.10.0.0/24"
      gateway: "10.10.0.1"
      dns: ["8.8.8.8", "8.8.4.4"]
      isolated: true

    - id: 20
      name: "employee"
      description: "Employee Network"
      network: "10.20.0.0/24"
      gateway: "10.20.0.1"
      dns: ["10.0.0.53"]
      isolated: false

    - id: 30
      name: "vip"
      description: "VIP Network"
      network: "10.30.0.0/24"
      gateway: "10.30.0.1"
      dns: ["10.0.0.53"]
      isolated: false

  role_vlans:
    guest: 10
    employee: 20
    vip: 30
```

### Affectation de VLAN

```go
// Affecter un VLAN à une session
err := vlanMgr.AssignVLAN(sessionID, username, mac, vlanID)

// Obtenir le VLAN par session
vlanID, exists := vlanMgr.GetVLANBySession(sessionID)

// Obtenir le VLAN par utilisateur
vlanID, exists := vlanMgr.GetVLANByUser(username)

// Obtenir le VLAN par rôle
vlanID, err := vlanMgr.GetVLANByRole("employee")
```

### Informations VLAN

```go
// Obtenir les informations d'un VLAN
vlanInfo, err := vlanMgr.GetVLANInfo(vlanID)
fmt.Printf("VLAN: %s (%d)\n", vlanInfo.Name, vlanInfo.ID)
fmt.Printf("Network: %s\n", vlanInfo.IPNetwork)
fmt.Printf("Users: %d\n", vlanInfo.UserCount)

// Lister tous les VLANs
vlans := vlanMgr.ListVLANs()
```

### Statistiques

```go
stats := vlanMgr.GetStats()
fmt.Printf("Total VLANs: %d\n", stats.TotalVLANs)
fmt.Printf("Active VLANs: %d\n", stats.ActiveVLANs)
fmt.Printf("Total assignments: %d\n", stats.TotalAssignments)
```

---

## Conformité RGPD

### Vue d'ensemble

Système complet de gestion de la conformité RGPD avec chiffrement des données personnelles.

### Configuration

```yaml
gdpr:
  enabled: true
  data_retention_days: 365
  anonymize_instead_of_delete: true
  encrypt_personal_data: true
  encryption_key: "votre_cle_de_chiffrement_32_caracteres"
```

### Catégories de Données

- `identity` : Identité (nom, email)
- `contact` : Contact (téléphone, adresse)
- `technical` : Technique (IP, MAC, session)
- `usage` : Utilisation (historique, bande passante)
- `location` : Localisation
- `financial` : Financier (paiement)

### Enregistrement des Sujets

```go
// Enregistrer un sujet de données
err := gdprMgr.RegisterSubject(
    userID,
    username,
    email,
    []string{"marketing", "analytics"},
)
```

### Stockage de Données Personnelles

```go
// Stocker des données personnelles
data := map[string]interface{}{
    "name": "John Doe",
    "email": "john@example.com",
}

err := gdprMgr.StorePersonalData(
    subjectID,
    gdpr.CategoryIdentity,
    data,
    "user_registration",
    "consent",
)
```

### Droits des Sujets de Données

#### Droit d'Accès

```go
// Demande d'accès aux données
request, err := gdprMgr.RequestAccess(subjectID)

// Vérifier le statut
if request.Status == gdpr.StatusCompleted {
    allData := request.Result.(map[gdpr.DataCategory][]map[string]interface{})
    // Fournir les données à l'utilisateur
}
```

#### Droit à l'Effacement

```go
// Demande d'effacement (droit à l'oubli)
request, err := gdprMgr.RequestErasure(subjectID, "user_request")

// Les données seront anonymisées ou supprimées selon la configuration
```

#### Droit à la Portabilité

```go
// Demande de portabilité des données
request, err := gdprMgr.RequestPortability(subjectID)

// Le résultat sera un export JSON
if request.Status == gdpr.StatusCompleted {
    jsonData := request.Result.(string)
    // Fournir le fichier JSON à l'utilisateur
}
```

### Journal d'Audit

```go
// Obtenir le journal d'audit RGPD
auditLog := gdprMgr.GetAuditLog()
for _, entry := range auditLog {
    fmt.Printf("[%s] %s: %s\n",
        entry.Timestamp,
        entry.Action,
        entry.Details)
}

// Exporter le journal d'audit
err := gdprMgr.ExportAuditLog("/var/log/gdpr_audit.json")
```

### Rétention des Données

Le système supprime automatiquement les données expirées selon la configuration :

```go
// La rétention est vérifiée automatiquement toutes les 24 heures
// Les données au-delà de data_retention_days sont supprimées
```

---

## Meilleures Pratiques

### Antimalware

1. Utilisez plusieurs scanners pour une meilleure détection
2. Configurez un TTL de cache approprié (30-60 minutes)
3. Surveillez les statistiques régulièrement
4. Bloquez automatiquement les IPs malveillantes

### IDS

1. Ajustez les seuils selon votre environnement
2. Configurez des callbacks pour les alertes en temps réel
3. Intégrez avec votre système de SIEM
4. Examinez régulièrement les événements détectés
5. Mettez à jour les signatures d'attaque

### TLS

1. Utilisez toujours TLS 1.2 minimum (1.3 recommandé)
2. Validez les certificats régulièrement
3. Renouvelez les certificats avant expiration
4. N'utilisez jamais `insecure_skip_verify` en production
5. Utilisez des certificats signés par une CA reconnue

### VLAN

1. Isolez les réseaux invités
2. Utilisez des VLANs dédiés par type d'utilisateur
3. Documentez votre schéma de VLANs
4. Surveillez l'utilisation des VLANs
5. Implémentez des ACL entre VLANs si nécessaire

### RGPD

1. Chiffrez toujours les données sensibles
2. Définissez une politique de rétention claire
3. Documentez toutes les opérations dans l'audit log
4. Traitez les demandes dans les 30 jours (exigence RGPD)
5. Formez votre équipe sur les procédures RGPD
6. Effectuez des audits réguliers

---

## Dépannage

### Antimalware

**Problème** : Les scans échouent systématiquement

**Solution** :
1. Vérifiez les clés API
2. Vérifiez la connectivité réseau
3. Consultez les logs pour les détails d'erreur

### IDS

**Problème** : Trop de faux positifs

**Solution** :
1. Augmentez les seuils de détection
2. Affinez les patterns de détection
3. Whitelistez les IPs de confiance

### TLS

**Problème** : Erreur de validation de certificat

**Solution** :
1. Vérifiez la date d'expiration
2. Vérifiez la chaîne de certificats
3. Assurez-vous que le CA est approuvé

### VLAN

**Problème** : Affectation de VLAN incorrecte

**Solution** :
1. Vérifiez la configuration role_vlans
2. Vérifiez que les VLANs existent
3. Consultez les logs pour les détails

### RGPD

**Problème** : Données non chiffrées

**Solution** :
1. Vérifiez que `encrypt_personal_data: true`
2. Vérifiez la clé de chiffrement
3. Vérifiez les catégories de données

---

## Intégration

### Avec SIEM

```go
// Envoyer les événements IDS vers un SIEM
ids.SetEventCallback(func(event IntrusionEvent) {
    siemClient.SendEvent(map[string]interface{}{
        "type": "intrusion",
        "severity": event.Severity,
        "source_ip": event.SourceIP.String(),
        "details": event.Description,
    })
})
```

### Avec EDR

```go
// Intégrer avec une solution EDR
if result.ThreatLevel >= ThreatLevelHigh {
    edrClient.ReportThreat(result.ThreatName, result.Hash)
}
```

### Avec DLP

```go
// Intégrer avec Data Loss Prevention
gdprMgr.StorePersonalData(/* ... */)
dlpClient.ScanData(data)
```
