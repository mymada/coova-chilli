# Audit de Sécurité - CoovaChilli-Go

**Date:** 2025-10-05
**Version:** 1.0.0
**Auditeur:** Claude (AI Security Analysis)

## Résumé Exécutif

Ce document présente les résultats d'un audit de sécurité complet du projet CoovaChilli-Go, un portail captif moderne écrit en Go.

### Statistiques
- **Packages audités:** 20
- **Vulnérabilités critiques:** 1 🔴
- **Vulnérabilités moyennes:** 3 🟡
- **Recommandations:** 8 🟢
- **Bonnes pratiques identifiées:** 5 ✅

---

## 🔴 Vulnérabilités Critiques

### 1. JSONP Callback Injection (CWE-79)
**Fichier:** `pkg/http/server.go:480`
**Sévérité:** CRITIQUE
**CVSS Score:** 7.5

#### Description
Le handler `handleJsonpStatus` accepte un paramètre `callback` sans validation, permettant une injection XSS via JSONP.

```go
// VULNÉRABLE
callback := r.URL.Query().Get("callback")
if callback == "" {
    http.Error(w, "Callback function name is required", http.StatusBadRequest)
    return
}
// ... utilise callback directement dans la réponse
```

#### Impact
- **Cross-Site Scripting (XSS)** via injection de code JavaScript
- **Session Hijacking** si combiné avec d'autres vulnérabilités
- **Data Exfiltration** vers des domaines malveillants

#### Preuve de Concept
```bash
curl "http://portal.example.com/jsonp/status?callback=alert(document.cookie)//"
```

#### Remédiation
✅ **CORRIGÉ** - Implémenter une validation stricte du callback:
```go
func isValidJSONPCallback(callback string) bool {
    // Autoriser uniquement [a-zA-Z0-9_.$]
    matched, _ := regexp.MatchString(`^[a-zA-Z_$][a-zA-Z0-9_$.]*$`, callback)
    return matched && len(callback) <= 100
}
```

---

## 🟡 Vulnérabilités Moyennes

### 2. Absence de Rate Limiting DNS (CWE-400)
**Fichier:** `pkg/dns/dns.go`
**Sévérité:** MOYENNE
**CVSS Score:** 5.3

#### Description
Le proxy DNS ne limite pas le nombre de requêtes par client, permettant des attaques par amplification DNS.

#### Impact
- **DNS Amplification Attacks**
- **Déni de Service (DoS)** du serveur upstream
- **Épuisement des ressources**

#### Remédiation
Implémenter un rate limiter par IP client (recommandation: 10 req/sec):
```go
type DNSRateLimiter struct {
    limiters map[string]*rate.Limiter
    mu       sync.RWMutex
}
```

### 3. Validation insuffisante des entrées HTTP
**Fichier:** `pkg/http/server.go:162-163`
**Sévérité:** MOYENNE
**CVSS Score:** 4.3

#### Description
Les paramètres `username` et `password` ne sont pas validés pour la longueur ou les caractères.

#### Impact
- **Buffer Overflow** potentiel dans les logs
- **RADIUS Server Overload** avec des payloads énormes
- **Logs Poisoning**

#### Remédiation
```go
const (
    maxUsernameLen = 253 // RFC 2865
    maxPasswordLen = 128
)

func validateInput(username, password string) error {
    if len(username) == 0 || len(username) > maxUsernameLen {
        return errors.New("invalid username length")
    }
    if len(password) > maxPasswordLen {
        return errors.New("invalid password length")
    }
    // Vérifier caractères invalides
    if strings.ContainsAny(username, "\x00\n\r") {
        return errors.New("invalid characters in username")
    }
    return nil
}
```

### 4. Absence de timeout sur les connexions RADIUS
**Fichier:** `pkg/radius/radius.go`
**Sévérité:** MOYENNE
**CVSS Score:** 4.0

#### Description
Les connexions RADIUS n'ont pas de timeout explicite, pouvant causer des blocages.

#### Impact
- **Hang de l'application** si le serveur RADIUS ne répond pas
- **Épuisement des goroutines**

#### Remédiation
✅ **PARTIELLEMENT CORRIGÉ** - Circuit breaker implémenté, mais ajouter timeout:
```go
c := &radius.Client{
    Timeout: 5 * time.Second,
}
```

---

## 🟢 Recommandations de Sécurité

### 5. Renforcement de la gestion des secrets
**Fichier:** `pkg/securestore/`
**Statut:** ✅ BON

#### Analyse
L'utilisation de `memguard` pour protéger les secrets en mémoire est **excellente**:
- ✅ Secrets chiffrés en mémoire
- ✅ Nettoyage automatique (defer Destroy())
- ✅ Protection contre les dump mémoire
- ✅ Comparaison en temps constant

#### Recommandations additionnelles
1. **Rotation des secrets:** Implémenter un mécanisme de rotation
2. **Audit logging:** Logger les accès aux secrets (sans révéler les valeurs)
3. **Key derivation:** Utiliser PBKDF2/Argon2 pour les mots de passe stockés

### 6. Isolation réseau et firewall
**Fichiers:** `pkg/firewall/*.go`
**Statut:** ✅ BON

#### Points forts
- ✅ Abstraction multi-backend (iptables/ufw)
- ✅ Nettoyage automatique des règles
- ✅ Gestion des sessions authentifiées vs non-authentifiées

#### Recommandations
1. **Principe du moindre privilège:** Restreindre davantage les règles par défaut
2. **Logging des événements firewall:** Tracer les connexions bloquées
3. **IPv6:** Vérifier l'équivalence de sécurité IPv4/IPv6

### 7. Authentification et autorisation
**Fichiers:** `pkg/admin/server.go`, `pkg/http/server.go`

#### API Admin
- ✅ Token d'authentification requis
- ✅ Stockage sécurisé du token (securestore)
- ⚠️ **MANQUE:** Pas de rotation de token
- ⚠️ **MANQUE:** Pas d'expiration de session

#### Portail Captif
- ✅ Intégration RADIUS pour auth
- ✅ Sessions avec timeout
- ⚠️ **MANQUE:** Protection CSRF
- ⚠️ **MANQUE:** Headers de sécurité HTTP

#### Remédiation
```go
// Ajouter headers de sécurité
func securityHeadersMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("X-XSS-Protection", "1; mode=block")
        w.Header().Set("Content-Security-Policy", "default-src 'self'")
        w.Header().Set("Strict-Transport-Security", "max-age=31536000")
        next.ServeHTTP(w, r)
    })
}
```

### 8. Protection contre les attaques réseau

#### DoS/DDoS
- ✅ Rate limiting sur API Admin
- ⚠️ **MANQUE:** Rate limiting DNS
- ⚠️ **MANQUE:** Rate limiting portail captif
- ⚠️ **MANQUE:** Connection limiting

#### Recommandations
```go
// Limiter les connexions concurrentes par IP
type ConnectionLimiter struct {
    connections map[string]int
    mu          sync.RWMutex
    maxPerIP    int
}
```

### 9. Validation et sanitization des entrées

#### État actuel
- ⚠️ Validation minimale des entrées utilisateur
- ⚠️ Pas de sanitization des logs
- ⚠️ Pas de protection injection

#### Recommandations
1. **Whitelist validation:** Valider tous les inputs contre une whitelist
2. **Length limits:** Imposer des limites strictes
3. **Encoding:** Encoder toutes les sorties (HTML, JSON, logs)
4. **Parameterized queries:** Déjà bon (pas de SQL)

### 10. Cryptographie

#### Points forts
- ✅ TLS pour RadSec
- ✅ Chiffrement Blowfish pour clustering
- ✅ Comparaisons en temps constant

#### Recommandations
1. **TLS 1.3 minimum:** Forcer TLS 1.3 pour RadSec
2. **Cipher suites:** Restreindre aux suites modernes
3. **Certificate pinning:** Considérer pour RadSec

```go
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS13,
    CipherSuites: []uint16{
        tls.TLS_AES_128_GCM_SHA256,
        tls.TLS_AES_256_GCM_SHA384,
        tls.TLS_CHACHA20_POLY1305_SHA256,
    },
}
```

---

## ✅ Bonnes Pratiques Identifiées

### 1. Architecture de sécurité
- Séparation claire des responsabilités (packages)
- Interfaces pour découplage et testabilité
- Gestion centralisée des erreurs

### 2. Gestion des ressources
- Utilisation appropriée de `defer` pour cleanup
- Context pour annulation et timeouts
- Channels pour communication sûre

### 3. Concurrence
- Mutexes pour protéger les accès concurrents
- RWMutex pour optimiser lectures/écritures
- Atomic operations où approprié

### 4. Logging sécurisé
- Utilisation de zerolog (structured logging)
- Levels de log appropriés
- ⚠️ Attention: vérifier qu'aucun secret n'est loggé

### 5. Tests
- Tests unitaires pour composants critiques
- Mocks pour isolation
- ✅ Coverage >50% sur composants critiques

---

## 📊 Matrice de Risques

| Composant | Confidentialité | Intégrité | Disponibilité | Score Global |
|-----------|-----------------|-----------|---------------|--------------|
| Secrets Management | 🟢 Élevée | 🟢 Élevée | 🟢 Élevée | **9/10** |
| Authentication | 🟡 Moyenne | 🟢 Élevée | 🟢 Élevée | **7/10** |
| Network Isolation | 🟢 Élevée | 🟢 Élevée | 🟢 Élevée | **8/10** |
| Input Validation | 🟡 Moyenne | 🟡 Moyenne | 🟡 Moyenne | **5/10** |
| API Security | 🟢 Élevée | 🟡 Moyenne | 🟡 Moyenne | **6/10** |
| DNS Proxy | 🟢 Élevée | 🟢 Élevée | 🔴 Faible | **6/10** |
| HTTP Portal | 🟡 Moyenne | 🟡 Moyenne | 🟡 Moyenne | **6/10** |

---

## 🎯 Plan d'Action Prioritaire

### Immédiat (P0) - À corriger avant production
1. ✅ **Corriger JSONP injection** - pkg/http/server.go
2. ⚠️ **Ajouter validation des entrées** - pkg/http/server.go
3. ⚠️ **Implémenter rate limiting DNS** - pkg/dns/dns.go

### Court terme (P1) - 1-2 semaines
4. Ajouter headers de sécurité HTTP
5. Implémenter rotation des tokens API
6. Ajouter connection limiting

### Moyen terme (P2) - 1 mois
7. Protection CSRF
8. Audit logging complet
9. Tests de pénétration
10. Documentation sécurité utilisateur

---

## 📝 Checklist de Déploiement Sécurisé

Avant tout déploiement en production:

- [ ] Toutes les vulnérabilités P0 corrigées
- [ ] Secrets configurés via variables d'environnement (pas de hardcoding)
- [ ] TLS activé pour toutes les communications externes
- [ ] Firewall configuré avec principe du moindre privilège
- [ ] Logs sécurisés et rotationnés
- [ ] Monitoring et alertes en place
- [ ] Plan de réponse aux incidents documenté
- [ ] Backups des configurations
- [ ] Tests de charge effectués
- [ ] Revue de code par pairs complétée

---

## 📚 Références

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Go Security Best Practices](https://golang.org/doc/security/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

**Conclusion:** Le projet démontre une bonne maturité en matière de sécurité avec des choix architecturaux solides. Les vulnérabilités identifiées sont corrigeables et ne remettent pas en cause la conception générale. Score global de sécurité: **7.5/10**.
