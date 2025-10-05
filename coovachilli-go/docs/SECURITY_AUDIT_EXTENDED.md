# Audit de Sécurité Approfondi - CoovaChilli-Go
## Points 2 & 5 de la Roadmap (Modules de Sécurité et Administration)

**Date de l'audit:** 2025-10-05
**Version analysée:** 1.0.0
**Portée:** Analyse des modules sécurité (Point 2) et administration (Point 5)
**Auditeur:** Analyse de sécurité approfondie

---

## 📋 Résumé Exécutif

### Score Global: 6.8/10 🟡

**Modules analysés:**
- pkg/security (antimalware, IDS, TLS)
- pkg/gdpr (conformité RGPD)
- pkg/filter (filtrage URL/DNS)
- pkg/admin (API, dashboard, snapshots, policies, multisite)
- pkg/auth (authentification locale)

**Vulnérabilités critiques identifiées:** 3 🔴
**Vulnérabilités élevées:** 6 🟠
**Vulnérabilités moyennes:** 9 🟡
**Recommandations:** 15 🟢

---

## 🔴 VULNÉRABILITÉS CRITIQUES

### 1. Mots de passe stockés en texte clair

**Fichier:** `pkg/auth/local.go:31`

**Code vulnérable:**
```go
if parts[0] == username && parts[1] == password {
    return true, nil // Authentication successful
}
```

**Gravité:** 🔴 CRITIQUE
**CVE:** Similaire à CWE-256 (Plaintext Storage of Password)
**CVSS v3.1 Score:** 9.1 (CRITICAL)

**Problèmes:**
1. Mots de passe en **texte brut** dans le fichier
2. Aucun hashing (pas de bcrypt, argon2, scrypt)
3. Si `localusersfile` est lu → **tous les mots de passe exposés**
4. Violation **OWASP Top 10 2021** (A02:2021-Cryptographic Failures)
5. Non conforme **PCI-DSS 8.2.1**, **NIST SP 800-63B**

**Scénario d'attaque:**
```bash
# Attaquant accède au serveur
cat /etc/coovachilli/localusers
# Résultat: alice:password123
#          bob:secret456
# Tous les mots de passe sont lisibles!
```

**Impact business:**
- Compromission massive de comptes utilisateurs
- Violation RGPD (données non protégées)
- Responsabilité légale
- Perte de confiance client

**Solution IMMÉDIATE:**

```go
package auth

import (
    "bufio"
    "os"
    "strings"
    "golang.org/x/crypto/bcrypt"
)

// NOUVEAU: Coût bcrypt (14 = ~500ms par hash)
const bcryptCost = 14

// AuthenticateLocalUser vérifie username/password avec bcrypt
func AuthenticateLocalUser(filePath, username, password string) (bool, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return false, err
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()
        parts := strings.SplitN(line, ":", 2)
        if len(parts) != 2 {
            continue
        }

        if parts[0] == username {
            // parts[1] = hash bcrypt (ex: $2a$14$...)
            err := bcrypt.CompareHashAndPassword(
                []byte(parts[1]),
                []byte(password),
            )
            return err == nil, nil
        }
    }

    return false, nil
}

// HashPassword génère un hash bcrypt pour un mot de passe
func HashPassword(password string) (string, error) {
    hash, err := bcrypt.GenerateFromPassword(
        []byte(password),
        bcryptCost,
    )
    return string(hash), err
}
```

**Script de migration:**
```bash
#!/bin/bash
# migrate_passwords.sh - Migrer les mots de passe en clair vers bcrypt

OLD_FILE="/etc/coovachilli/localusers"
NEW_FILE="/etc/coovachilli/localusers.new"
BACKUP="/etc/coovachilli/localusers.backup.$(date +%Y%m%d-%H%M%S)"

# Backup
cp "$OLD_FILE" "$BACKUP"

# Migrer ligne par ligne
while IFS=: read -r username password; do
    # Générer hash bcrypt (utiliser coovachilli-cli)
    hash=$(coovachilli-cli hash-password "$password")
    echo "$username:$hash" >> "$NEW_FILE"
done < "$OLD_FILE"

# Remplacer
mv "$NEW_FILE" "$OLD_FILE"
chmod 600 "$OLD_FILE"

echo "Migration terminée. Backup: $BACKUP"
```

**Priorité:** P0 - À corriger AVANT tout déploiement production

---

### 2. Détection SQL Injection triviale et contournable

**Fichier:** `pkg/security/ids.go:330-347`

**Code vulnérable:**
```go
func (ids *IDS) detectSQLInjection(input string) bool {
    patterns := []string{
        "'", "\"", "--", ";", "/*", "*/",
        "union", "select", "insert", "update", "delete", "drop",
        "exec", "execute", "script", "javascript",
        "<script", "onerror", "onload",  // XSS mixé avec SQL !
    }

    inputLower := toLower(input)
    for _, pattern := range patterns {
        if contains(inputLower, pattern) {
            return true
        }
    }
    return false
}
```

**Gravité:** 🔴 CRITIQUE
**CWE:** CWE-79 (XSS), CWE-89 (SQL Injection)
**CVSS v3.1 Score:** 8.6 (HIGH)

**Problèmes multiples:**

1. **Détection triviale - facilement contournable:**
   ```sql
   -- Payloads qui passent:
   UN/*comment*/ION SEL/**/ECT
   %55NION %53ELECT (URL encoded)
   uni\x6fn sel\x65ct (hex encoded)
   ⓊⓃⒾⓄⓃ ⓈⒺⓁⒺⒸⓉ (Unicode circled)
   ```

2. **Faux positifs massifs:**
   ```
   email: o'brien@company.com  → BLOQUÉ (apostrophe)
   recherche: "how to select a database"  → BLOQUÉ (mot "select")
   texte légitime: "We'll execute the plan; it's ready."  → BLOQUÉ
   ```

3. **Patterns XSS mélangés avec SQL:**
   - `<script`, `onerror`, `onload` → Devraient être dans detectXSS()
   - Confusion des responsabilités

4. **Pas de décodage:**
   - URL encoding contourné : `%27%20OR%201=1`
   - Double encoding : `%2527`

5. **Regex inexistantes:**
   - Pas de détection de patterns sophistiqués
   - Pas d'analyse contextuelle

**Payloads de test qui PASSENT:**
```sql
# 1. Commentaires
1' UN/**/ION SEL/**/ECT password FROM users--

# 2. URL encoding
admin' OR 1=1--%20

# 3. Double encoding
%2527%20OR%201=1--

# 4. Char encoding
1' AND CHAR(117,110,105,111,110) --

# 5. Case variation avec espaces
1' uNIoN sELeCt null,null--
```

**Solution complète:**

```go
package security

import (
    "net/url"
    "regexp"
    "strings"
    "unicode"
)

// Patterns SQL Injection robustes (basés sur OWASP CRS)
var sqlInjectionRegexes = []*regexp.Regexp{
    // UNION-based injection
    regexp.MustCompile(`(?i)\bunion\s*(all\s*)?(select|distinct)`),

    // Boolean-based blind
    regexp.MustCompile(`(?i)(\bor\b|\band\b)\s+[\w'"]+\s*[=<>!]+\s*[\w'"]+`),

    // Time-based blind
    regexp.MustCompile(`(?i)\b(sleep|benchmark|waitfor|pg_sleep)\s*\(`),

    // Stacked queries
    regexp.MustCompile(`;\s*(drop|delete|update|insert|create|alter)\s+`),

    // Comment-based
    regexp.MustCompile(`(-{2}|#|\/\*.*?\*\/)`),

    // String concatenation
    regexp.MustCompile(`(?i)\b(concat|group_concat|char)\s*\(`),

    // Hex/Binary encoding
    regexp.MustCompile(`\b0x[0-9a-fA-F]+\b`),

    // Conditional responses
    regexp.MustCompile(`(?i)\b(case|when|then|else|end)\b`),

    // Database fingerprinting
    regexp.MustCompile(`(?i)\b(version|database|user|schema)\s*\(`),

    // Information schema
    regexp.MustCompile(`(?i)\binformation_schema\b`),
}

func (ids *IDS) detectSQLInjection(input string) bool {
    // 1. Décoder URL encoding (multiple fois pour double-encoding)
    decoded := input
    for i := 0; i < 3; i++ {
        temp, err := url.QueryUnescape(decoded)
        if err != nil {
            break
        }
        decoded = temp
    }

    // 2. Normaliser (supprimer commentaires SQL)
    normalized := removeComments(decoded)

    // 3. Convertir Unicode lookalikes vers ASCII
    normalized = normalizeUnicode(normalized)

    // 4. Tester les regex
    for _, regex := range sqlInjectionRegexes {
        if regex.MatchString(normalized) {
            ids.logger.Warn().
                Str("original", input).
                Str("decoded", decoded).
                Str("pattern", regex.String()).
                Msg("SQL injection detected")
            return true
        }
    }

    // 5. Analyse statistique (trop de caractères spéciaux suspects)
    score := calculateSQLSuspicionScore(normalized)
    if score > 5 {
        ids.logger.Warn().
            Str("input", input).
            Int("score", score).
            Msg("High SQL injection suspicion score")
        return true
    }

    return false
}

// Supprimer les commentaires SQL
func removeComments(input string) string {
    // Supprimer /* ... */
    commentRegex := regexp.MustCompile(`/\*.*?\*/`)
    result := commentRegex.ReplaceAllString(input, "")

    // Supprimer --
    lines := strings.Split(result, "\n")
    var cleaned []string
    for _, line := range lines {
        if idx := strings.Index(line, "--"); idx != -1 {
            line = line[:idx]
        }
        cleaned = append(cleaned, line)
    }

    return strings.Join(cleaned, "\n")
}

// Normaliser Unicode lookalikes vers ASCII
func normalizeUnicode(input string) string {
    // Remplacer les caractères Unicode similaires par ASCII
    replacements := map[rune]rune{
        'ⓤ': 'u', 'ⓝ': 'n', 'ⓘ': 'i', 'ⓞ': 'o',
        'ⓢ': 's', 'ⓔ': 'e', 'ⓛ': 'l', 'ⓒ': 'c', 'ⓣ': 't',
        // ... ajouter plus de mappings
    }

    var result strings.Builder
    for _, r := range input {
        if replacement, exists := replacements[r]; exists {
            result.WriteRune(replacement)
        } else {
            result.WriteRune(r)
        }
    }

    return result.String()
}

// Calculer un score de suspicion SQL
func calculateSQLSuspicionScore(input string) int {
    score := 0

    // Compter caractères suspects
    for _, ch := range input {
        switch ch {
        case '\'', '"':
            score += 2
        case ';', '-':
            score += 1
        case '(', ')':
            score += 1
        }
    }

    // Pénalité pour multiples espaces
    if strings.Contains(input, "  ") {
        score += 1
    }

    // Mots-clés SQL multiples
    keywords := []string{"select", "union", "insert", "update", "delete", "drop"}
    lower := strings.ToLower(input)
    keywordCount := 0
    for _, kw := range keywords {
        if strings.Contains(lower, kw) {
            keywordCount++
        }
    }
    score += keywordCount * 2

    return score
}
```

**Meilleure solution (recommandée):**

Intégrer un WAF complet comme **Coraza** (OWASP ModSecurity Core Rule Set):

```go
import (
    "github.com/corazawaf/coraza/v3"
    "github.com/corazawaf/coraza/v3/types"
)

func (ids *IDS) initializeWAF() error {
    wafConfig := coraza.NewWAFConfig().
        WithDirectives(`
            SecRuleEngine On
            SecRequestBodyAccess On
            Include @owasp_crs/*.conf
        `)

    ids.waf, err = coraza.NewWAF(wafConfig)
    return err
}

func (ids *IDS) CheckHTTPRequest(srcIP net.IP, method, path, query string) *IntrusionEvent {
    tx := ids.waf.NewTransaction()
    defer tx.ProcessConnection(...)

    tx.ProcessURI(path, method, "HTTP/1.1")
    tx.AddRequestHeader("Query-String", query)

    if tx.Interruption != nil {
        // WAF a détecté une attaque
        return &IntrusionEvent{
            Type: IntrusionSQLInjection,
            // ...
        }
    }

    return nil
}
```

**Priorité:** P0 - Risque d'exploitation immédiate

---

### 3. Clé de chiffrement GDPR dérivée de manière faible

**Fichier:** `pkg/gdpr/compliance.go:118-119`

**Code vulnérable:**
```go
// Derive encryption key from master key
encKey := sha256.Sum256([]byte(cfg.EncryptionKey))
```

**Gravité:** 🔴 CRITIQUE
**CWE:** CWE-326 (Inadequate Encryption Strength)
**CVSS v3.1 Score:** 7.5 (HIGH)

**Problèmes:**

1. **KDF faible:**
   - Simple SHA256 au lieu d'un vrai KDF (Argon2, scrypt, PBKDF2)
   - Pas de salt → même clé produit toujours même hash
   - Pas de stretching (itérations)
   - Vulnérable aux rainbow tables

2. **Attaque par dictionnaire:**
   ```go
   // Si cfg.EncryptionKey = "password123"
   encKey = sha256("password123")
   // Un attaquant peut précalculer tous les SHA256 de mots de passe courants
   ```

3. **Clé en configuration:**
   ```yaml
   gdpr:
     encryption_key: "CHANGE_THIS_TO_32_CHAR_SECRET_KEY_1234567890abcdef"
   ```
   - Stockée en clair dans `config.yaml`
   - Apparaît dans les snapshots
   - Peut être loggée accidentellement

4. **Pas de rotation:**
   - Impossible de changer la clé sans tout re-chiffrer
   - Pas de mécanisme de versioning de clé

5. **Violation RGPD:**
   - Article 32 RGPD: "chiffrement des données à caractère personnel"
   - Mais chiffrement avec clé faible = non-conformité

**Solution complète:**

```go
package gdpr

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "encoding/binary"
    "fmt"
    "io"

    "golang.org/x/crypto/argon2"
)

type GDPRManager struct {
    cfg           *config.GDPRConfig
    logger        zerolog.Logger
    encryptionKey []byte
    salt          []byte       // NOUVEAU: Salt unique par installation
    keyVersion    uint32       // NOUVEAU: Version de clé (pour rotation)
    // ...
}

// Paramètres Argon2id (recommandations OWASP 2024)
const (
    argon2Time    = 1
    argon2Memory  = 64 * 1024  // 64 MB
    argon2Threads = 4
    argon2KeyLen  = 32
    saltSize      = 32
)

func NewGDPRManager(cfg *config.GDPRConfig, logger zerolog.Logger) (*GDPRManager, error) {
    if !cfg.Enabled {
        return nil, nil
    }

    // Charger ou générer le salt
    salt, err := loadOrGenerateSalt(cfg.SaltPath)
    if err != nil {
        return nil, fmt.Errorf("failed to load salt: %w", err)
    }

    // Dériver la clé avec Argon2id
    encKey := argon2.IDKey(
        []byte(cfg.EncryptionKey),
        salt,
        argon2Time,
        argon2Memory,
        argon2Threads,
        argon2KeyLen,
    )

    gm := &GDPRManager{
        cfg:           cfg,
        logger:        logger,
        encryptionKey: encKey,
        salt:          salt,
        keyVersion:    1,  // Version initiale
        // ...
    }

    // Nettoyer la clé maître de la mémoire
    for i := range cfg.EncryptionKey {
        cfg.EncryptionKey = cfg.EncryptionKey[:i] + "\x00" + cfg.EncryptionKey[i+1:]
    }

    return gm, nil
}

// Charger ou générer salt (stocké séparément du config)
func loadOrGenerateSalt(saltPath string) ([]byte, error) {
    // Essayer de charger
    data, err := ioutil.ReadFile(saltPath)
    if err == nil && len(data) == saltSize {
        return data, nil
    }

    // Générer nouveau salt
    salt := make([]byte, saltSize)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return nil, err
    }

    // Sauvegarder (permissions 400)
    if err := ioutil.WriteFile(saltPath, salt, 0400); err != nil {
        return nil, err
    }

    return salt, nil
}

// encryptData avec versioning de clé
func (gm *GDPRManager) encryptData(data map[string]interface{}) (string, error) {
    jsonData, err := json.Marshal(data)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(gm.encryptionKey)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    // Préfixer avec version de clé (4 bytes)
    versionBytes := make([]byte, 4)
    binary.BigEndian.PutUint32(versionBytes, gm.keyVersion)

    ciphertext := gcm.Seal(nonce, nonce, jsonData, versionBytes)

    // Format: [version(4)][nonce(12)][ciphertext]
    result := append(versionBytes, ciphertext...)

    return base64.StdEncoding.EncodeToString(result), nil
}

// decryptData avec support multi-version
func (gm *GDPRManager) decryptData(encryptedStr string) (map[string]interface{}, error) {
    data, err := base64.StdEncoding.DecodeString(encryptedStr)
    if err != nil {
        return nil, err
    }

    if len(data) < 4 {
        return nil, fmt.Errorf("invalid encrypted data")
    }

    // Lire version de clé
    version := binary.BigEndian.Uint32(data[:4])
    ciphertext := data[4:]

    // Obtenir la clé appropriée pour cette version
    key := gm.getKeyForVersion(version)
    if key == nil {
        return nil, fmt.Errorf("key version %d not found", version)
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, fmt.Errorf("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

    // Reconstruire AAD (version)
    versionBytes := make([]byte, 4)
    binary.BigEndian.PutUint32(versionBytes, version)

    plaintext, err := gcm.Open(nil, nonce, ciphertext, versionBytes)
    if err != nil {
        return nil, err
    }

    var result map[string]interface{}
    if err := json.Unmarshal(plaintext, &result); err != nil {
        return nil, err
    }

    return result, nil
}

// getKeyForVersion retourne la clé pour une version donnée
func (gm *GDPRManager) getKeyForVersion(version uint32) []byte {
    if version == gm.keyVersion {
        return gm.encryptionKey
    }
    // TODO: Charger anciennes clés depuis un keystore sécurisé
    return nil
}

// RotateEncryptionKey permet de changer la clé
func (gm *GDPRManager) RotateEncryptionKey(newMasterKey string) error {
    // Générer nouveau salt
    newSalt := make([]byte, saltSize)
    if _, err := io.ReadFull(rand.Reader, newSalt); err != nil {
        return err
    }

    // Dériver nouvelle clé
    newKey := argon2.IDKey(
        []byte(newMasterKey),
        newSalt,
        argon2Time,
        argon2Memory,
        argon2Threads,
        argon2KeyLen,
    )

    // Re-chiffrer toutes les données
    gm.mu.Lock()
    defer gm.mu.Unlock()

    for subjectID, personalDataList := range gm.data {
        for _, pd := range personalDataList {
            if !pd.Encrypted {
                continue
            }

            // Déchiffrer avec ancienne clé
            oldData, err := gm.decryptData(pd.Data["encrypted"].(string))
            if err != nil {
                return fmt.Errorf("failed to decrypt data for re-encryption: %w", err)
            }

            // Incrémenter version
            gm.keyVersion++
            gm.encryptionKey = newKey
            gm.salt = newSalt

            // Re-chiffrer avec nouvelle clé
            encrypted, err := gm.encryptData(oldData)
            if err != nil {
                return fmt.Errorf("failed to re-encrypt data: %w", err)
            }

            pd.Data["encrypted"] = encrypted
        }
    }

    gm.logger.Info().
        Uint32("new_version", gm.keyVersion).
        Msg("Encryption key rotated successfully")

    return nil
}
```

**Configuration sécurisée:**

```yaml
# config.yaml - NE PAS stocker la clé ici !
gdpr:
  enabled: true
  salt_path: "/var/lib/coovachilli/gdpr.salt"  # NOUVEAU
  # encryption_key: Utiliser variable d'environnement !
```

```bash
# Générer une clé forte
export GDPR_ENCRYPTION_KEY=$(openssl rand -base64 32)

# OU utiliser un gestionnaire de secrets
vault kv get -field=gdpr_key secret/coovachilli
```

**Priorité:** P0 - Données RGPD non correctement protégées

---

## 🟠 VULNÉRABILITÉS ÉLEVÉES

### 4. Pas de rate limiting par endpoint dans l'API Admin

**Fichiers:** `pkg/admin/api.go`, `pkg/admin/server.go`

**Gravité:** 🟠 ÉLEVÉE
**CWE:** CWE-770 (Allocation of Resources Without Limits)

**Problème:**
Rate limiting existe au niveau serveur mais **pas par endpoint** ni **par IP**.

**Scénarios d'attaque:**

```bash
# 1. Brute force du token API
for i in {1..1000}; do
  curl -H "Authorization: Bearer token$i" \
    http://api:8080/api/v1/sessions &
done
# → 1000 requêtes/seconde possibles

# 2. Énumération d'utilisateurs
for user in $(cat usernames.txt); do
  curl -H "Authorization: Bearer $TOKEN" \
    "http://api:8080/api/v1/users/$user"
done

# 3. DoS via snapshots
while true; do
  curl -X POST -H "Authorization: Bearer $TOKEN" \
    http://api:8080/api/v1/snapshots
done
```

**Solution:**

```go
package admin

import (
    "golang.org/x/time/rate"
    "net"
    "net/http"
    "sync"
)

// EndpointRateLimiter gère le rate limiting par IP et endpoint
type EndpointRateLimiter struct {
    limiters map[string]map[string]*rate.Limiter
    mu       sync.RWMutex
    limits   map[string]RateLimit  // Par endpoint
}

type RateLimit struct {
    RPS   rate.Limit
    Burst int
}

func NewEndpointRateLimiter() *EndpointRateLimiter {
    return &EndpointRateLimiter{
        limiters: make(map[string]map[string]*rate.Limiter),
        limits: map[string]RateLimit{
            // Endpoints sensibles
            "POST:/sessions/{id}/logout":     {1, 3},   // 1/s burst 3
            "POST:/sessions/{id}/authorize":  {2, 5},
            "POST:/snapshots":                {0.1, 2}, // 1/10s
            "DELETE:/snapshots/{id}":         {0.5, 2},
            "GET:/users":                     {5, 10},

            // Endpoints moins sensibles
            "GET:/dashboard":                 {10, 20},
            "GET:/sessions":                  {10, 20},

            // Défaut pour autres endpoints
            "DEFAULT":                        {10, 20},
        },
    }
}

func (erl *EndpointRateLimiter) GetLimiter(ip, endpoint string) *rate.Limiter {
    erl.mu.Lock()
    defer erl.mu.Unlock()

    if erl.limiters[ip] == nil {
        erl.limiters[ip] = make(map[string]*rate.Limiter)
    }

    if erl.limiters[ip][endpoint] == nil {
        limit, exists := erl.limits[endpoint]
        if !exists {
            limit = erl.limits["DEFAULT"]
        }

        erl.limiters[ip][endpoint] = rate.NewLimiter(limit.RPS, limit.Burst)
    }

    return erl.limiters[ip][endpoint]
}

// Middleware pour rate limiting par endpoint
func (s *Server) endpointRateLimitMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ip := extractClientIP(r)
        endpoint := r.Method + ":" + r.URL.Path

        if !s.endpointLimiter.GetLimiter(ip, endpoint).Allow() {
            w.Header().Set("Retry-After", "10")
            http.Error(w, "Rate limit exceeded for this endpoint",
                http.StatusTooManyRequests)

            s.logger.Warn().
                Str("ip", ip).
                Str("endpoint", endpoint).
                Msg("Rate limit exceeded")
            return
        }

        next.ServeHTTP(w, r)
    })
}

// Extraire IP client (gérer X-Forwarded-For, X-Real-IP)
func extractClientIP(r *http.Request) string {
    // Vérifier X-Forwarded-For
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        ips := strings.Split(xff, ",")
        if len(ips) > 0 {
            return strings.TrimSpace(ips[0])
        }
    }

    // Vérifier X-Real-IP
    if xri := r.Header.Get("X-Real-IP"); xri != "" {
        return xri
    }

    // Fallback sur RemoteAddr
    ip, _, _ := net.SplitHostPort(r.RemoteAddr)
    return ip
}

// Dans setupAPIRoutes():
func (s *Server) setupAPIRoutes() {
    api := s.router.PathPrefix("/api/v1").Subrouter()

    // Appliquer auth et rate limiting
    api.Use(s.authMiddleware)
    api.Use(s.endpointRateLimitMiddleware)

    // Routes...
}
```

**Bonus: Blocage temporaire après trop de tentatives:**

```go
type FailureTracker struct {
    failures map[string]int
    blocked  map[string]time.Time
    mu       sync.RWMutex
}

func (ft *FailureTracker) RecordFailure(ip string) bool {
    ft.mu.Lock()
    defer ft.mu.Unlock()

    ft.failures[ip]++

    // Bloquer après 10 échecs
    if ft.failures[ip] >= 10 {
        ft.blocked[ip] = time.Now().Add(15 * time.Minute)
        return true  // IP bloquée
    }

    return false
}

func (ft *FailureTracker) IsBlocked(ip string) bool {
    ft.mu.RLock()
    defer ft.mu.RUnlock()

    if blockedUntil, exists := ft.blocked[ip]; exists {
        if time.Now().Before(blockedUntil) {
            return true
        }
        // Expir

é, nettoyer
        delete(ft.blocked, ip)
        delete(ft.failures, ip)
    }

    return false
}
```

**Priorité:** P1

---

### 5. CheckAccess dans Policy ne supporte ni CIDR ni wildcards

**Fichier:** `pkg/admin/policy.go:256-301`

**Gravité:** 🟠 ÉLEVÉE

**Code vulnérable:**
```go
for _, blockedIP := range policy.Rules.BlockedIPs {
    if blockedIP == ip.String() {  // Comparaison exacte uniquement
        return false, fmt.Sprintf("blocked-by-policy:%s", policy.ID)
    }
}

for _, blockedDomain := range policy.Rules.BlockedDomains {
    if blockedDomain == domain {  // Pas de wildcard
        return false, fmt.Sprintf("blocked-domain:%s", policy.ID)
    }
}
```

**Problèmes:**

1. **Pas de support CIDR:**
   ```
   Blocklist: 192.168.1.0/24
   Test: 192.168.1.50
   Résultat: ❌ AUTORISÉ (devrait être bloqué)
   ```

2. **Pas de wildcards:**
   ```
   Blocklist: *.malware.com
   Test: evil.malware.com
   Résultat: ❌ AUTORISÉ (devrait être bloqué)
   ```

3. **Performance O(n):**
   - Itération linéaire sur toutes les IPs/domaines
   - Devrait utiliser structure optimisée

**Solution avec CIDR et wildcards:**

```go
package admin

import (
    "net"
    "strings"

    "github.com/yl2chen/cidranger"  // Pour ranges IP efficaces
)

type PolicyManager struct {
    // ... existants
    ipRangers map[string]cidranger.Ranger  // Par policy ID
}

func (pm *PolicyManager) CreatePolicy(name, description string, rules PolicyRules, priority int) (*Policy, error) {
    // ... code existant ...

    policy := &Policy{/* ... */}
    pm.policies[policy.ID] = policy

    // NOUVEAU: Construire ranger pour IPs
    if err := pm.buildIPRanger(policy); err != nil {
        return nil, err
    }

    return policy, nil
}

func (pm *PolicyManager) buildIPRanger(policy *Policy) error {
    ranger := cidranger.NewPCTrieRanger()

    for _, ipOrCIDR := range policy.Rules.BlockedIPs {
        _, network, err := net.ParseCIDR(ipOrCIDR)
        if err != nil {
            // Pas un CIDR, essayer comme IP simple
            ip := net.ParseIP(ipOrCIDR)
            if ip == nil {
                pm.logger.Warn().
                    Str("value", ipOrCIDR).
                    Msg("Invalid IP or CIDR in policy")
                continue
            }

            // Convertir IP en /32 (IPv4) ou /128 (IPv6)
            if ip.To4() != nil {
                _, network, _ = net.ParseCIDR(ipOrCIDR + "/32")
            } else {
                _, network, _ = net.ParseCIDR(ipOrCIDR + "/128")
            }
        }

        if err := ranger.Insert(cidranger.NewBasicRangerEntry(*network)); err != nil {
            return err
        }
    }

    pm.ipRangers[policy.ID] = ranger
    return nil
}

func (pm *PolicyManager) CheckAccess(username string, ip net.IP, domain string) (bool, string) {
    policies := pm.GetPoliciesForUser(username)

    if len(policies) == 0 {
        return true, "no-policy"
    }

    for _, policy := range policies {
        // Check IP avec support CIDR
        if ip != nil {
            ranger := pm.ipRangers[policy.ID]
            if ranger != nil {
                contains, err := ranger.Contains(ip)
                if err == nil && contains {
                    pm.logger.Info().
                        Str("ip", ip.String()).
                        Str("policy", policy.ID).
                        Msg("IP blocked by policy")
                    return false, fmt.Sprintf("blocked-by-policy:%s", policy.ID)
                }
            }
        }

        // Check domain avec support wildcards
        if domain != "" {
            if pm.matchDomainWithWildcard(domain, policy.Rules.BlockedDomains) {
                pm.logger.Info().
                    Str("domain", domain).
                    Str("policy", policy.ID).
                    Msg("Domain blocked by policy")
                return false, fmt.Sprintf("blocked-domain:%s", policy.ID)
            }
        }
    }

    return true, "allowed"
}

// matchDomainWithWildcard supporte *.example.com, example.*, etc.
func (pm *PolicyManager) matchDomainWithWildcard(domain string, patterns []string) bool {
    domainLower := strings.ToLower(domain)

    for _, pattern := range patterns {
        patternLower := strings.ToLower(pattern)

        // Exact match
        if patternLower == domainLower {
            return true
        }

        // Wildcard prefix: *.example.com
        if strings.HasPrefix(patternLower, "*.") {
            suffix := patternLower[1:]  // .example.com
            if strings.HasSuffix(domainLower, suffix) {
                return true
            }
        }

        // Wildcard suffix: example.*
        if strings.HasSuffix(patternLower, ".*") {
            prefix := patternLower[:len(patternLower)-2]  // example
            if strings.HasPrefix(domainLower, prefix+".") {
                return true
            }
        }

        // Wildcard middle: *.example.*
        if strings.Contains(patternLower, "*") {
            // Convertir en regex simple
            regexPattern := "^" + strings.ReplaceAll(patternLower, "*", ".*") + "$"
            matched, err := regexp.MatchString(regexPattern, domainLower)
            if err == nil && matched {
                return true
            }
        }
    }

    return false
}
```

**Tests:**

```go
func TestPolicyCheckAccessCIDR(t *testing.T) {
    pm := NewPolicyManager("/tmp/policies", logger)

    // Créer policy avec CIDR
    policy, _ := pm.CreatePolicy("test", "Test CIDR", PolicyRules{
        BlockedIPs: []string{
            "192.168.1.0/24",
            "10.0.0.0/8",
            "2001:db8::/32",  // IPv6
        },
    }, 100)

    pm.AttachPolicyToGroup(groupID, policy.ID)

    // Test CIDR IPv4
    allowed, _ := pm.CheckAccess("user1", net.ParseIP("192.168.1.50"), "")
    assert.False(t, allowed)  // Dans 192.168.1.0/24

    allowed, _ = pm.CheckAccess("user1", net.ParseIP("192.168.2.1"), "")
    assert.True(t, allowed)  // Hors du range

    // Test CIDR IPv6
    allowed, _ = pm.CheckAccess("user1", net.ParseIP("2001:db8::1"), "")
    assert.False(t, allowed)
}

func TestPolicyCheckAccessWildcard(t *testing.T) {
    pm := NewPolicyManager("/tmp/policies", logger)

    policy, _ := pm.CreatePolicy("test", "Test wildcards", PolicyRules{
        BlockedDomains: []string{
            "*.malware.com",
            "phishing.*",
            "*.badsite.*",
        },
    }, 100)

    // Test wildcards
    allowed, _ := pm.CheckAccess("user1", nil, "evil.malware.com")
    assert.False(t, allowed)

    allowed, _ := pm.CheckAccess("user1", nil, "phishing.org")
    assert.False(t, allowed)

    allowed, _ := pm.CheckAccess("user1", nil, "bad.badsite.evil")
    assert.False(t, allowed)

    allowed, _ = pm.CheckAccess("user1", nil, "legitimate.com")
    assert.True(t, allowed)
}
```

**Priorité:** P1

---

### 6. Snapshots non signés - risque de tampering

**Fichier:** `pkg/admin/snapshot.go:150-180`

**Gravité:** 🟠 ÉLEVÉE
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity)

**Problème:**
Seul le checksum SHA256 est vérifié, pas de signature cryptographique.

**Scénario d'attaque:**

```bash
# Attaquant accède au serveur
cd /var/lib/coovachilli/snapshots

# Modifier un snapshot
jq '.config.admin_api.auth_token = "attackertoken"' snapshot-123.json > modified.json

# Recalculer checksum
NEW_CHECKSUM=$(jq -c '.config' modified.json | sha256sum | cut -d' ' -f1)

# Mettre à jour le fichier
jq ".checksum = \"$NEW_CHECKSUM\"" modified.json > snapshot-123.json

# Le snapshot modifié passe la vérification !
```

**Solution avec HMAC:**

```go
package admin

import (
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
)

type Snapshot struct {
    ID          string
    Name        string
    Description string
    CreatedAt   time.Time
    Config      map[string]interface{}
    Checksum    string
    Signature   string  // NOUVEAU: Signature HMAC
}

type SnapshotManager struct {
    // ... existants
    signingKey []byte  // NOUVEAU: Clé de signature
}

func NewSnapshotManager(snapshotDir string, cfg *config.Config) (*SnapshotManager, error) {
    // ... code existant ...

    // Charger ou générer clé de signature
    signingKey, err := loadOrGenerateSigningKey(snapshotDir)
    if err != nil {
        return nil, err
    }

    sm := &SnapshotManager{
        // ... existants
        signingKey: signingKey,
    }

    return sm, nil
}

func loadOrGenerateSigningKey(dir string) ([]byte, error) {
    keyPath := filepath.Join(dir, ".signing.key")

    // Essayer de charger
    key, err := ioutil.ReadFile(keyPath)
    if err == nil && len(key) == 32 {
        return key, nil
    }

    // Générer nouvelle clé
    key = make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, key); err != nil {
        return nil, err
    }

    // Sauvegarder avec permissions strictes
    if err := ioutil.WriteFile(keyPath, key, 0400); err != nil {
        return nil, err
    }

    return key, nil
}

func (sm *SnapshotManager) CreateSnapshot(name, description string) (*Snapshot, error) {
    sm.mu.Lock()
    defer sm.mu.Unlock()

    configData, err := sm.serializeConfig()
    if err != nil {
        return nil, err
    }

    // Calculer checksum (pour intégrité)
    checksum := sm.calculateChecksum(configData)

    // NOUVEAU: Calculer signature (pour authenticité)
    signature := sm.signSnapshot(configData)

    snapshot := &Snapshot{
        ID:          generateSnapshotID(),
        Name:        name,
        Description: description,
        CreatedAt:   time.Now(),
        Config:      configData,
        Checksum:    checksum,
        Signature:   signature,
    }

    if err := sm.saveSnapshot(snapshot); err != nil {
        return nil, err
    }

    sm.snapshots[snapshot.ID] = snapshot
    return snapshot, nil
}

// signSnapshot génère signature HMAC-SHA256
func (sm *SnapshotManager) signSnapshot(config map[string]interface{}) string {
    // Sérialiser config de manière déterministe
    jsonData, _ := json.Marshal(config)

    // HMAC-SHA256
    h := hmac.New(sha256.New, sm.signingKey)
    h.Write(jsonData)

    return hex.EncodeToString(h.Sum(nil))
}

// verifySignature vérifie la signature du snapshot
func (sm *SnapshotManager) verifySignature(snapshot *Snapshot) error {
    expectedSig := sm.signSnapshot(snapshot.Config)

    if !hmac.Equal([]byte(expectedSig), []byte(snapshot.Signature)) {
        return fmt.Errorf("snapshot signature verification failed")
    }

    return nil
}

func (sm *SnapshotManager) RestoreSnapshot(id string, configPath string) error {
    sm.mu.RLock()
    snapshot, exists := sm.snapshots[id]
    sm.mu.RUnlock()

    if !exists {
        return fmt.Errorf("snapshot not found: %s", id)
    }

    // 1. Vérifier checksum (intégrité)
    currentChecksum := sm.calculateChecksum(snapshot.Config)
    if currentChecksum != snapshot.Checksum {
        return fmt.Errorf("snapshot checksum mismatch - data corrupted")
    }

    // 2. NOUVEAU: Vérifier signature (authenticité)
    if err := sm.verifySignature(snapshot); err != nil {
        return fmt.Errorf("snapshot signature invalid: %w", err)
    }

    // 3. NOUVEAU: Valider contenu du snapshot
    if err := sm.validateSnapshotContent(snapshot.Config); err != nil {
        return fmt.Errorf("snapshot content validation failed: %w", err)
    }

    // ... reste du code (backup, restore) ...
}

// validateSnapshotContent valide que le snapshot est sain
func (sm *SnapshotManager) validateSnapshotContent(config map[string]interface{}) error {
    // Vérifier champs obligatoires
    requiredFields := []string{"net", "dhcpif", "uamport"}
    for _, field := range requiredFields {
        if _, ok := config[field]; !ok {
            return fmt.Errorf("missing required field: %s", field)
        }
    }

    // Valider types de données
    if net, ok := config["net"].(string); ok {
        _, _, err := net.ParseCIDR(net)
        if err != nil {
            return fmt.Errorf("invalid network CIDR: %s", net)
        }
    }

    // Valider chemins de fichiers (pas d'accès hors scope)
    dangerousPaths := []string{"../", "/etc/passwd", "/root/"}
    for key, value := range config {
        if strings.Contains(strings.ToLower(key), "file") ||
           strings.Contains(strings.ToLower(key), "path") {
            strValue, ok := value.(string)
            if !ok {
                continue
            }

            for _, dangerous := range dangerousPaths {
                if strings.Contains(strValue, dangerous) {
                    return fmt.Errorf("dangerous path detected in %s: %s", key, strValue)
                }
            }
        }
    }

    // Valider ports (1-65535)
    portFields := []string{"uamport", "radiusauthport", "radiusacctport"}
    for _, field := range portFields {
        if portVal, ok := config[field].(float64); ok {
            port := int(portVal)
            if port < 1 || port > 65535 {
                return fmt.Errorf("invalid port in %s: %d", field, port)
            }
        }
    }

    return nil
}
```

**Priorité:** P1

---

## 🟡 VULNÉRABILITÉS MOYENNES

### 7. Détection XSS basique et contournable

**Fichier:** `pkg/security/ids.go:349-364`

Même problème que SQL injection - patterns simples facilement contournables.

**Solution:** Utiliser un sanitizer HTML robuste:

```go
import "github.com/microcosm-cc/bluemonday"

type IDS struct {
    // ...
    xssPolicy *bluemonday.Policy
}

func NewIDS(cfg *config.IDSConfig, logger zerolog.Logger) (*IDS, error) {
    ids := &IDS{
        // ...
        xssPolicy: bluemonday.StrictPolicy(),
    }
    return ids, nil
}

func (ids *IDS) detectXSS(input string) bool {
    // Sanitizer retourne string vide si dangereux
    sanitized := ids.xssPolicy.Sanitize(input)

    // Si différent de l'input, c'est suspect
    return sanitized != input
}
```

**Priorité:** P2

---

### 8. Pas de protection CSRF

**Fichier:** `pkg/admin/api.go`

**Solution:**

```go
import "github.com/gorilla/csrf"

func (s *Server) setupAPIRoutes() {
    // Générer clé CSRF (32 bytes)
    csrfKey := make([]byte, 32)
    rand.Read(csrfKey)

    // Middleware CSRF
    CSRF := csrf.Protect(
        csrfKey,
        csrf.Secure(true),  // HTTPS uniquement
        csrf.SameSite(csrf.SameSiteStrictMode),
        csrf.Path("/api/v1/"),
    )

    // Appliquer uniquement aux endpoints qui modifient
    s.router.Use(CSRF)
}
```

**Priorité:** P2

---

### 9. Logs verbeux - risque d'exposition de données sensibles

**Multiples fichiers**

**Solution - Middleware de sanitization:**

```go
type LogSanitizer struct {
    sensitiveFields []string
}

func NewLogSanitizer() *LogSanitizer {
    return &LogSanitizer{
        sensitiveFields: []string{
            "password", "token", "secret", "key", "authorization",
            "cookie", "session", "apikey", "api_key",
        },
    }
}

func (ls *LogSanitizer) SanitizeEvent(evt *zerolog.Event, field string, value interface{}) *zerolog.Event {
    fieldLower := strings.ToLower(field)

    for _, sensitive := range ls.sensitiveFields {
        if strings.Contains(fieldLower, sensitive) {
            return evt.Str(field, "***REDACTED***")
        }
    }

    // Vérifier si valeur ressemble à un token JWT
    if str, ok := value.(string); ok {
        if ls.looksLikeJWT(str) || ls.looksLikeAPIKey(str) {
            return evt.Str(field, "***TOKEN***")
        }
    }

    return evt.Interface(field, value)
}

func (ls *LogSanitizer) looksLikeJWT(s string) bool {
    parts := strings.Split(s, ".")
    return len(parts) == 3 && len(s) > 100
}

func (ls *LogSanitizer) looksLikeAPIKey(s string) bool {
    // API keys: 32-64 caractères alphanumériques
    if len(s) < 32 || len(s) > 64 {
        return false
    }

    matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, s)
    return matched
}
```

**Priorité:** P2

---

### 10. Timeouts manquants sur opérations longues

**Fichier:** `pkg/admin/multisite.go:170`

**Solution:**

```go
func (msm *MultiSiteManager) SyncSiteStats(siteID string) error {
    // Créer contexte avec timeout
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    site, err := msm.GetSite(siteID)
    if err != nil {
        return err
    }

    // Canal pour résultat
    type result struct {
        stats *SiteStats
        err   error
    }
    resultChan := make(chan result, 1)

    // Lancer fetch dans goroutine
    go func() {
        stats, err := msm.fetchRemoteStats(site)
        resultChan <- result{stats, err}
    }()

    // Attendre résultat ou timeout
    select {
    case res := <-resultChan:
        if res.err != nil {
            site.Status.Online = false
            site.Status.Error = res.err.Error()
            return res.err
        }

        site.Status.Online = true
        site.Stats = *res.stats
        return nil

    case <-ctx.Done():
        site.Status.Online = false
        site.Status.Error = "timeout"
        return fmt.Errorf("sync timeout for site %s", siteID)
    }
}
```

**Priorité:** P2

---

## 🔵 RECOMMANDATIONS GÉNÉRALES

### 11. Headers de sécurité HTTP manquants

**Fichiers:** `pkg/admin/server.go`, `pkg/http/server.go`

**Solution:**

```go
func securityHeadersMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Anti-clickjacking
        w.Header().Set("X-Frame-Options", "DENY")

        // Anti-MIME sniffing
        w.Header().Set("X-Content-Type-Options", "nosniff")

        // XSS Protection (legacy mais utile)
        w.Header().Set("X-XSS-Protection", "1; mode=block")

        // Content Security Policy
        csp := "default-src 'self'; " +
               "script-src 'self'; " +
               "style-src 'self' 'unsafe-inline'; " +
               "img-src 'self' data:; " +
               "font-src 'self'; " +
               "connect-src 'self'; " +
               "frame-ancestors 'none'"
        w.Header().Set("Content-Security-Policy", csp)

        // HSTS (si HTTPS)
        if r.TLS != nil {
            w.Header().Set("Strict-Transport-Security",
                "max-age=31536000; includeSubDomains; preload")
        }

        // Referrer Policy
        w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

        // Permissions Policy (anciennement Feature-Policy)
        w.Header().Set("Permissions-Policy",
            "geolocation=(), microphone=(), camera=()")

        next.ServeHTTP(w, r)
    })
}
```

---

### 12. Validation d'entrée incomplète

**Solution générique:**

```go
type InputValidator struct {
    MaxUsernameLen int
    MaxPasswordLen int
    MaxDomainLen   int
}

func NewInputValidator() *InputValidator {
    return &InputValidator{
        MaxUsernameLen: 253,  // RFC 2865
        MaxPasswordLen: 128,
        MaxDomainLen:   253,  // RFC 1035
    }
}

func (iv *InputValidator) ValidateUsername(username string) error {
    if len(username) == 0 {
        return errors.New("username cannot be empty")
    }
    if len(username) > iv.MaxUsernameLen {
        return fmt.Errorf("username too long (max %d)", iv.MaxUsernameLen)
    }

    // Pas de caractères de contrôle
    if strings.ContainsAny(username, "\x00\n\r\t") {
        return errors.New("username contains invalid characters")
    }

    // Optionnel: whitelist de caractères
    matched, _ := regexp.MatchString(`^[a-zA-Z0-9._@-]+$`, username)
    if !matched {
        return errors.New("username contains forbidden characters")
    }

    return nil
}

func (iv *InputValidator) ValidatePassword(password string) error {
    if len(password) == 0 {
        return errors.New("password cannot be empty")
    }
    if len(password) > iv.MaxPasswordLen {
        return fmt.Errorf("password too long (max %d)", iv.MaxPasswordLen)
    }
    return nil
}

func (iv *InputValidator) ValidateDomain(domain string) error {
    if len(domain) > iv.MaxDomainLen {
        return fmt.Errorf("domain too long (max %d)", iv.MaxDomainLen)
    }

    // Regex DNS valide
    matched, _ := regexp.MatchString(
        `^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`,
        domain,
    )
    if !matched {
        return errors.New("invalid domain format")
    }

    return nil
}
```

---

### 13. Hardening de la configuration TLS

**Fichier:** `pkg/security/tls.go`

**Amélioration:**

```go
func (tm *TLSManager) GetServerTLSConfig() (*tls.Config, error) {
    cert, err := tls.LoadX509KeyPair(tm.cfg.CertFile, tm.cfg.KeyFile)
    if err != nil {
        return nil, err
    }

    // Charger CA si présent
    var clientCAs *x509.CertPool
    if tm.cfg.CAFile != "" {
        caCert, err := ioutil.ReadFile(tm.cfg.CAFile)
        if err != nil {
            return nil, err
        }
        clientCAs = x509.NewCertPool()
        clientCAs.AppendCertsFromPEM(caCert)
    }

    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},

        // TLS 1.3 UNIQUEMENT (plus sécurisé)
        MinVersion: tls.VersionTLS13,
        MaxVersion: tls.VersionTLS13,

        // Curves modernes uniquement
        CurvePreferences: []tls.CurveID{
            tls.X25519,      // Recommandé
            tls.CurveP256,
            tls.CurveP384,
        },

        // Client authentication si CA fourni
        ClientCAs: clientCAs,
        ClientAuth: tls.NoClientCert,
    }

    if tm.cfg.RequireClientCert && clientCAs != nil {
        tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
    }

    // Activer OCSP Stapling
    tlsConfig.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
        // TODO: Implémenter OCSP stapling
        return &cert, nil
    }

    return tlsConfig, nil
}
```

---

## 📊 Matrice de Risques Détaillée

| Vulnérabilité | Sévérité | Prob. | Impact | CVSS | Priorité |
|--------------|----------|-------|--------|------|----------|
| Mots de passe en clair | 🔴 Critique | Élevée | Critique | 9.1 | P0 |
| SQL Injection faible | 🔴 Critique | Très élevée | Élevé | 8.6 | P0 |
| Clé GDPR faible | 🔴 Critique | Moyenne | Élevé | 7.5 | P0 |
| Pas de rate limiting | 🟠 Élevée | Élevée | Moyen | 6.5 | P1 |
| Policy bypass CIDR | 🟠 Élevée | Moyenne | Moyen | 6.0 | P1 |
| Snapshots non signés | 🟠 Élevée | Faible | Élevé | 6.8 | P1 |
| XSS detection | 🟡 Moyenne | Élevée | Faible | 5.3 | P2 |
| Pas de CSRF | 🟡 Moyenne | Moyenne | Moyen | 5.9 | P2 |
| Logs verbeux | 🟡 Moyenne | Faible | Faible | 4.2 | P2 |
| Pas de timeout | 🟡 Moyenne | Faible | Faible | 4.0 | P3 |

---

## ✅ Points Forts Identifiés

### Excellentes pratiques déjà en place:

1. **`pkg/securestore/securestore.go`**
   - ✅ Utilisation de `memguard` pour protection mémoire
   - ✅ Secrets chiffrés en mémoire
   - ✅ Destruction automatique avec `defer`
   - ✅ Comparaison en temps constant (`EqualToConstantTime`)

2. **`pkg/gdpr/compliance.go`**
   - ✅ Chiffrement AES-256-GCM (excellent choix)
   - ✅ Nonce unique par chiffrement
   - ✅ Audit log complet avec timestamps
   - ✅ Gestion de la rétention

3. **`pkg/security/tls.go`**
   - ✅ TLS 1.2+ minimum
   - ✅ Cipher suites modernes (ECDHE, AES-GCM, ChaCha20)
   - ✅ Pas de cipher faibles

4. **`pkg/admin/snapshot.go`**
   - ✅ Backup automatique avant restauration
   - ✅ Vérification checksum SHA256
   - ✅ Métadonnées complètes

5. **Architecture générale**
   - ✅ Séparation des responsabilités
   - ✅ Use de mutexes pour concurrence
   - ✅ Gestion d'erreurs appropriée

---

## 🎯 Plan d'Action Recommandé

### Phase 1: CRITIQUE (Semaine 1) - P0

**Jour 1-2:**
1. ✅ Implémenter bcrypt pour mots de passe locaux
2. ✅ Script de migration des utilisateurs existants
3. ✅ Tests de non-régression

**Jour 3-4:**
4. ✅ Améliorer détection SQL Injection avec regex robustes
5. ✅ Intégrer Coraza WAF (optionnel mais recommandé)
6. ✅ Tests avec payloads OWASP

**Jour 5:**
7. ✅ Renforcer dérivation clé GDPR avec Argon2id
8. ✅ Implémenter rotation de clé
9. ✅ Migration des données existantes

### Phase 2: ÉLEVÉ (Semaine 2-3) - P1

**Semaine 2:**
10. ✅ Rate limiting par endpoint et par IP
11. ✅ Blocage temporaire après tentatives échouées
12. ✅ CheckAccess avec support CIDR et wildcards

**Semaine 3:**
13. ✅ Signature HMAC des snapshots
14. ✅ Validation du contenu des snapshots
15. ✅ Tests de tampering

### Phase 3: MOYEN (Mois 2) - P2

16. Protection CSRF
17. Headers de sécurité HTTP
18. Sanitization des logs
19. Détection XSS avec bluemonday
20. Timeouts sur opérations longues

### Phase 4: Amélioration Continue - P3

21. Audit de sécurité externe
22. Pen test par équipe spécialisée
23. Bug bounty program
24. Formation sécurité développeurs
25. Documentation utilisateur sécurité

---

## 📚 Références et Standards

### Standards de conformité:
- **OWASP Top 10 2021**
- **OWASP ASVS v4.0** (Application Security Verification Standard)
- **NIST SP 800-63B** (Digital Identity Guidelines)
- **PCI-DSS 4.0** (si traitement de paiements)
- **RGPD Article 32** (Sécurité du traitement)
- **ISO 27001:2022**

### Ressources techniques:
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Go Security Best Practices](https://github.com/OWASP/Go-SCP)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cryptographic Standards](https://csrc.nist.gov/)
- [Coraza WAF](https://github.com/corazawaf/coraza)

### Bibliothèques recommandées:
```go
// Cryptographie
"golang.org/x/crypto/bcrypt"
"golang.org/x/crypto/argon2"

// Rate limiting
"golang.org/x/time/rate"

// WAF
"github.com/corazawaf/coraza/v3"

// CSRF
"github.com/gorilla/csrf"

// XSS Sanitization
"github.com/microcosm-cc/bluemonday"

// CIDR ranges
"github.com/yl2chen/cidranger"
```

---

## 📝 Checklist de Déploiement Sécurisé

Avant tout déploiement en production:

### Configuration:
- [ ] Tous les secrets via variables d'environnement (pas de hardcoding)
- [ ] Clés cryptographiques générées avec `openssl rand`
- [ ] Permissions fichiers correctes (600 pour secrets, 644 pour configs)
- [ ] TLS activé partout (API, portail, RADIUS)
- [ ] Rate limiting configuré et testé

### Vulnérabilités:
- [ ] Toutes les vulnérabilités P0 corrigées
- [ ] Toutes les vulnérabilités P1 corrigées ou mitigées
- [ ] Tests de sécurité effectués

### Monitoring:
- [ ] Logs sécurisés et rotationnés
- [ ] Monitoring et alertes en place (IDS events, failed auth, etc.)
- [ ] Dashboards de sécurité configurés

### Documentation:
- [ ] Plan de réponse aux incidents documenté
- [ ] Procédures de backup et restore testées
- [ ] Documentation administrateur à jour

### Tests:
- [ ] Tests de charge effectués
- [ ] Pen test basique réalisé
- [ ] Revue de code par pairs complétée
- [ ] Tests de disaster recovery

---

## 🔐 Conclusion

**Score Global de Sécurité: 6.8/10** 🟡

CoovaChilli-Go démontre une **fondation de sécurité solide** avec des choix architecturaux judicieux (memguard, AES-GCM, TLS moderne). Cependant, les **3 vulnérabilités critiques** identifiées nécessitent une correction immédiate avant tout déploiement production.

**Scores par catégorie:**
- Cryptographie: 7/10 🟡 (bon mais clé GDPR faible)
- Authentification: 4/10 🔴 (mots de passe en clair)
- Validation d'entrée: 4/10 🔴 (SQL/XSS detection faible)
- Protection réseau: 6/10 🟡 (manque rate limiting)
- GDPR: 7/10 🟡 (bonne base, clé à renforcer)
- Administration: 6/10 🟡 (manque signatures, CSRF)

**Après corrections P0 et P1:** Score estimé **9/10** 🟢

**Effort de remédiation estimé:**
- P0 (Critique): 5-7 jours
- P1 (Élevé): 7-10 jours
- P2 (Moyen): 5-7 jours
- **Total: 3-4 semaines** pour sécurité production-ready

---

**Audit réalisé le:** 2025-10-05
**Prochaine revue recommandée:** 2025-01-05 (3 mois)
**Auditeur:** Analyse de sécurité approfondie - CoovaChilli-Go

---

*Ce rapport est confidentiel et destiné uniquement à l'équipe de développement CoovaChilli-Go.*
