# Améliorations de l'authentification CoovaChilli-Go

## 📋 Résumé exécutif

Ce document analyse l'implémentation actuelle de l'authentification dans CoovaChilli-Go et propose des améliorations pour unifier, sécuriser et optimiser le système.

## 🔍 Analyse de l'existant

### Architecture actuelle

L'authentification est actuellement dispersée dans plusieurs packages :

```
pkg/
├── auth/
│   ├── local.go          # Authentification locale
│   ├── ldap/             # LDAP/AD
│   ├── qrcode/           # QR codes
│   └── sms/              # SMS OTP
├── sso/
│   ├── manager.go        # Gestionnaire SSO
│   ├── saml.go           # SAML 2.0
│   ├── oidc.go           # OpenID Connect
│   └── handlers.go       # Endpoints HTTP
├── fas/
│   └── token.go          # FAS JWT
├── guest/
│   └── guest.go          # Codes invités
├── roles/
│   └── roles.go          # Gestion des rôles
└── http/
    └── server.go         # Portail captif
```

### ✅ Points forts

1. **FAS (Forwarding Authentication Service)**
   - JWT avec HS256 ✅
   - Secret dans `securestore` ✅
   - Claims appropriés ✅
   - Expiration configurable ✅

2. **SSO**
   - SAML 2.0 complet ✅
   - OpenID Connect avec discovery ✅
   - Gestion des sessions ✅
   - Nettoyage automatique ✅

3. **Méthodes d'authentification riches**
   - RADIUS, Local, LDAP
   - SAML, OIDC
   - QR Code, SMS
   - Guest codes, MAC auth

### ⚠️ Problèmes identifiés

#### 1. **Architecture fragmentée**

**Problème :** Chaque méthode d'authentification vit dans son propre silo
- Pas de point d'entrée unifié
- Duplication de logique (tokens, sessions)
- Impossible de combiner plusieurs méthodes

**Impact :**
```go
// Actuellement : logique dispersée
handleLogin() → RADIUS
handleSAMLCallback() → retourne JSON brut
handleQRCode() → pas d'intégration
```

#### 2. **Gestion des sessions incohérente**

**Problème :** 4+ systèmes de sessions différents non synchronisés

```go
// Système 1: Core sessions
type Session struct {
    AuthResult chan bool  // Channel bloquant
}

// Système 2: HTTP cookies
cookie := "coova_session"

// Système 3: SSO sessions
type SSOSession struct {
    ID string
    State string
}

// Système 4: QR/SMS/Guest tokens
token := "qr_token_..."
```

**Conséquences :**
- Pas de vue unifiée des sessions actives
- Logout ne fonctionne que pour HTTP
- SSO n'intègre pas les sessions CoovaChilli

#### 3. **Flux d'authentification bloquants**

**Code actuel (http/server.go:241-288) :**

```go
s.radiusReqChan <- session

select {
case authOK := <-session.AuthResult:
    // Success
case <-time.After(10 * time.Second):
    // Timeout - pas de retry
}
```

**Problèmes :**
- ❌ Bloque la goroutine pendant 10s
- ❌ Pas de retry si RADIUS timeout
- ❌ Pas de fallback vers autre méthode
- ❌ Channel peut deadlock si jamais consommé

#### 4. **Intégration SSO incomplète**

**Code actuel (sso/handlers.go:99-107) :**

```go
func handleSAMLCallback() {
    user, err := mgr.HandleSAMLCallback(r)

    // ⚠️ Retourne juste du JSON
    json.NewEncoder(w).Encode(map[string]interface{}{
        "success": true,
        "username": user.Username,
    })
    // Pas de création de session CoovaChilli !
}
```

**Impact :**
- L'utilisateur est authentifié SSO mais pas connecté au réseau
- Nécessite un second login manuel
- Expérience utilisateur cassée

#### 5. **Sécurité à améliorer**

**Cookies non sécurisés (http/server.go:267-273) :**

```go
http.SetCookie(w, &http.Cookie{
    Name:     sessionCookieName,
    Value:    token,
    Expires:  time.Now().Add(24 * time.Hour),
    HttpOnly: true,
    Path:     "/",
    // ⚠️ Manque: Secure, SameSite
})
```

**Autres problèmes :**
- ❌ Pas de protection CSRF
- ❌ State OIDC dans cookie non signé (handlers.go:142-150)
- ❌ Tokens générés avec simple `hex.EncodeToString(rand)`
- ❌ Pas de rotation de secrets

#### 6. **Pas de Multi-Factor Authentication**

Impossible de :
- Demander SMS après password
- Combiner QR + PIN
- Guest code + SMS verification
- Role-based MFA requirements

#### 7. **Rôles non appliqués**

Les rôles existent (`pkg/roles/`) mais :
- ❌ Pas utilisés pour l'autorisation
- ❌ Pas appliqués aux sessions RADIUS
- ❌ Pas de vérification des permissions

## 🚀 Solutions proposées

### Solution 1 : AuthenticationManager unifié

**Fichier créé :** `pkg/auth/manager.go`

**Architecture :**

```
┌─────────────────────────────────────┐
│    AuthenticationManager            │
│  (Point d'entrée unique)            │
└──────────────┬──────────────────────┘
               │
       ┌───────┴────────┐
       │  Authenticate  │
       │  (req) → resp  │
       └───────┬────────┘
               │
       ┌───────┴────────────────────┐
       │                            │
       ▼                            ▼
┌──────────────┐          ┌──────────────┐
│ Auth Methods │          │   Sessions   │
├──────────────┤          ├──────────────┤
│ • RADIUS     │          │ • Unified    │
│ • Local      │◄────────►│ • Token-based│
│ • LDAP       │          │ • Role-aware │
│ • SAML/OIDC  │          │ • Expirable  │
│ • QR/SMS     │          │              │
│ • Guest      │          │              │
└──────────────┘          └──────────────┘
```

**Avantages :**

1. **API unifiée**
```go
req := &AuthRequest{
    Method:   AuthMethodSAML,
    Username: "user@company.com",
}

resp, err := authManager.Authenticate(req)
// Toujours même structure de réponse
```

2. **Gestion centralisée des sessions**
```go
// Toutes les méthodes créent le même type de session
type AuthSession struct {
    ID         string
    Username   string
    Method     AuthMethod  // Traçabilité
    RoleID     string
    ExpiresAt  time.Time
}
```

3. **Support du fallback**
```go
// Essayer LDAP, puis local
methods := []AuthMethod{AuthMethodLDAP, AuthMethodLocal}
for _, method := range methods {
    req.Method = method
    resp, err := authManager.Authenticate(req)
    if resp.Success {
        break
    }
}
```

4. **Intégration des rôles**
```go
func (am *AuthenticationManager) applyRoleSettings(resp *AuthResponse) {
    role := am.roleManager.GetUserRole(resp.Username)
    resp.BandwidthMaxDown = role.MaxBandwidthDown
    resp.VLANID = role.VLANID
    resp.SessionTimeout = role.MaxSessionDuration
}
```

5. **Statistiques centralisées**
```go
type AuthStats struct {
    TotalAttempts   uint64
    SuccessfulAuths uint64
    MethodStats     map[AuthMethod]uint64
    ActiveSessions  int
}
```

### Solution 2 : Améliorer la sécurité

#### 2.1 Cookies sécurisés

```go
http.SetCookie(w, &http.Cookie{
    Name:     sessionCookieName,
    Value:    token,
    Expires:  time.Now().Add(24 * time.Hour),
    HttpOnly: true,
    Secure:   true,                    // ✅ HTTPS only
    SameSite: http.SameSiteStrictMode, // ✅ CSRF protection
    Path:     "/",
})
```

#### 2.2 CSRF Tokens

```go
type AuthRequest struct {
    CSRFToken string
}

func (am *AuthenticationManager) ValidateCSRF(token string) bool {
    // Validate HMAC-signed token
}
```

#### 2.3 Tokens sécurisés

```go
// Utiliser crypto/rand + base64
func generateSessionToken() string {
    b := make([]byte, 32)
    rand.Read(b)
    return base64.URLEncoding.EncodeToString(b)
}
```

#### 2.4 Rate limiting

```go
type RateLimiter struct {
    attempts map[string]int
    mu       sync.Mutex
}

func (rl *RateLimiter) Allow(ip string) bool {
    // Max 5 attempts per 15 minutes
}
```

### Solution 3 : Authentification asynchrone

**Remplacer :**
```go
// ❌ Bloquant
select {
case authOK := <-session.AuthResult:
case <-time.After(10 * time.Second):
}
```

**Par :**
```go
// ✅ Non-bloquant avec callback
authManager.AuthenticateAsync(req, func(resp *AuthResponse, err error) {
    if resp.Success {
        createSession(resp)
    }
})
```

### Solution 4 : Intégration SSO complète

**Modifier :** `pkg/sso/handlers.go`

```go
func handleSAMLCallback() {
    user, err := mgr.HandleSAMLCallback(r)

    // ✅ Créer une session CoovaChilli
    req := &auth.AuthRequest{
        Method:   auth.AuthMethodSAML,
        Username: user.Username,
        Email:    user.Email,
    }

    resp, _ := authManager.Authenticate(req)

    // Créer cookie de session
    http.SetCookie(w, createSecureCookie(resp.SessionToken))

    // Autoriser l'accès réseau via firewall
    firewall.AuthorizeUser(session, resp)

    // Rediriger vers page de succès
    http.Redirect(w, r, "/status", http.StatusFound)
}
```

### Solution 5 : Multi-Factor Authentication

```go
type MFAConfig struct {
    Enabled      bool
    Methods      []AuthMethod
    RequiredFor  []string // role IDs
}

func (am *AuthenticationManager) RequiresMFA(username string) bool {
    role := am.roleManager.GetUserRole(username)
    return contains(am.cfg.MFA.RequiredFor, role.ID)
}

// Flux MFA
// 1. Login avec password
resp1 := authManager.Authenticate(&AuthRequest{
    Method:   AuthMethodLocal,
    Username: "user",
    Password: "pass",
})

// 2. Si MFA requis, envoyer SMS
if authManager.RequiresMFA(resp1.Username) {
    am.smsManager.SendCode(user.Phone, user.Username)

    // 3. Valider code SMS
    resp2 := authManager.Authenticate(&AuthRequest{
        Method:      AuthMethodSMS,
        PhoneNumber: user.Phone,
        Token:       smsCode,
    })
}
```

### Solution 6 : Audit et observabilité

```go
type AuthEvent struct {
    Timestamp time.Time
    Method    AuthMethod
    Username  string
    IP        net.IP
    Success   bool
    Error     string
    Duration  time.Duration
}

func (am *AuthenticationManager) logAuthEvent(event *AuthEvent) {
    // Log structuré
    am.logger.Info().
        Str("method", string(event.Method)).
        Str("user", event.Username).
        Bool("success", event.Success).
        Dur("duration", event.Duration).
        Msg("Authentication attempt")

    // Export vers SIEM si configuré
    if am.cfg.LogExport.Enabled {
        am.exporter.Export(event)
    }
}
```

## 📊 Plan d'implémentation

### Phase 1 : Fondations (1-2 jours)
- [x] Créer `AuthenticationManager`
- [ ] Migrer authentification locale
- [ ] Ajouter tests unitaires

### Phase 2 : Intégration (2-3 jours)
- [ ] Intégrer SSO au AuthManager
- [ ] Intégrer QR/SMS/Guest
- [ ] Unifier gestion des sessions

### Phase 3 : Sécurité (1-2 jours)
- [ ] Cookies sécurisés
- [ ] CSRF protection
- [ ] Rate limiting
- [ ] Audit logging

### Phase 4 : Features avancées (2-3 jours)
- [ ] MFA
- [ ] Role-based authorization
- [ ] Authentification asynchrone
- [ ] Fallback chains

### Phase 5 : Tests et documentation (1-2 jours)
- [ ] Tests d'intégration
- [ ] Tests de charge
- [ ] Documentation API
- [ ] Guide de migration

## 🎯 Bénéfices attendus

### Fonctionnels
- ✅ **Expérience utilisateur unifiée** : Un seul flux pour toutes les méthodes
- ✅ **SSO vraiment fonctionnel** : Auth SSO = accès réseau immédiat
- ✅ **MFA** : Sécurité renforcée pour comptes sensibles
- ✅ **Fallback automatique** : Si LDAP down, utiliser local

### Techniques
- ✅ **Code maintenable** : Point d'entrée unique
- ✅ **Testabilité** : Interface mockable
- ✅ **Performance** : Authentification async
- ✅ **Observabilité** : Metrics et logs centralisés

### Sécurité
- ✅ **HTTPS only cookies**
- ✅ **CSRF protection**
- ✅ **Rate limiting**
- ✅ **Audit trail complet**

## 📝 Exemple d'utilisation

### Avant (code actuel)

```go
// Authentification locale
handleLogin() {
    session.Redir.Username = username
    radiusReqChan <- session
    select {
    case authOK := <-session.AuthResult:
        // ...
    }
}

// Authentification SAML (séparée)
handleSAMLCallback() {
    user := ssoManager.HandleSAMLCallback()
    json.Encode(user) // ⚠️ Pas de session créée
}

// Authentification QR (séparée)
// Non intégrée au flux principal
```

### Après (avec AuthenticationManager)

```go
// Toutes les authentifications utilisent la même API
func handleAuth(w http.ResponseWriter, r *http.Request) {
    var req *auth.AuthRequest

    // Déterminer la méthode
    switch r.URL.Path {
    case "/login":
        req = &auth.AuthRequest{
            Method:   auth.AuthMethodLocal,
            Username: r.FormValue("username"),
            Password: r.FormValue("password"),
        }
    case "/qr-auth":
        req = &auth.AuthRequest{
            Method: auth.AuthMethodQRCode,
            Token:  r.FormValue("token"),
        }
    case "/sso/saml/acs":
        req = &auth.AuthRequest{
            Method:  auth.AuthMethodSAML,
            Context: r.Context(),
        }
    }

    // Authentifier (même code pour toutes les méthodes)
    resp, err := authManager.Authenticate(req)
    if err != nil || !resp.Success {
        renderError(w, "Authentication failed")
        return
    }

    // Créer session (unifié)
    createSession(w, resp)

    // Autoriser accès réseau (unifié)
    firewall.Authorize(session, resp)

    // Rediriger
    http.Redirect(w, r, "/status", http.StatusFound)
}
```

## 🔒 Considérations de sécurité

### Secrets management
- ✅ Tous les secrets dans `securestore`
- ✅ Rotation automatique possible
- ✅ Pas de secrets en clair dans logs

### Session security
- ✅ Tokens cryptographiquement sécurisés (32 bytes random)
- ✅ Expiration configurable par méthode
- ✅ Révocation possible
- ✅ Cleanup automatique

### Network security
- ✅ HTTPS obligatoire pour cookies
- ✅ Certificate pinning possible
- ✅ TLS 1.2+ minimum

## 📚 Références

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [SAML 2.0 Technical Overview](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 6749 - OAuth 2.0](https://tools.ietf.org/html/rfc6749)
- [RFC 7519 - JWT](https://tools.ietf.org/html/rfc7519)

## 🤝 Contribution

Pour contribuer à l'implémentation :

1. Commencer par la Phase 1 (fondations)
2. Suivre les patterns établis dans `pkg/auth/manager.go`
3. Ajouter tests pour chaque méthode d'authentification
4. Documenter les breaking changes

---

**Statut :** ✅ Analyse complète
**Prochaine étape :** Implémenter Phase 1
**Priorité :** 🔴 Haute (améliore sécurité et UX)
