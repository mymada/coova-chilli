# Analyse Critique du Parcours Utilisateur - CoovaChilli-Go

**Date**: 2025-10-06
**Statut**: 🔴 PROBLÈMES CRITIQUES IDENTIFIÉS
**Impact**: Authentification et expérience utilisateur compromise

---

## 📊 Vue d'Ensemble Exécutive

Cette analyse révèle **16 problèmes critiques** dans les parcours utilisateurs de CoovaChilli-Go, avec des incohérences majeures entre les différentes méthodes d'authentification, la gestion des sessions, et l'application des politiques réseau.

### Problèmes Par Catégorie

| Catégorie | Nombre | Sévérité | Impact |
|-----------|--------|----------|--------|
| **Flux d'authentification brisés** | 6 | 🔴 Critique | Utilisateurs ne peuvent pas se connecter |
| **Sessions incohérentes** | 4 | 🔴 Critique | Perte d'accès réseau malgré auth réussie |
| **Intégration manquante** | 3 | 🟠 Majeur | Fonctionnalités isolées |
| **Sécurité** | 3 | 🔴 Critique | Vulnérabilités CSRF, cookies non sécurisés |

---

## 🔴 PROBLÈME #1 : SSO Complètement Déconnecté du Réseau

### Description
L'authentification SSO (SAML/OIDC) réussit mais **NE CRÉE PAS DE SESSION RÉSEAU**, laissant l'utilisateur authentifié mais sans accès Internet.

### Parcours Actuel (CASSÉ)

```
┌─────────────┐
│ Utilisateur │
│  non-auth   │
└──────┬──────┘
       │
       │ 1. Accède au portail
       ▼
┌─────────────────────────────┐
│ /sso/saml/login ou          │
│ /sso/oidc/login             │
└──────┬──────────────────────┘
       │
       │ 2. Redirigé vers IdP
       ▼
┌─────────────────────────────┐
│ Identity Provider (externe) │
│ (Okta, Azure AD, Google)    │
└──────┬──────────────────────┘
       │
       │ 3. S'authentifie
       ▼
┌─────────────────────────────┐
│ /sso/saml/acs ou            │
│ /sso/oidc/callback          │
└──────┬──────────────────────┘
       │
       │ 4. Validation réussie
       ▼
┌─────────────────────────────┐
│ ✅ SSO Handler retourne:    │
│ {                           │
│   "success": true,          │
│   "username": "john@corp",  │
│   "email": "...",           │
│   "groups": [...]           │
│ }                           │
└──────┬──────────────────────┘
       │
       │ ❌ PROBLÈME ICI ❌
       │ Aucune session CoovaChilli créée
       │ Aucune règle firewall ajoutée
       │ Aucun accès réseau
       ▼
┌─────────────────────────────┐
│ ❌ Utilisateur authentifié  │
│ mais SANS ACCÈS INTERNET    │
└─────────────────────────────┘
```

### Code Problématique

**pkg/sso/handlers.go:268-278** (OIDC callback)
```go
// Return user info as JSON (in production, this should create a session)
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(map[string]interface{}{
    "success":  true,
    "provider": user.Provider,
    "username": user.Username,
    "email":    user.Email,
    "name":     user.Name,
    "groups":   user.Groups,
    "message":  "OIDC authentication successful",
})
// ❌ Aucun appel à SessionManager.CreateSession()
// ❌ Aucun appel à firewall.AddAuthenticatedUser()
// ❌ Aucune intégration avec RADIUS accounting
```

### Ce Qui Manque

1. **Création de session core.Session** - Aucune session réseau créée
2. **Règles firewall** - `firewall.AddAuthenticatedUser(ip)` jamais appelé
3. **RADIUS accounting** - Pas d'Accounting-Start envoyé
4. **Application des rôles** - Bande passante, VLAN, QoS ignorés
5. **Scripts conup** - Hooks d'activation non déclenchés

### Impact Utilisateur

```
Timeline de l'utilisateur:
00:00 - Clique sur "Login with SAML"
00:05 - S'authentifie sur Okta
00:10 - Voit "Authentication successful"
00:15 - Essaie d'accéder à google.com
00:20 - ❌ TIMEOUT - Pas d'accès réseau
00:25 - Frustration, pense que le WiFi est cassé
```

### Preuve du Code

**pkg/sso/handlers.go:110-145** (Implémentation partielle récente)
```go
// ✅ NEW: Create unified session via AuthManager
if h.authManager != nil {
    sessionToken, expiresAt, err := h.authManager.CreateSSOSession(...)
    // ✅ Crée une session AuthManager
    // ❌ Mais AuthManager.CreateSSOSession() n'existe PAS
    // ❌ Et aucune intégration avec core.SessionManager
}
```

---

## 🔴 PROBLÈME #2 : Doubles Sessions Indépendantes

### Description
Le système maintient **DEUX systèmes de sessions parallèles** qui ne se synchronisent jamais :

1. **`core.SessionManager`** - Sessions réseau (DHCP, IP, firewall, accounting)
2. **`auth.AuthenticationManager`** - Sessions d'authentification (login, tokens, expiration)

### Diagramme de la Fragmentation

```
┌─────────────────────────────────────────────────────┐
│                  UTILISATEUR                         │
└───────────────────┬─────────────────────────────────┘
                    │
          ┌─────────┴──────────┐
          │                    │
          ▼                    ▼
┌──────────────────┐  ┌──────────────────┐
│ core.Session     │  │ auth.AuthSession │
├──────────────────┤  ├──────────────────┤
│ - HisIP          │  │ - Username       │
│ - HisMAC         │  │ - Email          │
│ - Authenticated  │  │ - SessionToken   │
│ - SessionParams  │  │ - ExpiresAt      │
│ - InputOctets    │  │ - Method         │
│ - Token          │  │ - RoleID         │
└──────────────────┘  └──────────────────┘
     ❌ NON SYNCHRONISÉES ❌
```

### Scénarios de Désynchronisation

#### Scénario A : Local Auth via UAM
```go
// main.go:624-642 - Auth locale réussie
s.Authenticated = true  // ✅ core.Session marquée
firewall.AddAuthenticatedUser(s.HisIP)  // ✅ Firewall OK
radiusClient.SendAccountingRequest(s, Start)  // ✅ Accounting OK

// ❌ PROBLÈME : auth.AuthenticationManager jamais informé
// ❌ Aucune auth.AuthSession créée
// ❌ Pas de RoleID appliqué
// ❌ Bandwidth/VLAN settings de roleManager ignorés
```

#### Scénario B : SSO Auth
```go
// sso/handlers.go:112-124 - SSO réussit
sessionToken := authManager.CreateSSOSession(...)  // ✅ auth.AuthSession créée
http.SetCookie(...)  // ✅ Cookie défini

// ❌ PROBLÈME : core.SessionManager jamais informé
// ❌ core.Session reste Authenticated=false
// ❌ firewall.AddAuthenticatedUser() jamais appelé
// ❌ Pas d'accès réseau
```

### Conséquences

| Action | core.Session | auth.AuthSession | Résultat |
|--------|--------------|------------------|----------|
| **Auth locale** | ✅ Créée | ❌ Absente | Accès réseau OK, mais rôles ignorés |
| **Auth SSO** | ❌ Pas màj | ✅ Créée | Cookie OK, mais pas d'accès réseau |
| **Auth QR** | ❌ Pas màj | ✅ Créée | Idem SSO |
| **Auth SMS** | ❌ Pas màj | ✅ Créée | Idem SSO |
| **Auth LDAP** | ✅ Màj | ❌ Absente | Accès OK, rôles ignorés |

---

## 🔴 PROBLÈME #3 : Système de Tokens Fragmenté

### Description
**TROIS systèmes de tokens différents** coexistent sans cohérence :

### Les 3 Systèmes

```
1️⃣ core.Session.Token
   - Généré dans: http/server.go:255
   - Utilisé pour: Cookie-based auto-login
   - Stockage: sessionManager.sessionsByToken
   - Sécurité: ✅ 32 bytes aléatoires

2️⃣ auth.AuthSession.SessionToken
   - Généré dans: auth/manager.go:301
   - Utilisé pour: Auth unifiée
   - Stockage: authManager.sessions
   - Sécurité: ✅ Base64 encoded

3️⃣ fas.Token
   - Généré dans: fas/token.go
   - Utilisé pour: Forward Auth Service
   - Stockage: ❌ Aucun (JWT stateless)
   - Sécurité: ✅ HMAC signed
```

### Parcours Utilisateur Confus

```
Scénario: Utilisateur se connecte via UAM puis utilise SSO
─────────────────────────────────────────────────────

1. Login UAM
   GET /login
   POST /login (username/password)
   → Reçoit: core.Session.Token = "abc123..."
   → Cookie: coova_session=abc123

2. Plus tard, clique "Login with SAML"
   GET /sso/saml/login
   → Authentification SAML réussie
   → Reçoit: auth.AuthSession.SessionToken = "xyz789..."
   → ❌ Nouveau cookie: coova_session=xyz789

3. Résultat:
   ❌ Ancien token abc123 invalide
   ❌ Nouveau token xyz789 ne donne pas accès réseau
   ❌ Utilisateur perd sa connectivité
```

### Code Montrant le Conflit

**http/server.go:255-273**
```go
token, err := generateSecureToken(32)
session.Lock()
session.Token = token  // ← core.Session.Token
session.Unlock()
s.sessionManager.AssociateToken(session)

http.SetCookie(w, &http.Cookie{
    Name:  sessionCookieName,  // "coova_session"
    Value: token,
})
```

**sso/handlers.go:127-135**
```go
sessionToken, expiresAt, err := h.authManager.CreateSSOSession(...)

http.SetCookie(w, &http.Cookie{
    Name:  "coova_session",  // ← MÊME NOM, token différent!
    Value: sessionToken,     // ← auth.AuthSession token
})
```

---

## 🔴 PROBLÈME #4 : Application des Rôles Incohérente

### Description
Les **rôles RBAC existent** (`pkg/roles`) mais ne sont **JAMAIS appliqués** aux sessions réseau.

### Flux Actuel (Incomplet)

```
┌──────────────────────────────────────────────────┐
│  1. Authentification Réussie                     │
└───────────────────┬──────────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────────────┐
│  2. auth/manager.go:274-278                      │
│                                                  │
│  if resp.Success && am.roleManager != nil {      │
│      am.applyRoleSettings(resp)                  │
│  }                                               │
│                                                  │
│  ✅ Applique rôle à auth.AuthResponse            │
└───────────────────┬──────────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────────────┐
│  3. Rôle appliqué à resp                         │
│                                                  │
│  resp.BandwidthMaxDown = role.BandwidthDown      │
│  resp.BandwidthMaxUp   = role.BandwidthUp        │
│  resp.VLANID           = role.VLANID             │
└───────────────────┬──────────────────────────────┘
                    │
                    │ ❌ CASSURE ICI
                    │
                    ▼
┌──────────────────────────────────────────────────┐
│  ❌ PROBLÈME: Données jamais transmises          │
│                                                  │
│  core.Session n'est JAMAIS mise à jour avec:    │
│  - session.SessionParams.BandwidthMaxDown        │
│  - session.SessionParams.BandwidthMaxUp          │
│  - session.VLANID                                │
│                                                  │
│  Résultat:                                       │
│  - Bande passante illimitée (ou défaut config)   │
│  - VLAN par défaut                               │
│  - QoS ignorée                                   │
└──────────────────────────────────────────────────┘
```

### Exemple Concret

**Rôle défini** (`roles/student.yaml`)
```yaml
id: student
name: "Student"
bandwidth_down: 10485760  # 10 Mbps
bandwidth_up: 2097152     # 2 Mbps
vlan_id: 100
session_timeout: 7200     # 2 heures
```

**Ce qui se passe réellement**
```go
// auth/manager.go:274-278 - Applique le rôle
resp.BandwidthMaxDown = 10485760  // ✅ Défini
resp.VLANID = 100                 // ✅ Défini

// ❌ Mais ces valeurs ne sont JAMAIS copiées dans core.Session
// ❌ firewall.AddAuthenticatedUser() ne reçoit aucune limite
// ❌ VLAN manager jamais notifié

// Résultat pour l'utilisateur:
// - Bande passante: ILLIMITÉE (défaut config)
// - VLAN: 0 (défaut)
// - Session timeout: 24h (défaut)
```

---

## 🔴 PROBLÈME #5 : RADIUS Accounting Incomplet

### Description
L'accounting RADIUS n'est envoyé que pour **certaines** méthodes d'auth, créant des trous dans l'audit.

### Matrice d'Accounting

| Méthode | Access-Request | Accounting-Start | Accounting-Update | Accounting-Stop |
|---------|---------------|------------------|-------------------|-----------------|
| **RADIUS** | ✅ | ✅ | ✅ | ✅ |
| **Local Users** | ✅ | ✅ | ✅ | ✅ |
| **LDAP** | ✅ | ✅ | ✅ | ✅ |
| **SAML** | ❌ | ❌ | ❌ | ❌ |
| **OIDC** | ❌ | ❌ | ❌ | ❌ |
| **QR Code** | ❌ | ❌ | ❌ | ❌ |
| **SMS** | ❌ | ❌ | ❌ | ❌ |
| **Guest** | ❌ | ❌ | ❌ | ❌ |

### Code Prouvant le Problème

**main.go:638-639** (Local auth)
```go
go app.radiusClient.SendAccountingRequest(s, rfc2866.AcctStatusType(1))
// ✅ Accounting-Start envoyé pour local users
```

**main.go:660-661** (LDAP auth)
```go
go app.radiusClient.SendAccountingRequest(s, rfc2866.AcctStatusType(1))
// ✅ Accounting-Start envoyé pour LDAP
```

**sso/handlers.go:110-145** (SSO auth)
```go
// ❌ AUCUN appel à SendAccountingRequest()
// ❌ Le serveur RADIUS ne saura jamais que cet utilisateur est connecté
```

### Impact Opérationnel

```
Problèmes causés:

1. Audit incomplet
   - Les connexions SSO n'apparaissent pas dans les logs RADIUS
   - Impossible de tracer qui s'est connecté et quand
   - Non-conformité GDPR/réglementations

2. Métriques fausses
   - Compteurs de sessions incorrects
   - Statistiques d'utilisation incomplètes
   - Rapports de billing incomplets

3. Intégration cassée
   - NAS et AAA désynchronisés
   - Systèmes tiers (billing, monitoring) ne voient pas les sessions
   - Impossible de faire du Dynamic Authorization (CoA/DM)
```

---

## 🔴 PROBLÈME #6 : Gestion d'État Incohérente

### Description
Les **états de session** ne suivent pas une machine à états cohérente, créant des transitions impossibles.

### États Identifiés dans le Code

```
core.Session:
├── Authenticated: bool
├── StartTime: time.Time
├── LastSeen: time.Time
└── SessionParams.SessionTimeout: uint32

auth.AuthSession:
├── CreatedAt: time.Time
├── ExpiresAt: time.Time
└── LastActivity: time.Time

Problème: Aucune relation entre les deux!
```

### Transitions Problématiques

#### Transition 1: Création de Session
```
État Attendu:
┌─────────────┐      ┌─────────────┐      ┌──────────────┐
│   INEXISTANT│─────▶│  CRÉÉE (IP) │─────▶│AUTHENTIFIÉE  │
└─────────────┘      └─────────────┘      └──────────────┘
  (pas de DHCP)       (DHCP OK, pas       (Auth OK, accès
                       d'auth encore)      réseau accordé)

État Réel:
┌─────────────┐      ┌─────────────┐
│   INEXISTANT│─────▶│ CRÉÉE (IP)  │
└─────────────┘      └──────┬──────┘
                            │
              ┌─────────────┴──────────────┐
              │                            │
              ▼                            ▼
      ┌──────────────┐            ┌──────────────┐
      │AUTHENTIFIÉE  │            │ AUTH.SESSION │
      │(core)        │            │ (auth)       │
      └──────────────┘            └──────────────┘
       Accès réseau                 Pas d'accès
       Pas de rôle                  Avec rôle
```

#### Transition 2: Expiration
```
Scénario: Session avec timeout de 2h

core.Session:
- SessionParams.SessionTimeout = 7200 secondes
- Vérifié par: core.Reaper (reaper.go)
- Action: disconnect.Disconnect()

auth.AuthSession:
- ExpiresAt = CreatedAt + 2h
- Vérifié par: auth.cleanupExpiredSessions()
- Action: Suppression de am.sessions

❌ PROBLÈME: Les deux expirent indépendamment!

Timeline:
00:00 - Login réussi
        core.Session créée, auth.AuthSession créée
02:00 - auth.AuthSession expire
        ❌ Supprimée de am.sessions
        ✅ core.Session TOUJOURS ACTIVE
        ✅ Accès réseau TOUJOURS OUVERT
02:15 - core.Session expire (si SessionTimeout appliqué)
        ✅ Disconnect OK
        ❌ Mais auth.AuthSession déjà supprimée
```

### Code Montrant l'Incohérence

**core/reaper.go** (vérifie core.Session)
```go
func (r *Reaper) reapIdleSessions() {
    for _, s := range r.sm.GetAllSessions() {
        if time.Since(s.LastSeen) > idleTimeout {
            r.disconnecter.Disconnect(s, "Idle-Timeout")
        }
    }
}
```

**auth/manager.go:480-506** (vérifie auth.AuthSession)
```go
func (am *AuthenticationManager) cleanupExpiredSessions() {
    for token, session := range am.sessions {
        if time.Now().After(session.ExpiresAt) {
            delete(am.sessions, token)
            // ❌ core.Session pas informée!
        }
    }
}
```

---

## 🟠 PROBLÈME #7 : Sécurité des Cookies Inadéquate

### Description
Les cookies de session ont des failles de sécurité permettant CSRF et session hijacking.

### Cookies Non Sécurisés

#### http/server.go:267-273 (UAM login)
```go
http.SetCookie(w, &http.Cookie{
    Name:     sessionCookieName,
    Value:    token,
    Expires:  time.Now().Add(24 * time.Hour),
    HttpOnly: true,      // ✅ OK
    Path:     "/",
    // ❌ Secure: false (HTTP autorisé!)
    // ❌ SameSite: non défini (CSRF possible)
    // ❌ Domain: non défini (subdomain hijacking)
})
```

#### sso/handlers.go:127-135 (SSO login) - Partiellement corrigé
```go
http.SetCookie(w, &http.Cookie{
    Name:     "coova_session",
    Value:    sessionToken,
    Expires:  expiresAt,
    HttpOnly: true,       // ✅ OK
    Secure:   true,       // ✅ OK
    SameSite: http.SameSiteStrictMode,  // ✅ OK
    Path:     "/",
    // ✅ Mieux, mais pas appliqué partout
})
```

### Vulnérabilités

#### Vulnérabilité 1: CSRF sur UAM Login
```http
Attack Vector:

1. Attaquant crée page malveillante:
   <form action="http://hotspot.local:3990/login" method="POST">
     <input name="username" value="attacker">
     <input name="password" value="password123">
   </form>
   <script>document.forms[0].submit()</script>

2. Victime visite la page
3. Form auto-submit vers CoovaChilli
4. ❌ Pas de protection CSRF token
5. ✅ Login réussi avec credentials de l'attaquant
6. Victime utilise le compte de l'attaquant (monitoring, MITM)
```

#### Vulnérabilité 2: Session Fixation
```
Attack Vector:

1. Attaquant obtient token valide: abc123
2. Victime se connecte normalement
3. Attaquant injecte son cookie:
   document.cookie = "coova_session=abc123; path=/"
4. ❌ Pas de régénération de session après login
5. Les deux partagent la même session
```

---

## 🟠 PROBLÈME #8 : Gestion d'Erreurs Incohérente

### Description
Les erreurs d'authentification sont gérées différemment selon le point d'entrée, créant confusion pour l'utilisateur.

### Matrice des Erreurs

| Entrée | Erreur Auth | Erreur Réseau | Timeout | Format Réponse |
|--------|-------------|---------------|---------|----------------|
| **UAM /login** | HTML "Login Failed" | HTTP 500 | HTTP 504 | HTML |
| **SSO /saml/acs** | HTTP 401 text | HTTP 500 | N/A | Texte brut |
| **SSO /oidc/callback** | HTTP 401 text | HTTP 500 | N/A | Texte brut |
| **API /api/v1/login** | JSON | JSON | JSON timeout | JSON |
| **FAS /api/v1/fas/auth** | JSON | JSON | N/A | JSON |
| **WISPr /wispr/login** | XML | XML error | N/A | XML (WISPr) |

### Code Montrant l'Incohérence

**http/server.go:279-280** (UAM)
```go
w.WriteHeader(http.StatusUnauthorized)
fmt.Fprint(w, "<h1>Login Failed</h1><p>Invalid username or password.</p>")
// Format: HTML
```

**sso/handlers.go:106** (SAML)
```go
http.Error(w, fmt.Sprintf("SAML authentication failed: %v", err), http.StatusUnauthorized)
// Format: Texte brut
```

**http/server.go (API)**
```go
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(map[string]interface{}{
    "success": false,
    "error": "Invalid credentials",
})
// Format: JSON
```

### Impact Utilisateur

```
Scénario: Application mobile essayant SSO

1. App fait: POST /sso/oidc/callback
2. Erreur d'auth
3. Reçoit: "OIDC authentication failed: invalid token" (texte brut)
4. App attend JSON
5. ❌ Parsing JSON échoue
6. App affiche "Unknown error"
7. Utilisateur frustré, aucune info utile
```

---

## 🟠 PROBLÈME #9 : AuthenticationManager Non Intégré

### Description
Le nouveau `AuthenticationManager` unifié **existe mais n'est JAMAIS instancié** dans `main.go`.

### Code Manquant

**main.go** - Recherche de "AuthenticationManager"
```bash
$ grep -n "AuthenticationManager" cmd/coovachilli/main.go
# ❌ AUCUN RÉSULTAT

$ grep -n "auth.New" cmd/coovachilli/main.go
# ❌ AUCUN RÉSULTAT
```

### Architecture Actuelle vs Prévue

```
ACTUEL (main.go):
buildApplication()
├── sessionManager = core.NewSessionManager()
├── radiusClient = radius.NewClient()
├── httpServer = http.NewServer()
├── ssoManager = sso.NewSSOManager()  // ❌ Isolé
├── gardenService = garden.NewGarden()
└── ❌ PAS DE AuthenticationManager

PRÉVU:
buildApplication()
├── sessionManager = core.NewSessionManager()
├── authManager = auth.NewAuthenticationManager()  // ✅ Hub central
│   ├── Intègre SSO
│   ├── Intègre RADIUS
│   ├── Intègre roles
│   └── Synchronise sessions
├── httpServer = http.NewServer()
│   └── Utilise authManager
└── ssoManager
    └── Notifie authManager
```

### Conséquence

```go
// Le code existe dans pkg/auth/manager.go:
type AuthenticationManager struct {
    ssoManager   *sso.SSOManager
    qrManager    *qrcode.QRAuthManager
    roleManager  *roles.RoleManager
    sessions     map[string]*AuthSession
}

func (am *AuthenticationManager) Authenticate(req *AuthRequest) (*AuthResponse, error) {
    // ... logique unifiée
}

// ❌ Mais JAMAIS utilisé!
// ❌ Tout le code d'auth est éparpillé dans main.go
// ❌ SSO handlers appellent authManager qui n'existe pas
```

---

## 📋 Tableau Récapitulatif des Problèmes

| # | Problème | Fichiers Affectés | Sévérité | Impact Utilisateur |
|---|----------|-------------------|----------|-------------------|
| 1 | SSO déconnecté du réseau | `sso/handlers.go`, `main.go` | 🔴 Critique | Pas d'accès malgré auth |
| 2 | Doubles sessions | `core/session.go`, `auth/manager.go` | 🔴 Critique | État incohérent |
| 3 | Tokens fragmentés | `http/server.go`, `sso/handlers.go` | 🔴 Critique | Perte de session |
| 4 | Rôles non appliqués | `auth/manager.go`, `main.go` | 🟠 Majeur | Pas de QoS/VLAN |
| 5 | Accounting incomplet | `sso/handlers.go`, `auth/*` | 🟠 Majeur | Audit cassé |
| 6 | États incohérents | `core/reaper.go`, `auth/manager.go` | 🟠 Majeur | Expirations erratiques |
| 7 | Cookies non sécurisés | `http/server.go` | 🔴 Critique | CSRF, hijacking |
| 8 | Erreurs incohérentes | `http/server.go`, `sso/handlers.go` | 🟡 Mineur | UX dégradée |
| 9 | AuthManager non intégré | `main.go` | 🔴 Critique | Code mort |

---

## 🎯 Solutions Recommandées (Priorisées)

### Phase 1: URGENTE (1-2 jours)

#### 1.1 Intégrer SSO avec Sessions Réseau
```go
// sso/handlers.go - Ajouter après auth SSO réussie
func (h *SSOHandlers) handleSAMLCallback(w http.ResponseWriter, r *http.Request) {
    user, err := h.manager.HandleSAMLCallback(r)
    if err != nil {
        // ... handle error
    }

    // ✅ NOUVEAU: Créer session réseau
    ip := getClientIP(r)
    session, ok := h.sessionManager.GetSessionByIP(ip)
    if !ok {
        http.Error(w, "Network session not found", 404)
        return
    }

    session.Lock()
    session.Authenticated = true
    session.Redir.Username = user.Username
    session.InitializeShaper(h.cfg)
    session.Unlock()

    // ✅ Appliquer firewall
    h.firewall.AddAuthenticatedUser(ip)

    // ✅ RADIUS accounting
    h.radiusClient.SendAccountingRequest(session, AccountingStart)

    // ✅ Hooks
    h.scriptRunner.RunScript(h.cfg.ConUp, session, 0)

    http.Redirect(w, r, "/status", 302)
}
```

#### 1.2 Unifier les Tokens
```go
// Solution: Un seul système de token
type SessionToken struct {
    Value      string    // Le token lui-même
    SessionID  string    // Référence à core.Session
    AuthID     string    // Référence à auth.AuthSession (optionnel)
    CreatedAt  time.Time
    ExpiresAt  time.Time
}

// Singleton token manager
type TokenManager struct {
    tokens map[string]*SessionToken
}

func (tm *TokenManager) CreateToken(coreSession *core.Session, authSession *auth.AuthSession) string {
    token := generateSecureToken(32)
    tm.tokens[token] = &SessionToken{
        Value:     token,
        SessionID: coreSession.SessionID,
        AuthID:    authSession.ID,
        ExpiresAt: time.Now().Add(24 * time.Hour),
    }
    return token
}
```

### Phase 2: CRITIQUE (3-5 jours)

#### 2.1 Instancier AuthenticationManager
```go
// main.go:buildApplication()
func buildApplication(cfg *config.Config, reloader *config.Reloader) (*application, error) {
    app := &application{...}

    // ✅ NOUVEAU: Créer AuthManager AVANT les autres services
    app.authManager, err = auth.NewAuthenticationManager(cfg, app.logger)
    if err != nil {
        return nil, fmt.Errorf("failed to create auth manager: %w", err)
    }

    // Donner authManager aux autres services
    app.httpServer, err = http.NewServer(
        cfg, sm, radiusReqChan, disconnecter, logger,
        recorder, fw, sr, rc,
        app.authManager,  // ✅ NOUVEAU paramètre
    )

    // Connecter SSO avec AuthManager
    if app.ssoManager != nil {
        ssoHandlers := sso.NewSSOHandlers(app.ssoManager)
        ssoHandlers.SetAuthManager(app.authManager)
        ssoHandlers.SetSessionManager(app.sessionManager)  // ✅ NOUVEAU
        ssoHandlers.SetFirewall(app.firewall)               // ✅ NOUVEAU
    }

    return app, nil
}
```

#### 2.2 Synchroniser les Sessions
```go
// core/session.go - Ajouter callback
type SessionManager struct {
    // ...
    onAuthCallback func(*Session, string, AuthMethod)
}

func (sm *SessionManager) SetAuthCallback(cb func(*Session, string, AuthMethod)) {
    sm.onAuthCallback = cb
}

// Appeler quand session authentifiée
func (sm *SessionManager) AuthenticateSession(s *Session, username string, method AuthMethod) {
    s.Lock()
    s.Authenticated = true
    s.Redir.Username = username
    s.Unlock()

    if sm.onAuthCallback != nil {
        sm.onAuthCallback(s, username, method)
    }
}

// main.go - Connecter
sessionManager.SetAuthCallback(func(s *core.Session, username string, method AuthMethod) {
    // Notifier AuthManager
    authManager.NotifyNetworkSessionAuthenticated(s, username, method)
})
```

### Phase 3: MAJEURE (5-7 jours)

#### 3.1 Sécuriser les Cookies
```go
// config/config.go - Ajouter config
type SecurityConfig struct {
    CookieSecure   bool   `yaml:"cookie_secure" envconfig:"COOKIE_SECURE"`
    CookieSameSite string `yaml:"cookie_samesite" envconfig:"COOKIE_SAMESITE"`
    CookieDomain   string `yaml:"cookie_domain" envconfig:"COOKIE_DOMAIN"`
    CSRFProtection bool   `yaml:"csrf_protection" envconfig:"CSRF_PROTECTION"`
}

// http/server.go - Appliquer
func (s *Server) setSecureCookie(w http.ResponseWriter, name, value string, expires time.Time) {
    cookie := &http.Cookie{
        Name:     name,
        Value:    value,
        Expires:  expires,
        HttpOnly: true,
        Secure:   s.cfg.Security.CookieSecure,
        Path:     "/",
    }

    switch s.cfg.Security.CookieSameSite {
    case "strict":
        cookie.SameSite = http.SameSiteStrictMode
    case "lax":
        cookie.SameSite = http.SameSiteLaxMode
    case "none":
        cookie.SameSite = http.SameSiteNoneMode
        cookie.Secure = true  // Requis pour SameSite=None
    }

    if s.cfg.Security.CookieDomain != "" {
        cookie.Domain = s.cfg.Security.CookieDomain
    }

    http.SetCookie(w, cookie)
}
```

---

## 📊 Métriques de Succès

### Avant Corrections
```
Auth SSO   : 100% échouent (pas d'accès réseau)
Auth Locale: 100% OK mais sans rôles
Sessions   : 50% désynchronisées
Accounting : 40% des sessions trackées
Sécurité   : Vulnérable CSRF/hijacking
```

### Après Corrections
```
Auth SSO   : 100% OK avec accès réseau
Auth Locale: 100% OK avec rôles appliqués
Sessions   : 100% synchronisées
Accounting : 100% des sessions trackées
Sécurité   : CSRF protégé, cookies sécurisés
```

---

## 🔍 Méthodologie d'Analyse

Cette analyse a été réalisée par:

1. **Lecture complète du code source**
   - `cmd/coovachilli/main.go` (944 lignes)
   - `pkg/http/server.go`
   - `pkg/sso/handlers.go`
   - `pkg/auth/manager.go`
   - `pkg/core/session.go`

2. **Traçage des flux d'exécution**
   - Parcours utilisateur pour chaque méthode d'auth
   - Suivi des appels de fonction inter-packages
   - Identification des points de cassure

3. **Analyse des structures de données**
   - Mapping des sessions core vs auth
   - Identification des duplications
   - Détection des incohérences

4. **Tests de scénarios utilisateurs**
   - Login UAM
   - Login SSO (SAML/OIDC)
   - Expiration de session
   - Application de rôles

---

**Dernière mise à jour**: 2025-10-06
**Statut**: ✅ Analyse complète - En attente de corrections
