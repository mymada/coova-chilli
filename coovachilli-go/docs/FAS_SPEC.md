# CoovaChilli-Go - Spécification du Service d'Authentification Déléguée (FAS)

Version: 1.0

## 1. Vue d'ensemble

Le Service d'Authentification Déléguée (Forwarding Authentication Service - FAS) permet à CoovaChilli-Go de déléguer entièrement le processus d'authentification de l'utilisateur à un service web externe (le serveur FAS).

Cela permet une flexibilité maximale pour l'implémentation de logiques d'authentification complexes, telles que :
- Connexion via les réseaux sociaux (OAuth2)
- Paiement par carte de crédit
- Authentification par SMS
- Intégration avec des annuaires d'entreprise personnalisés (SAML, etc.)

Le flux d'interaction est sécurisé par un jeton JWT (JSON Web Token) signé avec un secret partagé, garantissant que seul le serveur FAS de confiance peut autoriser un utilisateur.

## 2. Flux d'Authentification

Le processus se déroule en trois étapes principales :

1.  **Redirection vers le FAS :** CoovaChilli-Go intercepte un utilisateur non authentifié et le redirige vers le serveur FAS externe. Des informations sur le client et un jeton de sécurité sont passés dans l'URL.
2.  **Authentification sur le FAS :** L'utilisateur interagit avec le serveur FAS pour s'authentifier. Cette étape est entièrement gérée par le service externe.
3.  **Callback vers CoovaChilli-Go :** Une fois l'authentification réussie, le serveur FAS redirige l'utilisateur vers un endpoint de "callback" sur CoovaChilli-Go, en fournissant le jeton de sécurité et les paramètres de session désirés.

```
       +----------------+         +-----------------+         +---------------------+
       | Utilisateur    |         | CoovaChilli-Go  |         | Serveur FAS Externe |
       +----------------+         +-----------------+         +---------------------+
              |                           |                           |
              | 1. Requête HTTP (ex: google.com) |                           |
              |-------------------------->|                           |
              |                           | 2. Intercepte et génère un jeton JWT |
              |                           |-------------------------->|
              | 3. Redirige l'utilisateur vers le FAS avec le jeton |
              |<--------------------------|                           |
              |                           |                           |
              | 4. Suit la redirection vers le FAS |                           |
              |------------------------------------------------------>|
              |                           |                           | 5. Authentifie l'utilisateur
              |                           |                           |    (login, paiement, etc.)
              |                           |                           |
              | 6. Redirige l'utilisateur vers le callback de CoovaChilli-Go |
              |<------------------------------------------------------|
              |                           |                           |
              | 7. Suit la redirection vers CoovaChilli-Go |                           |
              |-------------------------->|                           |
              |                           | 8. Valide le jeton JWT,   |
              |                           |    crée la session et     |
              |                           |    ouvre le pare-feu.     |
              |                           |-------------------------->|
              | 9. Redirige l'utilisateur vers sa destination finale |
              |<--------------------------|                           |
              |                           |                           |
              | 10. Accès Internet activé |                           |
              |-------------------------->|                           |
```

## 3. Spécification Détaillée

### Étape 1 : Redirection vers le FAS

CoovaChilli-Go redirige le navigateur de l'utilisateur vers l'URL configurée dans `fas_url` avec les paramètres suivants :

*   `token` : Le jeton de sécurité JWT (voir section 4).
*   `client_mac` : L'adresse MAC du client (format : `xx-xx-xx-xx-xx-xx`).
*   `client_ip` : L'adresse IP du client.
*   `nas_id` : L'identifiant du NAS (configuré dans CoovaChilli-Go).
*   `original_url` : L'URL que l'utilisateur essayait d'atteindre initialement (encodée en URL).

**Exemple de redirection :**
```
https://auth.example.com/login?token=eyJhbGciOi...&client_mac=00-de-ad-be-ef-00&client_ip=10.1.0.100&nas_id=chilli-01&original_url=http%3A%2F%2Fgoogle.com
```

### Étape 3 : Callback vers CoovaChilli-Go

Après une authentification réussie, le serveur FAS doit rediriger l'utilisateur vers l'endpoint de callback de CoovaChilli-Go : `/api/v1/fas/auth`.

*   `token` : Le même jeton JWT reçu à l'étape 1. **Requis.**
*   `continue_url` : (Optionnel) L'URL vers laquelle l'utilisateur sera redirigé après une authentification réussie. Si non fourni, CoovaChilli-Go utilisera l'`original_url` contenu dans le jeton.
*   `session_timeout` : (Optionnel) Durée de la session en secondes.
*   `idle_timeout` : (Optionnel) Durée d'inactivité maximale en secondes.
*   `download_speed` : (Optionnel) Limite de bande passante descendante en kbit/s.
*   `upload_speed` : (Optionnel) Limite de bande passante montante en kbit/s.

**Exemple de callback :**
```
http://<coovachilli_ip>:8080/api/v1/fas/auth?token=eyJhbGciOi...&session_timeout=3600&download_speed=1000
```

## 4. Spécification du Jeton de Sécurité (JWT)

Le jeton est la pierre angulaire de la sécurité du système.

*   **Algorithme :** HMAC-SHA256 (HS256)
*   **Secret :** Le jeton est signé avec le secret partagé configuré dans `fas_secret`.

### Contenu du Jeton (Claims)

| Claim | Type   | Description                                           |
|-------|--------|-------------------------------------------------------|
| `jti` | string | Un identifiant unique pour le jeton (JWT ID).         |
| `iat` | int64  | Timestamp de création du jeton (Issued At).           |
| `exp` | int64  | Timestamp d'expiration du jeton (Expiration Time). **Requis.** Doit être court (ex: 5 minutes) pour prévenir les attaques par rejeu. |
| `nas` | string | L'identifiant du NAS (`nas_id`).                      |
| `cli` | string | L'adresse MAC du client.                              |
| `cip` | string | L'adresse IP du client.                               |
| `url` | string | L'URL originale demandée par l'utilisateur.           |

## 5. Sécurité

*   Le secret partagé (`fas_secret`) doit être long, complexe et gardé confidentiel.
*   Il est **fortement recommandé** que le serveur FAS soit accessible uniquement via **HTTPS** pour protéger les données de l'utilisateur et le jeton pendant le transit.
*   CoovaChilli-Go doit valider la signature et la date d'expiration (`exp`) de chaque jeton reçu sur l'endpoint de callback pour s'assurer de son intégrité et de sa fraîcheur.