# Analyse de Parité Fonctionnelle (C vs. Rust)

Ce document détaille les fonctionnalités et options de configuration présentes dans la version C originale de CoovaChilli qui semblent manquer dans le portage Rust actuel. L'analyse est basée sur une comparaison du fichier `conf/defaults.in` (C) et de la structure `Config` dans `chilli-core/src/config.rs` (Rust).

## Fonctionnalités Majeures Manquantes

- **Configuration à distance (`HS_RADCONF`)**: La version C peut récupérer une partie de sa configuration depuis un serveur RADIUS ou une URL. Cette fonctionnalité est entièrement absente du portage Rust.
- **Utilisateurs Locaux (`HS_USELOCALUSERS`)**: Le portage Rust ne semble pas supporter l'authentification via un fichier d'utilisateurs local, se basant uniquement sur RADIUS ou l'authentification par adresse MAC.
- **Proxy Post-Authentification (`HS_POSTAUTH_PROXY`)**: La possibilité de rediriger le trafic d'un utilisateur authentifié vers un proxy n'est pas implémentée.
- **CGI pour le portail captif (`HS_WWWDIR`, `HS_WWWBIN`)**: La version Rust utilise un serveur web intégré (`axum`) et ne supporte pas le modèle de la version C qui permet de servir des pages et des scripts CGI depuis un répertoire externe. C'est un changement de conception fondamental.

## Options de Configuration Manquantes

### Réseau et Pare-feu
- `HS_WANIF`: Interface WAN, probablement utilisée pour des règles de pare-feu spécifiques.
- `HS_TCP_PORTS` / `HS_UDP_PORTS`: Permet de spécifier des ports à ouvrir dans le pare-feu pour les clients.
- `HS_DNSPARANOIA`: Une fonctionnalité de sécurité pour filtrer les requêtes DNS.

### Portail Captif (UAM)
- `HS_UAMUIPORT`: Port séparé pour l'interface utilisateur du portail, absent dans la version Rust.
- `HS_UAMFORMAT` / `HS_UAMHOMEPAGE` / `HS_UAMSERVICE`: Options de formatage avancées pour construire l'URL de redirection. La version Rust utilise une seule URL `uamurl`, ce qui est moins flexible.
- `HS_USE_MAP`: Une option de facilité pour ajouter les domaines Google Maps au jardin clos (walled garden).

### Authentification
- **MS-CHAPv1**: Intentionnellement retiré en raison de problèmes de dépendances cryptographiques et de faiblesses de sécurité.
- `HS_MACAUTHMODE`: Le mode "local" pour l'authentification MAC n'est pas explicitement supporté.
- `HS_OPENIDAUTH` / `HS_WPAGUESTS`: Options pour activer des flux d'authentification spécifiques qui ne sont pas implémentés.

### Paramètres par Défaut (RADIUS)
- `HS_DEFSESSIONTIMEOUT`, `HS_DEFIDLETIMEOUT`, `HS_DEFBANDWIDTHMAXDOWN`, `HS_DEFBANDWIDTHMAXUP`: La version C permet de définir des limites par défaut au niveau du serveur si RADIUS ne les fournit pas. Cette logique semble absente dans le portage Rust.

### WISPr
- La configuration granulaire de la localisation (`HS_LOC_NETWORK`, `HS_LOC_AC`, etc.) pour construire le `WISPr-Location-Id` a été remplacée par des champs directs (`radiuslocationid`, `radiuslocationname`).
