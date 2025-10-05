# Roadmap CoovaChilli-Go

Ce document suit la progression du développement de CoovaChilli-Go.

**Note sur les problèmes connus :** Pour une liste des problèmes techniques actuellement en cours d'investigation, veuillez consulter le fichier [test/KNOWN_ISSUES.md](./test/KNOWN_ISSUES.md).

## 0. Stabilisation de la base de code (Terminé)
- [x] **Refactoring des interfaces :** Géré (utilisation d'une interface locale dans `pkg/core` pour casser la dépendance).
- [x] **Correction des crashs (Panics) :** Terminé (tous les tests passent).
- [x] **Correction des erreurs de compilation :** Terminé (dépendance `libpcap-dev` installée).
- [x] **Validation complète des tests :** Terminé (`go test ./...` est vert).

## 1. Architecture modulaire et évolutive (Validé)
- [x] **Installation facile :** Terminé (implémentation d'un `Dockerfile` multi-étapes).
- [x] **Déploiement sur matériel léger :** Terminé (outils de build et documentation pour la compilation croisée via Docker).
- [x] **Intégration Cloud :** Terminé (configuration via les variables d'environnement).
- [x] **Base modulaire :** L'architecture `pkg/` a été confirmée comme étant modulaire.

## 2. Sécurité et conformité (Terminé ✅)
- [x] **Filtrage avancé des URL et DNS :** Terminé (implémenté dans `pkg/filter` avec support de blocklist, catégories et règles regex).
- [x] **Export des journaux :** Terminé (implémenté dans `pkg/logexport` avec support syslog, fichier, Elasticsearch).
- [ ] **Filtrage de contenu et de protocoles :** À faire (le filtrage SNI a été retiré, à remplacer par une approche plus robuste).
- [x] **Intégration antivirus/antimalware :** Terminé (implémenté dans `pkg/security` avec support VirusTotal, ClamAV, ThreatFox).
- [x] **Surveillance d'intrusion en temps réel :** Terminé (IDS complet dans `pkg/security` - port scan, brute force, DDoS, SQL injection, XSS).
- [x] **Chiffrement SSL/TLS complet :** Terminé (TLS 1.2/1.3 avec suites de chiffrement modernes dans `pkg/security`).
- [x] **Isolation des clients :** Terminé (implémenté via `clientisolation` dans la configuration).
- [x] **Support VLAN :** Terminé (gestion VLAN avancée dans `pkg/vlan` avec affectation par rôle/utilisateur).
- [x] **Journaux détaillés :** Déjà en place (configurable via `config.yaml`).
- [x] **Conformité RGPD :** Terminé (système complet dans `pkg/gdpr` - chiffrement, rétention, droit d'accès/effacement/portabilité, audit log).

## 3. Authentification flexible et universelle (En cours)
- [x] **Support RADIUS :** Déjà implémenté (`pkg/radius`).
- [x] **Comptes utilisateurs locaux :** Déjà possible via la configuration (`localusersfile`).
- [ ] **Support LDAP/Active Directory :** Ajouter un module d'authentification LDAP.
- [ ] **Support SAML :** Permettre l'intégration avec des fournisseurs d'identité SAML 2.0.
- [ ] **Support OAuth2/OpenID :** Permettre l'authentification via des services comme Google, Facebook, etc.
- [ ] **Authentification par réseaux sociaux.**
- [ ] **Authentification par QR code.**
- [ ] **Authentification par SMS/Paiement :** Intégrer des passerelles SMS et de paiement.
- [ ] **Gestion des codes invité :** Créer un système pour générer et gérer des accès temporaires.
- [ ] **Gestion des accès sponsorisés :** Mettre en place un workflow où un employé peut approuver un invité.
- [ ] **Gestion multi-rôles :** Définir des profils (invité, employé, VIP) avec des droits différents.

## 4. Expérience utilisateur optimisée (À faire)
- [ ] **Portail web entièrement personnalisable :** Le portail actuel est basique. Il faut permettre une personnalisation complète (logo, couleurs, textes).
- [ ] **Design responsive et multilingue :** Le nouveau portail doit être compatible avec tous les appareils et supporter plusieurs langues.
- [ ] **Messages dynamiques :** Afficher des informations contextuelles sur le portail.
- [ ] **Accès rapide "Click & Go".**
- [ ] **Page d'accueil interactive post-authentification.**
- [ ] **Notifications push sur mobile.**
- [ ] **Roaming transparent (multi-device).**

## 5. Administration centralisée et automatisée (Terminé ✅)
- [x] **Console web de gestion :** Une base existe (`pkg/admin`), maintenant étendue.
- [x] **Dashboard centralisé :** Terminé (implémenté dans `pkg/admin/dashboard.go` avec métriques temps réel).
- [x] **Gestion multi-site :** Terminé (implémenté dans `pkg/admin/multisite.go` avec synchronisation auto).
- [x] **Gestion de groupes d'utilisateurs et de politiques :** Terminé (système complet dans `pkg/admin/policy.go`).
- [x] **API REST complète :** Terminé (30+ endpoints dans `pkg/admin/api.go` pour intégration CRM/ERP/SIEM).
- [ ] **Mises à jour automatiques et sécurisées :** À faire (nécessite système de versioning).
- [x] **Snapshots et restauration de configuration :** Terminé (implémenté dans `pkg/admin/snapshot.go` avec checksum SHA256).

## 6. Scalabilité, coût et support (Terminé ✅)
- [x] **SSO pour les grands groupes :** Terminé (implémenté SAML 2.0 et OpenID Connect dans `pkg/sso/`).
- [x] **Montée en charge progressive :** Terminé (cache LRU et connection pooling dans `pkg/performance/`).
- [x] **Documentation exhaustive :** Terminé (documentation complète dans `docs/POINT_6_SCALABILITY.md`).
- [ ] **Création d'une communauté active (forums, etc.) :** À faire (nécessite plateforme externe - Discourse/Forum).