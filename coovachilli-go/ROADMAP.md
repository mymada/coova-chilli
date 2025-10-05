# Roadmap CoovaChilli-Go

Ce document suit la progression du développement de CoovaChilli-Go.

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

## 2. Sécurité et conformité (En cours)
- [ ] **Filtrage avancé des URL et DNS :** À faire.
- [ ] **Export des journaux :** À faire.
- [ ] **Filtrage de contenu et de protocoles :** À faire.
- [ ] **Intégration antivirus/antimalware :** À faire.
- [ ] **Surveillance d'intrusion en temps réel :** À faire.
- [ ] **Chiffrement SSL/TLS complet :** À faire.
- [ ] **Isolation des clients et VLANs :** À faire.
- [x] **Journaux détaillés :** Déjà en place (configurable via `config.yaml`).
- [ ] **Conformité RGPD :** À faire.

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

## 5. Administration centralisée et automatisée (En cours)
- [x] **Console web de gestion :** Une base existe (`pkg/admin`), mais elle est limitée.
- [ ] **Dashboard centralisé :** Créer un tableau de bord avec trafic, statistiques, utilisateurs connectés.
- [ ] **Gestion multi-site :** Piloter plusieurs instances CoovaChilli-Go depuis une seule interface.
- [ ] **Gestion de groupes d'utilisateurs et de politiques.**
- [ ] **API REST complète :** Étendre l'API pour l'intégration avec des systèmes tiers (CRM, ERP).
- [ ] **Mises à jour automatiques et sécurisées.**
- [ ] **Snapshots et restauration de configuration.**

## 6. Scalabilité, coût et support (À faire)
- [ ] **SSO pour les grands groupes.**
- [ ] **Montée en charge progressive :** Optimiser les performances pour supporter un grand nombre d'utilisateurs simultanés.
- [ ] **Documentation exhaustive :** Améliorer la documentation pour les développeurs et les administrateurs.
- [ ] **Création d'une communauté active (forums, etc.).**