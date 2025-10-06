# CoovaChilli-Go - Spécification de l'API d'Administration

Version: 1.0

Ce document définit l'API REST pour l'administration centralisée et multi-sites des portails captifs CoovaChilli-Go.

## 1. Concepts de Base

*   **API Root:** Toutes les URLs de l'API sont préfixées par `/api/v1`.
*   **Format des Données:** Toutes les données sont envoyées et reçues au format `application/json`.
*   **Authentification:** Chaque requête à l'API doit inclure un en-tête `Authorization` avec un jeton de type Bearer.
    ```
    Authorization: Bearer <VOTRE_JETON_D_API_SECRET>
    ```
    L'échec de l'authentification retournera une erreur `401 Unauthorized`.
*   **Site:** Une ressource "Site" représente une instance de portail captif unique, avec sa propre configuration, ses utilisateurs et ses modèles.

## 2. Endpoints de l'API

---

### 2.1. Gestion des Sites (`/sites`)

La ressource `Site` est l'élément central de la gestion.

#### `GET /api/v1/sites`
*   **Description:** Récupère la liste de tous les sites gérés.
*   **Réponse (200 OK):**
    ```json
    [
      {
        "id": "site-01-paris",
        "name": "Portail Captif - Paris WiFi",
        "description": "Portail pour les bureaux de Paris.",
        "created_at": "2023-10-27T10:00:00Z"
      },
      {
        "id": "site-02-lyon",
        "name": "Portail Captif - Lyon Guest",
        "description": "Portail pour les invités à Lyon.",
        "created_at": "2023-10-27T10:05:00Z"
      }
    ]
    ```

#### `POST /api/v1/sites`
*   **Description:** Crée un nouveau site.
*   **Corps de la Requête:**
    ```json
    {
      "id": "site-03-lille",
      "name": "Portail de Lille",
      "description": "Nouveau portail pour les bureaux de Lille."
    }
    ```
*   **Réponse (201 Created):**
    ```json
    {
      "id": "site-03-lille",
      "name": "Portail de Lille",
      "description": "Nouveau portail pour les bureaux de Lille.",
      "created_at": "2023-10-27T10:10:00Z"
    }
    ```

#### `GET /api/v1/sites/{site_id}`
*   **Description:** Récupère les détails d'un site spécifique.
*   **Réponse (200 OK):** Similaire à la réponse de `POST /api/v1/sites`.

#### `PUT /api/v1/sites/{site_id}`
*   **Description:** Met à jour les informations d'un site.
*   **Corps de la Requête:**
    ```json
    {
      "name": "Portail de Lille (Mis à jour)",
      "description": "Description mise à jour."
    }
    ```
*   **Réponse (200 OK):** L'objet site mis à jour.

#### `DELETE /api/v1/sites/{site_id}`
*   **Description:** Supprime un site et sa configuration.
*   **Réponse (204 No Content):** Aucune donnée dans le corps de la réponse.

---

### 2.2. Gestion de la Configuration (`/sites/{site_id}/config`) - À VENIR

*Note: La gestion fine de la configuration par site via l'API n'est pas encore implémentée. Ces endpoints sont réservés pour une future version.*

#### `GET /api/v1/sites/{site_id}/config`
*   **Description:** (Futur) Récupère la configuration complète pour un site donné.

#### `PUT /api/v1/sites/{site_id}/config`
*   **Description:** (Futur) Met à jour et remplace l'intégralité de la configuration d'un site.

---

### 2.3. Gestion des Sessions (`/sites/{site_id}/sessions`)

#### `GET /api/v1/sites/{site_id}/sessions`
*   **Description:** Liste toutes les sessions utilisateur actives pour un site donné.
*   **Réponse (200 OK):**
    ```json
    [
      {
        "session_id": "session-xyz",
        "username": "john.doe",
        "ip_address": "10.1.0.150",
        "mac_address": "00:de:ad:be:ef:00",
        "start_time": "2023-10-27T11:00:00Z",
        "session_duration_seconds": 1250,
        "input_octets": 1048576,
        "output_octets": 2097152
      }
    ]
    ```

#### `DELETE /api/v1/sites/{site_id}/sessions/{session_id}`
*   **Description:** Déconnecte de force une session utilisateur.
*   **Réponse (204 No Content):** Aucune donnée dans le corps de la réponse.

---

### 2.4. Gestion des Modèles (`/sites/{site_id}/templates`)

#### `GET /api/v1/sites/{site_id}/templates/{template_name}`
*   **Description:** Récupère le contenu d'un fichier de modèle (ex: `login.html`, `status.html`).
*   **Réponse (200 OK):**
    ```json
    {
      "name": "login.html",
      "content": "<!DOCTYPE html><html>...</html>",
      "last_modified": "2023-10-27T12:00:00Z"
    }
    ```

#### `PUT /api/v1/sites/{site_id}/templates/{template_name}`
*   **Description:** Met à jour le contenu d'un fichier de modèle.
*   **Corps de la Requête:**
    ```json
    {
      "content": "<!DOCTYPE html><html>... (nouveau contenu) ...</html>"
    }
    ```
*   **Réponse (200 OK):** L'objet modèle mis à jour.