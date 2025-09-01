# Projet Dashboard Admin - Dipco

Ce projet est une application web complète avec un frontend pour l'administration et un backend pour la gestion des données. Cette version a été restructurée pour une meilleure maintenabilité et sécurité.

## Aperçu

L'application permet aux administrateur de se connecter à un tableau de bord sécurisé pour gérer des articles (produits) et des utilisateurs. Il y a aussi une page publique pour visualiser le catalogue d'articles.

- **Frontend Public**: Une page statique qui affiche le catalogue des articles avec des filtres et une recherche.
- **Frontend Admin**: Une application à page unique (SPA) pour l'administration. Elle inclut une page de connexion et un tableau de bord pour le CRUD des articles et des utilisateurs.
- **Backend**: Une API RESTful construite avec Node.js et Express.js. Elle gère l'authentification avec JWT (via des cookies httpOnly) et interagit avec une base de données MySQL.

## Structure du Projet

Le projet est maintenant organisé de la manière suivante pour une meilleure séparation des préoccupations :

```
/
├── admin/
│   ├── assets/
│   │   ├── css/
│   │   │   └── style.css
│   │   └── js/
│   │       ├── api.js
│   │       ├── articles.js
│   │       ├── auth.js
│   │       ├── main.js
│   │       ├── ui.js
│   │       └── users.js
│   └── index.html
├── backend/
│   ├── src/
│   │   ├── config/
│   │   │   └── database.js
│   │   ├── controllers/
│   │   │   ├── articleController.js
│   │   │   ├── authController.js
│   │   │   └── userController.js
│   │   ├── middleware/
│   │   │   ├── auth.js
│   │   │   └── validators.js
│   │   └── routes/
│   │       ├── articles.js
│   │       ├── auth.js
│   │       └── users.js
│   ├── app.js
│   ├── package.json
│   └── ...
├── public/
│   ├── assets/
│   │   ├── css/
│   │   │   └── style.css
│   │   └── js/
│   │       └── app.js
│   └── index.html
└── ...
```

## Technologies utilisées

- **Frontend**:
  - HTML5, CSS3, JavaScript (ES6+)
  - Font Awesome (pour les icônes)
  - Tailwind CSS (utilisé via CDN pour la page publique)

- **Backend**:
  - Node.js, Express.js
  - MySQL2 (pour la connexion à la base de données MySQL)
  - JSON Web Tokens (JWT) pour l'authentification
  - bcrypt pour le hachage des mots de passe
  - dotenv pour la gestion des variables d'environnement
  - express-validator pour la validation des entrées
  - cors, cookie-parser, express-rate-limit

## Installation et Lancement

### Prérequis

- Node.js et npm installés
- Une base de données MySQL fonctionnelle

### 1. Configuration de la base de données

1.  Importez le fichier `pricelist.sql` dans votre base de données MySQL.
2.  Assurez-vous que votre base de données contient les tables `articles` et `users`.

### 2. Configuration du Backend

1.  Naviguez dans le dossier `backend`:
    ```sh
    cd backend
    ```

2.  Installez les dépendances npm:
    ```sh
    npm install
    ```

3.  Créez un fichier `.env` à la racine du dossier `backend` et remplissez-le avec les variables suivantes :

    ```env
    # Configuration du serveur
    PORT=3000

    # Configuration de la base de données
    DB_HOST=localhost
    DB_USER=votre_utilisateur_mysql
    DB_PASSWORD=votre_mot_de_passe_mysql
    DB_DATABASE=votre_base_de_donnees

    # Configuration JWT
    JWT_SECRET=un_secret_tres_long_et_securise
    JWT_EXPIRES_IN=1h
    ```

4.  Démarrez le serveur backend:
    ```sh
    node app.js
    ```
    Le serveur devrait maintenant tourner sur `http://localhost:3000`.

### 3. Lancement de l'Application

Le backend sert maintenant les parties frontend de l'application.

-   **Page publique**: Ouvrez votre navigateur et allez à `http://localhost:3000`.
-   **Page d'administration**: Ouvrez votre navigateur et allez à `http://localhost:3000/admin`.

Le serveur Express est configuré pour servir les fichiers statiques des dossiers `public` et `admin`.
