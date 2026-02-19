# 🚀 GUIDE COMPLET - Bill Checker v3.0
## Netlify + Supabase + Toutes fonctionnalités

---

## 📦 ARCHITECTURE COMPLÈTE

### Fonctionnalités incluses :
✅ Authentification complète (inscription, connexion, reset password)
✅ Système d'abonnements (Free/Premium/Business)
✅ Limitation des scans selon le plan
✅ Analyse IA avec OpenAI GPT-4 Vision
✅ Paiements Lygos (Mobile Money)
✅ Paiements PayPal (Carte + Compte)
✅ Interface admin améliorée avec statistiques
✅ Gestion des utilisateurs et abonnements
✅ Stockage d'images Cloudinary

---

## 📋 ÉTAPE 1 : Créer un compte Supabase (Base de données gratuite)

### 1.1 Inscription
1. Allez sur **https://supabase.com**
2. Cliquez **"Start your project"**
3. Connectez-vous avec GitHub
4. Créez une nouvelle organisation

### 1.2 Créer un projet
1. Cliquez **"New Project"**
2. Remplissez :
   - **Name** : `billchecker`
   - **Database Password** : (généré automatiquement, copiez-le)
   - **Region** : Choisissez le plus proche
   - **Pricing Plan** : **Free**
3. Cliquez **"Create new project"**
4. Attendez 2-3 minutes

### 1.3 Récupérer la connection string
1. Dans votre projet, allez dans **Settings** → **Database**
2. Cherchez **Connection string** → **URI**
3. Copiez l'URL (format: `postgresql://postgres:[PASSWORD]@[HOST]/postgres`)
4. Remplacez `[PASSWORD]` par le mot de passe que vous avez copié à l'étape 1.2
5. **Gardez cette URL précieusement**

---

## 📋 ÉTAPE 2 : Créer les comptes de services

### 2.1 Cloudinary (Stockage images)
1. https://cloudinary.com/users/register/free
2. Notez : **Cloud Name**, **API Key**, **API Secret**

### 2.2 OpenAI (Analyse IA)
1. https://platform.openai.com/signup
2. Ajoutez $5-10 de crédits
3. Créez une clé API
4. Notez la clé : `sk-proj-xxxxx`

### 2.3 Gmail (Envoi d'emails)
1. Allez sur https://myaccount.google.com/apppasswords
2. Créez un mot de passe d'application pour "Mail"
3. Notez : **Votre email** et **le mot de passe d'application**

### 2.4 PayPal (Paiements)
1. https://developer.paypal.com
2. Créez un compte développeur
3. Dans **Dashboard** → **Apps & Credentials**
4. Créez une app Sandbox
5. Notez : **Client ID** et **Secret**

### 2.5 Lygos (Mobile Money - Optionnel pour test)
1. Contactez Lygos pour obtenir un compte développeur
2. Obtenez votre **API Key**
3. Pour les tests, on simulera les paiements

---

## 📋 ÉTAPE 3 : Structure du projet GitHub

Votre repo doit avoir cette structure :

```
billct/
├── netlify/
│   └── functions/
│       └── api.js                # Fonction serverless principale
├── public/
│   ├── index.html               # Page de connexion/inscription
│   ├── dashboard.html           # Dashboard utilisateur
│   ├── admin.html               # Dashboard admin amélioré
│   ├── pricing.html             # Page des tarifs
│   ├── payment.html             # Page de paiement
│   ├── forgot-password.html     # Demande reset password
│   ├── reset-password.html      # Réinitialisation password
│   ├── profile.html             # Profil utilisateur
│   └── styles/
│       └── main.css             # Styles globaux
├── package.json
├── netlify.toml
├── .gitignore
└── README.md
```

---

## 📋 ÉTAPE 4 : Base de données - Tables SQL

Connectez-vous à Supabase et exécutez ces requêtes SQL :

### 4.1 Dans Supabase : SQL Editor

```sql
-- Table users (avec reset password et plan)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    plan VARCHAR(50) DEFAULT 'free',
    reset_token TEXT,
    reset_token_expiry TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table subscriptions
CREATE TABLE IF NOT EXISTS subscriptions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) UNIQUE,
    plan VARCHAR(50) NOT NULL DEFAULT 'free',
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    scans_used INTEGER DEFAULT 0,
    scans_limit INTEGER DEFAULT 5,
    start_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_date TIMESTAMP,
    payment_method VARCHAR(50),
    last_payment_date TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table scans
CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    currency VARCHAR(10) NOT NULL,
    image_url TEXT NOT NULL,
    authenticity VARCHAR(50) NOT NULL,
    confidence INTEGER NOT NULL,
    features_detected JSONB,
    warnings JSONB,
    recommendation TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table alerts
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    severity VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    resolved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table payments
CREATE TABLE IF NOT EXISTS payments (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    amount DECIMAL(10, 2) NOT NULL,
    currency VARCHAR(3) DEFAULT 'XAF',
    payment_method VARCHAR(50) NOT NULL,
    transaction_id TEXT UNIQUE,
    status VARCHAR(50) NOT NULL,
    plan VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Créer admin par défaut
INSERT INTO users (username, email, password, role, plan)
VALUES ('admin', 'admin@billchecker.com', '$2b$10$HASH_HERE', 'admin', 'business')
ON CONFLICT (username) DO NOTHING;
```

**IMPORTANT** : Le hash du mot de passe admin sera créé automatiquement au premier démarrage.

---

## 📋 ÉTAPE 5 : Fichiers à créer sur GitHub

Je vais vous donner le contenu de chaque fichier un par un car c'est très long.

### Récapitulatif des fichiers à créer :

**Configuration :**
1. ✅ `package.json` - Dépendances
2. ✅ `netlify.toml` - Configuration Netlify
3. ✅ `.gitignore` - Fichiers à ignorer

**Backend :**
4. ✅ `netlify/functions/api.js` - API serverless complète

**Frontend :**
5. ✅ `public/index.html` - Connexion/Inscription
6. ✅ `public/dashboard.html` - Dashboard utilisateur
7. ✅ `public/admin.html` - Dashboard admin
8. ✅ `public/pricing.html` - Page tarifs
9. ✅ `public/payment.html` - Page de paiement
10. ✅ `public/forgot-password.html` - Demande reset
11. ✅ `public/reset-password.html` - Réinitialisation
12. ✅ `public/profile.html` - Profil utilisateur

---

## 📋 ÉTAPE 6 : Variables d'environnement Netlify

Dans **Netlify** → **Site settings** → **Environment variables**, ajoutez :

```
DATABASE_URL = postgresql://postgres:[PASSWORD]@[HOST]/postgres
JWT_SECRET = billcheckerSecretKey123456789
CLOUDINARY_CLOUD_NAME = votre_cloud_name
CLOUDINARY_API_KEY = votre_api_key
CLOUDINARY_API_SECRET = votre_api_secret
OPENAI_API_KEY = sk-proj-xxxxx
EMAIL_USER = votre-email@gmail.com
EMAIL_PASS = votre_mot_de_passe_application
PAYPAL_CLIENT_ID = votre_paypal_client_id
PAYPAL_CLIENT_SECRET = votre_paypal_secret
PAYPAL_MODE = sandbox
LYGOS_API_KEY = votre_lygos_key
FRONTEND_URL = https://votre-app.netlify.app
```

---

## 💰 TARIFICATION RECOMMANDÉE

### Plan Gratuit
- Prix : **0 FCFA/mois**
- Scans : **5/mois**
- Historique : 30 jours
- Export PDF : ❌

### Plan Premium
- Prix : **5000 FCFA/mois** (~8€)
- Scans : **Illimités**
- Historique : Complet
- Export PDF : ✅
- Support prioritaire : ✅

### Plan Business
- Prix : **50000 FCFA/mois** (~80€)
- Scans : **Illimités**
- Multi-utilisateurs : ✅ (5+)
- API access : ✅
- Rapports mensuels : ✅
- Support dédié : ✅

---

## 🔧 FONCTIONNEMENT DES PAIEMENTS

### Workflow Lygos (Mobile Money)
1. Utilisateur choisit Premium/Business
2. Choisit Mobile Money
3. Redirigé vers Lygos
4. Paie avec Orange/MTN/Moov Money
5. Webhook confirme le paiement
6. Abonnement activé automatiquement

### Workflow PayPal
1. Utilisateur choisit Premium/Business
2. Choisit PayPal
3. Redirigé vers PayPal
4. Paie avec carte ou compte PayPal
5. Retour à l'app
6. Abonnement activé automatiquement

---

## 📊 DASHBOARD ADMIN - Fonctionnalités

✅ **Statistiques globales**
- Total utilisateurs
- Total scans
- Scans par plan (Free/Premium/Business)
- Revenus du mois
- Graphiques en temps réel

✅ **Gestion utilisateurs**
- Liste complète
- Voir détails (scans, plan, paiements)
- Changer le plan manuellement
- Bloquer/Débloquer utilisateur

✅ **Gestion abonnements**
- Voir tous les abonnements actifs
- Abonnements expirés
- Renouvellements à venir

✅ **Paiements**
- Liste des transactions
- Filtrer par méthode (Lygos/PayPal)
- Exporter en CSV

✅ **Alertes**
- Billets suspects détectés
- Marquer comme résolu
- Statistiques de fraude

---

## 🎯 PROCHAINES ÉTAPES

Dites-moi par quel fichier vous voulez commencer :

1. Les fichiers de configuration (package.json, netlify.toml)
2. Le backend complet (api.js)
3. Les pages frontend (index, dashboard, admin, etc.)

Je vais vous les créer un par un avec tout le code complet ! 😊

---

**Quelle partie voulez-vous en premier ?**
