const express = require('express');
const cors = require('cors');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'votre-secret-key-changez-en-production';

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use('/uploads', express.static('uploads'));

// Servir les fichiers frontend
app.use(express.static('public'));

// Créer le dossier uploads
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// Configuration multer pour uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }
});

// Base de données SQLite
const db = new sqlite3.Database('./billchecker.db', (err) => {
    if (err) {
        console.error('Erreur DB:', err);
    } else {
        console.log('✅ Connecté à la base de données');
        initDatabase();
    }
});

// Initialiser les tables
function initDatabase() {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        currency TEXT NOT NULL,
        image_path TEXT NOT NULL,
        authenticity TEXT NOT NULL,
        confidence INTEGER NOT NULL,
        features_detected TEXT,
        warnings TEXT,
        recommendation TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        severity TEXT NOT NULL,
        message TEXT NOT NULL,
        resolved BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    )`);

    // Créer admin par défaut
    const defaultPassword = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT OR IGNORE INTO users (username, email, password, role) 
            VALUES ('admin', 'admin@billchecker.com', ?, 'admin')`, [defaultPassword]);
}

// Middleware d'authentification
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token requis' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token invalide' });
        }
        req.user = user;
        next();
    });
}

// Middleware admin
function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Accès admin requis' });
    }
    next();
}

// ============ ROUTES AUTH ============

// Inscription
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Tous les champs requis' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        db.run(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        return res.status(400).json({ error: 'Username ou email déjà utilisé' });
                    }
                    return res.status(500).json({ error: 'Erreur inscription' });
                }

                res.status(201).json({ 
                    message: 'Utilisateur créé',
                    userId: this.lastID
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Connexion
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Erreur serveur' });
        }

        if (!user) {
            return res.status(401).json({ error: 'Identifiants invalides' });
        }

        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json({ error: 'Identifiants invalides' });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role
            }
        });
    });
});

// ============ ROUTES SCAN ============

// Analyser un billet (VERSION SIMPLIFIÉE)
app.post('/api/scan/analyze', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { currency } = req.body;
        const imagePath = req.file.path;

        // SIMULATION - Résultats aléatoires
        const authenticity = ['GENUINE', 'SUSPICIOUS', 'UNCERTAIN'][Math.floor(Math.random() * 3)];
        const confidence = Math.floor(Math.random() * 40) + 60; // 60-100

        const analysis = {
            authenticity: authenticity,
            confidence: confidence,
            features_detected: [
                'Filigrane détecté',
                'Fil de sécurité visible',
                'Impression en relief confirmée'
            ],
            warnings: authenticity === 'SUSPICIOUS' ? ['Qualité d\'image insuffisante'] : [],
            recommendation: authenticity === 'GENUINE' 
                ? 'Le billet semble authentique' 
                : 'Vérification manuelle recommandée'
        };

        // Sauvegarder dans la DB
        db.run(
            `INSERT INTO scans (user_id, currency, image_path, authenticity, confidence, features_detected, warnings, recommendation)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                req.user.id,
                currency,
                imagePath,
                analysis.authenticity,
                analysis.confidence,
                JSON.stringify(analysis.features_detected),
                JSON.stringify(analysis.warnings),
                analysis.recommendation
            ],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: 'Erreur sauvegarde' });
                }

                const scanId = this.lastID;

                // Créer alerte si suspect
                if (analysis.authenticity === 'SUSPICIOUS') {
                    db.run(
                        'INSERT INTO alerts (scan_id, severity, message) VALUES (?, ?, ?)',
                        [scanId, 'high', `Billet suspect: ${currency}`]
                    );
                }

                res.json({
                    scanId,
                    ...analysis,
                    imagePath: `/${imagePath}`
                });
            }
        );

    } catch (error) {
        console.error('Erreur analyse:', error);
        res.status(500).json({ error: 'Erreur analyse' });
    }
});

// Historique utilisateur
app.get('/api/scan/history', authenticateToken, (req, res) => {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;

    db.all(
        `SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`,
        [req.user.id, limit, offset],
        (err, rows) => {
            if (err) {
                return res.status(500).json({ error: 'Erreur récupération' });
            }

            const scans = rows.map(row => ({
                ...row,
                features_detected: JSON.parse(row.features_detected || '[]'),
                warnings: JSON.parse(row.warnings || '[]')
            }));

            res.json(scans);
        }
    );
});

// ============ ROUTES ADMIN ============

// Statistiques
app.get('/api/admin/stats', authenticateToken, requireAdmin, (req, res) => {
    const stats = {};

    db.get('SELECT COUNT(*) as total FROM scans', (err, row) => {
        if (err) return res.status(500).json({ error: 'Erreur' });
        stats.totalScans = row.total;

        db.all('SELECT authenticity, COUNT(*) as count FROM scans GROUP BY authenticity', (err, rows) => {
            if (err) return res.status(500).json({ error: 'Erreur' });
            stats.byAuthenticity = rows;

            db.all('SELECT currency, COUNT(*) as count FROM scans GROUP BY currency', (err, rows) => {
                if (err) return res.status(500).json({ error: 'Erreur' });
                stats.byCurrency = rows;

                db.get('SELECT COUNT(*) as total FROM users', (err, row) => {
                    if (err) return res.status(500).json({ error: 'Erreur' });
                    stats.totalUsers = row.total;

                    db.get('SELECT COUNT(*) as total FROM alerts WHERE resolved = 0', (err, row) => {
                        if (err) return res.status(500).json({ error: 'Erreur' });
                        stats.unresolvedAlerts = row.total;

                        res.json(stats);
                    });
                });
            });
        });
    });
});

// Liste scans (admin)
app.get('/api/admin/scans', authenticateToken, requireAdmin, (req, res) => {
    const limit = parseInt(req.query.limit) || 100;

    db.all(
        `SELECT scans.*, users.username 
         FROM scans 
         JOIN users ON scans.user_id = users.id 
         ORDER BY scans.created_at DESC 
         LIMIT ?`,
        [limit],
        (err, rows) => {
            if (err) {
                return res.status(500).json({ error: 'Erreur' });
            }

            const scans = rows.map(row => ({
                ...row,
                features_detected: JSON.parse(row.features_detected || '[]'),
                warnings: JSON.parse(row.warnings || '[]')
            }));

            res.json(scans);
        }
    );
});

// Route racine
app.get('/', (req, res) => {
    res.send(`
        <h1>Bill Checker API</h1>
        <p>Backend fonctionnel ✅</p>
        <ul>
            <li><a href="/api/admin/stats">Stats (nécessite authentification)</a></li>
        </ul>
    `);
});

// Démarrage serveur
app.listen(PORT, () => {
    console.log(`🚀 Serveur démarré sur le port ${PORT}`);
    console.log(`📊 Admin: username=admin, password=admin123`);
});

// Gestion arrêt
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) console.error(err);
        console.log('Base de données fermée');
        process.exit(0);
    });
});
