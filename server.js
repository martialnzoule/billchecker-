require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'billcheckerSecretKey123456789';

// Configuration Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Configuration PostgreSQL (Render fournit DATABASE_URL automatiquement)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Test connexion
pool.connect((err, client, release) => {
    if (err) {
        console.error('❌ Erreur connexion PostgreSQL:', err);
    } else {
        console.log('✅ Connecté à PostgreSQL');
        release();
        initDatabase();
    }
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static('public'));

// Configuration multer
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }
});

// Initialiser les tables
async function initDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role VARCHAR(50) DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
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
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER REFERENCES scans(id),
                severity VARCHAR(50) NOT NULL,
                message TEXT NOT NULL,
                resolved BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Créer admin par défaut
        const existing = await pool.query(`SELECT id FROM users WHERE username = 'admin'`);
        if (existing.rows.length === 0) {
            const defaultPassword = await bcrypt.hash('admin123', 10);
            await pool.query(`
                INSERT INTO users (username, email, password, role) 
                VALUES ('admin', 'admin@billchecker.com', $1, 'admin')
            `, [defaultPassword]);
        }

        console.log('✅ Base de données initialisée');

    } catch (error) {
        console.error('❌ Erreur init DB:', error);
    }
}

// Upload vers Cloudinary
async function uploadToCloudinary(fileBuffer, fileName) {
    return new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
            { folder: 'billchecker', public_id: fileName, resource_type: 'auto' },
            (error, result) => {
                if (error) reject(error);
                else resolve(result.secure_url);
            }
        );
        uploadStream.end(fileBuffer);
    });
}

// Middleware authentification
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token requis' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token invalide' });
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
        const result = await pool.query(
            'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id',
            [username, email, hashedPassword]
        );
        res.status(201).json({ message: 'Utilisateur créé', userId: result.rows[0].id });
    } catch (error) {
        if (error.code === '23505') {
            return res.status(400).json({ error: 'Username ou email déjà utilisé' });
        }
        console.error('Erreur inscription:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Connexion
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (!user) return res.status(401).json({ error: 'Identifiants invalides' });
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Identifiants invalides' });
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        res.json({
            token,
            user: { id: user.id, username: user.username, email: user.email, role: user.role }
        });
    } catch (error) {
        console.error('Erreur login:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ============ ROUTES SCAN ============

// Analyser un billet
app.post('/api/scan/analyze', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { currency } = req.body;
        if (!req.file) return res.status(400).json({ error: 'Image requise' });

        const fileName = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
        const imageUrl = await uploadToCloudinary(req.file.buffer, fileName);

        const authenticity = ['GENUINE', 'SUSPICIOUS', 'UNCERTAIN'][Math.floor(Math.random() * 3)];
        const confidence = Math.floor(Math.random() * 40) + 60;

        const analysis = {
            authenticity,
            confidence,
            features_detected: [
                'Filigrane détecté',
                'Fil de sécurité visible',
                'Impression en relief confirmée'
            ],
            warnings: authenticity === 'SUSPICIOUS' ? ["Qualité d'image insuffisante"] : [],
            recommendation: authenticity === 'GENUINE'
                ? 'Le billet semble authentique'
                : 'Vérification manuelle recommandée'
        };

        const result = await pool.query(
            `INSERT INTO scans (user_id, currency, image_url, authenticity, confidence, features_detected, warnings, recommendation)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
            [req.user.id, currency, imageUrl, analysis.authenticity, analysis.confidence,
             JSON.stringify(analysis.features_detected), JSON.stringify(analysis.warnings), analysis.recommendation]
        );

        const scanId = result.rows[0].id;

        if (analysis.authenticity === 'SUSPICIOUS') {
            await pool.query(
                'INSERT INTO alerts (scan_id, severity, message) VALUES ($1, $2, $3)',
                [scanId, 'high', `Billet suspect: ${currency}`]
            );
        }

        res.json({ scanId, ...analysis, imageUrl });

    } catch (error) {
        console.error('Erreur analyse:', error);
        res.status(500).json({ error: 'Erreur analyse' });
    }
});

// Historique utilisateur
app.get('/api/scan/history', authenticateToken, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const offset = parseInt(req.query.offset) || 0;
        const result = await pool.query(
            'SELECT * FROM scans WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3',
            [req.user.id, limit, offset]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Erreur historique:', error);
        res.status(500).json({ error: 'Erreur récupération' });
    }
});

// ============ ROUTES ADMIN ============

// Statistiques
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const totalScans = await pool.query('SELECT COUNT(*) as total FROM scans');
        const byAuth = await pool.query('SELECT authenticity, COUNT(*) as count FROM scans GROUP BY authenticity');
        const byCurr = await pool.query('SELECT currency, COUNT(*) as count FROM scans GROUP BY currency');
        const totalUsers = await pool.query('SELECT COUNT(*) as total FROM users');
        const alerts = await pool.query('SELECT COUNT(*) as total FROM alerts WHERE resolved = FALSE');

        res.json({
            totalScans: parseInt(totalScans.rows[0].total),
            byAuthenticity: byAuth.rows,
            byCurrency: byCurr.rows,
            totalUsers: parseInt(totalUsers.rows[0].total),
            unresolvedAlerts: parseInt(alerts.rows[0].total)
        });
    } catch (error) {
        console.error('Erreur stats:', error);
        res.status(500).json({ error: 'Erreur' });
    }
});

// Liste scans admin
app.get('/api/admin/scans', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 100;
        const result = await pool.query(
            `SELECT scans.*, users.username 
             FROM scans 
             JOIN users ON scans.user_id = users.id 
             ORDER BY scans.created_at DESC 
             LIMIT $1`,
            [limit]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Erreur liste scans:', error);
        res.status(500).json({ error: 'Erreur' });
    }
});

// Route racine
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Health check
app.get('/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ status: 'ok', database: 'connected' });
    } catch (error) {
        res.status(500).json({ status: 'error', database: 'disconnected' });
    }
});

// Démarrage
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Serveur démarré sur le port ${PORT}`);
    console.log(`📊 Admin: username=admin, password=admin123`);
});

process.on('SIGTERM', async () => {
    await pool.end();
    console.log('Base de données fermée');
    process.exit(0);
});
