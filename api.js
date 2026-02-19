require('dotenv').config();
const express = require('express');
const serverless = require('serverless-http');
const cors = require('cors');
const multer = require('multer');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const OpenAI = require('openai');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const axios = require('axios');
const paypal = require('@paypal/checkout-server-sdk');

const app = express();
const router = express.Router();

// ========== CONFIGURATION ==========

const JWT_SECRET = process.env.JWT_SECRET || 'billcheckerSecretKey123456789';

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
});

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Configuration PayPal
function paypalEnvironment() {
    let clientId = process.env.PAYPAL_CLIENT_ID;
    let clientSecret = process.env.PAYPAL_CLIENT_SECRET;
    if (process.env.PAYPAL_MODE === 'production') {
        return new paypal.core.LiveEnvironment(clientId, clientSecret);
    }
    return new paypal.core.SandboxEnvironment(clientId, clientSecret);
}

const paypalClient = new paypal.core.PayPalHttpClient(paypalEnvironment());

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

const storage = multer.memoryStorage();
const upload = multer({ storage: storage, limits: { fileSize: 10 * 1024 * 1024 } });

// ========== FONCTIONS UTILITAIRES ==========

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

async function analyzeWithOpenAI(imageUrl, currency) {
    try {
        const response = await openai.chat.completions.create({
            model: "gpt-4o-mini",
            messages: [{
                role: "user",
                content: [{
                    type: "text",
                    text: `Analyse ce billet (${currency}). Réponds en JSON: {"currency":"","denomination":"","authenticity":"GENUINE/SUSPICIOUS/UNCERTAIN","confidence":60-100,"features_detected":[],"warnings":[],"recommendation":""}`
                }, {
                    type: "image_url",
                    image_url: { url: imageUrl }
                }]
            }],
            max_tokens: 800,
            temperature: 0.3
        });
        
        const content = response.choices[0].message.content.trim();
        const cleanContent = content.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
        const analysis = JSON.parse(cleanContent);
        
        return {
            currency: analysis.currency || currency,
            denomination: analysis.denomination || 'Inconnu',
            authenticity: analysis.authenticity,
            confidence: analysis.confidence,
            features_detected: analysis.features_detected || [],
            warnings: analysis.warnings || [],
            recommendation: analysis.recommendation
        };
    } catch (error) {
        console.error('Erreur OpenAI:', error.message);
        return {
            currency, denomination: 'Non déterminé', authenticity: 'UNCERTAIN', confidence: 65,
            features_detected: ['Analyse non disponible'], warnings: ['Erreur IA'],
            recommendation: 'Vérification manuelle recommandée'
        };
    }
}

async function sendEmail(to, subject, html) {
    try {
        await transporter.sendMail({
            from: `"Bill Checker" <${process.env.EMAIL_USER}>`,
            to, subject, html
        });
        return true;
    } catch (error) {
        console.error('Erreur email:', error);
        return false;
    }
}

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

function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Accès admin requis' });
    }
    next();
}

async function checkScanLimit(req, res, next) {
    try {
        const result = await pool.query(
            'SELECT * FROM subscriptions WHERE user_id = $1',
            [req.user.id]
        );
        
        let subscription = result.rows[0];
        
        if (!subscription) {
            await pool.query(
                `INSERT INTO subscriptions (user_id, plan, status, scans_used, scans_limit)
                 VALUES ($1, 'free', 'active', 0, 5)`,
                [req.user.id]
            );
            subscription = { plan: 'free', scans_used: 0, scans_limit: 5 };
        }
        
        if (subscription.scans_limit !== null && subscription.scans_used >= subscription.scans_limit) {
            return res.status(403).json({
                error: 'Limite de scans atteinte',
                message: 'Passez au plan Premium pour des scans illimités',
                plan: subscription.plan,
                scans_used: subscription.scans_used,
                scans_limit: subscription.scans_limit
            });
        }
        
        req.subscription = subscription;
        next();
    } catch (error) {
        console.error('Erreur vérification plan:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
}

// ========== ROUTES AUTH ==========

router.post('/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Tous les champs requis' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Mot de passe : minimum 6 caractères' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        
        const result = await pool.query(
            'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email',
            [username, email, hashedPassword]
        );
        
        res.status(201).json({ 
            message: 'Compte créé avec succès',
            user: result.rows[0]
        });
    } catch (error) {
        if (error.code === '23505') {
            if (error.constraint.includes('username')) {
                return res.status(400).json({ error: 'Ce nom d\'utilisateur est déjà pris' });
            }
            return res.status(400).json({ error: 'Cet email est déjà utilisé' });
        }
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

router.post('/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        
        if (!user) {
            return res.status(401).json({ error: 'Identifiants incorrects' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'Identifiants incorrects' });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: { id: user.id, username: user.username, email: user.email, role: user.role, plan: user.plan }
        });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

router.post('/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return res.json({ message: 'Si cet email existe, un lien a été envoyé' });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenExpiry = new Date(Date.now() + 3600000);

        await pool.query(
            'UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE id = $3',
            [resetToken, resetTokenExpiry, user.id]
        );

        const resetUrl = `${process.env.FRONTEND_URL}/reset-password.html?token=${resetToken}`;
        
        const emailHtml = `
            <h2>Réinitialisation de mot de passe</h2>
            <p>Bonjour ${user.username},</p>
            <p>Cliquez sur ce lien pour réinitialiser votre mot de passe :</p>
            <a href="${resetUrl}">Réinitialiser mon mot de passe</a>
            <p>Ce lien expire dans 1 heure.</p>
        `;

        await sendEmail(email, 'Réinitialisation - Bill Checker', emailHtml);
        res.json({ message: 'Si cet email existe, un lien a été envoyé' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

router.post('/auth/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'Mot de passe : minimum 6 caractères' });
        }

        const result = await pool.query(
            'SELECT * FROM users WHERE reset_token = $1 AND reset_token_expiry > NOW()',
            [token]
        );

        const user = result.rows[0];
        if (!user) {
            return res.status(400).json({ error: 'Token invalide ou expiré' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await pool.query(
            'UPDATE users SET password = $1, reset_token = NULL, reset_token_expiry = NULL WHERE id = $2',
            [hashedPassword, user.id]
        );

        res.json({ message: 'Mot de passe réinitialisé avec succès' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ========== ROUTES SCAN ==========

router.post('/scan/analyze', authenticateToken, checkScanLimit, upload.single('image'), async (req, res) => {
    try {
        const { currency } = req.body;
        if (!req.file) return res.status(400).json({ error: 'Image requise' });

        const fileName = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
        const imageUrl = await uploadToCloudinary(req.file.buffer, fileName);

        const analysis = await analyzeWithOpenAI(imageUrl, currency);

        const result = await pool.query(
            `INSERT INTO scans (user_id, currency, image_url, authenticity, confidence, features_detected, warnings, recommendation)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
            [req.user.id, analysis.currency, imageUrl, analysis.authenticity, analysis.confidence,
             JSON.stringify(analysis.features_detected), JSON.stringify(analysis.warnings), analysis.recommendation]
        );

        const scanId = result.rows[0].id;

        if (analysis.authenticity === 'SUSPICIOUS') {
            await pool.query(
                'INSERT INTO alerts (scan_id, severity, message) VALUES ($1, $2, $3)',
                [scanId, 'high', `Billet suspect: ${analysis.currency}`]
            );
        }

        await pool.query('UPDATE subscriptions SET scans_used = scans_used + 1 WHERE user_id = $1', [req.user.id]);

        res.json({ scanId, ...analysis, imageUrl });
    } catch (error) {
        console.error('Erreur analyse:', error);
        res.status(500).json({ error: 'Erreur analyse' });
    }
});

router.get('/scan/history', authenticateToken, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const offset = parseInt(req.query.offset) || 0;
        const result = await pool.query(
            'SELECT * FROM scans WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3',
            [req.user.id, limit, offset]
        );
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Erreur récupération' });
    }
});

// ========== ROUTES SUBSCRIPTION ==========

router.get('/subscription/status', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM subscriptions WHERE user_id = $1',
            [req.user.id]
        );
        
        const subscription = result.rows[0] || {
            plan: 'free',
            scans_used: 0,
            scans_limit: 5,
            status: 'active'
        };
        
        res.json(subscription);
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ========== ROUTES PAIEMENT ==========

router.post('/payment/lygos/initiate', authenticateToken, async (req, res) => {
    try {
        const { plan, phone_number } = req.body;
        
        const prices = { premium: 5000, business: 50000 };
        const amount = prices[plan];
        
        if (!amount) {
            return res.status(400).json({ error: 'Plan invalide' });
        }

        // Appel API Lygos
        const lygosResponse = await axios.post('https://api.lygos.co/v1/payment/initiate', {
            amount,
            currency: 'XAF',
            phone_number,
            description: `Abonnement ${plan} - Bill Checker`,
            callback_url: `${process.env.FRONTEND_URL}/api/payment/lygos/callback`
        }, {
            headers: {
                'Authorization': `Bearer ${process.env.LYGOS_API_KEY}`,
                'Content-Type': 'application/json'
            }
        });

        // Sauvegarder la transaction
        await pool.query(
            `INSERT INTO payments (user_id, amount, currency, payment_method, transaction_id, status, plan)
             VALUES ($1, $2, 'XAF', 'lygos', $3, 'pending', $4)`,
            [req.user.id, amount, lygosResponse.data.transaction_id, plan]
        );

        res.json({
            transaction_id: lygosResponse.data.transaction_id,
            payment_url: lygosResponse.data.payment_url
        });
    } catch (error) {
        console.error('Erreur Lygos:', error);
        res.status(500).json({ error: 'Erreur initiation paiement' });
    }
});

router.post('/payment/lygos/callback', async (req, res) => {
    try {
        const { transaction_id, status } = req.body;

        if (status === 'success') {
            const payment = await pool.query(
                'SELECT * FROM payments WHERE transaction_id = $1',
                [transaction_id]
            );

            if (payment.rows.length > 0) {
                const { user_id, plan } = payment.rows[0];

                await pool.query(
                    'UPDATE payments SET status = $1 WHERE transaction_id = $2',
                    ['completed', transaction_id]
                );

                const scansLimit = plan === 'premium' || plan === 'business' ? null : 5;

                await pool.query(
                    `INSERT INTO subscriptions (user_id, plan, status, scans_used, scans_limit, start_date, end_date)
                     VALUES ($1, $2, 'active', 0, $3, NOW(), NOW() + INTERVAL '30 days')
                     ON CONFLICT (user_id) DO UPDATE SET
                        plan = $2, status = 'active', scans_limit = $3,
                        start_date = NOW(), end_date = NOW() + INTERVAL '30 days'`,
                    [user_id, plan, scansLimit]
                );

                await pool.query('UPDATE users SET plan = $1 WHERE id = $2', [plan, user_id]);
            }
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Erreur callback Lygos:', error);
        res.status(500).json({ error: 'Erreur traitement' });
    }
});

router.post('/payment/paypal/create', authenticateToken, async (req, res) => {
    try {
        const { plan } = req.body;
        
        const prices = { premium: 8, business: 80 }; // USD
        const amount = prices[plan];
        
        if (!amount) {
            return res.status(400).json({ error: 'Plan invalide' });
        }

        const request = new paypal.orders.OrdersCreateRequest();
        request.prefer("return=representation");
        request.requestBody({
            intent: 'CAPTURE',
            purchase_units: [{
                amount: {
                    currency_code: 'USD',
                    value: amount.toString()
                },
                description: `Bill Checker - ${plan}`
            }],
            application_context: {
                return_url: `${process.env.FRONTEND_URL}/payment-success.html`,
                cancel_url: `${process.env.FRONTEND_URL}/pricing.html`
            }
        });

        const order = await paypalClient.execute(request);

        await pool.query(
            `INSERT INTO payments (user_id, amount, currency, payment_method, transaction_id, status, plan)
             VALUES ($1, $2, 'USD', 'paypal', $3, 'pending', $4)`,
            [req.user.id, amount, order.result.id, plan]
        );

        res.json({
            orderId: order.result.id,
            approvalUrl: order.result.links.find(link => link.rel === 'approve').href
        });
    } catch (error) {
        console.error('Erreur PayPal:', error);
        res.status(500).json({ error: 'Erreur création commande' });
    }
});

router.post('/payment/paypal/capture/:orderId', authenticateToken, async (req, res) => {
    try {
        const request = new paypal.orders.OrdersCaptureRequest(req.params.orderId);
        const capture = await paypalClient.execute(request);

        if (capture.result.status === 'COMPLETED') {
            const payment = await pool.query(
                'SELECT * FROM payments WHERE transaction_id = $1',
                [req.params.orderId]
            );

            if (payment.rows.length > 0) {
                const { user_id, plan } = payment.rows[0];

                await pool.query(
                    'UPDATE payments SET status = $1 WHERE transaction_id = $2',
                    ['completed', req.params.orderId]
                );

                const scansLimit = plan === 'premium' || plan === 'business' ? null : 5;

                await pool.query(
                    `INSERT INTO subscriptions (user_id, plan, status, scans_used, scans_limit, start_date, end_date)
                     VALUES ($1, $2, 'active', 0, $3, NOW(), NOW() + INTERVAL '30 days')
                     ON CONFLICT (user_id) DO UPDATE SET
                        plan = $2, status = 'active', scans_limit = $3,
                        start_date = NOW(), end_date = NOW() + INTERVAL '30 days'`,
                    [user_id, plan, scansLimit]
                );

                await pool.query('UPDATE users SET plan = $1 WHERE id = $2', [plan, user_id]);
            }
        }

        res.json({ success: true, capture: capture.result });
    } catch (error) {
        console.error('Erreur capture PayPal:', error);
        res.status(500).json({ error: 'Erreur capture paiement' });
    }
});

// ========== ROUTES ADMIN ==========

router.get('/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const totalScans = await pool.query('SELECT COUNT(*) as total FROM scans');
        const byAuth = await pool.query('SELECT authenticity, COUNT(*) as count FROM scans GROUP BY authenticity');
        const byCurr = await pool.query('SELECT currency, COUNT(*) as count FROM scans GROUP BY currency');
        const totalUsers = await pool.query('SELECT COUNT(*) as total FROM users');
        const byPlan = await pool.query('SELECT plan, COUNT(*) as count FROM users GROUP BY plan');
        const alerts = await pool.query('SELECT COUNT(*) as total FROM alerts WHERE resolved = FALSE');
        const revenue = await pool.query('SELECT SUM(amount) as total FROM payments WHERE status = $1', ['completed']);
        const recentPayments = await pool.query('SELECT * FROM payments ORDER BY created_at DESC LIMIT 10');

        res.json({
            totalScans: parseInt(totalScans.rows[0].total),
            byAuthenticity: byAuth.rows,
            byCurrency: byCurr.rows,
            totalUsers: parseInt(totalUsers.rows[0].total),
            byPlan: byPlan.rows,
            unresolvedAlerts: parseInt(alerts.rows[0].total),
            totalRevenue: parseFloat(revenue.rows[0].total || 0),
            recentPayments: recentPayments.rows
        });
    } catch (error) {
        res.status(500).json({ error: 'Erreur' });
    }
});

router.get('/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT users.*, subscriptions.plan as subscription_plan, subscriptions.scans_used, subscriptions.scans_limit
             FROM users
             LEFT JOIN subscriptions ON users.id = subscriptions.user_id
             ORDER BY users.created_at DESC`
        );
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Erreur' });
    }
});

router.get('/admin/scans', authenticateToken, requireAdmin, async (req, res) => {
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
        res.status(500).json({ error: 'Erreur' });
    }
});

router.patch('/admin/user/:userId/plan', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { plan } = req.body;
        const { userId } = req.params;

        await pool.query('UPDATE users SET plan = $1 WHERE id = $2', [plan, userId]);

        const scansLimit = plan === 'free' ? 5 : null;
        await pool.query(
            `INSERT INTO subscriptions (user_id, plan, status, scans_limit)
             VALUES ($1, $2, 'active', $3)
             ON CONFLICT (user_id) DO UPDATE SET plan = $2, scans_limit = $3`,
            [userId, plan, scansLimit]
        );

        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur' });
    }
});

// Health check
router.get('/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ 
            status: 'ok', 
            database: 'connected',
            openai: process.env.OPENAI_API_KEY ? 'configured' : 'not configured',
            email: process.env.EMAIL_USER ? 'configured' : 'not configured'
        });
    } catch (error) {
        res.status(500).json({ status: 'error', database: 'disconnected' });
    }
});

app.use('/.netlify/functions/api', router);

module.exports.handler = serverless(app);
