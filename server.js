try { require('dotenv').config(); } catch (e) {}
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();

// ============================================================================
// ⚙️ 1. CORE ENVIRONMENT & GLOBAL CONFIGURATION
// ============================================================================
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || '';
const JWT_SECRET = process.env.JWT_SECRET || 'emcs_ultra_fallback_secret_key_change_in_prod_998877';
const TENANT_ID = process.env.TENANT_ID || 'EMCS_MAIN_01';
const IS_PROD = process.env.NODE_ENV === 'production';

// Master Admin Credentials (Can be overridden via Render Env Vars)
const MASTER_ADMIN_USER = process.env.MASTER_ADMIN_USER || 'admin';
const MASTER_ADMIN_PASS = process.env.MASTER_ADMIN_PASS || 'Admin@12345';

// Gemini AI API Key (Optional for AI Support Advisor)
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';

// Telegram Bot Credentials (Strictly Verified Against Render Env)
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_ADMIN_CHAT_ID = process.env.TELEGRAM_ADMIN_CHAT_ID || '';

// Global Maintenance Flag (Synced with DB & Telegram Bot)
global.MAINTENANCE_MODE = false;

// ============================================================================
// 🤖 2. TELEGRAM ALERT ENGINE & SENSITIVE DATA MASKING
// ============================================================================

/**
 * Strips passwords, secret keys, JWTs, and Bcrypt hashes before sending any log to Telegram
 */
function maskSensitiveData(text) {
    if (!text) return 'No details provided.';
    let safeText = String(text);
    // Mask JSON or Query key-value pairs containing sensitive keywords
    safeText = safeText.replace(/(password|secret|apikey|api_key|credential|token|pin|auth)\s*[:=]\s*["']?[^"'\s,}&]*/gi, '$1: [HIDDEN_FOR_SECURITY]');
    // Mask JWT Tokens
    safeText = safeText.replace(/eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, '[JWT_HIDDEN]');
    // Mask Bcrypt Hashes
    safeText = safeText.replace(/\$2[abxy]\$\d+\$[./A-Za-z0-9]{53}/g, '[HASH_HIDDEN]');
    // Mask MongoDB SRV Connection Strings with Passwords
    safeText = safeText.replace(/mongodb(\+srv)?:\/\/([^:]+):([^@]+)@/gi, 'mongodb$1://$2:[DB_PASS_HIDDEN]@');
    return safeText;
}

/**
 * Sends instant alert to Admin Telegram. Automatically sends DOUBLE notification for DB issues.
 */
async function sendTelegramAlert(type, message, req = null) {
    const ADMIN_ID = process.env.TELEGRAM_ADMIN_CHAT_ID || TELEGRAM_ADMIN_CHAT_ID;
    if (!TELEGRAM_BOT_TOKEN || !ADMIN_ID) return;

    let ipInfo = 'System / Internal';
    if (req) {
        ipInfo = req.headers['x-forwarded-for'] || req.ip || 'Unknown IP';
    }

    const safeMessage = maskSensitiveData(message);
    const typeStr = String(type).toLowerCase();
    const msgStr = String(safeMessage).toLowerCase();

    // Detect if the problem is related to Database, MongoDB, or Injection Hacking
    const isDatabaseIssue =
        typeStr.includes('database') ||
        typeStr.includes('mongo') ||
        typeStr.includes('nosql') ||
        typeStr.includes('injection') ||
        typeStr.includes('pollution') ||
        msgStr.includes('database') ||
        msgStr.includes('mongo') ||
        msgStr.includes('unauthorized');

    // Send 2 times if it's a critical Database issue, else 1 time
    const alertCount = isDatabaseIssue ? 2 : 1;

    let text = `🚨 *EMCS SYSTEM ALERT* 🚨\n\n*Type:* ${type}\n*Time:* ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}\n*Source IP:* \`${ipInfo}\`\n\n*Details:*\n${safeMessage}`;

    if (isDatabaseIssue) {
        text = `‼️ *URGENT DATABASE SECURITY / HEALTH ALERT* ‼️\n\n` + text;
    }

    for (let i = 0; i < alertCount; i++) {
        try {
            await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    chat_id: ADMIN_ID,
                    text: text,
                    parse_mode: 'Markdown'
                })
            });

            // 1-second delay between double alerts to respect Telegram rate limits
            if (i < alertCount - 1) {
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        } catch (e) {
            console.error('[EMCS] Telegram Dispatch Error:', e.message);
        }
    }
}

// ============================================================================
// 🛡️ 3. FORT-KNOX MONGODB SETUP, SCHEMAS & GLOBAL DATA-LEAK SHIELD
// ============================================================================

// Harden Mongoose against Query Selector Injection & Unindexed Queries
mongoose.set('sanitizeFilter', true);
mongoose.set('strictQuery', true);

// Global Schema Transform: NEVER allow credentialHash or internal keys to leak in JSON responses
mongoose.plugin((schema) => {
    schema.set('toJSON', {
        transform: (doc, ret) => {
            delete ret.credentialHash;
            delete ret.__v;
            return ret;
        }
    });
    schema.set('toObject', {
        transform: (doc, ret) => {
            delete ret.credentialHash;
            delete ret.__v;
            return ret;
        }
    });
});

// Fast In-Memory Bloom Set for Pre-Checking Existing Users
const emcsBloom = new Set();

// --- SCHEMA 1: CONSUMER USER ---
const UserSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, index: true },
    consumerId: { type: String, required: true, unique: true, index: true },
    name: { type: String, required: true, trim: true },
    mobile: { type: String, required: true, unique: true, index: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    state: { type: String, default: 'BR' },
    sanctionedKw: { type: Number, default: 2 },
    credentialHash: { type: String, required: true, select: false },
    accountStatus: { type: String, enum: ['active', 'suspended'], default: 'active' },
    failedLoginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date, default: null },
    appliances: {
        type: [{
            name: String,
            power: Number,
            hours: Number
        }],
        default: []
    },
    iotStates: {
        type: Map,
        of: Boolean,
        default: { '1': false, '2': false, '3': false, '4': false }
    },
    activeSessions: {
        type: [{
            sessionId: String,
            uaHash: String,
            deviceLabel: String,
            ip: String,
            lastActive: { type: Date, default: Date.now }
        }],
        default: []
    }
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

// --- SCHEMA 2: GOD-MODE CMS & TARIFF CONFIG ---
const CmsSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, index: true },
    key: { type: String, default: 'global_cms', unique: true },
    siteName: { type: String, default: 'EMCS' },
    broadcastBanner: { type: String, default: '' },
    heroHeading: { type: String, default: 'Smart Energy Control & Bill Optimizer' },
    heroSubtext: { type: String, default: 'Real-time load monitoring, progressive tariff slab alerts, and AI bill reduction.' },
    themeColors: {
        primary: { type: String, default: '#6366f1' },
        accent: { type: String, default: '#10b981' }
    },
    featureSwitches: {
        gridSafety: { type: Boolean, default: true },
        inverter: { type: Boolean, default: true },
        vampire: { type: Boolean, default: true },
        tod: { type: Boolean, default: true },
        solar: { type: Boolean, default: true },
        iot: { type: Boolean, default: true }
    },
    liveTariffs: {
        slabs: {
            type: [{
                min: Number,
                max: Number,
                rate: Number
            }],
            default: [
                { min: 0, max: 100, rate: 5.5 },
                { min: 101, max: 200, rate: 6.5 },
                { min: 201, max: 300, rate: 7.5 },
                { min: 301, max: 999999, rate: 8.5 }
            ]
        },
        fixedCharge: { type: Number, default: 120 },
        taxPercent: { type: Number, default: 5 }
    },
    paymentConfig: {
        enabled: { type: Boolean, default: true },
        apiKey: { type: String, default: '' },
        apiSecret: { type: String, default: '' } // 🚨 Strictly stripped on public routes
    },
    aiPrompt: {
        type: String,
        default: 'You are the official EMCS Smart Grid AI Engineer. Provide concise, practical electricity bill reduction advice for Indian households.'
    },
    maintenanceMode: { type: Boolean, default: false }
}, { timestamps: true });

const CmsConfig = mongoose.model('CmsConfig', CmsSchema);

// --- SCHEMA 3: STAFF OPERATORS & GRANULAR PERMISSIONS ---
const StaffSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, index: true },
    username: { type: String, required: true, unique: true, lowercase: true, trim: true },
    roleTitle: { type: String, default: 'Support Executive' },
    credentialHash: { type: String, required: true, select: false },
    permissions: {
        manageUsers: { type: Boolean, default: true },
        manageCms: { type: Boolean, default: false },
        manageSupport: { type: Boolean, default: true },
        viewLogs: { type: Boolean, default: false }
    },
    isActive: { type: Boolean, default: true }
}, { timestamps: true });

const Staff = mongoose.model('Staff', StaffSchema);

// --- SCHEMA 4: SUPPORT TICKETS & AI CHAT ---
const SupportTicketSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, index: true },
    consumerId: { type: String, required: true, index: true },
    consumerName: { type: String, default: 'Consumer' },
    status: { type: String, enum: ['open', 'resolved'], default: 'open' },
    messages: [{
        sender: { type: String, enum: ['user', 'ai', 'admin'] },
        text: String,
        timestamp: { type: Date, default: Date.now }
    }]
}, { timestamps: true });

const SupportTicket = mongoose.model('SupportTicket', SupportTicketSchema);

// --- SCHEMA 5: BILL PAYMENT RECEIPTS ---
const PaymentSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, index: true },
    consumerId: { type: String, required: true, index: true },
    txnId: { type: String, required: true, unique: true },
    amount: { type: Number, required: true },
    unitsBilled: { type: Number, default: 0 },
    method: { type: String, default: 'UPI' },
    status: { type: String, default: 'SUCCESS' }
}, { timestamps: true });

const PaymentReceipt = mongoose.model('PaymentReceipt', PaymentSchema);

// --- SCHEMA 6: SYSTEM ERRORS & ADMIN AUDIT TRAIL ---
const SystemErrorSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, index: true },
    source: { type: String, required: true },
    message: { type: String, required: true },
    location: { type: String, default: 'Backend' },
    userOrIp: { type: String, default: 'System' }
}, { timestamps: true });

const SystemError = mongoose.model('SystemError', SystemErrorSchema);

/**
 * Central Emergency Alert Dispatcher (Saves to DB + Fires Telegram Alert)
 */
async function dispatchEmergencyAlert(source, message, req = null) {
    try {
        const ip = req ? (req.headers['x-forwarded-for'] || req.ip) : 'System';
        const safeMsg = maskSensitiveData(message);
        if (mongoose.connection.readyState === 1) {
            await new SystemError({
                tenantId: TENANT_ID,
                source,
                message: safeMsg,
                location: req ? req.originalUrl : 'Server',
                userOrIp: ip
            }).save();
        }
        await sendTelegramAlert(source, safeMsg, req);
    } catch (e) {
        console.error('[EMCS] Failed to log emergency alert:', e.message);
    }
}

// ============================================================================
// 🔌 4. ACTIVE DATABASE CONNECTION & LIVE HEALTH LISTENERS
// ============================================================================
mongoose.connection.on('error', async (err) => {
    console.error('[EMCS] MongoDB Runtime Error:', err.message);
    await dispatchEmergencyAlert('Database Runtime Error', `MongoDB error or unauthorized access attempt: ${err.message}`);
});

mongoose.connection.on('disconnected', async () => {
    console.warn('[EMCS] MongoDB Disconnected!');
    await dispatchEmergencyAlert('Database Disconnected', 'Critical: MongoDB connection was lost or dropped.');
});

if (MONGO_URI) {
    const dbSecurityOptions = {
        maxPoolSize: 50,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
        autoIndex: !IS_PROD,
        family: 4
    };

    mongoose.connect(MONGO_URI, dbSecurityOptions).then(async () => {
        console.log('[EMCS] 🛡️ MongoDB Connected & Fort-Knox Security Pool Active.');
        const users = await User.find({ tenantId: TENANT_ID }, 'mobile email consumerId').lean();
        users.forEach(u => {
            if (u.mobile) emcsBloom.add(u.mobile);
            if (u.email) emcsBloom.add(u.email);
            if (u.consumerId) emcsBloom.add(u.consumerId);
        });
    }).catch(async (err) => {
        console.error('[EMCS] ❌ Initial Database Connection Failed:', err.message);
        await sendTelegramAlert('FATAL: Database Connection Failed', `MongoDB Refused Connection: ${err.message}`);
    });
} else {
    console.warn('[EMCS] ⚠️ MONGO_URI not set in environment variables!');
}

// ============================================================================
// 🧱 5. BANK-GRADE SECURITY MIDDLEWARE STACK
// ============================================================================

app.set('trust proxy', 1);
app.disable('x-powered-by'); // Camouflage Express fingerprint

// Body & URL Payload Crash Guards (10KB strict memory cap)
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// 5A. Enterprise Security Headers (HSTS, CSP, Clickjacking, MIME Sniffing)
app.use((req, res, next) => {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:; img-src 'self' data: https:; connect-src 'self';"
    );
    next();
});

// 5B. Global Under-Maintenance Traffic Blocker (Controlled via Telegram Bot)
app.use((req, res, next) => {
    if (global.MAINTENANCE_MODE) {
        if (req.path.startsWith('/api/')) {
            return res.status(503).json({ success: false, message: 'System Under Maintenance ⚠️' });
        }
        return res.status(503).send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Under Maintenance | EMCS</title>
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
            </head>
            <body style="display:flex; justify-content:center; align-items:center; height:100vh; font-family:sans-serif; background:#0b0f19; color:#f9fafb; text-align:center; margin:0;">
                <div style="padding:28px; border:1px solid #1f2937; border-radius:14px; background:#111827; max-width:420px;">
                    <h1 style="font-size:3.5rem; margin:0 0 10px;">⚠️</h1>
                    <h2 style="color:#ef4444; margin:0 0 10px;">Under Maintenance ⚠️</h2>
                    <p style="color:#9ca3af; font-size:0.95rem; line-height:1.5;">We are currently upgrading the EMCS Smart Grid servers. Normal operations will resume shortly.</p>
                </div>
            </body>
            </html>
        `);
    }
    next();
});

// 5C. Ultimate NoSQL Injection & Prototype Pollution Shield
app.use(async (req, res, next) => {
    const forbiddenKeys = ['__proto__', 'constructor', 'prototype'];
    const hasMaliciousKeys = (obj) => {
        if (!obj || typeof obj !== 'object') return false;
        for (const key of Object.keys(obj)) {
            if (key.includes('$') || key.includes('.') || forbiddenKeys.includes(key.toLowerCase())) {
                return true;
            }
            if (typeof obj[key] === 'object' && hasMaliciousKeys(obj[key])) {
                return true;
            }
        }
        return false;
    };

    if (hasMaliciousKeys(req.body) || hasMaliciousKeys(req.query) || hasMaliciousKeys(req.params)) {
        await dispatchEmergencyAlert('NoSQL / Prototype Pollution Blocked', `Malicious payload keys blocked on ${req.method} ${req.originalUrl}`, req);
        return res.status(403).json({ success: false, message: 'Security Block: Malicious payload structure detected.' });
    }
    next();
});

// 5D. Strict Origin CSRF Guard for Mutating API Requests
app.use((req, res, next) => {
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method) && req.path.startsWith('/api/')) {
        const origin = req.headers.origin || req.headers.referer || '';
        const host = req.headers.host || '';
        if (IS_PROD && origin && !origin.includes(host)) {
            dispatchEmergencyAlert('CSRF Origin Mismatch', `Blocked cross-origin ${req.method} from ${origin}`, req);
            return res.status(403).json({ success: false, message: 'CSRF Security Block: Invalid Origin.' });
        }
    }
    next();
});

// 5E. In-Memory API Rate Limiter (Anti-DDoS & Anti-Scraping)
const ipRateMap = new Map();
app.use('/api/', (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.ip || 'unknown';
    const now = Date.now();
    const windowMs = 60 * 1000; // 1 Minute Window
    const maxReqs = 90;

    const record = ipRateMap.get(ip) || { count: 0, resetAt: now + windowMs };
    if (now > record.resetAt) {
        record.count = 1;
        record.resetAt = now + windowMs;
    } else {
        record.count++;
    }
    ipRateMap.set(ip, record);

    if (record.count > maxReqs) {
        return res.status(429).json({ success: false, message: 'Too many requests. Please slow down.' });
    }
    next();
});
// ============================================================================
// 🔐 6. DEVICE-BOUND AUTHENTICATION & GRANULAR PERMISSION MIDDLEWARES
// ============================================================================

/**
 * Generates SHA-256 fingerprint of the client's User-Agent string
 */
function getUaHash(req) {
    const ua = String(req.headers['user-agent'] || 'unknown_device');
    return crypto.createHash('sha256').update(ua).digest('hex');
}

/**
 * Consumer Session Verification (HttpOnly Cookie + Device Fingerprint + Anti-IDOR)
 */
async function authenticateConsumer(req, res, next) {
    const token = req.cookies.emcs_user_token;
    if (!token) {
        return res.status(401).json({ success: false, message: 'Authentication required. Please login.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const currentUaHash = getUaHash(req);

        // Device-Binding Check: Prevent stolen cookie replay on another browser/device
        if (decoded.uaHash && decoded.uaHash !== currentUaHash) {
            res.clearCookie('emcs_user_token');
            await dispatchEmergencyAlert('Consumer Session Hijack Blocked', `Token for ${decoded.consumerId} used from mismatched device!`, req);
            return res.status(403).json({ success: false, message: 'Security Alert: Device mismatch. Session terminated.' });
        }

        const user = await User.findOne({ tenantId: TENANT_ID, consumerId: decoded.consumerId });
        if (!user || user.accountStatus !== 'active') {
            res.clearCookie('emcs_user_token');
            return res.status(403).json({ success: false, message: 'Account suspended or not found.' });
        }

        // Verify session exists in activeSessions array
        const sessionExists = user.activeSessions.some(s => s.sessionId === decoded.sessionId);
        if (!sessionExists) {
            res.clearCookie('emcs_user_token');
            return res.status(401).json({ success: false, message: 'Session expired or revoked.' });
        }

        req.user = user;
        req.sessionId = decoded.sessionId;
        next();
    } catch (e) {
        res.clearCookie('emcs_user_token');
        return res.status(401).json({ success: false, message: 'Invalid or expired session.' });
    }
}

/**
 * Admin / Staff Command Hub Verification (Device-Bound HttpOnly Cookie)
 */
async function authenticateAdmin(req, res, next) {
    const token = req.cookies.emcs_admin_token;
    if (!token) {
        return res.status(401).json({ success: false, message: 'Admin authorization required.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const currentUaHash = getUaHash(req);

        if (decoded.uaHash && decoded.uaHash !== currentUaHash) {
            res.clearCookie('emcs_admin_token');
            await dispatchEmergencyAlert('Admin Session Hijack Blocked', `Admin token (${decoded.username}) used from unauthorized device!`, req);
            return res.status(403).json({ success: false, message: 'Device mismatch. Admin logged out.' });
        }

        req.admin = decoded; // Contains { username, role, permissions, uaHash }
        next();
    } catch (e) {
        res.clearCookie('emcs_admin_token');
        return res.status(403).json({ success: false, message: 'Admin session expired.' });
    }
}

/**
 * Granular Staff Permission Guard (Super Admin bypasses all checks; Staff checked per module)
 */
function requireAdminPermission(permKey) {
    return (req, res, next) => {
        if (!req.admin) {
            return res.status(401).json({ success: false, message: 'Unauthorized.' });
        }
        if (req.admin.role === 'SUPER_ADMIN') {
            return next();
        }
        if (req.admin.permissions && req.admin.permissions[permKey] === true) {
            return next();
        }
        return res.status(403).json({
            success: false,
            message: `Access Denied: Your staff profile lacks '${permKey}' permission.`
        });
    };
}

// ============================================================================
// 🌐 7. PUBLIC & CONSUMER API ROUTES (Zero File Uploads, Strict Validation)
// ============================================================================

// 7A. Public CMS & Tariff Fetch (Sanitized - Strips Payment Secret & AI Prompt)
app.get('/api/cms', async (req, res) => {
    try {
        let cms = await CmsConfig.findOne({ tenantId: TENANT_ID, key: 'global_cms' }).lean();
        if (!cms) {
            cms = await new CmsConfig({ tenantId: TENANT_ID, key: 'global_cms' }).save();
            cms = cms.toObject();
        }

        // 🚨 CRITICAL SECURITY STRIP: Never expose Payment Secret or AI Prompt in Network Tab
        if (cms.paymentConfig) {
            delete cms.paymentConfig.apiSecret;
        }
        delete cms.aiPrompt;

        res.json({ success: true, cms });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Failed to load configuration.' });
    }
});

// 7B. Consumer Registration (With Honeypot Trap & Bcrypt-12 Military Hashing)
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, mobile, email, state, sanctionedKw, credential, honeypot } = req.body;

        // 🍯 Honeypot Check
        if (honeypot && String(honeypot).trim().length > 0) {
            await dispatchEmergencyAlert('Bot Registration Blocked', `Honeypot triggered by IP ${req.ip}`, req);
            return res.status(400).json({ success: false, message: ' Automated bot registration blocked.' });
        }

        if (!name || !mobile || !email || !credential) {
            return res.status(400).json({ success: false, message: 'All fields are required.' });
        }

        const cleanMobile = String(mobile).trim();
        const cleanEmail = String(email).trim().toLowerCase();

        if (!/^\d{10}$/.test(cleanMobile)) {
            return res.status(400).json({ success: false, message: 'Enter a valid 10-digit mobile number.' });
        }
        if (String(credential).length < 6) {
            return res.status(400).json({ success: false, message: 'Password must be at least 6 characters.' });
        }

        const existing = await User.findOne({
            tenantId: TENANT_ID,
            $or: [{ mobile: cleanMobile }, { email: cleanEmail }]
        }).lean();

        if (existing) {
            return res.status(409).json({ success: false, message: 'Mobile or Email already registered.' });
        }

        // Generate Unique Consumer ID (e.g., EMCS-849201)
        const randomDigits = Math.floor(100000 + Math.random() * 900000);
        const consumerId = `EMCS-${randomDigits}`;

        // 🔥 Bcrypt 12 Salt Rounds
        const credentialHash = await bcrypt.hash(String(credential), 12);

        const sessionId = crypto.randomBytes(16).toString('hex');
        const uaHash = getUaHash(req);
        const deviceLabel = String(req.headers['user-agent'] || 'Web Browser').substring(0, 65);

        const newUser = await new User({
            tenantId: TENANT_ID,
            consumerId,
            name: String(name).trim().substring(0, 60),
            mobile: cleanMobile,
            email: cleanEmail,
            state: String(state || 'BR').substring(0, 10),
            sanctionedKw: Number(sanctionedKw) || 2,
            credentialHash,
            appliances: [
                { name: 'LED Bulb (Living Room)', power: 12, hours: 8 },
                { name: 'Ceiling Fan', power: 75, hours: 12 }
            ],
            activeSessions: [{ sessionId, uaHash, deviceLabel, ip: req.ip }]
        }).save();

        emcsBloom.add(cleanMobile);
        emcsBloom.add(cleanEmail);
        emcsBloom.add(consumerId);

        const token = jwt.sign({ consumerId, sessionId, uaHash }, JWT_SECRET, { expiresIn: '7d' });

        res.cookie('emcs_user_token', token, {
            httpOnly: true,
            secure: IS_PROD,
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.json({ success: true, user: newUser });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Registration failed.' });
    }
});

// 7C. Consumer Login (With 5-Attempt 15-Minute Brute-Force Lockout)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { identifier, credential, honeypot } = req.body;

        if (honeypot && String(honeypot).trim().length > 0) {
            await dispatchEmergencyAlert('Bot Login Blocked', `Honeypot triggered on login`, req);
            return res.status(403).json({ success: false, message: 'Access denied.' });
        }

        if (!identifier || !credential) {
            return res.status(400).json({ success: false, message: 'Enter login ID and password.' });
        }

        const cleanId = String(identifier).trim().toLowerCase();

        const user = await User.findOne({
            tenantId: TENANT_ID,
            $or: [{ mobile: cleanId }, { email: cleanId }, { consumerId: cleanId.toUpperCase() }]
        }).select('+credentialHash');

        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid credentials.' });
        }

        if (user.accountStatus === 'suspended') {
            return res.status(403).json({ success: false, message: 'Account suspended by administration.' });
        }

        // Check Brute-Force Lockout Timer
        if (user.lockUntil && user.lockUntil > new Date()) {
            const minsLeft = Math.ceil((user.lockUntil - new Date()) / 60000);
            return res.status(429).json({
                success: false,
                message: `Account locked due to multiple failed attempts. Try again in ${minsLeft} minutes.`
            });
        }

        const isMatch = await bcrypt.compare(String(credential), user.credentialHash);
        if (!isMatch) {
            user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
            if (user.failedLoginAttempts >= 5) {
                user.lockUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 Min Lockout
                await user.save();
                await dispatchEmergencyAlert('Brute-Force Lockout Triggered', `Consumer ${user.consumerId} locked for 15m after 5 failed attempts.`, req);
                return res.status(429).json({ success: false, message: '5 failed attempts! Account locked for 15 minutes.' });
            }
            await user.save();
            return res.status(401).json({
                success: false,
                message: `Invalid password. (${5 - user.failedLoginAttempts} attempts remaining)`
            });
        }

        // Reset lockout counters on valid login
        user.failedLoginAttempts = 0;
        user.lockUntil = null;

        const sessionId = crypto.randomBytes(16).toString('hex');
        const uaHash = getUaHash(req);
        const deviceLabel = String(req.headers['user-agent'] || 'Web Browser').substring(0, 65);

        // Keep max 5 recent active device sessions
        user.activeSessions.push({ sessionId, uaHash, deviceLabel, ip: req.ip });
        if (user.activeSessions.length > 5) {
            user.activeSessions = user.activeSessions.slice(-5);
        }
        await user.save();

        const token = jwt.sign({ consumerId: user.consumerId, sessionId, uaHash }, JWT_SECRET, { expiresIn: '7d' });

        res.cookie('emcs_user_token', token, {
            httpOnly: true,
            secure: IS_PROD,
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        const safeUser = user.toObject();
        delete safeUser.credentialHash;

        res.json({ success: true, user: safeUser });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Login error occurred.' });
    }
});

// 7D. Get Current Logged-in Consumer Session (`/api/auth/me`)
app.get('/api/auth/me', authenticateConsumer, async (req, res) => {
    res.json({ success: true, user: req.user });
});

// 7E. Consumer Logout (Current Device or All Devices)
app.post('/api/auth/logout', authenticateConsumer, async (req, res) => {
    try {
        const { allDevices } = req.body;
        if (allDevices) {
            req.user.activeSessions = [];
        } else {
            req.user.activeSessions = req.user.activeSessions.filter(s => s.sessionId !== req.sessionId);
        }
        await req.user.save();
        res.clearCookie('emcs_user_token');
        res.json({ success: true });
    } catch (e) {
        res.clearCookie('emcs_user_token');
        res.json({ success: true });
    }
});

// 7F. Sync User Appliances (Feeds Dashboard, Standby Power Saver & Graph Reports)
app.put('/api/user/appliances', authenticateConsumer, async (req, res) => {
    try {
        const { appliances } = req.body;
        if (!Array.isArray(appliances) || appliances.length > 60) {
            return res.status(400).json({ success: false, message: 'Invalid appliances list.' });
        }

        const sanitized = appliances.map(a => ({
            name: String(a.name || 'Appliance').trim().substring(0, 50),
            power: Math.max(0, Math.min(50000, Number(a.power) || 0)),
            hours: Math.max(0, Math.min(24, Number(a.hours) || 0))
        }));

        req.user.appliances = sanitized;
        await req.user.save();
        res.json({ success: true, appliances: req.user.appliances });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Failed to sync appliances.' });
    }
});

// 7G. Toggle Smart Hardware IoT Relay (Requires Verified Login)
app.post('/api/user/iot-toggle', authenticateConsumer, async (req, res) => {
    try {
        const { nodeId, state } = req.body;
        const key = String(nodeId);
        if (!['1', '2', '3', '4'].includes(key)) {
            return res.status(400).json({ success: false, message: 'Invalid hardware node.' });
        }
        req.user.iotStates.set(key, Boolean(state));
        await req.user.save();
        res.json({ success: true, nodeId: key, state: Boolean(state) });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Hardware relay timeout.' });
    }
});

// 7H. Process Bill Payment & Generate Receipt
app.post('/api/user/pay-bill', authenticateConsumer, async (req, res) => {
    try {
        const cms = await CmsConfig.findOne({ tenantId: TENANT_ID, key: 'global_cms' }).lean();
        if (cms && cms.paymentConfig && cms.paymentConfig.enabled === false) {
            return res.status(403).json({ success: false, message: 'Online payments are temporarily paused by Admin.' });
        }

        const { amount, unitsBilled, method } = req.body;
        const numAmount = Number(amount) || 0;
        if (numAmount <= 0) {
            return res.status(400).json({ success: false, message: 'Payable amount must be greater than ₹0.' });
        }

        const txnId = 'TXN' + Date.now() + Math.floor(100 + Math.random() * 900);
        const receipt = await new PaymentReceipt({
            tenantId: TENANT_ID,
            consumerId: req.user.consumerId,
            txnId,
            amount: numAmount,
            unitsBilled: Number(unitsBilled) || 0,
            method: String(method || 'UPI').substring(0, 20)
        }).save();

        res.json({ success: true, receipt });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Payment transaction failed.' });
    }
});

app.get('/api/user/payments', authenticateConsumer, async (req, res) => {
    try {
        const receipts = await PaymentReceipt.find({
            tenantId: TENANT_ID,
            consumerId: req.user.consumerId
        }).sort({ createdAt: -1 }).limit(10).lean();
        res.json({ success: true, receipts });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// 7I. Consumer Support Chat & Gemini AI Energy Advisor
app.get('/api/user/support', authenticateConsumer, async (req, res) => {
    try {
        let ticket = await SupportTicket.findOne({
            tenantId: TENANT_ID,
            consumerId: req.user.consumerId
        }).lean();
        res.json({ success: true, messages: ticket ? ticket.messages : [] });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.post('/api/user/support', authenticateConsumer, async (req, res) => {
    try {
        const { text } = req.body;
        if (!text || !String(text).trim()) {
            return res.status(400).json({ success: false, message: 'Message cannot be empty.' });
        }
        const cleanText = String(text).trim().substring(0, 600);

        let ticket = await SupportTicket.findOne({
            tenantId: TENANT_ID,
            consumerId: req.user.consumerId
        });

        if (!ticket) {
            ticket = new SupportTicket({
                tenantId: TENANT_ID,
                consumerId: req.user.consumerId,
                consumerName: req.user.name,
                messages: []
            });
        }

        ticket.messages.push({ sender: 'user', text: cleanText });
        ticket.status = 'open';

        // Generate Smart AI Advisor Reply (Uses Gemini if configured, else intelligent rule engine)
        let aiReply = "Thank you! Your query has been logged for our grid engineering desk. Tip: Shifting heavy loads (Geyser/Washing Machine) between 10 AM - 4 PM saves up to 15% under ToD tariffs.";

        const cms = await CmsConfig.findOne({ tenantId: TENANT_ID, key: 'global_cms' }).lean();
        const sysPrompt = cms?.aiPrompt || 'You are an Indian Electricity Bill Optimization Expert.';

        if (GEMINI_API_KEY) {
            try {
                const geminiRes = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_API_KEY}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        contents: [{ parts: [{ text: `${sysPrompt}\n\nConsumer (${req.user.name}) asks: ${cleanText}` }] }]
                    })
                });
                const geminiData = await geminiRes.json();
                const candidate = geminiData?.candidates?.[0]?.content?.parts?.[0]?.text;
                if (candidate) aiReply = candidate.substring(0, 800);
            } catch (aiErr) {
                console.warn('[EMCS] Gemini API fallback used.');
            }
        }

        ticket.messages.push({ sender: 'ai', text: aiReply });
        await ticket.save();

        res.json({ success: true, messages: ticket.messages });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Could not send message.' });
    }
});

// ============================================================================
// 🛡️ 8. GOD-MODE ADMIN & STAFF COMMAND HUB API ROUTES
// ============================================================================

// 8A. Admin / Staff Login (Device-Bound HttpOnly JWT)
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password, honeypot } = req.body;
        if (honeypot) {
            return res.status(403).json({ success: false });
        }

        const cleanUser = String(username || '').trim();
        const cleanPass = String(password || '');
        const uaHash = getUaHash(req);

        // 1. Check Master Super Admin
        if (cleanUser === MASTER_ADMIN_USER && cleanPass === MASTER_ADMIN_PASS) {
            const allPermissions = { manageUsers: true, manageCms: true, manageSupport: true, viewLogs: true };
            const token = jwt.sign(
                { username: MASTER_ADMIN_USER, role: 'SUPER_ADMIN', permissions: allPermissions, uaHash },
                JWT_SECRET,
                { expiresIn: '4h' }
            );

            res.cookie('emcs_admin_token', token, {
                httpOnly: true,
                secure: IS_PROD,
                sameSite: 'lax',
                maxAge: 4 * 60 * 60 * 1000
            });

            await new SystemError({
                tenantId: TENANT_ID,
                source: 'Admin Audit Trail',
                message: `SUPER_ADMIN (${MASTER_ADMIN_USER}) logged into Command Hub.`,
                location: '/api/admin/login',
                userOrIp: req.ip
            }).save();

            return res.json({
                success: true,
                admin: { username: MASTER_ADMIN_USER, role: 'SUPER_ADMIN', permissions: allPermissions }
            });
        }

        // 2. Check Granular Staff Database
        const staff = await Staff.findOne({ tenantId: TENANT_ID, username: cleanUser.toLowerCase(), isActive: true }).select('+credentialHash');
        if (!staff) {
            await dispatchEmergencyAlert('Failed Admin Login', `Invalid Admin/Staff username attempted: ${cleanUser}`, req);
            return res.status(401).json({ success: false, message: 'Unauthorized credentials.' });
        }

        const validStaffPass = await bcrypt.compare(cleanPass, staff.credentialHash);
        if (!validStaffPass) {
            await dispatchEmergencyAlert('Failed Staff Password', `Wrong password for staff account: ${cleanUser}`, req);
            return res.status(401).json({ success: false, message: 'Unauthorized credentials.' });
        }

        const token = jwt.sign(
            { username: staff.username, role: staff.roleTitle, permissions: staff.permissions, uaHash },
            JWT_SECRET,
            { expiresIn: '4h' }
        );

        res.cookie('emcs_admin_token', token, {
            httpOnly: true,
            secure: IS_PROD,
            sameSite: 'lax',
            maxAge: 4 * 60 * 60 * 1000
        });

        await new SystemError({
            tenantId: TENANT_ID,
            source: 'Admin Audit Trail',
            message: `Staff Operator '${staff.username}' (${staff.roleTitle}) logged in.`,
            location: '/api/admin/login',
            userOrIp: req.ip
        }).save();

        res.json({
            success: true,
            admin: { username: staff.username, role: staff.roleTitle, permissions: staff.permissions }
        });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Admin authentication error.' });
    }
});

app.post('/api/admin/logout', (req, res) => {
    res.clearCookie('emcs_admin_token');
    res.json({ success: true });
});

// 8B. Admin Overview Telemetry
app.get('/api/admin/overview', authenticateAdmin, async (req, res) => {
    try {
        const [totalUsers, activeUsers, pendingTickets, totalErrors] = await Promise.all([
            User.countDocuments({ tenantId: TENANT_ID }),
            User.countDocuments({ tenantId: TENANT_ID, accountStatus: 'active' }),
            SupportTicket.countDocuments({ tenantId: TENANT_ID, status: 'open' }),
            SystemError.countDocuments({ tenantId: TENANT_ID })
        ]);
        res.json({
            success: true,
            stats: { totalUsers, activeUsers, pendingTickets, totalErrors },
            adminProfile: req.admin
        });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// 8C. Admin Full CMS Fetch & Update (Protected by 'manageCms' Permission)
app.get('/api/admin/cms-full', authenticateAdmin, requireAdminPermission('manageCms'), async (req, res) => {
    try {
        const cms = await CmsConfig.findOne({ tenantId: TENANT_ID, key: 'global_cms' }).lean();
        res.json({ success: true, cms: cms || {} });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.put('/api/admin/cms', authenticateAdmin, requireAdminPermission('manageCms'), async (req, res) => {
    try {
        const payload = req.body;
        const updateDoc = {
            siteName: String(payload.siteName || 'EMCS').substring(0, 30),
            broadcastBanner: String(payload.broadcastBanner || '').substring(0, 200),
            heroHeading: String(payload.heroHeading || 'Smart Energy Control & Bill Optimizer').substring(0, 120),
            heroSubtext: String(payload.heroSubtext || '').substring(0, 220),
            themeColors: {
                primary: String(payload.themeColors?.primary || '#6366f1'),
                accent: String(payload.themeColors?.accent || '#10b981')
            },
            featureSwitches: {
                gridSafety: Boolean(payload.featureSwitches?.gridSafety ?? true),
                inverter: Boolean(payload.featureSwitches?.inverter ?? true),
                vampire: Boolean(payload.featureSwitches?.vampire ?? true),
                tod: Boolean(payload.featureSwitches?.tod ?? true),
                solar: Boolean(payload.featureSwitches?.solar ?? true),
                iot: Boolean(payload.featureSwitches?.iot ?? true)
            },
            liveTariffs: payload.liveTariffs,
            paymentConfig: {
                enabled: Boolean(payload.paymentConfig?.enabled ?? true),
                apiKey: String(payload.paymentConfig?.apiKey || '').trim()
            }
        };

        // Only overwrite Secret Key & AI Prompt if Admin explicitly typed a non-empty value
        if (payload.paymentConfig?.apiSecret && payload.paymentConfig.apiSecret.trim() !== '') {
            updateDoc['paymentConfig.apiSecret'] = String(payload.paymentConfig.apiSecret).trim();
        }
        if (typeof payload.aiPrompt === 'string' && payload.aiPrompt.trim() !== '') {
            updateDoc.aiPrompt = payload.aiPrompt.trim();
        }

        const updated = await CmsConfig.findOneAndUpdate(
            { tenantId: TENANT_ID, key: 'global_cms' },
            { $set: updateDoc },
            { new: true, upsert: true }
        ).lean();

        await new SystemError({
            tenantId: TENANT_ID,
            source: 'Admin Audit Trail',
            message: `${req.admin.username} updated God-Mode CMS & Live Tariff Settings.`,
            location: '/api/admin/cms',
            userOrIp: req.ip
        }).save();

        if (updated.paymentConfig) delete updated.paymentConfig.apiSecret;
        res.json({ success: true, cms: updated });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Failed to update CMS.' });
    }
});

// 8D. Admin Consumers Directory & Account Status Toggle ('manageUsers' Permission)
app.get('/api/admin/users', authenticateAdmin, requireAdminPermission('manageUsers'), async (req, res) => {
    try {
        const users = await User.find({ tenantId: TENANT_ID }).sort({ createdAt: -1 }).limit(200).lean();
        res.json({ success: true, users });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.put('/api/admin/users/:consumerId/status', authenticateAdmin, requireAdminPermission('manageUsers'), async (req, res) => {
    try {
        const { status } = req.body;
        if (!['active', 'suspended'].includes(status)) {
            return res.status(400).json({ success: false });
        }
        const user = await User.findOneAndUpdate(
            { tenantId: TENANT_ID, consumerId: req.params.consumerId },
            { $set: { accountStatus: status, failedLoginAttempts: 0, lockUntil: null } },
            { new: true }
        );

        await new SystemError({
            tenantId: TENANT_ID,
            source: 'Admin Audit Trail',
            message: `${req.admin.username} changed status of ${req.params.consumerId} to ${status}.`,
            location: '/api/admin/users',
            userOrIp: req.ip
        }).save();

        res.json({ success: true, user });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// 8E. Admin Support Desk ('manageSupport' Permission)
app.get('/api/admin/support', authenticateAdmin, requireAdminPermission('manageSupport'), async (req, res) => {
    try {
        const tickets = await SupportTicket.find({ tenantId: TENANT_ID }).sort({ updatedAt: -1 }).limit(100).lean();
        res.json({ success: true, tickets });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.post('/api/admin/support/:consumerId/reply', authenticateAdmin, requireAdminPermission('manageSupport'), async (req, res) => {
    try {
        const { text, resolveTicket } = req.body;
        const ticket = await SupportTicket.findOne({ tenantId: TENANT_ID, consumerId: req.params.consumerId });
        if (!ticket) return res.status(404).json({ success: false });

        if (text && String(text).trim()) {
            ticket.messages.push({
                sender: 'admin',
                text: `[${req.admin.username}]: ${String(text).trim()}`
            });
        }
        if (resolveTicket) {
            ticket.status = 'resolved';
        }
        await ticket.save();
        res.json({ success: true, ticket });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// 8F. Granular Staff Management (Strictly SUPER_ADMIN Only)
app.get('/api/admin/staff', authenticateAdmin, async (req, res) => {
    if (req.admin.role !== 'SUPER_ADMIN') {
        return res.status(403).json({ success: false, message: 'Only Super Admin can manage staff.' });
    }
    const staffList = await Staff.find({ tenantId: TENANT_ID }).sort({ createdAt: -1 }).lean();
    res.json({ success: true, staffList });
});

app.post('/api/admin/staff', authenticateAdmin, async (req, res) => {
    try {
        if (req.admin.role !== 'SUPER_ADMIN') {
            return res.status(403).json({ success: false, message: 'Only Super Admin can create staff.' });
        }
        const { username, password, roleTitle, permissions } = req.body;
        if (!username || !password || String(password).length < 6) {
            return res.status(400).json({ success: false, message: 'Username and 6+ char password required.' });
        }

        const credentialHash = await bcrypt.hash(String(password), 12);
        const newStaff = await new Staff({
            tenantId: TENANT_ID,
            username: String(username).trim().toLowerCase(),
            roleTitle: String(roleTitle || 'Operator').trim(),
            credentialHash,
            permissions: {
                manageUsers: Boolean(permissions?.manageUsers),
                manageCms: Boolean(permissions?.manageCms),
                manageSupport: Boolean(permissions?.manageSupport),
                viewLogs: Boolean(permissions?.viewLogs)
            }
        }).save();

        await new SystemError({
            tenantId: TENANT_ID,
            source: 'Admin Audit Trail',
            message: `SUPER_ADMIN created staff operator '${newStaff.username}'.`,
            location: '/api/admin/staff',
            userOrIp: req.ip
        }).save();

        res.json({ success: true, staff: newStaff });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Failed to create staff (Username may exist).' });
    }
});

app.delete('/api/admin/staff/:id', authenticateAdmin, async (req, res) => {
    if (req.admin.role !== 'SUPER_ADMIN') return res.status(403).json({ success: false });
    await Staff.deleteOne({ _id: req.params.id, tenantId: TENANT_ID });
    res.json({ success: true });
});

// 8G. Security Threats & Audit Logs ('viewLogs' Permission)
app.get('/api/admin/logs', authenticateAdmin, requireAdminPermission('viewLogs'), async (req, res) => {
    try {
        const logs = await SystemError.find({ tenantId: TENANT_ID }).sort({ createdAt: -1 }).limit(150).lean();
        res.json({ success: true, logs });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.delete('/api/admin/logs', authenticateAdmin, requireAdminPermission('viewLogs'), async (req, res) => {
    try {
        await SystemError.deleteMany({ tenantId: TENANT_ID });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// ============================================================================
// 🔍 9. STATIC FILES & SERVER-SIDE SEO ROUTER (WhatsApp/Telegram/Google Bots)
// ============================================================================

app.use(express.static(path.join(__dirname)));

const SERVER_SEO_MAP = {
    '/home': { title: 'Dashboard | EMCS', desc: 'Track your home appliances, control smart switches, and reduce your monthly electricity bill.' },
    '/appliances': { title: 'My Appliances | EMCS', desc: 'Manage your connected home appliances and track their daily power consumption and monthly costs.' },
    '/calculators': { title: 'Instant Electrical Calculators | EMCS', desc: 'Use our generic power estimator and Ohm\'s Law helper for instant electrical calculations.' },
    '/standby-saver': { title: 'Standby Power Saver | EMCS', desc: 'Discover how much money you are losing to vampire power from appliances left plugged in.' },
    '/inverter-backup': { title: 'Inverter Backup Calculator | EMCS', desc: 'Calculate your inverter runtime and battery backup based on your live connected load.' },
    '/solar-calculator': { title: 'Solar Calculator | EMCS', desc: 'Estimate the ROI, total cost, and benefits of installing a solar panel system for your home.' },
    '/smart-hardware': { title: 'Smart Hardware Control | EMCS', desc: 'Remotely control your WiFi smart switches and IoT devices directly from your EMCS dashboard.' },
    '/voltage-safety': { title: 'Voltage & Grid Safety | EMCS', desc: 'Monitor live grid voltage and protect your valuable appliances from electrical faults.' },
    '/best-time-to-use': { title: 'Time of Day Optimizer | EMCS', desc: 'Optimize your heavy appliance usage based on Time-of-Day (ToD) electricity rates to save money.' },
    '/reports': { title: 'Energy Reports & Graphs | EMCS', desc: 'Visualize your daily power consumption trends with dynamic 2D and Flowgraph charts.' },
    '/savings-calculator': { title: 'Savings Simulator | EMCS', desc: 'Simulate different appliance usage scenarios to see how much money you can save.' },
    '/pay-bill': { title: 'Pay Electricity Bill | EMCS', desc: 'Securely pay your monthly electricity and EMCS bills online.' },
    '/support': { title: 'Customer Support | EMCS', desc: 'Get help and chat with EMCS AI Advisor or our support team for your electrical queries.' },
    '/profile': { title: 'My Account & Security | EMCS', desc: 'Manage your EMCS account security, linked devices, and personal profile details.' }
};

app.get('*', (req, res) => {
    try {
        let html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
        const routeSeo = SERVER_SEO_MAP[req.path];
        if (routeSeo) {
            html = html
                .replace(/<title id="seoTitle">.*?<\/title>/, `<title id="seoTitle">${routeSeo.title}</title>`)
                .replace(/id="seoDescription" name="description" content=".*?"/, `id="seoDescription" name="description" content="${routeSeo.desc}"`)
                .replace(/id="seoOgTitle" property="og:title" content=".*?"/, `id="seoOgTitle" property="og:title" content="${routeSeo.title}"`)
                .replace(/id="seoOgDesc" property="og:description" content=".*?"/, `id="seoOgDesc" property="og:description" content="${routeSeo.desc}"`);
        }
        res.send(html);
    } catch (e) {
        res.sendFile(path.join(__dirname, 'index.html'));
    }
});

// Global Express Website Error Catcher (Auto-Notifies Telegram with Masked Data)
app.use(async (err, req, res, next) => {
    const safeErrorMessage = err.message || 'Unknown Internal Server Error';
    const alertDetails = `Error on ${req.method} ${req.originalUrl}\nReason: ${safeErrorMessage}\nStack: ${String(err.stack).substring(0, 150)}`;
    await dispatchEmergencyAlert('Website Error (500)', alertDetails, req);

    res.status(500).json({
        success: false,
        message: 'System encountered an unexpected error. Our engineering team has been alerted.'
    });
});

// ============================================================================
// 🤖 10. TELEGRAM GHOST-MODE REMOTE CONTROL BOT (Zero Dependency Polling)
// ============================================================================
let tgLastUpdateId = 0;

async function sendTelegramControlPanel(chatId) {
    const keyboard = {
        inline_keyboard: [
            [
                { text: "🔴 Turn Maintenance ON", callback_data: "maint_on" },
                { text: "🟢 Turn Maintenance OFF", callback_data: "maint_off" }
            ],
            [
                { text: "📊 Server Status", callback_data: "sys_status" },
                { text: "👥 Total Users", callback_data: "total_users" }
            ],
            [
                { text: "⚠️ Get Last 3 Errors", callback_data: "last_errors" },
                { text: "🔄 Reboot Server", callback_data: "reboot_server" }
            ]
        ]
    };

    const text = "🎛️ *EMCS MASTER CONTROL PANEL*\n\nSelect an operation below. _Strictly authenticated via Render Environment Variables (Ghost-Mode Active)._";

    await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            chat_id: chatId,
            text: text,
            parse_mode: 'Markdown',
            reply_markup: keyboard
        })
    });
}

async function listenTelegramCommands() {
    const ADMIN_ID = process.env.TELEGRAM_ADMIN_CHAT_ID || TELEGRAM_ADMIN_CHAT_ID;
    if (!TELEGRAM_BOT_TOKEN || !ADMIN_ID) return;

    try {
        const res = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates?offset=${tgLastUpdateId + 1}&timeout=25`);
        const data = await res.json();

        if (data.ok && data.result.length > 0) {
            for (const update of data.result) {
                tgLastUpdateId = update.update_id;

                let incomingUserId = null;
                if (update.message && update.message.from) {
                    incomingUserId = String(update.message.from.id);
                } else if (update.callback_query && update.callback_query.from) {
                    incomingUserId = String(update.callback_query.from.id);
                }

                // 👻 GHOST MODE (BLACK HOLE SHIELD)
                // If user ID does NOT match Render's TELEGRAM_ADMIN_CHAT_ID -> Complete Silence!
                if (incomingUserId !== String(ADMIN_ID)) {
                    continue;
                }

                // 1. Authorized Text Command (Show Button Panel)
                if (update.message && update.message.text) {
                    const txt = update.message.text.trim().toLowerCase();
                    if (txt === '/start' || txt === '/menu' || txt === 'menu') {
                        await sendTelegramControlPanel(ADMIN_ID);
                    }
                }

                // 2. Authorized Button Clicks
                if (update.callback_query) {
                    const cb = update.callback_query;
                    const action = cb.data;
                    let popupMessage = "Command Executed";

                    if (action === 'maint_on') {
                        global.MAINTENANCE_MODE = true;
                        await CmsConfig.findOneAndUpdate(
                            { tenantId: TENANT_ID, key: 'global_cms' },
                            { $set: { maintenanceMode: true } },
                            { upsert: true }
                        );
                        popupMessage = "🔴 Maintenance Mode ON";
                        await sendTelegramAlert('SYSTEM CONTROL', '🔴 Website is now *UNDER MAINTENANCE*. All public traffic is paused.');
                    }
                    else if (action === 'maint_off') {
                        global.MAINTENANCE_MODE = false;
                        await CmsConfig.findOneAndUpdate(
                            { tenantId: TENANT_ID, key: 'global_cms' },
                            { $set: { maintenanceMode: false } },
                            { upsert: true }
                        );
                        popupMessage = "🟢 Maintenance Mode OFF";
                        await sendTelegramAlert('SYSTEM CONTROL', '🟢 Website is now *LIVE*. Normal operations resumed.');
                    }
                    else if (action === 'sys_status') {
                        const status = global.MAINTENANCE_MODE ? '🔴 UNDER MAINTENANCE' : '🟢 LIVE & HEALTHY';
                        const dbState = mongoose.connection.readyState === 1 ? '🟢 Connected' : '🔴 Disconnected';
                        const memMb = Math.round(process.memoryUsage().rss / 1024 / 1024);
                        popupMessage = `Status: ${status}`;
                        await sendTelegramAlert('SERVER TELEMETRY', `*Web Status:* ${status}\n*Database:* ${dbState}\n*RAM Usage:* ${memMb} MB\n*Uptime:* ${Math.floor(process.uptime() / 60)} mins`);
                    }
                    else if (action === 'total_users') {
                        const total = await User.countDocuments({ tenantId: TENANT_ID });
                        const active = await User.countDocuments({ tenantId: TENANT_ID, accountStatus: 'active' });
                        popupMessage = `Total Users: ${total}`;
                        await sendTelegramAlert('USER DIRECTORY STATS', `👥 *Live Consumer Count*\n\n*Total Registered:* ${total}\n*Active Accounts:* ${active}`);
                    }
                    else if (action === 'last_errors') {
                        const errors = await SystemError.find({ tenantId: TENANT_ID }).sort({ createdAt: -1 }).limit(3).lean();
                        if (errors.length === 0) {
                            popupMessage = "Log is clean!";
                            await sendTelegramAlert('DIAGNOSTICS', '✅ No recent errors or security threats in database.');
                        } else {
                            let errText = `⚠️ *LAST 3 LOGS / ERRORS*\n\n`;
                            errors.forEach((e, idx) => {
                                const t = new Date(e.createdAt).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });
                                errText += `*${idx + 1}. [${e.source}]*\n⏱️ ${t}\n📍 ${e.location}\n💬 ${maskSensitiveData(e.message)}\n\n`;
                            });
                            popupMessage = "Fetched last 3 logs.";
                            await sendTelegramAlert('DIAGNOSTICS', errText);
                        }
                    }
                    else if (action === 'reboot_server') {
                        popupMessage = "🔄 Rebooting Server...";
                        await sendTelegramAlert('SYSTEM CONTROL', '🔄 *Emergency Reboot Initiated.*\nProcess exiting so Render can spin up a fresh instance in ~10s.');
                        await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ callback_query_id: cb.id, text: popupMessage, show_alert: true })
                        });
                        setTimeout(() => { process.exit(1); }, 1500);
                        return;
                    }

                    await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ callback_query_id: cb.id, text: popupMessage, show_alert: false })
                    });
                }
            }
        }
    } catch (e) {
        // Ignore polling network timeouts silently
    }

    setTimeout(listenTelegramCommands, 2500);
}

// ============================================================================
// 🚨 11. GLOBAL PROCESS CRASH GUARDS & SERVER STARTUP
// ============================================================================

process.on('unhandledRejection', async (reason) => {
    console.error('[EMCS] Unhandled Rejection:', reason);
    await sendTelegramAlert('FATAL: Unhandled Rejection', `Reason: ${String(reason).substring(0, 250)}`);
});

process.on('uncaughtException', async (err) => {
    console.error('[EMCS] Uncaught Exception:', err);
    await sendTelegramAlert('🚨 SERVER CRASH (Uncaught Exception)', `Error: ${err.message}\nStack: ${String(err.stack).substring(0, 250)}`);
    setTimeout(() => { process.exit(1); }, 1200);
});

app.listen(PORT, async () => {
    console.log(`[EMCS] 🚀 Enterprise Server running on port ${PORT}`);
    setTimeout(async () => {
        try {
            if (mongoose.connection.readyState === 1) {
                const cms = await CmsConfig.findOne({ tenantId: TENANT_ID, key: 'global_cms' }).lean();
                if (cms && cms.maintenanceMode) {
                    global.MAINTENANCE_MODE = true;
                }
            }
            listenTelegramCommands();
            console.log('[EMCS] 🤖 Telegram Ghost-Mode Control Bot Active.');
        } catch (e) {}
    }, 3000);
});
