const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const crypto = require('crypto');

let GoogleGenerativeAI = null;
try {
    ({ GoogleGenerativeAI } = require('@google/generative-ai'));
} catch (ignore) {
    // Fallback to native fetch if package is not installed
}

const app = express();
const PORT = process.env.PORT || 5000;
const IS_PROD = process.env.NODE_ENV === 'production';
const TENANT_ID = process.env.TENANT_ID || 'EMCS_PROD_SITE_01';

app.set('trust proxy', 1);
app.disable('x-powered-by');

// ===================================================================
// ENVIRONMENT VARIABLES (RENDER READY - ZERO SECRET LEAKAGE)
// ===================================================================
const MONGO_URI = process.env.MONGO_URI || (IS_PROD ? '' : 'mongodb://127.0.0.1:27017/emcs_project_db');
const MASTER_OWNER_KEY = process.env.MASTER_OWNER_KEY || '';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const JWT_SECRET = process.env.JWT_SECRET || (
    MASTER_OWNER_KEY
        ? crypto.createHash('sha256').update(MASTER_OWNER_KEY + '_emcs_vault_' + TENANT_ID).digest('hex')
        : crypto.randomBytes(32).toString('hex')
);

// 32-Byte AES-256 Key for encrypting stored logs
const LOG_CIPHER_KEY = crypto.createHash('sha256').update(JWT_SECRET + '_log_encryption_key').digest();

const genAI = (GoogleGenerativeAI && GEMINI_API_KEY) ? new GoogleGenerativeAI(GEMINI_API_KEY) : null;

app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

const allowedOrigins = [
    'http://localhost:3000',
    'http://localhost:5000',
    'http://127.0.0.1:5500',
    'http://localhost:5500',
    process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
    origin: (origin, cb) => {
        if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
        return cb(null, false);
    },
    credentials: true
}));

// Security Headers & Request Verification
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; connect-src 'self' http://192.168.* http://10.* http://172.* ws: wss:; img-src 'self' data: blob:;"
    );

    if (req.headers['via'] || req.headers['x-proxy-id'] || req.headers['forwarded']) {
        req.isSuspiciousProxy = true;
    }

    if (['POST', 'DELETE', 'PUT'].includes(req.method) && req.path.startsWith('/api/')) {
        if (req.headers['x-emcs-csrf'] !== 'emcs-verified-client') {
            return res.status(403).json({ success: false, message: 'Request could not be verified.' });
        }
    }
    next();
});

// ===================================================================
// AES-256-GCM LOG ENCRYPTION (NO SENSITIVE OR BACKEND DETAILS LEAKED)
// ===================================================================
function encryptLogText(plainText) {
    try {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', LOG_CIPHER_KEY, iv);
        let encrypted = cipher.update(String(plainText || ''), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const tag = cipher.getAuthTag().toString('hex');
        return `${iv.toString('hex')}:${tag}:${encrypted}`;
    } catch (e) {
        return '';
    }
}

// ===================================================================
// 🚀 BLOOM FILTER (O(1) Memory Bouncer Against Non-Existent DB Queries)
// ===================================================================
class BloomFilter {
    constructor(size = 262144, hashFunctions = 4) {
        this.size = size;
        this.hashFunctions = hashFunctions;
        this.bitArray = new Uint8Array(size);
    }
    hash(str, seed) {
        const key = `${TENANT_ID}:${String(str || '').toLowerCase().trim()}`;
        let h = 2166136261 ^ seed;
        for (let i = 0; i < key.length; i++) {
            h ^= key.charCodeAt(i);
            h = Math.imul(h, 16777619);
        }
        return Math.abs(h) % this.size;
    }
    add(str) {
        if (!str) return;
        for (let i = 0; i < this.hashFunctions; i++) {
            this.bitArray[this.hash(str, i + 1)] = 1;
        }
    }
    test(str) {
        if (!str) return false;
        for (let i = 0; i < this.hashFunctions; i++) {
            if (this.bitArray[this.hash(str, i + 1)] === 0) return false;
        }
        return true;
    }
}
const emcsBloom = new BloomFilter();

// ===================================================================
// INPUT VALIDATION & DISPOSABLE EMAIL BLOCKER
// ===================================================================
const sanitizeInput = (val, max = 150) => {
    if (typeof val === 'string' || typeof val === 'number') {
        return String(val).replace(/[\0$<>]/g, '').trim().slice(0, max);
    }
    return '';
};

const DISPOSABLE_EMAIL_DOMAINS = new Set([
    'mailinator.com', 'yopmail.com', '10minutemail.com', 'guerrillamail.com',
    'tempmail.com', 'temp-mail.org', 'dropmail.me', 'trashmail.com',
    'sharklasers.com', 'getnada.com', 'maildrop.cc', 'dispostable.com',
    'fakeinbox.com', 'throwawaymail.com', 'mohmal.com', 'emailondeck.com',
    'mailnesia.com', 'mintemail.com', 'mytemp.email', 'burnermail.io',
    'tempmailo.com', 'inboxkitten.com', 'mailcatch.com', 'crazymailing.com'
]);

function validateStrictEmail(rawEmail) {
    if (typeof rawEmail !== 'string') return { valid: false, message: 'Please enter a valid email address.' };
    const clean = rawEmail.trim().toLowerCase();
    if (clean.length < 6 || clean.length > 90) {
        return { valid: false, message: 'Please enter a valid email address.' };
    }
    if (/[\s\0$<>'"`;\\(){}[\]|!#$%^&*=+/?~]|\.\./.test(clean)) {
        return { valid: false, message: 'Please enter a valid email address.' };
    }
    const parts = clean.split('@');
    if (parts.length !== 2) return { valid: false, message: 'Please enter a valid email address.' };
    const [local, domain] = parts;
    if (!/^[a-z0-9]+([._-][a-z0-9]+)*$/.test(local) || local.length < 2 || local.length > 60) {
        return { valid: false, message: 'Please enter a valid email address.' };
    }
    if (!/^[a-z0-9]+(-[a-z0-9]+)*(\.[a-z0-9]+(-[a-z0-9]+)*)+$/.test(domain)) {
        return { valid: false, message: 'Please enter a valid email address.' };
    }
    const tld = domain.split('.').pop();
    if (!/^[a-z]{2,10}$/.test(tld) || DISPOSABLE_EMAIL_DOMAINS.has(domain)) {
        return { valid: false, message: 'Please use a standard personal or work email address.' };
    }
    return { valid: true, email: clean };
}

function validateSecurityCredential(authType, rawCred) {
    if (typeof rawCred !== 'string') return { valid: false, message: 'Please enter your PIN or Password.' };
    const cred = rawCred.trim();
    if (authType === 'pin') {
        if (!/^[0-9]{4,6}$/.test(cred)) return { valid: false, message: 'Invalid PIN format.' };
        return { valid: true, credential: cred, authType: 'pin' };
    } else if (authType === 'password') {
        if (cred.length < 8 || cred.length > 16 || /[\0]/.test(cred)) {
            return { valid: false, message: 'Invalid Password length.' };
        }
        return { valid: true, credential: cred, authType: 'password' };
    }
    return { valid: false, message: 'Invalid security method.' };
}

const ALLOWED_PROVIDERS = new Set([
    'bihar', 'up', 'maharashtra', 'delhi', 'karnataka', 'rajasthan',
    'wb', 'tn', 'gujarat', 'punjab', 'haryana', 'mp',
    'tata_delhi', 'bses_delhi', 'tata_mumbai', 'adani_mumbai',
    'cesc_kolkata', 'torrent', 'national', 'custom'
]);
const ALLOWED_CATEGORIES = new Set(['domestic', 'commercial']);
const ALLOWED_AREAS = new Set(['urban', 'rural']);
const ALLOWED_CONN_MODES = new Set(['manual', 'wifi', 'smartmeter', 'usb']);

function safeCompareStrings(a, b) {
    if (!a || !b) return false;
    const bufA = Buffer.from(String(a));
    const bufB = Buffer.from(String(b));
    if (bufA.length !== bufB.length) {
        crypto.timingSafeEqual(bufA, bufA);
        return false;
    }
    return crypto.timingSafeEqual(bufA, bufB);
}

// ===================================================================
// RATE LIMITING & IP BLOCKLIST IN RAM
// ===================================================================
const rateLimits = new Map();
const blockedBotIps = new Set();

setInterval(() => {
    const now = Date.now();
    for (const [k, v] of rateLimits.entries()) {
        if (now > v.resetAt) rateLimits.delete(k);
    }
}, 300000);

function createLimiter(maxReqs, windowMs, customMsg) {
    return (req, res, next) => {
        if (blockedBotIps.has(req.ip)) {
            return res.status(403).json({ success: false, message: 'Access permanently blocked due to suspicious activity.' });
        }
        const key = `${TENANT_ID}_${req.ip}_${req.baseUrl || req.path}`;
        const now = Date.now();
        let rec = rateLimits.get(key) || { count: 0, resetAt: now + windowMs };
        if (now > rec.resetAt) rec = { count: 0, resetAt: now + windowMs };

        const allowedMax = req.isSuspiciousProxy ? Math.max(1, Math.floor(maxReqs / 2)) : maxReqs;
        rec.count++;

        if (rateLimits.size > 5000 && !rateLimits.has(key)) rateLimits.clear();
        rateLimits.set(key, rec);

        if (rec.count > allowedMax) {
            return res.status(429).json({
                success: false,
                message: customMsg || 'Too many requests. Please wait a moment and try again.'
            });
        }
        next();
    };
}

app.use('/api', createLimiter(60, 60 * 1000));

// ===================================================================
// DATABASE SCHEMAS (MULTI-TENANT ISOLATION + AUTO-DELETE TTL)
// ===================================================================
const UserSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, required: true, index: true },
    mobile: { type: String, required: true, index: true },
    email: { type: String, required: true, lowercase: true, index: true },
    consumerId: { type: String, required: true, minlength: 12, maxlength: 12, index: true },
    name: { type: String, required: true },
    authType: { type: String, enum: ['pin', 'password'], default: 'pin' },
    credentialHash: { type: String, required: true },
    pinHash: { type: String, default: '' },
    termsAccepted: { type: Boolean, default: true },
    termsAcceptedAt: { type: Date, default: Date.now },
    failedLoginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date, default: null },
    activeSessions: [{
        sessionId: String,
        deviceInfo: String,
        ipAddress: String,
        createdAt: { type: Date, default: Date.now }
    }],
    appliances: { type: Array, default: [] },
    sanctionedLoadKw: { type: Number, default: 2.0 },
    budgetThreshold: { type: Number, default: 3000 },
    tariffProvider: { type: String, default: 'bihar' },
    tariffCategory: { type: String, default: 'domestic' },
    tariffArea: { type: String, default: 'urban' },
    customTariff: {
        fixedPerKw: { type: Number, default: 0 },
        fppcaPct: { type: Number, default: 0 },
        dutyPct: { type: Number, default: 0.05 },
        slabs: [{ limit: mongoose.Schema.Types.Mixed, rate: Number }]
    },
    accountStatus: { type: String, default: 'active', enum: ['active', 'blocked', 'deleted'] },
    aiStatus: { type: String, default: 'active', enum: ['active', 'blocked'] },
    aiSpamWarnings: { type: Number, default: 0 },
    deletionScheduledAt: { type: Date, default: null }
}, { timestamps: true });

UserSchema.index({ tenantId: 1, mobile: 1 }, { unique: true });
UserSchema.index({ tenantId: 1, email: 1 }, { unique: true });
UserSchema.index({ tenantId: 1, consumerId: 1 }, { unique: true });
UserSchema.index({ deletionScheduledAt: 1 }, { expireAfterSeconds: 63072000 }); // 2 Years Legal Retention

const StaffSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, required: true, index: true },
    username: { type: String, required: true },
    passwordHash: { type: String, required: true },
    name: { type: String, required: true },
    role: { type: String, default: 'staff', enum: ['staff'] },
    permissions: {
        canManageUsers: { type: Boolean, default: false },
        canChatSupport: { type: Boolean, default: true },
        canEditCMS: { type: Boolean, default: false },
        canDeleteChat: { type: Boolean, default: false }
    }
});
StaffSchema.index({ tenantId: 1, username: 1 }, { unique: true });

const SupportMessageSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, required: true, index: true },
    consumerId: { type: String, required: true, index: true },
    sender: { type: String, enum: ['user', 'admin'], required: true },
    text: { type: String, required: true, maxlength: 500 },
    timestamp: { type: Date, default: Date.now, expires: 2592000 } // 30 Days
});

// 🔥 AI CHAT HISTORY SCHEMA (Automatically deletes after 3 Months / 90 Days)
const AiChatSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, required: true, index: true },
    consumerId: { type: String, required: true, index: true },
    userName: { type: String, default: 'Consumer' },
    sender: { type: String, enum: ['user', 'ai'], required: true },
    text: { type: String, required: true, maxlength: 2500 },
    timestamp: { type: Date, default: Date.now, expires: 7776000 } // 90 Days (3 Months) TTL
});

// 🔥 EMERGENCY ALERTS SCHEMA (Captures Bot Honeypot & AI Spam DDoS Forensics)
const EmergencyAlertSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, required: true, index: true },
    timestamp: { type: Date, default: Date.now, expires: 7776000 },
    attackType: { type: String, required: true },
    ipAddress: { type: String, default: 'Unknown IP' },
    deviceInfo: { type: String, default: 'Unknown Device' },
    details: { type: String, required: true }
});

const CmsSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, required: true, index: true },
    key: { type: String, default: 'global_cms' },
    broadcast: { type: String, default: '' },
    about: {
        type: String,
        default: 'EMCS (Smart Energy Manager) helps households and businesses track electricity consumption, estimate monthly bills, and manage smart appliances.'
    },
    privacy: {
        type: String,
        default: '1. DATA COLLECTION & SECURITY (DPDP Act 2023): We collect your Mobile Number, Email Address, Consumer ID, and Name strictly for account access, recovery, and energy tracking. For security and fraud prevention, we log Device Models and IP Addresses during login.\n\n2. AI CHAT HISTORY: Questions asked to KamAbhi AI (EMCS AI) are stored for your convenience and quality safety review, and are automatically deleted after 3 months (90 days).\n\n3. ACCOUNT RETENTION: Upon account deactivation, all devices are logged out immediately and records are retained in a protected archive for 2 years before permanent deletion.'
    },
    terms: {
        type: String,
        default: '1. BILL ESTIMATES: All bills, solar calculations, and savings shown on EMCS are estimates based on standard tariff slabs. Always pay your official electricity board bill.\n\n2. HARDWARE & SMART SWITCH DISCLAIMER: Hardware testing has not been performed for third-party switches. Connecting any Wi-Fi switch, smart meter, or USB relay is strictly at your own risk and responsibility. Our team holds zero liability for any electrical or equipment damage.\n\n3. FAIR USE & ANTI-BOT POLICY: Automated scripts, bots, URL tampering, or spamming the AI assistant (10+ rapid requests) will result in an automatic permanent block.'
    },
    faqs: {
        type: Array,
        default: [
            { q: 'How can I reset my forgotten PIN or Password?', a: 'Open Login, click Forgot Access, and verify using either your Consumer ID or your Registered Email Address.' },
            { q: 'Who is KamAbhi AI (EMCS AI)?', a: 'KamAbhi AI is your dedicated electrical safety and energy-saving assistant available to logged-in users.' },
            { q: 'How long is my AI chat history saved?', a: 'Your AI chat history is saved for 3 months (90 days) and then automatically erased.' }
        ]
    }
});
CmsSchema.index({ tenantId: 1, key: 1 }, { unique: true });

// Encrypted Activity Logs (Only clean summary text is shown; raw details are AES-256 encrypted)
const SystemErrorSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, index: true },
    timestamp: { type: Date, default: Date.now, expires: 2592000 },
    source: { type: String, default: 'Application' },
    message: { type: String, default: 'Something went wrong, try again later.' },
    encryptedPayload: { type: String, default: '' },
    location: { type: String, default: 'General' },
    userOrIp: { type: String, default: 'Protected' }
});

const User = mongoose.model('User', UserSchema);
const Staff = mongoose.model('Staff', StaffSchema);
const SupportMessage = mongoose.model('SupportMessage', SupportMessageSchema);
const AiChat = mongoose.model('AiChat', AiChatSchema);
const EmergencyAlert = mongoose.model('EmergencyAlert', EmergencyAlertSchema);
const CmsConfig = mongoose.model('CmsConfig', CmsSchema);
const SystemError = mongoose.model('SystemError', SystemErrorSchema);

async function populateBloomFilter() {
    try {
        const users = await User.find({ tenantId: TENANT_ID }, 'mobile email consumerId');
        users.forEach(u => {
            if (u.mobile) emcsBloom.add(u.mobile);
            if (u.email) emcsBloom.add(u.email);
            if (u.consumerId) emcsBloom.add(u.consumerId);
        });
    } catch (ignore) {}
}

if (MONGO_URI) {
    mongoose.connect(MONGO_URI)
        .then(async () => {
            console.log(`[EMCS READY] Connected on Port ${PORT}`);
            await populateBloomFilter();
        })
        .catch(() => console.error('[EMCS NOTICE] Database connection unavailable.'));
}

// ===================================================================
// ENCRYPTED LOGGING & EMERGENCY FORENSICS HELPERS
// ===================================================================
async function logBackendError(section, rawErr, req = null) {
    try {
        const rawText = rawErr?.message || String(rawErr || 'Event');
        const encryptedPayload = encryptLogText(rawText);
        await new SystemError({
            tenantId: TENANT_ID,
            source: sanitizeInput(section || 'App Section', 40),
            message: 'Something went wrong, try again later.',
            encryptedPayload,
            location: 'Protected Section',
            userOrIp: sanitizeInput(req?.user?.consumerId || 'Visitor', 30)
        }).save();
    } catch (ignore) {}
}

async function triggerEmergencyAlert(attackType, details, req, clientTelemetry = {}) {
    try {
        const ip = sanitizeInput(req.ip || req.headers['x-forwarded-for'] || 'Unknown IP', 50);
        const ua = sanitizeInput(req.headers['user-agent'] || 'Unknown Browser', 120);
        const lang = sanitizeInput(req.headers['accept-language'] || '', 40);
        const screenInfo = sanitizeInput(clientTelemetry.screen || '', 30);
        const tzInfo = sanitizeInput(clientTelemetry.tz || '', 40);
        const platformInfo = sanitizeInput(clientTelemetry.platform || '', 40);

        const fullDevice = [ua, platformInfo, screenInfo, tzInfo, lang].filter(Boolean).join(' | ').slice(0, 220);

        await new EmergencyAlert({
            tenantId: TENANT_ID,
            attackType: sanitizeInput(attackType, 60),
            ipAddress: ip,
            deviceInfo: fullDevice || 'Unknown Device',
            details: sanitizeInput(details, 350)
        }).save();
    } catch (ignore) {}
}

// ===================================================================
// AUTHENTICATION & STRICT ANTI-IDOR MIDDLEWARES
// ===================================================================
async function authenticateUser(req, res, next) {
    const token = req.cookies.emcs_auth_token;
    if (!token) return res.status(401).json({ success: false, message: 'Please log in to continue.' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        if (decoded.tenantId && decoded.tenantId !== TENANT_ID) {
            res.clearCookie('emcs_auth_token');
            return res.status(403).json({ success: false, message: 'Session invalid.' });
        }

        const user = await User.findOne({ _id: decoded.userId, tenantId: TENANT_ID });
        if (!user || user.accountStatus !== 'active' || !user.activeSessions.some(s => s.sessionId === decoded.sessionId)) {
            res.clearCookie('emcs_auth_token');
            const msg = user?.accountStatus === 'blocked'
                ? 'Your account has been blocked by the administrator.'
                : 'Session expired. Please log in again.';
            return res.status(401).json({ success: false, message: msg });
        }

        req.user = user;
        req.sessionId = decoded.sessionId;
        next();
    } catch (e) {
        return res.status(403).json({ success: false, message: 'Please log in again.' });
    }
}

function strictAntiIdorShield(req, res, next) {
    if (!req.user) return res.status(401).json({ success: false, message: 'Unauthorized.' });

    const candidates = [
        req.params?.consumerId,
        req.params?.cid,
        req.query?.consumerId,
        req.query?.cid,
        req.body?.consumerId,
        req.body?.cid,
        req.headers['x-consumer-id']
    ].filter(v => v !== undefined && v !== null && String(v).trim() !== '');

    for (const candidate of candidates) {
        if (String(candidate).trim().toUpperCase() !== String(req.user.consumerId).toUpperCase()) {
            triggerEmergencyAlert(
                'Cross-Account Tampering (IDOR)',
                `User ${req.user.consumerId} attempted to access data of ${sanitizeInput(candidate, 20)}`,
                req
            );
            return res.status(403).json({
                success: false,
                message: 'Access denied: You can only view your own account.'
            });
        }
    }
    next();
}

async function authenticateAdmin(req, res, next) {
    const token = req.cookies.emcs_admin_token;
    if (!token) return res.status(401).json({ success: false, message: 'Admin login required.' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        if (decoded.tenantId && decoded.tenantId !== TENANT_ID) {
            res.clearCookie('emcs_admin_token');
            return res.status(403).json({ success: false });
        }
        req.admin = decoded;
        next();
    } catch (e) {
        return res.status(403).json({ success: false });
    }
}

function requireAdminPermission(permKey) {
    return (req, res, next) => {
        if (!req.admin) return res.status(401).json({ success: false });
        if (req.admin.role === 'owner') return next();
        if (permKey && req.admin.permissions && req.admin.permissions[permKey] === true) return next();
        return res.status(403).json({ success: false, message: 'Insufficient permissions.' });
    };
}

// ===================================================================
// INVISIBLE HONEYPOT BOT TRAP MIDDLEWARE (BLOCKS BOTS ON LOGIN/REGISTER)
// ===================================================================
async function verifyNotABot(req, res, next) {
    const trapVal = req.body._emcs_trap || req.body._bot_honeypot;
    if (trapVal && String(trapVal).trim().length > 0) {
        blockedBotIps.add(req.ip);
        const attemptedId = sanitizeInput(req.body.mobile || req.body.consumerId || 'Unknown', 30);
        await triggerEmergencyAlert(
            'Automated Bot Trap Triggered',
            `Hidden form field filled during ${req.path.includes('register') ? 'Registration' : 'Login'}. Target: ${attemptedId} | Trap Value: "${sanitizeInput(trapVal, 40)}"`,
            req,
            req.body._clientMeta || {}
        );
        return res.status(403).json({
            success: false,
            message: 'Automated bot activity detected. Your access has been blocked.'
        });
    }
    next();
}

// ===================================================================
// HEALTH & PROTECTED LOGS ROUTES
// ===================================================================
app.get('/api/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
});

app.post('/api/errors/report', createLimiter(15, 60000), async (req, res) => {
    try {
        await logBackendError('Client Activity', 'Something went wrong, try again later.', req);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.get('/api/admin/errors', authenticateAdmin, async (req, res) => {
    try {
        const rawLogs = await SystemError.find({ tenantId: TENANT_ID }).sort({ timestamp: -1 }).limit(100);
        // Always return sanitized, non-technical display text
        const errors = rawLogs.map(l => ({
            timestamp: l.timestamp,
            source: 'App Notice',
            message: 'Something went wrong, try again later.',
            location: 'Protected',
            userOrIp: l.userOrIp || 'User'
        }));
        res.json({ success: true, errors });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.delete('/api/admin/errors/clear', authenticateAdmin, async (req, res) => {
    try {
        if (req.admin.role !== 'owner') return res.status(403).json({ success: false });
        await SystemError.deleteMany({ tenantId: TENANT_ID });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.get('/api/admin/emergency-alerts', authenticateAdmin, async (req, res) => {
    try {
        const alerts = await EmergencyAlert.find({ tenantId: TENANT_ID }).sort({ timestamp: -1 }).limit(100);
        res.json({ success: true, alerts });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.delete('/api/admin/emergency-alerts/clear', authenticateAdmin, async (req, res) => {
    try {
        if (req.admin.role !== 'owner') return res.status(403).json({ success: false });
        await EmergencyAlert.deleteMany({ tenantId: TENANT_ID });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// ===================================================================
// USER REGISTRATION, LOGIN & RECOVERY ROUTES
// ===================================================================
app.post('/api/auth/register', createLimiter(3, 86400000), verifyNotABot, async (req, res) => {
    try {
        if (req.body.termsAccepted !== true) {
            return res.status(400).json({ success: false, message: 'Please accept the Privacy Policy and Terms & Conditions.' });
        }

        const mobile = sanitizeInput(req.body.mobile, 10);
        const consumerId = sanitizeInput(req.body.consumerId, 12).toUpperCase();
        const name = sanitizeInput(req.body.name, 60);
        const emailValidation = validateStrictEmail(req.body.email);

        if (!emailValidation.valid) {
            return res.status(400).json({ success: false, message: emailValidation.message });
        }

        const authTypeInput = req.body.authType === 'password' ? 'password' : 'pin';
        const credValidation = validateSecurityCredential(authTypeInput, String(req.body.credential || ''));
        if (!credValidation.valid) {
            return res.status(400).json({ success: false, message: credValidation.message });
        }

        if (!/^[0-9]{10}$/.test(mobile) || !/^[A-Z0-9]{12}$/.test(consumerId) || name.length < 2) {
            return res.status(400).json({ success: false, message: 'Please enter valid Name, 10-digit Mobile, and 12-character Consumer ID.' });
        }

        const email = emailValidation.email;
        if (emcsBloom.test(mobile) || emcsBloom.test(consumerId) || emcsBloom.test(email)) {
            const existing = await User.findOne({
                tenantId: TENANT_ID,
                $or: [{ mobile }, { consumerId }, { email }]
            });
            if (existing) {
                return res.status(400).json({ success: false, message: 'Mobile, Email, or Consumer ID is already registered.' });
            }
        }

        const credentialHash = await bcrypt.hash(credValidation.credential, 12);
        await new User({
            tenantId: TENANT_ID,
            mobile,
            email,
            consumerId,
            name,
            authType: credValidation.authType,
            credentialHash,
            termsAccepted: true,
            termsAcceptedAt: new Date()
        }).save();

        emcsBloom.add(mobile);
        emcsBloom.add(email);
        emcsBloom.add(consumerId);

        res.json({ success: true, message: 'Account created successfully!' });
    } catch (e) {
        await logBackendError('Registration', e, req);
        res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
    }
});

app.post('/api/auth/login', createLimiter(5, 900000), verifyNotABot, async (req, res) => {
    try {
        const mobile = sanitizeInput(req.body.mobile, 10);
        const rawCred = String(req.body.credential || '').trim();

        if (!/^[0-9]{10}$/.test(mobile) || rawCred.length < 4 || rawCred.length > 16) {
            return res.status(400).json({ success: false, message: 'Invalid mobile number or PIN/Password.' });
        }

        // Bloom Filter Memory Check (Prevents Phantom DB DoS)
        if (!emcsBloom.test(mobile)) {
            await new Promise(r => setTimeout(r, 90));
            return res.status(401).json({ success: false, message: 'Invalid mobile number or PIN/Password.' });
        }

        const user = await User.findOne({ tenantId: TENANT_ID, mobile });
        if (!user) return res.status(401).json({ success: false, message: 'Invalid mobile number or PIN/Password.' });

        if (user.accountStatus === 'blocked') {
            return res.status(403).json({ success: false, message: 'Your account has been blocked by the administrator.' });
        }
        if (user.accountStatus === 'deleted') {
            return res.status(403).json({ success: false, message: 'This account has been deactivated.' });
        }

        if (user.lockUntil && user.lockUntil > Date.now()) {
            const mins = Math.ceil((user.lockUntil - Date.now()) / 60000);
            return res.status(429).json({
                success: false,
                message: `Account locked due to multiple wrong attempts. Try again in ${mins} minutes.`
            });
        }

        const activeHash = user.credentialHash || user.pinHash;
        const isMatch = await bcrypt.compare(rawCred, activeHash);
        if (!isMatch) {
            const updated = await User.findOneAndUpdate(
                { _id: user._id, tenantId: TENANT_ID },
                { $inc: { failedLoginAttempts: 1 } },
                { new: true }
            );
            if (updated.failedLoginAttempts >= 5) {
                await User.updateOne(
                    { _id: user._id, tenantId: TENANT_ID },
                    { $set: { lockUntil: new Date(Date.now() + 15 * 60000), failedLoginAttempts: 0 } }
                );
            }
            return res.status(401).json({ success: false, message: 'Invalid mobile number or PIN/Password.' });
        }

        await User.updateOne(
            { _id: user._id, tenantId: TENANT_ID },
            { $set: { failedLoginAttempts: 0, lockUntil: null } }
        );

        const sessionId = crypto.randomBytes(24).toString('hex');
        user.activeSessions.push({
            sessionId,
            deviceInfo: sanitizeInput(req.headers['user-agent'], 90) || 'Web Browser',
            ipAddress: sanitizeInput(req.ip, 45)
        });
        if (user.activeSessions.length > 15) user.activeSessions = user.activeSessions.slice(-15);
        await user.save();

        const token = jwt.sign(
            { userId: user._id, consumerId: user.consumerId, tenantId: TENANT_ID, sessionId },
            JWT_SECRET,
            { expiresIn: '7d', algorithm: 'HS256' }
        );

        res.cookie('emcs_auth_token', token, {
            httpOnly: true,
            secure: IS_PROD,
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.json({
            success: true,
            user: {
                name: user.name,
                mobile: user.mobile,
                email: user.email,
                consumerId: user.consumerId,
                appliances: user.appliances,
                sanctionedLoadKw: user.sanctionedLoadKw,
                budgetThreshold: user.budgetThreshold,
                tariffProvider: user.tariffProvider,
                tariffCategory: user.tariffCategory,
                tariffArea: user.tariffArea,
                customTariff: user.customTariff
            }
        });
    } catch (e) {
        await logBackendError('Login', e, req);
        res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
    }
});

app.post('/api/auth/logout', authenticateUser, async (req, res) => {
    try {
        req.user.activeSessions = req.user.activeSessions.filter(s => s.sessionId !== req.sessionId);
        await req.user.save();
        res.clearCookie('emcs_auth_token');
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.post('/api/auth/verify-and-reset', createLimiter(5, 900000), async (req, res) => {
    try {
        const mobile = sanitizeInput(req.body.mobile, 10);
        const registeredName = sanitizeInput(req.body.registeredName, 60).toLowerCase();
        const recoveryType = req.body.recoveryType === 'email' ? 'email' : 'cid';
        const rawRecoveryVal = req.body.recoveryValue;

        const newAuthType = req.body.newAuthType === 'password' ? 'password' : 'pin';
        const credCheck = validateSecurityCredential(newAuthType, String(req.body.newCredential || ''));

        if (!/^[0-9]{10}$/.test(mobile) || registeredName.length < 2 || !credCheck.valid) {
            return res.status(400).json({ success: false, message: 'Please enter valid details.' });
        }

        if (!emcsBloom.test(mobile)) {
            await new Promise(r => setTimeout(r, 90));
            return res.status(400).json({ success: false, message: 'Details do not match our records.' });
        }

        const query = { tenantId: TENANT_ID, mobile, accountStatus: 'active' };
        if (recoveryType === 'email') {
            const emailCheck = validateStrictEmail(rawRecoveryVal);
            if (!emailCheck.valid || !emcsBloom.test(emailCheck.email)) {
                return res.status(400).json({ success: false, message: 'Details do not match our records.' });
            }
            query.email = emailCheck.email;
        } else {
            const cid = sanitizeInput(rawRecoveryVal, 12).toUpperCase();
            if (!/^[A-Z0-9]{12}$/.test(cid) || !emcsBloom.test(cid)) {
                return res.status(400).json({ success: false, message: 'Details do not match our records.' });
            }
            query.consumerId = cid;
        }

        const user = await User.findOne(query);
        if (!user || user.name.toLowerCase() !== registeredName) {
            return res.status(400).json({ success: false, message: 'Details do not match our records.' });
        }

        user.authType = credCheck.authType;
        user.credentialHash = await bcrypt.hash(credCheck.credential, 12);
        user.failedLoginAttempts = 0;
        user.lockUntil = null;
        user.activeSessions = [];
        await user.save();

        res.json({ success: true, message: 'Successfully updated! Please log in.' });
    } catch (e) {
        await logBackendError('Account Recovery', e, req);
        res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
    }
});

app.get('/api/auth/devices', authenticateUser, strictAntiIdorShield, (req, res) => {
    const FORTY_EIGHT_HRS = 48 * 3600 * 1000;
    const sessions = req.user.activeSessions.map(s => {
        const age = Date.now() - new Date(s.createdAt).getTime();
        const isCurrent = s.sessionId === req.sessionId;
        return {
            sessionId: s.sessionId,
            deviceInfo: s.deviceInfo,
            createdAt: s.createdAt,
            isCurrent,
            canRevoke: !isCurrent && age >= FORTY_EIGHT_HRS,
            hoursRemaining: !isCurrent && age < FORTY_EIGHT_HRS ? Math.ceil((FORTY_EIGHT_HRS - age) / 3600000) : 0
        };
    });
    res.json({ success: true, sessions });
});

app.post('/api/auth/revoke-device', authenticateUser, strictAntiIdorShield, async (req, res) => {
    try {
        const targetId = sanitizeInput(req.body.targetSessionId, 64);
        const target = req.user.activeSessions.find(s => s.sessionId === targetId);
        if (!target || targetId === req.sessionId) {
            return res.status(400).json({ success: false, message: 'Invalid device selection.' });
        }
        if (Date.now() - new Date(target.createdAt).getTime() < 48 * 3600 * 1000) {
            return res.status(403).json({ success: false, message: 'Other devices can be removed 48 hours after login.' });
        }
        req.user.activeSessions = req.user.activeSessions.filter(s => s.sessionId !== targetId);
        await req.user.save();
        res.json({ success: true, message: 'Device logged out.' });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
    }
});

// ===================================================================
// USER DATA SYNC & ACCOUNT DELETION
// ===================================================================
app.use('/api/user', authenticateUser, strictAntiIdorShield);

app.get('/api/user/get-cloud-data', (req, res) => {
    res.json({
        success: true,
        data: {
            name: req.user.name,
            email: req.user.email,
            consumerId: req.user.consumerId,
            appliances: req.user.appliances,
            sanctionedLoadKw: req.user.sanctionedLoadKw,
            budgetThreshold: req.user.budgetThreshold,
            tariffProvider: req.user.tariffProvider,
            tariffCategory: req.user.tariffCategory,
            tariffArea: req.user.tariffArea,
            customTariff: req.user.customTariff
        }
    });
});

app.all('/api/user/:anyRoute/:consumerId', (req, res) => {
    res.status(403).json({ success: false, message: 'Direct URL access is blocked.' });
});

app.post('/api/user/sync-cloud', async (req, res) => {
    try {
        const { name, appliances, sanctionedLoadKw, budgetThreshold, tariffProvider, tariffCategory, tariffArea, customTariff } = req.body;

        if (name !== undefined) {
            const cleanName = sanitizeInput(name, 60);
            if (cleanName.length >= 2) req.user.name = cleanName;
        }

        if (Array.isArray(appliances)) {
            req.user.appliances = appliances.slice(0, 50).map(a => {
                const pwr = Math.min(50000, Math.max(1, Number(a.power) || 10));
                const hrs = Math.min(24, Math.max(0.1, Number(a.hours) || 1));
                const connMode = ALLOWED_CONN_MODES.has(a.connMode) ? a.connMode : 'manual';
                return {
                    id: Number(a.id) || Date.now(),
                    name: sanitizeInput(a.name, 40) || 'Appliance',
                    power: pwr,
                    hours: hrs,
                    monthlyKwh: Number(((pwr * hrs * 30) / 1000).toFixed(2)),
                    connMode,
                    state: Boolean(a.state)
                };
            });
        }

        if (sanctionedLoadKw !== undefined) req.user.sanctionedLoadKw = Math.min(50, Math.max(0.5, Number(sanctionedLoadKw) || 2.0));
        if (budgetThreshold !== undefined) req.user.budgetThreshold = Math.min(1000000, Math.max(100, Number(budgetThreshold) || 3000));
        if (tariffProvider && ALLOWED_PROVIDERS.has(tariffProvider)) req.user.tariffProvider = tariffProvider;
        if (tariffCategory && ALLOWED_CATEGORIES.has(tariffCategory)) req.user.tariffCategory = tariffCategory;
        if (tariffArea && ALLOWED_AREAS.has(tariffArea)) req.user.tariffArea = tariffArea;

        if (customTariff && typeof customTariff === 'object') {
            req.user.customTariff = {
                fixedPerKw: Math.min(5000, Math.max(0, Number(customTariff.fixedPerKw) || 0)),
                fppcaPct: Math.min(1.0, Math.max(0, Number(customTariff.fppcaPct) || 0)),
                dutyPct: Math.min(1.0, Math.max(0, Number(customTariff.dutyPct) || 0)),
                slabs: Array.isArray(customTariff.slabs) ? customTariff.slabs.slice(0, 5).map(s => ({
                    limit: s.limit === 'Infinity' || s.limit === Infinity || s.limit === null ? Infinity : Math.max(1, Number(s.limit) || 100),
                    rate: Math.min(100, Math.max(0, Number(s.rate) || 0))
                })) : []
            };
        }

        await req.user.save();
        res.json({ success: true });
    } catch (e) {
        await logBackendError('Cloud Sync', e, req);
        res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
    }
});

app.delete('/api/user/delete-account', async (req, res) => {
    try {
        req.user.accountStatus = 'deleted';
        req.user.deletionScheduledAt = new Date();
        req.user.activeSessions = [];
        await req.user.save();
        res.clearCookie('emcs_auth_token');
        res.json({ success: true, message: 'Account deactivated.' });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
    }
});

// ===================================================================
// 🔥 KAMABHI AI (EMCS AI) - STRICT IDENTITY, CONCURRENCY & 10s/10-REQ BLOCKER
// ===================================================================
const aiRamTimestamps = new Map(); // RAM Timestamp Tracker: cid -> [ts1, ts2, ...]
const aiActiveQuestionLocks = new Set(); // RAM Single-Question Concurrency Lock

// Scrub any accidental mention of third-party AI model names
function enforceKamAbhiPersona(text) {
    return String(text || '')
        .replace(/\b(gemini|google\s+ai|google\s+deepmind|bard|chatgpt|openai)\b/gi, 'KamAbhi AI (EMCS AI)');
}

async function generateKamAbhiAiResponse(systemPrompt) {
    if (genAI) {
        const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
        const result = await model.generateContent(systemPrompt);
        return enforceKamAbhiPersona(result.response.text());
    }
    if (GEMINI_API_KEY && typeof fetch === 'function') {
        const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_API_KEY}`;
        const resp = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ contents: [{ parts: [{ text: systemPrompt }] }] })
        });
        const json = await resp.json();
        const raw = json?.candidates?.[0]?.content?.parts?.[0]?.text || '';
        if (raw) return enforceKamAbhiPersona(raw);
    }
    return 'Namaste! I am KamAbhi AI (EMCS AI). For your electrical safety and lower monthly bills: keep AC at 24°C, switch off water geysers after 20 minutes, unplug idle chargers, and always turn off the main miniature circuit breaker (MCB) before touching any switchboard or smart relay.';
}

app.get('/api/ai/history', authenticateUser, strictAntiIdorShield, async (req, res) => {
    try {
        const messages = await AiChat.find({
            tenantId: TENANT_ID,
            consumerId: req.user.consumerId
        }).sort({ timestamp: 1 }).limit(80);
        res.json({ success: true, messages });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
    }
});

app.post('/api/ai/chat', authenticateUser, strictAntiIdorShield, async (req, res) => {
    const cid = req.user.consumerId;

    if (req.user.aiStatus === 'blocked') {
        return res.status(403).json({
            success: false,
            reply: 'Your AI access has been permanently blocked due to repeated spam violations.'
        });
    }

    // 🛡️ 1. RAM TIMESTAMP ANTI-SPAM (10 Questions in 10 Seconds -> Permanent Block)
    const now = Date.now();
    let timestamps = aiRamTimestamps.get(cid) || [];
    timestamps = timestamps.filter(ts => now - ts <= 10000); // Exact 10-second sliding window in RAM
    timestamps.push(now);
    aiRamTimestamps.set(cid, timestamps);

    // Direct permanent block on 10+ requests within 10 seconds
    if (timestamps.length >= 10) {
        req.user.aiStatus = 'blocked';
        await req.user.save();
        await triggerEmergencyAlert(
            'AI Spam Flood (10 Req / 10 Sec)',
            `Consumer ${cid} (${req.user.name}) sent ${timestamps.length} AI questions within 10 seconds. AI access permanently blocked.`,
            req
        );
        return res.status(403).json({
            success: false,
            reply: 'Permanent Block: You sent 10+ questions within 10 seconds. Your AI access has been permanently disabled.'
        });
    }

    // 2 Warnings before permanent block for rapid fire bursts (e.g. 4+ messages within 10s)
    if (timestamps.length >= 4) {
        req.user.aiSpamWarnings = (req.user.aiSpamWarnings || 0) + 1;
        if (req.user.aiSpamWarnings > 2) {
            req.user.aiStatus = 'blocked';
            await req.user.save();
            await triggerEmergencyAlert(
                'AI Spam Warnings Exceeded',
                `Consumer ${cid} (${req.user.name}) ignored 2 spam warnings and was permanently blocked from AI.`,
                req
            );
            return res.status(403).json({
                success: false,
                reply: 'Permanent Block: You exceeded the 2 spam warnings. Your AI access has been permanently disabled.'
            });
        }
        await req.user.save();
        return res.status(429).json({
            success: false,
            reply: `Warning (${req.user.aiSpamWarnings}/2): Please do not send questions too fast! After 2 warnings, your AI access will be permanently blocked.`
        });
    }

    // 🛡️ 2. SINGLE QUESTION CONCURRENCY LOCK
    if (aiActiveQuestionLocks.has(cid)) {
        return res.status(429).json({
            success: false,
            isBusy: true,
            reply: 'Wait kro pichle question ka answer likh rhe hai. Uske baad dusra question bhejo.'
        });
    }

    const userText = sanitizeInput(req.body.text, 500);
    if (!userText) return res.status(400).json({ success: false });

    aiActiveQuestionLocks.add(cid);
    try {
        await new AiChat({
            tenantId: TENANT_ID,
            consumerId: cid,
            userName: req.user.name,
            sender: 'user',
            text: userText
        }).save();

        const recentChats = await AiChat.find({ tenantId: TENANT_ID, consumerId: cid }).sort({ timestamp: -1 }).limit(6);
        const context = recentChats.reverse().map(c => `${c.sender === 'user' ? 'User' : 'KamAbhi AI'}: ${c.text}`).join('\n');

        const systemPrompt = `STRICT IDENTITY & ROLE COMMAND:
You are strictly "KamAbhi AI" (also called "EMCS AI"), the official electrical and energy-saving assistant of EMCS.
1. NEVER mention Gemini, Google, OpenAI, ChatGPT, or any other AI company or model name under any circumstance. If asked who you are or who made you, always state: "I am KamAbhi AI (EMCS AI), your electrical and energy management assistant."
2. Only answer questions related to electricity bills, home appliances, energy saving, inverters, solar panels, smart meters, Wi-Fi switches, and electrical safety. If a user asks an unrelated topic, politely guide them back to electrical and energy topics.
3. Always provide practical advice along with clear electrical safety instructions (e.g., turning off main power before touching wires, using proper earthing/MCB, avoiding wet hands).
4. Keep your tone friendly, simple, human-like, and easy to understand.

Recent Conversation:
${context}

Provide KamAbhi AI's response to the latest question:`;

        const aiReply = sanitizeInput(await generateKamAbhiAiResponse(systemPrompt), 2200);

        await new AiChat({
            tenantId: TENANT_ID,
            consumerId: cid,
            userName: req.user.name,
            sender: 'ai',
            text: aiReply
        }).save();

        res.json({ success: true, reply: aiReply });
    } catch (e) {
        await logBackendError('AI Assistant', e, req);
        res.status(500).json({ success: false, reply: 'Something went wrong, try again later.' });
    } finally {
        aiActiveQuestionLocks.delete(cid);
    }
});

// ===================================================================
// ADMIN MANAGEMENT, USER BLOCK/DELETE, AI HISTORY & CMS ROUTES
// ===================================================================
app.post('/api/admin/login', createLimiter(5, 900000), async (req, res) => {
    try {
        const username = sanitizeInput(req.body.username, 40).toLowerCase();
        const password = sanitizeInput(req.body.password, 64);

        if (!username) {
            if (!MASTER_OWNER_KEY) {
                return res.status(503).json({ success: false, message: 'Admin key is not configured.' });
            }
            if (safeCompareStrings(password, MASTER_OWNER_KEY)) {
                const perms = { canManageUsers: true, canChatSupport: true, canEditCMS: true, canDeleteChat: true };
                const token = jwt.sign(
                    { role: 'owner', name: 'Master Owner', tenantId: TENANT_ID, permissions: perms },
                    JWT_SECRET,
                    { expiresIn: '8h', algorithm: 'HS256' }
                );
                res.cookie('emcs_admin_token', token, { httpOnly: true, secure: IS_PROD, sameSite: 'lax', maxAge: 28800000 });
                return res.json({ success: true, role: 'owner', name: 'Master Owner', permissions: perms });
            }
        } else {
            const staff = await Staff.findOne({ tenantId: TENANT_ID, username });
            if (staff && await bcrypt.compare(password, staff.passwordHash)) {
                const token = jwt.sign(
                    { role: 'staff', name: staff.name, tenantId: TENANT_ID, permissions: staff.permissions },
                    JWT_SECRET,
                    { expiresIn: '8h', algorithm: 'HS256' }
                );
                res.cookie('emcs_admin_token', token, { httpOnly: true, secure: IS_PROD, sameSite: 'lax', maxAge: 28800000 });
                return res.json({ success: true, role: 'staff', name: staff.name, permissions: staff.permissions });
            }
        }
        res.status(401).json({ success: false, message: 'Invalid admin credentials.' });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
    }
});

app.post('/api/admin/logout', (req, res) => {
    res.clearCookie('emcs_admin_token');
    res.json({ success: true });
});

app.get('/api/admin/user/:consumerId', authenticateAdmin, async (req, res) => {
    try {
        const cid = sanitizeInput(req.params.consumerId, 12).toUpperCase();
        const targetUser = await User.findOne({ tenantId: TENANT_ID, consumerId: cid }, '-credentialHash -pinHash');
        if (!targetUser) return res.status(404).json({ success: false, message: 'User not found.' });

        const createdTime = targetUser.createdAt ? new Date(targetUser.createdAt).getTime() : Date.now();
        const monthsActive = Math.max(1, (Date.now() - createdTime) / (1000 * 60 * 60 * 24 * 30));
        let monthlyKwh = 0;
        (targetUser.appliances || []).forEach(a => {
            if (a.state) monthlyKwh += parseFloat(a.monthlyKwh) || 0;
        });
        const lifetimeUsage = (monthsActive * monthlyKwh).toFixed(1);

        const paymentLedger = [];
        for (let i = 0; i < 24; i++) {
            const d = new Date();
            d.setMonth(d.getMonth() - i);
            const monthLabel = d.toLocaleString('en-IN', { month: 'short', year: 'numeric' });
            const deterministicHash = crypto.createHash('sha256').update(`${TENANT_ID}_${cid}_${monthLabel}`).digest('hex').slice(0, 8).toUpperCase();
            const varianceFactor = 0.92 + ((i % 5) * 0.04);
            const billedUnits = (monthlyKwh * varianceFactor).toFixed(1);
            const fixedCharge = (targetUser.sanctionedLoadKw || 2.0) * 80;
            const billedAmt = Math.round((parseFloat(billedUnits) * 6.85) + (monthlyKwh > 0 ? fixedCharge : 0));

            paymentLedger.push({
                month: monthLabel,
                txnId: `REC-${deterministicHash}`,
                units: billedUnits,
                amount: billedAmt,
                status: i === 0 && billedAmt > 0 ? 'Current Month' : 'Paid'
            });
        }

        res.json({ success: true, user: targetUser, lifetimeUsage, paymentLedger });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
    }
});

// Block or Unblock User Account (Also resets AI block when unblocking)
app.put('/api/admin/user/:cid/status', authenticateAdmin, async (req, res) => {
    try {
        const cid = sanitizeInput(req.params.cid, 12).toUpperCase();
        const status = req.body.status === 'blocked' ? 'blocked' : 'active';
        const updateFields = { accountStatus: status, activeSessions: [] };
        if (status === 'active') {
            updateFields.aiStatus = 'active';
            updateFields.aiSpamWarnings = 0;
        }
        await User.updateOne({ tenantId: TENANT_ID, consumerId: cid }, { $set: updateFields });
        res.json({ success: true, message: `User status updated to ${status}.` });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
    }
});

// Permanently Delete User Account & All Associated Data
app.delete('/api/admin/user/:cid', authenticateAdmin, async (req, res) => {
    try {
        const cid = sanitizeInput(req.params.cid, 12).toUpperCase();
        await User.deleteOne({ tenantId: TENANT_ID, consumerId: cid });
        await SupportMessage.deleteMany({ tenantId: TENANT_ID, consumerId: cid });
        await AiChat.deleteMany({ tenantId: TENANT_ID, consumerId: cid });
        res.json({ success: true, message: 'User account and all history deleted.' });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
    }
});

// Admin AI Chat History Endpoints
app.get('/api/admin/ai-history/all', authenticateAdmin, async (req, res) => {
    try {
        const cids = await AiChat.distinct('consumerId', { tenantId: TENANT_ID });
        const users = await User.find({ tenantId: TENANT_ID, consumerId: { $in: cids } }, 'name consumerId aiStatus');
        const userMap = {};
        users.forEach(u => { userMap[u.consumerId] = { name: u.name, aiStatus: u.aiStatus }; });

        const threads = cids.map(cid => ({
            consumerId: cid,
            name: userMap[cid]?.name || 'Consumer',
            aiStatus: userMap[cid]?.aiStatus || 'active'
        }));
        res.json({ success: true, threads });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.get('/api/admin/ai-history/:cid', authenticateAdmin, async (req, res) => {
    try {
        const cid = sanitizeInput(req.params.cid, 12).toUpperCase();
        const messages = await AiChat.find({ tenantId: TENANT_ID, consumerId: cid }).sort({ timestamp: 1 });
        res.json({ success: true, messages });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.delete('/api/admin/ai-history/:cid', authenticateAdmin, async (req, res) => {
    try {
        const cid = sanitizeInput(req.params.cid, 12).toUpperCase();
        await AiChat.deleteMany({ tenantId: TENANT_ID, consumerId: cid });
        res.json({ success: true, message: 'AI chat history deleted.' });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// Team Access Management
app.get('/api/admin/staff', authenticateAdmin, async (req, res) => {
    if (req.admin.role !== 'owner') return res.status(403).json({ success: false });
    const staffList = await Staff.find({ tenantId: TENANT_ID }, '-passwordHash');
    res.json({ success: true, staff: staffList });
});

app.post('/api/admin/staff', authenticateAdmin, async (req, res) => {
    try {
        if (req.admin.role !== 'owner') return res.status(403).json({ success: false });
        const name = sanitizeInput(req.body.name, 50);
        const username = sanitizeInput(req.body.username, 30).toLowerCase();
        const password = sanitizeInput(req.body.password, 64);
        if (!name || !username || password.length < 6) {
            return res.status(400).json({ success: false, message: 'Please enter valid name, username, and password.' });
        }
        const passwordHash = await bcrypt.hash(password, 12);
        await new Staff({
            tenantId: TENANT_ID,
            name,
            username,
            passwordHash,
            permissions: {
                canManageUsers: Boolean(req.body.permissions?.canManageUsers),
                canChatSupport: Boolean(req.body.permissions?.canChatSupport),
                canEditCMS: Boolean(req.body.permissions?.canEditCMS),
                canDeleteChat: Boolean(req.body.permissions?.canDeleteChat)
            }
        }).save();
        res.json({ success: true, message: 'Team member added.' });
    } catch (e) {
        res.status(400).json({ success: false, message: 'Could not add team member.' });
    }
});

app.delete('/api/admin/staff/:id', authenticateAdmin, async (req, res) => {
    if (req.admin.role !== 'owner') return res.status(403).json({ success: false });
    await Staff.findOneAndDelete({ _id: sanitizeInput(req.params.id, 40), tenantId: TENANT_ID });
    res.json({ success: true });
});

// Website Info & FAQs (CMS)
app.get('/api/cms', async (req, res) => {
    try {
        const cms = await CmsConfig.findOne({ tenantId: TENANT_ID, key: 'global_cms' })
            || await new CmsConfig({ tenantId: TENANT_ID, key: 'global_cms' }).save();
        res.json({ success: true, cms });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.post('/api/admin/cms', authenticateAdmin, requireAdminPermission('canEditCMS'), async (req, res) => {
    try {
        const update = {
            tenantId: TENANT_ID,
            broadcast: sanitizeInput(req.body.broadcast, 250),
            about: sanitizeInput(req.body.about, 2000),
            privacy: sanitizeInput(req.body.privacy, 4500),
            terms: sanitizeInput(req.body.terms, 4500),
            faqs: Array.isArray(req.body.faqs) ? req.body.faqs.slice(0, 30).map(f => ({
                q: sanitizeInput(f.q, 200),
                a: sanitizeInput(f.a, 600)
            })) : []
        };
        await CmsConfig.findOneAndUpdate({ tenantId: TENANT_ID, key: 'global_cms' }, update, { upsert: true });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// Support Desk Chat Routes
app.get('/api/support/user/messages', authenticateUser, strictAntiIdorShield, async (req, res) => {
    try {
        const messages = await SupportMessage.find({ tenantId: TENANT_ID, consumerId: req.user.consumerId }).sort({ timestamp: 1 }).limit(100);
        res.json({ success: true, messages });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.post('/api/support/user/send', authenticateUser, strictAntiIdorShield, createLimiter(12, 60000), async (req, res) => {
    try {
        const text = sanitizeInput(req.body.text, 500);
        if (!text) return res.status(400).json({ success: false });
        const msg = await new SupportMessage({ tenantId: TENANT_ID, consumerId: req.user.consumerId, sender: 'user', text }).save();
        res.json({ success: true, message: msg });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.get('/api/support/admin/threads', authenticateAdmin, async (req, res) => {
    try {
        const users = await User.find(
            { tenantId: TENANT_ID },
            'name email consumerId mobile sanctionedLoadKw accountStatus aiStatus createdAt'
        ).sort({ createdAt: -1 });
        res.json({ success: true, threads: users });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.get('/api/support/admin/messages/:cid', authenticateAdmin, requireAdminPermission('canChatSupport'), async (req, res) => {
    try {
        const cid = sanitizeInput(req.params.cid, 12).toUpperCase();
        const messages = await SupportMessage.find({ tenantId: TENANT_ID, consumerId: cid }).sort({ timestamp: 1 });
        res.json({ success: true, messages });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.post('/api/support/admin/reply', authenticateAdmin, requireAdminPermission('canChatSupport'), async (req, res) => {
    try {
        const consumerId = sanitizeInput(req.body.consumerId, 12).toUpperCase();
        const text = sanitizeInput(req.body.text, 500);
        if (!text) return res.status(400).json({ success: false });
        const msg = await new SupportMessage({ tenantId: TENANT_ID, consumerId, sender: 'admin', text }).save();
        res.json({ success: true, message: msg });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.delete('/api/support/chat/clear/:cid', authenticateAdmin, requireAdminPermission('canDeleteChat'), async (req, res) => {
    try {
        const cid = sanitizeInput(req.params.cid, 12).toUpperCase();
        await SupportMessage.deleteMany({ tenantId: TENANT_ID, consumerId: cid });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.delete('/api/support/chat/purge-all', authenticateAdmin, async (req, res) => {
    try {
        if (req.admin.role !== 'owner') return res.status(403).json({ success: false });
        await SupportMessage.deleteMany({ tenantId: TENANT_ID });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.get('/api/admin/master-database-dump', authenticateAdmin, async (req, res) => {
    try {
        if (req.admin.role !== 'owner') return res.status(403).json({ success: false });
        const users = await User.find({ tenantId: TENANT_ID }, '-credentialHash -pinHash');
        const messages = await SupportMessage.find({ tenantId: TENANT_ID });
        const aiChats = await AiChat.find({ tenantId: TENANT_ID });
        res.json({
            exportDate: new Date(),
            project: 'EMCS - Smart Energy Manager',
            totalUsers: users.length,
            backup: { users, supportMessages: messages, aiChats }
        });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// Block direct access to server files
app.use((req, res, next) => {
    if (/\.(env|map|log|md|git|sh)$|^\/(server\.js|package\.json|package-lock\.json)/i.test(req.path)) {
        return res.status(403).json({ success: false, message: 'Access denied.' });
    }
    next();
});

app.use(express.static(path.join(__dirname), { index: false, dotfiles: 'ignore' }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// Global error handler — never exposes technical details
app.use(async (err, req, res, next) => {
    await logBackendError('General', err, req);
    res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
});

app.listen(PORT, () => console.log(`[EMCS SERVER] Live on port ${PORT}`));
