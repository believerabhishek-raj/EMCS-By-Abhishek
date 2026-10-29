const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 5000;
const IS_PROD = process.env.NODE_ENV === 'production';

// Trust reverse proxy (Render / Cloudflare) for accurate client IP
app.set('trust proxy', 1);
app.disable('x-powered-by'); // Prevent Express version leakage

// ===================================================================
// SECRETS MANAGEMENT (NO HARDCODED PRODUCTION SECRETS)
// ===================================================================
const MONGO_URI = process.env.MONGO_URI || (IS_PROD ? '' : 'mongodb://127.0.0.1:27017/emcs_project_db');
const MASTER_OWNER_KEY = process.env.MASTER_OWNER_KEY || '';
const JWT_SECRET = process.env.JWT_SECRET || (
    MASTER_OWNER_KEY
        ? crypto.createHash('sha256').update(MASTER_OWNER_KEY + '_emcs_prod_vault').digest('hex')
        : crypto.randomBytes(32).toString('hex')
);

// Telegram Bot Credentials (Strictly Verified Against Render Env)
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_ADMIN_CHAT_ID = process.env.TELEGRAM_ADMIN_CHAT_ID || '';
global.MAINTENANCE_MODE = false;

if (!MASTER_OWNER_KEY) {
    console.warn('[SECURITY WARNING] MASTER_OWNER_KEY is not set in Environment Variables! Master Owner login will remain disabled until configured.');
}

// Strict payload size limit (10kb) to prevent memory exhaustion
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

// ============================================================================
// 🤖 TELEGRAM ALERT ENGINE & SENSITIVE DATA MASKING
// ============================================================================

function maskSensitiveData(text) {
    if (!text) return 'No details provided.';
    let safeText = String(text);
    safeText = safeText.replace(/(password|secret|apikey|api_key|credential|token|pin|auth)\s*[:=]\s*["']?[^"'\s,}&]*/gi, '$1: [HIDDEN_FOR_SECURITY]');
    safeText = safeText.replace(/eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, '[JWT_HIDDEN]');
    safeText = safeText.replace(/\$2[abxy]\$\d+\$[./A-Za-z0-9]{53}/g, '[HASH_HIDDEN]');
    safeText = safeText.replace(/mongodb(\+srv)?:\/\/([^:]+):([^@]+)@/gi, 'mongodb$1://$2:[DB_PASS_HIDDEN]@');
    return safeText;
}

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

    const isDatabaseIssue =
        typeStr.includes('database') || typeStr.includes('mongo') || typeStr.includes('nosql') ||
        typeStr.includes('injection') || typeStr.includes('pollution') || msgStr.includes('database') ||
        msgStr.includes('mongo') || msgStr.includes('unauthorized');

    const alertCount = isDatabaseIssue ? 2 : 1;
    let text = `🚨 *EMCS SYSTEM ALERT* 🚨\n\n*Type:* ${type}\n*Time:* ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}\n*Source IP:* \`${ipInfo}\`\n\n*Details:*\n${safeMessage}`;

    if (isDatabaseIssue) text = `‼️ *URGENT DATABASE SECURITY / HEALTH ALERT* ‼️\n\n` + text;

    for (let i = 0; i < alertCount; i++) {
        try {
            await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ chat_id: ADMIN_ID, text: text, parse_mode: 'Markdown' })
            });
            if (i < alertCount - 1) await new Promise(resolve => setTimeout(resolve, 1000));
        } catch (e) {
            console.error('[EMCS] Telegram Dispatch Error:', e.message);
        }
    }
}

// Security Headers & Anti-CSRF Verification
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

    if (['POST', 'DELETE', 'PUT', 'PATCH'].includes(req.method) && req.path.startsWith('/api/')) {
        const csrf = req.headers['x-emcs-csrf'];
        if (csrf !== 'emcs-verified-client') {
            return res.status(403).json({ success: false, message: 'Forbidden: Invalid request signature.' });
        }
    }
    next();
});

// Global Under-Maintenance Traffic Blocker
app.use((req, res, next) => {
    if (global.MAINTENANCE_MODE) {
        if (req.path.startsWith('/api/')) {
            return res.status(503).json({ success: false, message: 'System Under Maintenance ⚠️' });
        }
        return res.status(503).send(`
            <!DOCTYPE html>
            <html lang="en">
            <head><meta charset="UTF-8"><title>Under Maintenance | EMCS</title></head>
            <body style="display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;background:#0b0f19;color:#f9fafb;text-align:center;">
                <div><h1 style="font-size:3.5rem;">⚠️</h1><h2 style="color:#ef4444;">Under Maintenance ⚠️</h2><p>We are currently upgrading the EMCS Smart Grid servers.</p></div>
            </body>
            </html>
        `);
    }
    next();
});

// Ultimate NoSQL Injection & Prototype Pollution Shield
app.use(async (req, res, next) => {
    const forbiddenKeys = ['__proto__', 'constructor', 'prototype'];
    const hasMaliciousKeys = (obj) => {
        if (!obj || typeof obj !== 'object') return false;
        for (const key of Object.keys(obj)) {
            if (key.includes('$') || key.includes('.') || forbiddenKeys.includes(key.toLowerCase())) return true;
            if (typeof obj[key] === 'object' && hasMaliciousKeys(obj[key])) return true;
        }
        return false;
    };

    if (hasMaliciousKeys(req.body) || hasMaliciousKeys(req.query) || hasMaliciousKeys(req.params)) {
        await sendTelegramAlert('NoSQL / Prototype Pollution Blocked', `Malicious payload keys blocked on ${req.method} ${req.originalUrl}`, req);
        return res.status(403).json({ success: false, message: 'Security Block: Malicious payload structure detected.' });
    }
    next();
});


// ===================================================================
// STRICT INPUT VALIDATION & SANITIZATION HELPERS
// ===================================================================
const sanitizeInput = (val, max = 150) => {
    if (typeof val === 'string' || typeof val === 'number') {
        return String(val).replace(/[\0$]/g, '').trim().slice(0, max);
    }
    return '';
};

const ALLOWED_PROVIDERS = new Set([
    'bihar', 'up', 'maharashtra', 'delhi', 'karnataka', 'rajasthan',
    'wb', 'tn', 'gujarat', 'punjab', 'haryana', 'mp',
    'tata_delhi', 'bses_delhi', 'tata_mumbai', 'adani_mumbai',
    'cesc_kolkata', 'torrent', 'national', 'custom'
]);
const ALLOWED_CATEGORIES = new Set(['domestic', 'commercial']);
const ALLOWED_AREAS = new Set(['urban', 'rural']);

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
// MULTI-TIER RATE LIMITING (PER-IP & MEMORY GUARDED)
// ===================================================================
const rateLimits = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of rateLimits.entries()) {
        if (now > v.resetAt) rateLimits.delete(k);
    }
}, 300000);

function createLimiter(maxReqs, windowMs, customMsg) {
    return (req, res, next) => {
        const key = `${req.ip}_${req.baseUrl || req.path}`;
        const now = Date.now();
        let rec = rateLimits.get(key) || { count: 0, resetAt: now + windowMs };
        if (now > rec.resetAt) rec = { count: 0, resetAt: now + windowMs };

        const allowedMax = req.isSuspiciousProxy ? Math.max(1, Math.floor(maxReqs / 2)) : maxReqs;
        rec.count++;

        // Prevent memory exhaustion from spoofed IP floods
        if (rateLimits.size > 5000 && !rateLimits.has(key)) {
            rateLimits.clear();
        }
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

const globalApiLimiter = createLimiter(60, 60 * 1000, 'API rate limit exceeded. Please slow down.');
const strictRegisterLimiter = createLimiter(3, 24 * 60 * 60 * 1000, 'Maximum 3 accounts can be created from a single IP within 24 hours.');
const loginLimiter = createLimiter(5, 15 * 60 * 1000, 'Too many login attempts. Please wait 15 minutes.');
const chatLimiter = createLimiter(12, 60 * 1000, 'Sending messages too fast. Please wait a moment.');
const errorReportLimiter = createLimiter(15, 60 * 1000, 'Telemetry limit reached.');

app.use('/api', globalApiLimiter);

// ===================================================================
// FORT-KNOX MONGODB SETUP, SCHEMAS & GLOBAL DATA-LEAK SHIELD
// ===================================================================

mongoose.set('sanitizeFilter', true);
mongoose.set('strictQuery', true);

mongoose.plugin((schema) => {
    schema.set('toJSON', {
        transform: (doc, ret) => {
            delete ret.pinHash;
            delete ret.passwordHash;
            delete ret.__v;
            return ret;
        }
    });
    schema.set('toObject', {
        transform: (doc, ret) => {
            delete ret.pinHash;
            delete ret.passwordHash;
            delete ret.__v;
            return ret;
        }
    });
});

mongoose.connection.on('error', async (err) => {
    console.error('[EMCS] MongoDB Runtime Error:', err.message);
    await sendTelegramAlert('Database Runtime Error', `MongoDB error: ${err.message}`);
});

mongoose.connection.on('disconnected', async () => {
    console.warn('[EMCS] MongoDB Disconnected!');
    await sendTelegramAlert('Database Disconnected', 'Critical: MongoDB connection was lost or dropped.');
});

if (MONGO_URI) {
    const dbSecurityOptions = {
        maxPoolSize: 50,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
        autoIndex: !IS_PROD,
        family: 4
    };
    mongoose.connect(MONGO_URI, dbSecurityOptions)
        .then(() => console.log('[EMCS VAULT] Connected to database successfully.'))
        .catch(err => {
            console.error('[EMCS VAULT] Connection failed:', err.message);
            sendTelegramAlert('FATAL: Database Connection Failed', `MongoDB Refused Connection: ${err.message}`);
        });
} else {
    console.warn('[EMCS] ⚠️ MONGO_URI not set in environment variables!');
}

// ===================================================================
// DATABASE SCHEMAS & 2-YEAR TTL INDEX
// ===================================================================
const UserSchema = new mongoose.Schema({
    mobile: { type: String, required: true, unique: true, index: true },
    consumerId: { type: String, required: true, unique: true, minlength: 12, maxlength: 12, index: true },
    name: { type: String, required: true },
    pinHash: { type: String, required: true },
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
    accountStatus: { type: String, default: 'active', enum: ['active', 'deleted', 'suspended'] },
    deletionScheduledAt: { type: Date, default: null }
}, { timestamps: true });

UserSchema.index({ deletionScheduledAt: 1 }, { expireAfterSeconds: 63072000 });

const StaffSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
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

const SupportMessageSchema = new mongoose.Schema({
    consumerId: { type: String, required: true, index: true },
    sender: { type: String, enum: ['user', 'admin'], required: true },
    text: { type: String, required: true, maxlength: 500 },
    timestamp: { type: Date, default: Date.now, expires: 2592000 }
});

const CmsSchema = new mongoose.Schema({
    key: { type: String, default: 'global_cms', unique: true },
    broadcast: { type: String, default: '' },
    about: {
        type: String,
        default: 'EMCS (Energy Management Control System) is an intelligent energy monitoring, tariff estimation, and load automation platform.'
    },
    privacy: {
        type: String,
        default: '1. DATA COLLECTION (DPDP Act 2023 Compliance): We collect minimal data (Mobile, Consumer ID, Name) strictly for authentication and load monitoring. We do not sell your data to third parties.\n\n2. OCR & FILE UPLOADS: Bill images uploaded for OCR and CSV files are processed securely in memory. We do not permanently store images of your physical electricity bills.\n\n3. DATA RETENTION & ERASURE: Upon account deactivation, all sessions are revoked, and records enter a secured 2-year retention archive for compliance before automatic permanent erasure.\n\n4. COOKIES: We use HTTP-only cookies strictly for session authorization.'
    },
    terms: {
        type: String,
        default: '1. ACCEPTANCE OF TERMS: By using EMCS, you agree to these legal terms.\n\n2. NO FINANCIAL LIABILITY: The electricity bills, solar ROI, and tariff calculations provided by EMCS are "Estimates" based on standard utility slabs. EMCS is not an official billing authority. You must pay your actual utility provider based on their official meter readings.\n\n3. HARDWARE & IOT SAFETY WAIVER: The hardware relay control, voltage surge guard, and IoT features are provided "AS IS". EMCS and its developers are NOT liable for any electrical damage, short circuits, hardware failure, fire hazards, or personal injury resulting from automated appliance switching. Use IoT features at your own risk.\n\n4. PAYMENTS: EMCS provides a simulated settlement ledger. No real financial transactions are processed on this platform.'
    },
    faqs: {
        type: Array,
        default: [
            { q: 'Are the electricity bills shown here official?', a: 'No. All bills and solar ROI figures are estimates calculated using state/private DISCOM tariff slabs for planning and energy-saving purposes.' },
            { q: 'How does the 2-year account deletion policy work?', a: 'When you deactivate your account, all active devices are logged out immediately and your records are automatically erased after 2 years.' },
            { q: 'Is it safe to connect my ESP32 / Arduino relay?', a: 'Yes, local hardware triggers use HMAC-SHA256 signatures, but always ensure qualified electrical insulation when dealing with 230V AC loads.' }
        ]
    }
});

const SystemErrorSchema = new mongoose.Schema({
    timestamp: { type: Date, default: Date.now, expires: 2592000 },
    source: { type: String, default: 'Secure Storage Layer' },
    message: { type: String, required: true },
    location: { type: String, default: '' },
    userOrIp: { type: String, default: '' }
});

const User = mongoose.model('User', UserSchema);
const Staff = mongoose.model('Staff', StaffSchema);
const SupportMessage = mongoose.model('SupportMessage', SupportMessageSchema);
const CmsConfig = mongoose.model('CmsConfig', CmsSchema);
const SystemError = mongoose.model('SystemError', SystemErrorSchema);

// Internal server-side error logger (Never leaks stack traces to client)
async function logBackendError(source, err, req = null) {
    try {
        const safeMsg = sanitizeInput(err?.message || String(err), 300);
        await new SystemError({
            source: sanitizeInput(source || 'Secure Storage Layer', 50),
            message: safeMsg,
            location: sanitizeInput(req ? `${req.method}${req.originalUrl}` : 'Internal', 150),
            userOrIp: sanitizeInput(req ? (req.user?.consumerId || req.ip) : 'System', 60)
        }).save();
        await sendTelegramAlert(source, safeMsg, req);
    } catch (ignore) {}
}

// ===================================================================
// AUTHENTICATION & AUTHORIZATION (RBAC & OWNERSHIP)
// ===================================================================

function getUaHash(req) {
    const ua = String(req.headers['user-agent'] || 'unknown_device');
    return crypto.createHash('sha256').update(ua).digest('hex');
}

async function authenticateUser(req, res, next) {
    const token = req.cookies.emcs_auth_token;
    if (!token) return res.status(401).json({ success: false, message: 'Authentication required. Please log in.' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        const currentUaHash = getUaHash(req);

        if (decoded.uaHash && decoded.uaHash !== currentUaHash) {
            res.clearCookie('emcs_auth_token');
            await logBackendError('Consumer Session Hijack Blocked', `Token for ${decoded.userId} used from mismatched device!`, req);
            return res.status(403).json({ success: false, message: 'Security Alert: Device mismatch. Session terminated.' });
        }

        const user = await User.findById(decoded.userId);

        if (!user || user.accountStatus === 'deleted' || user.accountStatus === 'suspended' || !user.activeSessions.some(s => s.sessionId === decoded.sessionId)) {
            res.clearCookie('emcs_auth_token');
            return res.status(401).json({ success: false, message: 'Session expired, invalid, or account suspended.' });
        }

        req.user = user;
        req.sessionId = decoded.sessionId;
        next();
    } catch (e) {
        return res.status(403).json({ success: false, message: 'Invalid session credentials.' });
    }
}

async function authenticateAdmin(req, res, next) {
    const token = req.cookies.emcs_admin_token;
    if (!token) return res.status(401).json({ success: false, message: 'Admin authentication required.' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        const currentUaHash = getUaHash(req);
        
        if (decoded.uaHash && decoded.uaHash !== currentUaHash) {
            res.clearCookie('emcs_admin_token');
            await logBackendError('Admin Session Hijack Blocked', `Admin token used from mismatched device!`, req);
            return res.status(403).json({ success: false, message: 'Security Alert: Device mismatch. Session terminated.' });
        }
        
        req.admin = decoded;
        next();
    } catch (e) {
        return res.status(403).json({ success: false, message: 'Invalid admin session.' });
    }
}

function requireAdminPermission(permKey) {
    return (req, res, next) => {
        if (!req.admin) return res.status(401).json({ success: false, message: 'Unauthorized.' });
        if (req.admin.role === 'owner') return next();
        if (permKey && req.admin.permissions && req.admin.permissions[permKey] === true) {
            return next();
        }
        return res.status(403).json({ success: false, message: 'Forbidden: Insufficient role permissions.' });
    };
}

// ===================================================================
// HEALTH CHECK & ERROR TELEMETRY ROUTES
// ===================================================================
app.get('/api/health', (req, res) => {
    res.status(200).json({ status: 'ok', uptime: Math.floor(process.uptime()) });
});

app.post('/api/errors/report', errorReportLimiter, async (req, res) => {
    try {
        const source = sanitizeInput(req.body.source || 'Client Component', 50);
        const message = sanitizeInput(req.body.message, 300);
        const location = sanitizeInput(req.body.location, 150);
        const userOrIp = sanitizeInput(req.body.userOrIp || req.ip, 60);

        if (!message) return res.status(400).json({ success: false });
        await new SystemError({ source, message, location, userOrIp }).save();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.get('/api/admin/errors', authenticateAdmin, async (req, res) => {
    try {
        const errors = await SystemError.find({}).sort({ timestamp: -1 }).limit(100);
        res.json({ success: true, errors });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Could not retrieve error logs.' });
    }
});

app.delete('/api/admin/errors/clear', authenticateAdmin, requireAdminPermission(null), async (req, res) => {
    try {
        if (req.admin.role !== 'owner') {
            return res.status(403).json({ success: false, message: 'Only Master Owner can clear system error logs.' });
        }
        await SystemError.deleteMany({});
        res.json({ success: true, message: 'All error logs cleared.' });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// ===================================================================
// USER AUTHENTICATION & REGISTRATION ROUTES
// ===================================================================
app.post('/api/auth/register', strictRegisterLimiter, async (req, res) => {
    try {
        if (req.body._bot_honeypot && String(req.body._bot_honeypot).length > 0) {
            await logBackendError('Bot Registration Blocked', `Honeypot triggered on register`, req);
            return res.status(403).json({ success: false, message: 'Automated registration blocked.' });
        }

        if (req.body.termsAccepted !== true) {
            return res.status(400).json({ success: false, message: 'You must accept the Privacy Policy and Terms & Conditions.' });
        }

        const mobile = sanitizeInput(req.body.mobile, 10);
        const consumerId = sanitizeInput(req.body.consumerId, 12).toUpperCase();
        const pin = sanitizeInput(req.body.pin, 4);
        const name = sanitizeInput(req.body.name, 60);

        if (!/^[0-9]{10}$/.test(mobile) || !/^[A-Z0-9]{12}$/.test(consumerId) || !/^[0-9]{4}$/.test(pin) || name.length < 2) {
            return res.status(400).json({ success: false, message: 'Invalid input format. Check mobile, 12-char alphanumeric ID, and 4-digit PIN.' });
        }

        const existing = await User.findOne({ $or: [{ mobile }, { consumerId }] });
        if (existing) {
            return res.status(400).json({ success: false, message: 'Registration failed: Mobile or Consumer ID is already in use.' });
        }

        const pinHash = await bcrypt.hash(pin, 12);
        const newUser = await new User({
            mobile,
            consumerId,
            name,
            pinHash,
            termsAccepted: true,
            termsAcceptedAt: new Date()
        }).save();

        res.json({ success: true, message: 'Account created successfully.', user: { name: newUser.name, consumerId: newUser.consumerId }});
    } catch (e) {
        await logBackendError('Register Route', e, req);
        res.status(500).json({ success: false, message: 'Something went wrong. Please try again later.' });
    }
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        if (req.body._bot_honeypot && String(req.body._bot_honeypot).length > 0) {
            await logBackendError('Bot Login Blocked', `Honeypot triggered on login`, req);
            return res.status(403).json({ success: false, message: 'Access denied.' });
        }
        
        const mobile = sanitizeInput(req.body.mobile, 10);
        const pin = sanitizeInput(req.body.pin, 4);

        if (!/^[0-9]{10}$/.test(mobile) || !/^[0-9]{4}$/.test(pin)) {
            return res.status(400).json({ success: false, message: 'Invalid mobile number or PIN.' });
        }

        const user = await User.findOne({ mobile });
        if (!user) return res.status(401).json({ success: false, message: 'Invalid mobile number or PIN.' });

        if (user.accountStatus === 'deleted') {
            return res.status(403).json({ success: false, message: 'This account has been deactivated.' });
        }
        if (user.accountStatus === 'suspended') {
            return res.status(403).json({ success: false, message: 'Account suspended by administration.' });
        }

        if (user.lockUntil && user.lockUntil > Date.now()) {
            const mins = Math.ceil((user.lockUntil - Date.now()) / 60000);
            return res.status(429).json({
                success: false,
                isLocked: true,
                message: `Account temporarily locked. Please try again in ${mins} minutes.`
            });
        }

        const isMatch = await bcrypt.compare(pin, user.pinHash);
        if (!isMatch) {
            const updatedUser = await User.findOneAndUpdate(
                { _id: user._id },
                { $inc: { failedLoginAttempts: 1 } },
                { new: true }
            );

            if (updatedUser.failedLoginAttempts >= 5) {
                await User.updateOne(
                    { _id: user._id },
                    { $set: { lockUntil: new Date(Date.now() + 15 * 60000), failedLoginAttempts: 0 } }
                );
                await logBackendError('Brute-Force Lockout Triggered', `Consumer ${user.consumerId} locked for 15m after 5 failed attempts.`, req);
                return res.status(429).json({ success: false, message: '5 failed attempts! Account locked for 15 minutes.' });
            }
            return res.status(401).json({ success: false, message: `Invalid PIN. (${5 - updatedUser.failedLoginAttempts} attempts remaining)` });
        }

        await User.updateOne(
            { _id: user._id },
            { $set: { failedLoginAttempts: 0, lockUntil: null } }
        );

        const sessionId = crypto.randomBytes(24).toString('hex');
        const uaHash = getUaHash(req);
        
        user.activeSessions.push({
            sessionId,
            deviceInfo: sanitizeInput(req.headers['user-agent'], 70),
            ipAddress: req.ip
        });

        if (user.activeSessions.length > 5) {
            user.activeSessions = user.activeSessions.slice(-5);
        }
        await user.save();

        const token = jwt.sign({ userId: user._id, sessionId, uaHash }, JWT_SECRET, { expiresIn: '7d', algorithm: 'HS256' });

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
        await logBackendError('Login Route', e, req);
        res.status(500).json({ success: false, message: 'Something went wrong. Please try again later.' });
    }
});

app.get('/api/auth/me', authenticateUser, async (req, res) => {
    res.json({ success: true, user: { name: req.user.name, consumerId: req.user.consumerId, appliances: req.user.appliances } });
});

app.post('/api/auth/logout', authenticateUser, async (req, res) => {
    try {
        const { allDevices } = req.body;
        if(allDevices) {
            req.user.activeSessions = [];
        } else {
            req.user.activeSessions = req.user.activeSessions.filter(s => s.sessionId !== req.sessionId);
        }
        await req.user.save();
        res.clearCookie('emcs_auth_token');
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.post('/api/auth/verify-and-reset-pin', loginLimiter, async (req, res) => {
    try {
        const mobile = sanitizeInput(req.body.mobile, 10);
        const consumerId = sanitizeInput(req.body.consumerId, 12).toUpperCase();
        const registeredName = sanitizeInput(req.body.registeredName, 60).toLowerCase();
        const newPin = sanitizeInput(req.body.newPin, 4);

        if (!/^[0-9]{10}$/.test(mobile) || !/^[A-Z0-9]{12}$/.test(consumerId) || !/^[0-9]{4}$/.test(newPin)) {
            return res.status(400).json({ success: false, message: 'Invalid recovery details provided.' });
        }

        const user = await User.findOne({ mobile, consumerId, accountStatus: 'active' });
        if (!user || user.name.toLowerCase() !== registeredName) {
            return res.status(400).json({ success: false, message: 'Verification failed. Details do not match our records.' });
        }

        user.pinHash = await bcrypt.hash(newPin, 12);
        user.failedLoginAttempts = 0;
        user.lockUntil = null;
        user.activeSessions = [];
        await user.save();

        res.json({ success: true, message: 'PIN reset successful! Please log in.' });
    } catch (e) {
        await logBackendError('PIN Reset Route', e, req);
        res.status(500).json({ success: false, message: 'Something went wrong. Please try again later.' });
    }
});

app.get('/api/auth/devices', authenticateUser, (req, res) => {
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

app.post('/api/auth/revoke-device', authenticateUser, async (req, res) => {
    try {
        const targetId = sanitizeInput(req.body.targetSessionId, 64);
        const target = req.user.activeSessions.find(s => s.sessionId === targetId);

        if (!target || targetId === req.sessionId) {
            return res.status(400).json({ success: false, message: 'Invalid device session.' });
        }

        if (Date.now() - new Date(target.createdAt).getTime() < 48 * 3600 * 1000) {
            return res.status(403).json({ success: false, message: 'Secondary devices can only be revoked 48 hours after login.' });
        }

        req.user.activeSessions = req.user.activeSessions.filter(s => s.sessionId !== targetId);
        await req.user.save();
        res.json({ success: true, message: 'Device session revoked.' });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// ===================================================================
// USER DATA SYNC & ACCOUNT DELETION (OWNERSHIP ENFORCED)
// ===================================================================
app.get('/api/user/get-cloud-data', authenticateUser, (req, res) => {
    res.json({
        success: true,
        data: {
            name: req.user.name,
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

app.put('/api/user/appliances', authenticateUser, async (req, res) => {
    try {
        const { appliances } = req.body;
        if (!Array.isArray(appliances) || appliances.length > 60) {
            return res.status(400).json({ success: false, message: 'Invalid appliances list.' });
        }

        const sanitized = appliances.map(a => ({
            name: String(a.name || 'Appliance').trim().substring(0, 50),
            power: Math.max(0, Math.min(50000, Number(a.power) || 0)),
            hours: Math.max(0, Math.min(24, Number(a.hours) || 0)),
            mode: String(a.mode || 'manual').trim().substring(0, 20)
        }));

        req.user.appliances = sanitized;
        await req.user.save();
        res.json({ success: true, appliances: req.user.appliances });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Failed to sync appliances.' });
    }
});

app.post('/api/user/sync-cloud', authenticateUser, async (req, res) => {
    try {
        const {
            name,
            appliances,
            sanctionedLoadKw,
            budgetThreshold,
            tariffProvider,
            tariffCategory,
            tariffArea,
            customTariff
        } = req.body;

        if (name !== undefined) {
            const cleanName = sanitizeInput(name, 60);
            if (cleanName.length >= 2) req.user.name = cleanName;
        }

        if (Array.isArray(appliances)) {
            req.user.appliances = appliances.slice(0, 50).map(a => {
                const pwr = Math.min(50000, Math.max(1, Number(a.power) || 10));
                const hrs = Math.min(24, Math.max(0.1, Number(a.hours) || 1));
                return {
                    id: Number(a.id) || Date.now(),
                    name: sanitizeInput(a.name, 40) || 'Appliance',
                    power: pwr,
                    hours: hrs,
                    monthlyKwh: Number(((pwr * hrs * 30) / 1000).toFixed(2)),
                    state: Boolean(a.state),
                    mode: String(a.mode || 'manual').trim().substring(0,20)
                };
            });
        }

        if (sanctionedLoadKw !== undefined) {
            req.user.sanctionedLoadKw = Math.min(50, Math.max(0.5, Number(sanctionedLoadKw) || 2.0));
        }
        if (budgetThreshold !== undefined) {
            req.user.budgetThreshold = Math.min(1000000, Math.max(100, Number(budgetThreshold) || 3000));
        }
        if (tariffProvider && ALLOWED_PROVIDERS.has(tariffProvider)) {
            req.user.tariffProvider = tariffProvider;
        }
        if (tariffCategory && ALLOWED_CATEGORIES.has(tariffCategory)) {
            req.user.tariffCategory = tariffCategory;
        }
        if (tariffArea && ALLOWED_AREAS.has(tariffArea)) {
            req.user.tariffArea = tariffArea;
        }

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
        res.json({ success: true, message: 'Settings synced.' });
    } catch (e) {
        await logBackendError('Cloud Sync Route', e, req);
        res.status(500).json({ success: false, message: 'Something went wrong. Please try again later.' });
    }
});

app.delete('/api/user/delete-account', authenticateUser, async (req, res) => {
    try {
        req.user.accountStatus = 'deleted';
        req.user.deletionScheduledAt = new Date();
        req.user.activeSessions = [];
        await req.user.save();

        res.clearCookie('emcs_auth_token');
        res.json({
            success: true,
            message: 'Account deactivated. Records will be automatically erased after 2 years.'
        });
    } catch (e) {
        await logBackendError('Account Delete Route', e, req);
        res.status(500).json({ success: false });
    }
});

// ===================================================================
// ADMIN, STAFF RBAC, CMS & SUPPORT DESK ROUTES
// ===================================================================
app.post('/api/admin/login', loginLimiter, async (req, res) => {
    try {
        const username = sanitizeInput(req.body.username, 40);
        const password = sanitizeInput(req.body.password, 64);

        if (!username) {
            if (!MASTER_OWNER_KEY) {
                return res.status(503).json({ success: false, message: 'Master Owner key is not configured on the server.' });
            }
            if (safeCompareStrings(password, MASTER_OWNER_KEY)) {
                const perms = { canManageUsers: true, canChatSupport: true, canEditCMS: true, canDeleteChat: true };
                const uaHash = getUaHash(req);
                const token = jwt.sign({ role: 'owner', name: 'Master Owner', permissions: perms, uaHash }, JWT_SECRET, { expiresIn: '8h', algorithm: 'HS256' });
                res.cookie('emcs_admin_token', token, { httpOnly: true, secure: IS_PROD, sameSite: 'lax', maxAge: 28800000 });
                return res.json({ success: true, admin: { role: 'owner', username: 'Master Owner', permissions: perms } });
            }
        } else {
            const staff = await Staff.findOne({ username });
            if (staff && await bcrypt.compare(password, staff.passwordHash)) {
                const uaHash = getUaHash(req);
                const token = jwt.sign({ role: 'staff', name: staff.name, permissions: staff.permissions, uaHash }, JWT_SECRET, { expiresIn: '8h', algorithm: 'HS256' });
                res.cookie('emcs_admin_token', token, { httpOnly: true, secure: IS_PROD, sameSite: 'lax', maxAge: 28800000 });
                return res.json({ success: true, admin: { role: 'staff', username: staff.username, permissions: staff.permissions } });
            }
        }

        res.status(401).json({ success: false, message: 'Invalid administrative credentials.' });
    } catch (e) {
        await logBackendError('Admin Login Route', e, req);
        res.status(500).json({ success: false, message: 'Something went wrong. Please try again later.' });
    }
});

app.post('/api/admin/logout', (req, res) => {
    res.clearCookie('emcs_admin_token');
    res.json({ success: true });
});

app.get('/api/admin/overview', authenticateAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments({});
        const activeUsers = await User.countDocuments({ accountStatus: 'active' });
        res.json({ success: true, stats: { totalUsers, activeUsers, pendingTickets: 0, totalErrors: 0 }, adminProfile: req.admin });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});


// Staff RBAC Management (Owner Only)
app.get('/api/admin/staff', authenticateAdmin, async (req, res) => {
    if (req.admin.role !== 'owner') return res.status(403).json({ success: false });
    const staffList = await Staff.find({}, '-passwordHash');
    res.json({ success: true, staffList });
});

app.post('/api/admin/staff', authenticateAdmin, async (req, res) => {
    try {
        if (req.admin.role !== 'owner') return res.status(403).json({ success: false, message: 'Owner privilege required.' });
        const name = sanitizeInput(req.body.name, 50);
        const username = sanitizeInput(req.body.username, 30).toLowerCase();
        const password = sanitizeInput(req.body.password, 64);
        const roleTitle = sanitizeInput(req.body.roleTitle, 50) || 'Operator';

        if (!username || password.length < 6) {
            return res.status(400).json({ success: false, message: 'Valid username, and password (min 6 chars) required.' });
        }

        const passwordHash = await bcrypt.hash(password, 12);
        await new Staff({
            name: name || username,
            username,
            passwordHash,
            role: roleTitle,
            permissions: {
                canManageUsers: Boolean(req.body.permissions?.manageUsers),
                canChatSupport: Boolean(req.body.permissions?.manageSupport),
                canEditCMS: Boolean(req.body.permissions?.manageCms),
                canDeleteChat: Boolean(req.body.permissions?.viewLogs)
            }
        }).save();

        res.json({ success: true, message: 'Staff account created.' });
    } catch (e) {
        res.status(400).json({ success: false, message: 'Could not create staff account (username may already exist).' });
    }
});

app.delete('/api/admin/staff/:id', authenticateAdmin, async (req, res) => {
    if (req.admin.role !== 'owner') return res.status(403).json({ success: false });
    await Staff.findByIdAndDelete(sanitizeInput(req.params.id, 40));
    res.json({ success: true });
});

app.get('/api/admin/users', authenticateAdmin, requireAdminPermission('canManageUsers'), async (req, res) => {
    try {
        const users = await User.find({}, '-pinHash');
        res.json({ success: true, users });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.get('/api/cms', async (req, res) => {
    try {
        const cms = await CmsConfig.findOne({ key: 'global_cms' }) || await new CmsConfig().save();
        res.json({ success: true, cms });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});
app.get('/api/admin/cms-full', authenticateAdmin, requireAdminPermission('canEditCMS'), async (req, res) => {
    try {
        const cms = await CmsConfig.findOne({ key: 'global_cms' }) || await new CmsConfig().save();
        res.json({ success: true, cms });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.put('/api/admin/cms', authenticateAdmin, requireAdminPermission('canEditCMS'), async (req, res) => {
    try {
        const update = {
            broadcast: sanitizeInput(req.body.broadcastBanner, 250),
            about: sanitizeInput(req.body.aboutUs, 2000),
            privacy: sanitizeInput(req.body.privacy, 4000),
            terms: sanitizeInput(req.body.terms, 4000),
            faqs: Array.isArray(req.body.faqs) ? req.body.faqs.slice(0, 30).map(f => ({
                q: sanitizeInput(f.q, 200),
                a: sanitizeInput(f.a, 600)
            })) : []
        };
        await CmsConfig.findOneAndUpdate({ key: 'global_cms' }, update, { upsert: true });
        res.json({ success: true });
    } catch (e) {
        await logBackendError('CMS Update Route', e, req);
        res.status(500).json({ success: false });
    }
});

// Two-Way User Support Chat Routes (Row-Level Security Enforced)
app.get('/api/user/support', authenticateUser, async (req, res) => {
    try {
        const messages = await SupportMessage.find({ consumerId: req.user.consumerId }).sort({ timestamp: 1 }).limit(100);
        res.json({ success: true, messages });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.post('/api/user/support', authenticateUser, chatLimiter, async (req, res) => {
    try {
        const text = sanitizeInput(req.body.text, 500);
        if (!text) return res.status(400).json({ success: false });
        const msg = await new SupportMessage({ consumerId: req.user.consumerId, sender: 'user', text }).save();
        res.json({ success: true, messages: [msg] });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.get('/api/admin/support', authenticateAdmin, async (req, res) => {
    try {
        if (req.admin.role !== 'owner' && !req.admin.permissions?.canChatSupport && !req.admin.permissions?.canManageUsers) {
            return res.status(403).json({ success: false, message: 'Forbidden: Insufficient permissions.' });
        }
        res.json({ success: true, tickets: [] }); // placeholder for threading
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.get('/api/support/admin/messages/:cid', authenticateAdmin, requireAdminPermission('canChatSupport'), async (req, res) => {
    try {
        const cid = sanitizeInput(req.params.cid, 12).toUpperCase();
        const messages = await SupportMessage.find({ consumerId: cid }).sort({ timestamp: 1 });
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
        const msg = await new SupportMessage({ consumerId, sender: 'admin', text }).save();
        res.json({ success: true, message: msg });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.delete('/api/support/chat/clear/:cid', authenticateAdmin, requireAdminPermission('canDeleteChat'), async (req, res) => {
    try {
        const cid = sanitizeInput(req.params.cid, 12).toUpperCase();
        await SupportMessage.deleteMany({ consumerId: cid });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.delete('/api/support/chat/purge-all', authenticateAdmin, async (req, res) => {
    try {
        if (req.admin.role !== 'owner') return res.status(403).json({ success: false });
        await SupportMessage.deleteMany({});
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.get('/api/admin/master-database-dump', authenticateAdmin, async (req, res) => {
    try {
        if (req.admin.role !== 'owner') return res.status(403).json({ success: false });
        const users = await User.find({}, '-pinHash');
        const messages = await SupportMessage.find({});
        const errors = await SystemError.find({});
        res.json({
            exportDate: new Date(),
            project: 'EMCS - Energy Management Control System',
            totalUsers: users.length,
            database: { users, supportMessages: messages, systemErrors: errors }
        });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// ===================================================================
// SOURCE FILE EXPOSURE PROTECTION (NO .ENV / SERVER.JS / .MAP LEAK)
// ===================================================================
app.use((req, res, next) => {
    const blockedPattern = /\.(env|map|log|md|git|sh)$|^\/(server\.js|package\.json|package-lock\.json)/i;
    if (blockedPattern.test(req.path)) {
        return res.status(403).json({ success: false, message: 'Access denied.' });
    }
    next();
});

app.use(express.static(path.join(__dirname), { index: false, dotfiles: 'ignore' }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// SAFE GLOBAL ERROR HANDLER (NO STACK TRACE LEAKAGE)
app.use(async (err, req, res, next) => {
    await logBackendError('Express Unhandled Error', err, req);
    res.status(500).json({ success: false, message: 'Something went wrong. Please try again later.' });
});

// ============================================================================
// 🤖 TELEGRAM GHOST-MODE REMOTE CONTROL BOT
// ============================================================================
let tgLastUpdateId = 0;

async function sendTelegramControlPanel(chatId) {
    const keyboard = {
        inline_keyboard: [
            [
                { text: "🔴 Maint ON", callback_data: "maint_on" },
                { text: "🟢 Maint OFF", callback_data: "maint_off" }
            ],
            [
                { text: "📊 Status", callback_data: "sys_status" },
                { text: "👥 Users", callback_data: "total_users" }
            ],
            [
                { text: "🧹 Clean RAM", callback_data: "clean_ram" },
                { text: "⚠️ Last 3 Errors", callback_data: "last_errors" }
            ]
        ]
    };

    const text = "🎛️ *EMCS MASTER CONTROL PANEL*

Select an operation below. _Strictly authenticated via Render Environment Variables (Ghost-Mode Active)._";

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

                // 👻 GHOST MODE
                if (incomingUserId !== String(ADMIN_ID)) continue;

                if (update.message && update.message.text) {
                    const txt = update.message.text.trim().toLowerCase();
                    if (txt === '/start' || txt === '/menu' || txt === 'menu') {
                        await sendTelegramControlPanel(ADMIN_ID);
                    }
                }

                if (update.callback_query) {
                    const cb = update.callback_query;
                    const action = cb.data;
                    let popupMessage = "Command Executed";

                    if (action === 'maint_on') {
                        global.MAINTENANCE_MODE = true;
                        popupMessage = "🔴 Maintenance Mode ON";
                        await sendTelegramAlert('SYSTEM CONTROL', '🔴 Website is now *UNDER MAINTENANCE*. All public traffic is paused.');
                    }
                    else if (action === 'maint_off') {
                        global.MAINTENANCE_MODE = false;
                        popupMessage = "🟢 Maintenance Mode OFF";
                        await sendTelegramAlert('SYSTEM CONTROL', '🟢 Website is now *LIVE*. Normal operations resumed.');
                    }
                    else if (action === 'sys_status') {
                        const status = global.MAINTENANCE_MODE ? '🔴 UNDER MAINTENANCE' : '🟢 LIVE & HEALTHY';
                        const dbState = mongoose.connection.readyState === 1 ? '🟢 Connected' : '🔴 Disconnected';
                        const memMb = Math.round(process.memoryUsage().rss / 1024 / 1024);
                        popupMessage = `Status: ${status}`;
                        await sendTelegramAlert('SERVER TELEMETRY', `*Web Status:* ${status}
*Database:* ${dbState}
*RAM Usage:* ${memMb} MB
*Uptime:* ${Math.floor(process.uptime() / 60)} mins`);
                    }
                    else if (action === 'total_users') {
                        const total = await User.countDocuments({});
                        const active = await User.countDocuments({ accountStatus: 'active' });
                        popupMessage = `Total Users: ${total}`;
                        await sendTelegramAlert('USER DIRECTORY STATS', `👥 *Live Consumer Count*

*Total Registered:* ${total}
*Active Accounts:* ${active}`);
                    }
                    else if (action === 'clean_ram') {
                        await SystemError.deleteMany({});
                        if (typeof global.gc === 'function') global.gc();
                        popupMessage = "🧹 RAM & System Logs Cleared!";
                        await sendTelegramAlert('SYSTEM CONTROL', '🧹 *Memory Cleared*
Purged old system logs from database and freed Node.js memory successfully.');
                    }
                    else if (action === 'last_errors') {
                        const errors = await SystemError.find({}).sort({ timestamp: -1 }).limit(3).lean();
                        if (errors.length === 0) {
                            popupMessage = "Log is clean!";
                            await sendTelegramAlert('DIAGNOSTICS', '✅ No recent errors or security threats in database.');
                        } else {
                            let errText = `⚠️ *LAST 3 LOGS / ERRORS*

`;
                            errors.forEach((e, idx) => {
                                const t = new Date(e.timestamp).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });
                                errText += `*${idx + 1}. [${e.source}]*
⏱️ ${t}
📍 ${e.location}
💬 ${maskSensitiveData(e.message)}

`;
                            });
                            popupMessage = "Fetched last 3 logs.";
                            await sendTelegramAlert('DIAGNOSTICS', errText);
                        }
                    }

                    await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ callback_query_id: cb.id, text: popupMessage, show_alert: false })
                    });
                }
            }
        }
    } catch (e) {}
    setTimeout(listenTelegramCommands, 2500);
}

app.listen(PORT, () => {
    console.log(`[EMCS SERVER] Live on port ${PORT}`);
    setTimeout(() => {
        listenTelegramCommands();
        console.log('[EMCS] 🤖 Telegram Ghost-Mode Control Bot Active.');
    }, 3000);
});
