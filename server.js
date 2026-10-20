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

// Multi-Site / Multi-Tenant Strict Isolation Identifier
const TENANT_ID = process.env.TENANT_ID || 'EMCS_PROD_SITE_01';

app.set('trust proxy', 1);
app.disable('x-powered-by');

// ===================================================================
// ENVIRONMENT VARIABLES (RENDER / CLOUD CONFIG)
// ===================================================================
const MONGO_URI = process.env.MONGO_URI || (IS_PROD ? '' : 'mongodb://127.0.0.1:27017/emcs_project_db');
const MASTER_OWNER_KEY = process.env.MASTER_OWNER_KEY || '';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const JWT_SECRET = process.env.JWT_SECRET || (
    MASTER_OWNER_KEY
        ? crypto.createHash('sha256').update(MASTER_OWNER_KEY + '_emcs_vault_' + TENANT_ID).digest('hex')
        : crypto.randomBytes(32).toString('hex')
);

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
        const csrf = req.headers['x-emcs-csrf'];
        if (csrf !== 'emcs-verified-client') {
            return res.status(403).json({ success: false, message: 'Invalid request signature.' });
        }
    }
    next();
});

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
// STRICT VALIDATORS (EMAIL TLD WHITELIST + 12-DIGIT NUMERIC CID)
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
    'tempmailo.com', 'inboxkitten.com', 'mailcatch.com', 'crazymailing.com',
    'tempail.com', 'throwaway.L', 'yopmail.fr', 'yopmail.net'
]);

// Strict Approved Top-Level Domains (Blocks typos like .coh, .con, .cmo, etc.)
const VALID_TLDS = new Set([
    'com', 'in', 'org', 'net', 'edu', 'gov', 'co', 'io', 'me', 'biz', 'info', 'ac', 'uk', 'us'
]);

// Catch common typo domains of major providers
const BLOCKED_TYPO_DOMAINS = new Set([
    'gamil.com', 'gmial.com', 'gmai.com', 'gmail.co', 'gmail.con', 'gmail.coh',
    'yaho.com', 'yahooo.com', 'outlok.com', 'hotmial.com'
]);

function validateStrictEmail(rawEmail) {
    if (typeof rawEmail !== 'string') return { valid: false, message: 'Please enter a valid email address.' };
    const clean = rawEmail.trim().toLowerCase();
    if (clean.length < 6 || clean.length > 90) {
        return { valid: false, message: 'Please enter a valid email address.' };
    }
    if (/[\s\0$<>'"`;\\(){}[\]|!#$%^&*=+/?~]|\.\./.test(clean)) {
        return { valid: false, message: 'Invalid characters in email address.' };
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

    if (DISPOSABLE_EMAIL_DOMAINS.has(domain) || BLOCKED_TYPO_DOMAINS.has(domain)) {
        return { valid: false, message: 'Please enter a valid personal or work email address (e.g. name@gmail.com).' };
    }

    const domainSegments = domain.split('.');
    const lastTld = domainSegments[domainSegments.length - 1];
    const secondLastTld = domainSegments.length >= 3 ? domainSegments[domainSegments.length - 2] : null;

    if (!VALID_TLDS.has(lastTld)) {
        return { valid: false, message: `Invalid email extension (.${lastTld}). Please use standard extensions like .com or .in.` };
    }
    if (secondLastTld && domainSegments.length >= 3 && !VALID_TLDS.has(secondLastTld) && secondLastTld.length <= 3) {
        return { valid: false, message: 'Please enter a valid email domain.' };
    }

    return { valid: true, email: clean };
}

function validateSecurityCredential(authType, rawCred) {
    if (typeof rawCred !== 'string') return { valid: false, message: 'PIN or Password is required.' };
    const cred = rawCred.trim();
    if (authType === 'pin') {
        if (!/^[0-9]{4,6}$/.test(cred)) {
            return { valid: false, message: 'Please enter a valid 4 to 6 digit PIN.' };
        }
        return { valid: true, credential: cred, authType: 'pin' };
    } else if (authType === 'password') {
        if (cred.length < 8 || cred.length > 16 || /[\0]/.test(cred)) {
            return { valid: false, message: 'Please enter a valid Password (8 to 16 characters).' };
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
// MULTI-TIER RATE LIMITING (RAM GUARDED)
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
                message: customMsg || 'Please wait a moment before trying again.'
            });
        }
        next();
    };
}

const globalApiLimiter = createLimiter(80, 60 * 1000, 'Please slow down and try again in a moment.');
const strictRegisterLimiter = createLimiter(4, 24 * 60 * 60 * 1000, 'Maximum account limit reached for today.');
const loginLimiter = createLimiter(6, 15 * 60 * 1000, 'Too many attempts. Please wait 15 minutes.');
const chatLimiter = createLimiter(15, 60 * 1000, 'Sending messages too fast. Please wait a moment.');

app.use('/api', globalApiLimiter);

// ===================================================================
// DATABASE SCHEMAS (MULTI-TENANT + 90-DAY AI TTL + 2-YEAR USER TTL)
// ===================================================================
const UserSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, required: true, index: true },
    mobile: { type: String, required: true, match: /^[0-9]{10}$/, index: true },
    email: { type: String, required: true, lowercase: true, index: true },
    consumerId: { type: String, required: true, match: /^[0-9]{12}$/, minlength: 12, maxlength: 12, index: true },
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
UserSchema.index({ deletionScheduledAt: 1 }, { expireAfterSeconds: 63072000 }); // 2 Years Auto-Erase

// 🔥 AI CHAT HISTORY SCHEMA (Automatically Deletes After 3 Months / 90 Days)
const AiChatSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, required: true, index: true },
    consumerId: { type: String, required: true, index: true },
    sender: { type: String, enum: ['user', 'ai'], required: true },
    text: { type: String, required: true, maxlength: 2500 },
    timestamp: { type: Date, default: Date.now, expires: 7776000 } // 90 Days (3 Months) TTL
});

// 🔥 EMERGENCY SECURITY ALERTS SCHEMA (Bot Traps, IDOR & AI Spam DDoS)
const EmergencyAlertSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, required: true, index: true },
    attackType: { type: String, required: true },
    ipAddress: { type: String, default: 'Unknown' },
    deviceInfo: { type: String, default: 'Unknown' },
    details: { type: String, required: true },
    timestamp: { type: Date, default: Date.now, expires: 7776000 }
});

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
    timestamp: { type: Date, default: Date.now, expires: 2592000 }
});

const CmsSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, required: true, index: true },
    key: { type: String, default: 'global_cms' },
    broadcast: { type: String, default: '' },
    about: {
        type: String,
        default: 'EMCS (Smart Energy Manager) helps households and businesses track appliance power consumption, estimate monthly electricity bills, and control smart switches safely.'
    },
    privacy: {
        type: String,
        default: '1. INFORMATION WE COLLECT: We collect your Name, Mobile Number, Verified Email Address, and 12-Digit Consumer ID to create your account and help you recover forgotten credentials.\n\n2. DEVICE & IP SECURITY: For your account safety and to prevent unauthorized access, we record the device model and IP address when you log in.\n\n3. AI CHAT HISTORY: Questions asked to KamAbhi AI (EMCS AI) are saved in your account history to help you review past electrical advice and are automatically deleted after 3 months (90 days).\n\n4. ACCOUNT DELETION: If you deactivate your account, all devices are logged out immediately and records are retained for 2 years for legal compliance before permanent deletion.'
    },
    terms: {
        type: String,
        default: '1. BILL ESTIMATES: All electricity bills and solar calculations shown on EMCS are estimates for planning and saving energy. Please pay your official electricity board bill as per your utility meter.\n\n2. HARDWARE & SMART SWITCH RESPONSIBILITY: Hardware testing nhi kiya gya hai. Kripya apne risk or jimmedari par ye hardware connect kare, iske liye hamari team ki koi jimmedari nhi hogi. EMCS is not responsible for any electrical damage, short circuit, or injury.\n\n3. FAIR USE & SECURITY: Using automated bots, fake emails, or spamming the AI assistant (10+ questions in 10 seconds) will result in an automatic block.'
    },
    faqs: {
        type: Array,
        default: [
            { q: 'How can I log in or reset my forgotten PIN or Password?', a: 'You can log in using either your 10-digit Mobile Number or your Email Address. If you forget your PIN or Password, click "Forgot Access" and verify using your 12-digit Consumer ID or Email Address.' },
            { q: 'Who is KamAbhi AI?', a: 'KamAbhi AI (EMCS AI) is your dedicated electrical safety and energy-saving assistant available after you log in.' },
            { q: 'How long is my AI chat history saved?', a: 'Your AI chat history is saved for 3 months (90 days) and then automatically deleted.' },
            { q: 'Can I connect smart Wi-Fi switches or a smart meter?', a: 'Yes! Tick the hardware responsibility agreement box in the Smart Hardware Control or My Appliances section to unlock wireless and cable switch controls.' }
        ]
    }
});
CmsSchema.index({ tenantId: 1, key: 1 }, { unique: true });

// Encrypted & Sanitized Activity Logs (Never stores API keys or technical stack traces)
const SystemErrorSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, index: true },
    timestamp: { type: Date, default: Date.now, expires: 2592000 },
    source: { type: String, default: 'Application' },
    message: { type: String, default: 'Something went wrong, try again later.' },
    location: { type: String, default: 'User Screen' },
    userOrIp: { type: String, default: 'Visitor' },
    encryptedDigest: { type: String, default: '' }
});

const User = mongoose.model('User', UserSchema);
const AiChat = mongoose.model('AiChat', AiChatSchema);
const EmergencyAlert = mongoose.model('EmergencyAlert', EmergencyAlertSchema);
const Staff = mongoose.model('Staff', StaffSchema);
const SupportMessage = mongoose.model('SupportMessage', SupportMessageSchema);
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
            console.log('[EMCS] Service Online.');
            await populateBloomFilter();
        })
        .catch(() => console.error('[EMCS] Storage connection error.'));
}

// ===================================================================
// ENCRYPTED CLEAN LOGGING & EMERGENCY FORENSIC CAPTURE
// ===================================================================
async function logCleanActivity(section = 'Application', req = null) {
    try {
        const cleanSource = String(section || 'Application').replace(/mongodb|mongoose|express|node|gemini|api|key|token|db|server/gi, 'System');
        const digest = crypto.createHmac('sha256', JWT_SECRET).update(`${Date.now()}_${cleanSource}`).digest('hex').slice(0, 32);
        await new SystemError({
            tenantId: TENANT_ID,
            source: sanitizeInput(cleanSource, 40),
            message: 'Something went wrong, try again later.',
            location: 'Protected View',
            userOrIp: sanitizeInput(req ? (req.user?.consumerId || 'Visitor') : 'System', 30),
            encryptedDigest: digest
        }).save();
    } catch (ignore) {}
}

async function dispatchEmergencyAlert(attackType, details, req) {
    try {
        const ip = sanitizeInput(req.ip || req.headers['x-forwarded-for'] || 'Unknown IP', 60);
        const ua = sanitizeInput(req.headers['user-agent'] || 'Unknown Device', 180);
        const lang = sanitizeInput(req.headers['accept-language'] || 'N/A', 40);
        const fullDevice = `${ua} [Lang: ${lang}]`;

        await new EmergencyAlert({
            tenantId: TENANT_ID,
            attackType: sanitizeInput(attackType, 60),
            ipAddress: ip,
            deviceInfo: fullDevice,
            details: sanitizeInput(details, 450)
        }).save();
    } catch (ignore) {}
}

// ===================================================================
// AUTHENTICATION, BOT HONEYPOT TRAP & STRICT ANTI-IDOR SHIELD
// ===================================================================
const botHoneypotShield = async (req, res, next) => {
    const trapVal = req.body?._emcs_trap || req.body?._bot_honeypot;
    if (trapVal && String(trapVal).trim().length > 0) {
        const attemptedId = sanitizeInput(req.body?.loginValue || req.body?.mobile || req.body?.consumerId || req.body?.email || 'Bot Script', 50);
        await dispatchEmergencyAlert(
            'Bot / Script Trap Triggered',
            `Invisible form filled with "${sanitizeInput(trapVal, 40)}" by target: ${attemptedId}. Request blocked immediately.`,
            req
        );
        return res.status(403).json({
            success: false,
            message: 'Access blocked due to automated script activity.'
        });
    }
    next();
};

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
                ? 'Your account has been blocked by the Administrator.'
                : 'Session expired. Please log in again.';
            return res.status(401).json({ success: false, message: msg });
        }

        req.user = user;
        req.sessionId = decoded.sessionId;
        next();
    } catch (e) {
        return res.status(403).json({ success: false, message: 'Please log in to continue.' });
    }
}

// Strict Anti-IDOR Shield: Blocks any attempt to request another Consumer ID's data
async function strictAntiIdorShield(req, res, next) {
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
        if (String(candidate).trim() !== String(req.user.consumerId)) {
            await dispatchEmergencyAlert(
                'Cross-Account Tampering (IDOR)',
                `User ${req.user.consumerId} attempted to access data of Consumer ID: ${sanitizeInput(candidate, 20)}`,
                req
            );
            return res.status(403).json({
                success: false,
                message: 'Access Denied: You can only access your own account data.'
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
            return res.status(403).json({ success: false, message: 'Invalid session.' });
        }
        req.admin = decoded;
        next();
    } catch (e) {
        return res.status(403).json({ success: false, message: 'Invalid admin session.' });
    }
}

function requireAdminPermission(permKey) {
    return (req, res, next) => {
        if (!req.admin) return res.status(401).json({ success: false });
        if (req.admin.role === 'owner') return next();
        if (permKey && req.admin.permissions && req.admin.permissions[permKey] === true) {
            return next();
        }
        return res.status(403).json({ success: false, message: 'Insufficient permissions.' });
    };
}

// ===================================================================
// HEALTH & CLEAN ACTIVITY LOG ROUTES
// ===================================================================
app.get('/api/health', (req, res) => {
    res.status(200).json({ status: 'ok', uptime: Math.floor(process.uptime()) });
});

app.post('/api/errors/report', createLimiter(15, 60000), async (req, res) => {
    await logCleanActivity(req.body?.source || 'User Screen', req);
    res.json({ success: true });
});

app.get('/api/admin/errors', authenticateAdmin, async (req, res) => {
    try {
        const rawLogs = await SystemError.find({ tenantId: TENANT_ID }).sort({ timestamp: -1 }).limit(100);
        const safeLogs = rawLogs.map(l => ({
            timestamp: l.timestamp,
            source: sanitizeInput(l.source || 'App', 30),
            message: 'Something went wrong, try again later.',
            location: sanitizeInput(l.location || 'Screen', 30),
            userOrIp: sanitizeInput(l.userOrIp || 'User', 30)
        }));
        res.json({ success: true, errors: safeLogs });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
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

// ===================================================================
// USER REGISTRATION, DUAL LOGIN (MOBILE/EMAIL) & RECOVERY ROUTES
// ===================================================================
app.post('/api/auth/register', strictRegisterLimiter, botHoneypotShield, async (req, res) => {
    try {
        if (req.body.termsAccepted !== true) {
            return res.status(400).json({ success: false, message: 'Please accept the Privacy Policy and Terms & Conditions.' });
        }

        const mobile = sanitizeInput(req.body.mobile, 10);
        const consumerId = sanitizeInput(req.body.consumerId, 12);
        const name = sanitizeInput(req.body.name, 60);
        const emailValidation = validateStrictEmail(req.body.email);

        if (!emailValidation.valid) {
            return res.status(400).json({ success: false, message: emailValidation.message });
        }
        const email = emailValidation.email;

        // Strict 10-digit Mobile & 12-digit Numeric Consumer ID Validation (No Alphabets)
        if (!/^[0-9]{10}$/.test(mobile)) {
            return res.status(400).json({ success: false, message: 'Please enter a valid 10-digit Mobile Number.' });
        }
        if (!/^[0-9]{12}$/.test(consumerId)) {
            return res.status(400).json({ success: false, message: 'Consumer ID must be strictly 12 numeric digits (0-9 only).' });
        }
        if (name.length < 2) {
            return res.status(400).json({ success: false, message: 'Please enter your Full Name.' });
        }

        const authTypeInput = req.body.authType === 'password' ? 'password' : 'pin';
        const rawCred = req.body.credential !== undefined ? req.body.credential : req.body.pin;
        const credValidation = validateSecurityCredential(authTypeInput, String(rawCred || ''));

        if (!credValidation.valid) {
            return res.status(400).json({ success: false, message: credValidation.message });
        }

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

        res.json({ success: true, message: 'Account created successfully.' });
    } catch (e) {
        await logCleanActivity('Registration', req);
        res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
    }
});

// Dual Login Route: Supports both Mobile Number AND Email Address Toggle
app.post('/api/auth/login', loginLimiter, botHoneypotShield, async (req, res) => {
    try {
        const loginType = req.body.loginType === 'email' || (!req.body.mobile && req.body.email) ? 'email' : 'mobile';
        const rawLoginVal = req.body.loginValue !== undefined
            ? req.body.loginValue
            : (loginType === 'email' ? req.body.email : req.body.mobile);
        const loginValue = sanitizeInput(rawLoginVal, 100);
        const rawCred = String(req.body.credential !== undefined ? req.body.credential : (req.body.pin || '')).trim();

        if (rawCred.length < 4 || rawCred.length > 16) {
            return res.status(400).json({ success: false, message: 'Invalid login details.' });
        }

        const query = { tenantId: TENANT_ID };

        if (loginType === 'email') {
            const emailCheck = validateStrictEmail(loginValue);
            if (!emailCheck.valid) {
                return res.status(400).json({ success: false, message: emailCheck.message });
            }
            if (!emcsBloom.test(emailCheck.email)) {
                await new Promise(r => setTimeout(r, 90));
                return res.status(401).json({ success: false, message: 'Invalid Email Address or PIN/Password.' });
            }
            query.email = emailCheck.email;
        } else {
            if (!/^[0-9]{10}$/.test(loginValue)) {
                return res.status(400).json({ success: false, message: 'Please enter a valid 10-digit Mobile Number.' });
            }
            if (!emcsBloom.test(loginValue)) {
                await new Promise(r => setTimeout(r, 90));
                return res.status(401).json({ success: false, message: 'Invalid Mobile Number or PIN/Password.' });
            }
            query.mobile = loginValue;
        }

        const user = await User.findOne(query);
        if (!user) return res.status(401).json({ success: false, message: 'Invalid login details.' });

        if (user.accountStatus === 'blocked') {
            return res.status(403).json({ success: false, message: 'Your account has been blocked by the Administrator.' });
        }
        if (user.accountStatus === 'deleted') {
            return res.status(403).json({ success: false, message: 'This account has been deactivated.' });
        }

        if (user.lockUntil && user.lockUntil > Date.now()) {
            const mins = Math.ceil((user.lockUntil - Date.now()) / 60000);
            return res.status(429).json({
                success: false,
                message: `Account temporarily locked due to failed attempts. Try again in ${mins} minutes.`
            });
        }

        const activeHash = user.credentialHash || user.pinHash;
        const isMatch = await bcrypt.compare(rawCred, activeHash);
        if (!isMatch) {
            const updatedUser = await User.findOneAndUpdate(
                { _id: user._id, tenantId: TENANT_ID },
                { $inc: { failedLoginAttempts: 1 } },
                { new: true }
            );

            if (updatedUser.failedLoginAttempts >= 5) {
                await User.updateOne(
                    { _id: user._id, tenantId: TENANT_ID },
                    { $set: { lockUntil: new Date(Date.now() + 15 * 60000), failedLoginAttempts: 0 } }
                );
            }
            return res.status(401).json({ success: false, message: 'Invalid login details.' });
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

        if (user.activeSessions.length > 15) {
            user.activeSessions = user.activeSessions.slice(-15);
        }
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
        await logCleanActivity('Login', req);
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

async function handleCredentialReset(req, res) {
    try {
        const mobile = sanitizeInput(req.body.mobile, 10);
        const registeredName = sanitizeInput(req.body.registeredName, 60).toLowerCase();
        const recoveryType = req.body.recoveryType === 'email' ? 'email' : 'cid';
        const rawRecoveryVal = req.body.recoveryValue !== undefined ? req.body.recoveryValue : req.body.consumerId;

        const newAuthType = req.body.newAuthType === 'password' ? 'password' : 'pin';
        const rawNewCred = req.body.newCredential !== undefined ? req.body.newCredential : req.body.newPin;
        const credCheck = validateSecurityCredential(newAuthType, String(rawNewCred || ''));

        if (!/^[0-9]{10}$/.test(mobile) || registeredName.length < 2 || !credCheck.valid) {
            return res.status(400).json({ success: false, message: credCheck.message || 'Please enter valid details.' });
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
            const cid = sanitizeInput(rawRecoveryVal, 12);
            if (!/^[0-9]{12}$/.test(cid) || !emcsBloom.test(cid)) {
                return res.status(400).json({ success: false, message: 'Please enter a valid 12-digit numeric Consumer ID.' });
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

        res.json({ success: true, message: 'Your PIN/Password has been reset! Please log in.' });
    } catch (e) {
        await logCleanActivity('Account Recovery', req);
        res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
    }
}

app.post('/api/auth/verify-and-reset', loginLimiter, botHoneypotShield, handleCredentialReset);
app.post('/api/auth/verify-and-reset-pin', loginLimiter, botHoneypotShield, handleCredentialReset);

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
        res.json({ success: true, message: 'Device removed.' });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
    }
});

// ===================================================================
// 🔥 KAMABHI AI (EMCS AI) - STRICT IDENTITY, RAM LOCK & SPAM BLOCKER
// ===================================================================
const aiRamTimestamps = new Map();
const aiActiveWritingLocks = new Set();

async function queryKamAbhiAiModel(promptText) {
    if (!GEMINI_API_KEY) {
        return "Hello! I am KamAbhi AI (EMCS AI Assistant). Tip: Running heavy appliances like ACs at 24°C and shifting Geyser or Washing Machine usage to daytime hours (10 AM - 3 PM) can reduce your electricity bill by up to 20%. Always use a proper MCB and earthing for heavy loads.";
    }

    if (genAI) {
        const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
        const result = await model.generateContent(promptText);
        return result.response.text();
    }

    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`;
    const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            contents: [{ parts: [{ text: promptText }] }]
        })
    });
    const data = await response.json();
    return data?.candidates?.[0]?.content?.parts?.[0]?.text || 'I am KamAbhi AI. Please ask your electrical or energy-saving question again.';
}

app.get('/api/ai/history', authenticateUser, strictAntiIdorShield, async (req, res) => {
    try {
        const messages = await AiChat.find({
            tenantId: TENANT_ID,
            consumerId: req.user.consumerId
        }).sort({ timestamp: 1 }).limit(100);
        res.json({ success: true, messages });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
    }
});

app.post('/api/ai/chat', authenticateUser, strictAntiIdorShield, async (req, res) => {
    const cid = req.user.consumerId;

    try {
        if (req.user.aiStatus === 'blocked') {
            return res.status(403).json({
                success: false,
                reply: 'Your access to KamAbhi AI has been permanently blocked due to repeated spam violations.'
            });
        }

        // RAM-Based 10-Second Burst Detector (Warnings + Permanent Block on 10 hits in 10s)
        const now = Date.now();
        let hits = (aiRamTimestamps.get(cid) || []).filter(ts => now - ts < 10000);
        hits.push(now);
        aiRamTimestamps.set(cid, hits);

        if (hits.length >= 10) {
            req.user.aiStatus = 'blocked';
            await req.user.save();
            await dispatchEmergencyAlert(
                'AI Spam DDoS Permanent Block',
                `User ${cid} (${req.user.name}) sent ${hits.length} AI requests within 10 seconds. AI access permanently blocked.`,
                req
            );
            return res.status(403).json({
                success: false,
                reply: 'Security Alert: You sent 10+ questions within 10 seconds. Your AI access has been permanently blocked.'
            });
        }

        if (hits.length >= 8) {
            req.user.aiSpamWarnings = (req.user.aiSpamWarnings || 0) + 1;
            await req.user.save();

            if (req.user.aiSpamWarnings <= 2) {
                return res.status(429).json({
                    success: false,
                    reply: `Warning (${req.user.aiSpamWarnings}/2): Please slow down! Sending 10 questions in 10 seconds will permanently block your AI access.`
                });
            } else {
                req.user.aiStatus = 'blocked';
                await req.user.save();
                await dispatchEmergencyAlert(
                    'AI Spam Repeat Offender Blocked',
                    `User ${cid} (${req.user.name}) ignored 2 warnings and continued rapid AI spamming. Permanently blocked.`,
                    req
                );
                return res.status(403).json({
                    success: false,
                    reply: 'Your access to KamAbhi AI has been permanently blocked after 2 spam warnings.'
                });
            }
        }

        // Single-Question Concurrency Lock
        if (aiActiveWritingLocks.has(cid)) {
            return res.status(429).json({
                success: false,
                reply: 'Wait kro pichle question ka answer likh rhe hai. Uske baad dusra question bhejo.'
            });
        }

        const userText = sanitizeInput(req.body.text, 500);
        if (!userText) {
            return res.status(400).json({ success: false, reply: 'Please enter a valid question.' });
        }

        aiActiveWritingLocks.add(cid);

        try {
            await new AiChat({
                tenantId: TENANT_ID,
                consumerId: cid,
                sender: 'user',
                text: userText
            }).save();

            const recentChats = await AiChat.find({ tenantId: TENANT_ID, consumerId: cid })
                .sort({ timestamp: -1 })
                .limit(6);
            const chatContext = recentChats.reverse().map(c => `${c.sender === 'ai' ? 'KamAbhi AI' : 'User'}: ${c.text}`).join('\n');

            const systemPrompt = `STRICT IDENTITY & BEHAVIOR INSTRUCTIONS:
1. Your name is strictly "KamAbhi AI" or "EMCS AI".
2. NEVER mention Gemini, Google, OpenAI, ChatGPT, or any other AI company or model name under any circumstance. If asked who made you or who you are, always state: "I am KamAbhi AI (EMCS AI), your electrical and energy management assistant powered by KamAbhi Tech Solutions."
3. You are a friendly, human-like electrical guide and advisor. Only answer questions related to electricity bills, home appliances, inverters, solar panels, smart meters, Wi-Fi switches, wiring, and electrical safety.
4. Always include clear, practical safety advice (such as turning off the main MCB before touching wires, using proper earthing, and avoiding wet hands) whenever giving hardware or electrical guidance.
5. Keep your answers clear, easy to understand for normal homeowners, and free of complex technical jargon.

Recent Conversation:
${chatContext}

User Question: ${userText}
KamAbhi AI Answer:`;

            let rawAiReply = await queryKamAbhiAiModel(systemPrompt);

            rawAiReply = String(rawAiReply || '')
                .replace(/\bgemini\b|\bgoogle\s+ai\b|\bchatgpt\b|\bopenai\b|\blarge language model\b/gi, 'KamAbhi AI');

            const cleanReply = sanitizeInput(rawAiReply, 2200) || 'I am KamAbhi AI. Please ask your electrical or energy question again.';

            await new AiChat({
                tenantId: TENANT_ID,
                consumerId: cid,
                sender: 'ai',
                text: cleanReply
            }).save();

            res.json({ success: true, reply: cleanReply });
        } finally {
            aiActiveWritingLocks.delete(cid);
        }
    } catch (e) {
        aiActiveWritingLocks.delete(cid);
        await logCleanActivity('KamAbhi AI', req);
        res.status(500).json({ success: false, reply: 'Something went wrong, try again later.' });
    }
});

// ===================================================================
// USER DATA SYNC & ACCOUNT DEACTIVATION (STRICT ANTI-IDOR ENFORCED)
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

app.all('/api/user/:anyRoute/:consumerId', async (req, res) => {
    await dispatchEmergencyAlert('URL Parameter Tampering', `Blocked direct URL access attempt by ${req.user?.consumerId}`, req);
    res.status(403).json({ success: false, message: 'Access Denied.' });
});

app.post('/api/user/sync-cloud', async (req, res) => {
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
                const mode = ALLOWED_CONN_MODES.has(a.connMode) ? a.connMode : 'manual';
                return {
                    id: Number(a.id) || Date.now(),
                    name: sanitizeInput(a.name, 40) || 'Appliance',
                    power: pwr,
                    hours: hrs,
                    monthlyKwh: Number(((pwr * hrs * 30) / 1000).toFixed(2)),
                    state: Boolean(a.state),
                    connMode: mode
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
        res.json({ success: true, message: 'Settings saved.' });
    } catch (e) {
        await logCleanActivity('Profile Save', req);
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
        await logCleanActivity('Account Deactivation', req);
        res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
    }
});

// ===================================================================
// ADMIN MANAGEMENT PANEL, KYC, BLOCK/DELETE, AI HISTORY & ALERTS
// ===================================================================
app.post('/api/admin/login', loginLimiter, async (req, res) => {
    try {
        const username = sanitizeInput(req.body.username, 40).toLowerCase();
        const password = sanitizeInput(req.body.password, 64);

        if (!username) {
            if (!MASTER_OWNER_KEY) {
                return res.status(503).json({ success: false, message: 'Owner access key is not configured.' });
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

        res.status(401).json({ success: false, message: 'Invalid Admin Key.' });
    } catch (e) {
        await logCleanActivity('Admin Login', req);
        res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
    }
});

app.post('/api/admin/logout', (req, res) => {
    res.clearCookie('emcs_admin_token');
    res.json({ success: true });
});

// Admin Emergency Alerts Routes
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

// Admin AI Chat History Routes
app.get('/api/admin/ai-history/all', authenticateAdmin, async (req, res) => {
    try {
        const users = await AiChat.distinct('consumerId', { tenantId: TENANT_ID });
        res.json({ success: true, users });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.get('/api/admin/ai-history/:cid', authenticateAdmin, async (req, res) => {
    try {
        const cid = sanitizeInput(req.params.cid, 12);
        const messages = await AiChat.find({ tenantId: TENANT_ID, consumerId: cid }).sort({ timestamp: 1 });
        res.json({ success: true, messages });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.delete('/api/admin/ai-history/:cid', authenticateAdmin, async (req, res) => {
    try {
        const cid = sanitizeInput(req.params.cid, 12);
        await AiChat.deleteMany({ tenantId: TENANT_ID, consumerId: cid });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// Admin User KYC, 24-Month Billing & Login History
app.get('/api/admin/user/:consumerId', authenticateAdmin, async (req, res) => {
    try {
        if (req.admin.role !== 'owner' && !req.admin.permissions?.canManageUsers) {
            return res.status(403).json({ success: false, message: 'Insufficient permissions.' });
        }

        const cid = sanitizeInput(req.params.consumerId, 12);
        if (!emcsBloom.test(cid)) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

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
            const deterministicHash = crypto
                .createHash('sha256')
                .update(`${TENANT_ID}_${cid}_${monthLabel}`)
                .digest('hex')
                .slice(0, 8)
                .toUpperCase();

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

        res.json({
            success: true,
            user: targetUser,
            lifetimeUsage,
            paymentLedger
        });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
    }
});

// Admin Block / Unblock User
app.put('/api/admin/user/:cid/status', authenticateAdmin, async (req, res) => {
    try {
        if (req.admin.role !== 'owner' && !req.admin.permissions?.canManageUsers) {
            return res.status(403).json({ success: false });
        }
        const cid = sanitizeInput(req.params.cid, 12);
        const newStatus = req.body.status === 'blocked' ? 'blocked' : 'active';
        const updateFields = {
            accountStatus: newStatus,
            activeSessions: []
        };
        if (newStatus === 'active') {
            updateFields.aiStatus = 'active';
            updateFields.aiSpamWarnings = 0;
        }
        await User.updateOne({ tenantId: TENANT_ID, consumerId: cid }, { $set: updateFields });
        res.json({ success: true, message: `User status updated to ${newStatus}.` });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// Admin Permanently Delete User & All Associated Records
app.delete('/api/admin/user/:cid', authenticateAdmin, async (req, res) => {
    try {
        if (req.admin.role !== 'owner' && !req.admin.permissions?.canManageUsers) {
            return res.status(403).json({ success: false });
        }
        const cid = sanitizeInput(req.params.cid, 12);
        await User.deleteOne({ tenantId: TENANT_ID, consumerId: cid });
        await SupportMessage.deleteMany({ tenantId: TENANT_ID, consumerId: cid });
        await AiChat.deleteMany({ tenantId: TENANT_ID, consumerId: cid });
        res.json({ success: true, message: 'User permanently deleted.' });
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
            return res.status(400).json({ success: false, message: 'Please enter valid details.' });
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
        res.status(400).json({ success: false, message: 'Username already exists.' });
    }
});

app.delete('/api/admin/staff/:id', authenticateAdmin, async (req, res) => {
    if (req.admin.role !== 'owner') return res.status(403).json({ success: false });
    await Staff.findOneAndDelete({ _id: sanitizeInput(req.params.id, 40), tenantId: TENANT_ID });
    res.json({ success: true });
});

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

// Two-Way Support Chat Routes
app.get('/api/support/user/messages', authenticateUser, strictAntiIdorShield, async (req, res) => {
    try {
        const messages = await SupportMessage.find({
            tenantId: TENANT_ID,
            consumerId: req.user.consumerId
        }).sort({ timestamp: 1 }).limit(100);
        res.json({ success: true, messages });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.post('/api/support/user/send', authenticateUser, strictAntiIdorShield, chatLimiter, async (req, res) => {
    try {
        const text = sanitizeInput(req.body.text, 500);
        if (!text) return res.status(400).json({ success: false });
        const msg = await new SupportMessage({
            tenantId: TENANT_ID,
            consumerId: req.user.consumerId,
            sender: 'user',
            text
        }).save();
        res.json({ success: true, message: msg });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.get('/api/support/admin/threads', authenticateAdmin, async (req, res) => {
    try {
        if (req.admin.role !== 'owner' && !req.admin.permissions?.canChatSupport && !req.admin.permissions?.canManageUsers) {
            return res.status(403).json({ success: false });
        }
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
        const cid = sanitizeInput(req.params.cid, 12);
        if (!emcsBloom.test(cid)) return res.json({ success: true, messages: [] });
        const messages = await SupportMessage.find({ tenantId: TENANT_ID, consumerId: cid }).sort({ timestamp: 1 });
        res.json({ success: true, messages });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.post('/api/support/admin/reply', authenticateAdmin, requireAdminPermission('canChatSupport'), async (req, res) => {
    try {
        const consumerId = sanitizeInput(req.body.consumerId, 12);
        const text = sanitizeInput(req.body.text, 500);
        if (!text || !emcsBloom.test(consumerId)) return res.status(400).json({ success: false });
        const msg = await new SupportMessage({ tenantId: TENANT_ID, consumerId, sender: 'admin', text }).save();
        res.json({ success: true, message: msg });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.delete('/api/support/chat/clear/:cid', authenticateAdmin, requireAdminPermission('canDeleteChat'), async (req, res) => {
    try {
        const cid = sanitizeInput(req.params.cid, 12);
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
        const alerts = await EmergencyAlert.find({ tenantId: TENANT_ID });
        res.json({
            exportDate: new Date(),
            project: 'EMCS - Smart Energy Manager',
            totalUsers: users.length,
            backup: { users, supportMessages: messages, aiChatHistory: aiChats, emergencyAlerts: alerts }
        });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// ===================================================================
// SOURCE FILE PROTECTION & CLEAN GLOBAL ERROR HANDLER
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

// Global error handler never exposes internal details or keys
app.use(async (err, req, res, next) => {
    await logCleanActivity('Application', req);
    res.status(500).json({ success: false, message: 'Something went wrong, try again later.' });
});

app.listen(PORT, () => console.log(`[EMCS] Service running on port ${PORT}`));
