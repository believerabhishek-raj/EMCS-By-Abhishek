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

// Multi-Site / Multi-Tenant Strict Isolation Identifier
const TENANT_ID = process.env.TENANT_ID || 'EMCS_PROD_SITE_01';

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
        ? crypto.createHash('sha256').update(MASTER_OWNER_KEY + '_emcs_prod_vault_' + TENANT_ID).digest('hex')
        : crypto.randomBytes(32).toString('hex')
);

if (!MASTER_OWNER_KEY) {
    console.warn('[SECURITY WARNING] MASTER_OWNER_KEY is not set in Environment Variables! Master Owner login will remain disabled until configured.');
}

// Strict payload size limit (10kb) to prevent memory exhaustion / freeze attacks
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

    if (['POST', 'DELETE', 'PUT'].includes(req.method) && req.path.startsWith('/api/')) {
        const csrf = req.headers['x-emcs-csrf'];
        if (csrf !== 'emcs-verified-client') {
            return res.status(403).json({ success: false, message: 'Forbidden: Invalid request signature.' });
        }
    }
    next();
});

// ===================================================================
// 🚀 BLOOM FILTER IMPLEMENTATION (O(1) Memory Bouncer Against Phantom DoS)
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
// STRICT INPUT VALIDATION, EMAIL SECURITY & SANITIZATION HELPERS
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
    if (typeof rawEmail !== 'string') return { valid: false, message: 'Email address is required.' };
    const clean = rawEmail.trim().toLowerCase();
    if (clean.length < 6 || clean.length > 90) {
        return { valid: false, message: 'Email address must be between 6 and 90 characters.' };
    }
    // Block control chars, quotes, brackets, spaces, SQL/NoSQL operators, and consecutive dots
    if (/[\s\0$<>'"`;\\(){}[\]|!#$%^&*=+/?~]|\.\./.test(clean)) {
        return { valid: false, message: 'Security Block: Email contains restricted characters.' };
    }
    // Strict RFC-compliant structure check (No ReDoS backtracking risk)
    const parts = clean.split('@');
    if (parts.length !== 2) return { valid: false, message: 'Invalid email format.' };
    const [local, domain] = parts;

    if (!/^[a-z0-9]+([._-][a-z0-9]+)*$/.test(local) || local.length < 2 || local.length > 60) {
        return { valid: false, message: 'Invalid email username format.' };
    }
    if (!/^[a-z0-9]+(-[a-z0-9]+)*(\.[a-z0-9]+(-[a-z0-9]+)*)+$/.test(domain)) {
        return { valid: false, message: 'Invalid email domain format.' };
    }
    const tld = domain.split('.').pop();
    if (!/^[a-z]{2,10}$/.test(tld)) {
        return { valid: false, message: 'Invalid email top-level domain.' };
    }
    if (DISPOSABLE_EMAIL_DOMAINS.has(domain)) {
        return { valid: false, message: 'Security Block: Temporary or disposable email addresses are strictly prohibited.' };
    }
    return { valid: true, email: clean };
}

function validateSecurityCredential(authType, rawCred) {
    if (typeof rawCred !== 'string') return { valid: false, message: 'Security credential is required.' };
    const cred = rawCred.trim();
    if (authType === 'pin') {
        if (!/^[0-9]{4,6}$/.test(cred)) {
            return { valid: false, message: 'Security PIN must be strictly 4 to 6 numeric digits.' };
        }
        return { valid: true, credential: cred, authType: 'pin' };
    } else if (authType === 'password') {
        if (cred.length < 8 || cred.length > 16 || /[\0]/.test(cred)) {
            return { valid: false, message: 'Security Password must be between 8 and 16 characters.' };
        }
        return { valid: true, credential: cred, authType: 'password' };
    }
    return { valid: false, message: 'Invalid security method selected.' };
}

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
        const key = `${TENANT_ID}_${req.ip}_${req.baseUrl || req.path}`;
        const now = Date.now();
        let rec = rateLimits.get(key) || { count: 0, resetAt: now + windowMs };
        if (now > rec.resetAt) rec = { count: 0, resetAt: now + windowMs };

        const allowedMax = req.isSuspiciousProxy ? Math.max(1, Math.floor(maxReqs / 2)) : maxReqs;
        rec.count++;

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
// DATABASE SCHEMAS (STRICT TENANT_ID ISOLATION & 2-YEAR TTL INDEX)
// ===================================================================
const UserSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, required: true, index: true },
    mobile: { type: String, required: true, index: true },
    email: { type: String, required: true, lowercase: true, index: true },
    consumerId: { type: String, required: true, minlength: 12, maxlength: 12, index: true },
    name: { type: String, required: true },
    authType: { type: String, enum: ['pin', 'password'], default: 'pin' },
    credentialHash: { type: String, required: true },
    pinHash: { type: String, default: '' }, // Legacy backward compatibility
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
    accountStatus: { type: String, default: 'active', enum: ['active', 'deleted'] },
    deletionScheduledAt: { type: Date, default: null }
}, { timestamps: true });

// Compound indexes ensure zero cross-site collision even on a shared database cluster
UserSchema.index({ tenantId: 1, mobile: 1 }, { unique: true });
UserSchema.index({ tenantId: 1, email: 1 }, { unique: true });
UserSchema.index({ tenantId: 1, consumerId: 1 }, { unique: true });
UserSchema.index({ deletionScheduledAt: 1 }, { expireAfterSeconds: 63072000 });

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
        default: 'EMCS (Energy Management Control System) is an intelligent energy monitoring, tariff estimation, and load automation platform.'
    },
    privacy: {
        type: String,
        default: '1. DATA COLLECTION & SECURITY (DPDP Act 2023 Compliance): We collect minimal data (Mobile, Verified Email ID, Consumer ID, Name) strictly for authentication, account recovery, and load monitoring. FOR SECURITY & ANTI-FRAUD PURPOSES, we explicitly log your Device Models (OS/Browser) and IP Addresses during login to prevent unauthorized cross-account access (Anti-IDOR) and secure active sessions.\n\n2. OCR & FILE UPLOADS: Bill images uploaded for OCR and CSV files are processed securely in memory. We do not permanently store images of your physical electricity bills.\n\n3. DATA RETENTION & ERASURE: Upon account deactivation, all sessions are revoked immediately, and records enter a secured 2-year retention archive for compliance before automatic permanent erasure.\n\n4. COOKIES: We use HTTP-only cookies strictly for session authorization.'
    },
    terms: {
        type: String,
        default: '1. ACCEPTANCE OF TERMS: By using EMCS, you agree to these legal terms.\n\n2. NO FINANCIAL LIABILITY: The electricity bills, solar ROI, and tariff calculations provided by EMCS are "Estimates" based on standard utility slabs. EMCS is not an official billing authority. You must pay your actual utility provider based on their official meter readings.\n\n3. ACCOUNT & EMAIL SECURITY: Users must register with a valid, non-disposable email address. Attempting to manipulate URLs, Consumer IDs, or API payloads to access another consumer\'s profile is a strict security violation and will result in immediate session termination and IP logging.\n\n4. HARDWARE & IOT SAFETY WAIVER: The hardware relay control, voltage surge guard, and IoT features are provided "AS IS". EMCS and its developers are NOT liable for any electrical damage, short circuits, hardware failure, fire hazards, or personal injury resulting from automated appliance switching. Use IoT features at your own risk.\n\n5. PAYMENTS: EMCS provides a simulated 24-month settlement ledger. No real financial transactions are processed on this platform.'
    },
    faqs: {
        type: Array,
        default: [
            { q: 'How can I reset my forgotten PIN or Password?', a: 'Open the Login modal, select "Forgot Access", and verify your identity using either your 12-Character Consumer ID OR your Registered Email ID to set a new 4-6 digit PIN or 8-16 character Password.' },
            { q: 'Why does EMCS log my Device Model and IP Address?', a: 'For your account security. Logging device models and IP addresses allows you and system administrators to detect suspicious logins, block cross-account (IDOR) tampering, and revoke unauthorized sessions.' },
            { q: 'Are temporary or disposable email addresses allowed?', a: 'No. To protect the platform from automated bots and ensure reliable account recovery, disposable email domains are strictly blocked.' },
            { q: 'Are the electricity bills shown here official?', a: 'No. All bills and solar ROI figures are estimates calculated using state/private DISCOM tariff slabs for planning and energy-saving purposes.' },
            { q: 'How does the 2-year account deletion policy work?', a: 'When you deactivate your account, all active devices are logged out immediately and your records are automatically erased after 2 years.' }
        ]
    }
});
CmsSchema.index({ tenantId: 1, key: 1 }, { unique: true });

const SystemErrorSchema = new mongoose.Schema({
    tenantId: { type: String, default: TENANT_ID, index: true },
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

async function populateBloomFilter() {
    try {
        const users = await User.find({ tenantId: TENANT_ID }, 'mobile email consumerId');
        users.forEach(u => {
            if (u.mobile) emcsBloom.add(u.mobile);
            if (u.email) emcsBloom.add(u.email);
            if (u.consumerId) emcsBloom.add(u.consumerId);
        });
        console.log(`[BLOOM FILTER] Hydrated ${users.length} records for tenant: ${TENANT_ID}`);
    } catch (e) {
        console.error('[BLOOM FILTER] Hydration error:', e.message);
    }
}

if (MONGO_URI) {
    mongoose.connect(MONGO_URI)
        .then(async () => {
            console.log(`[EMCS VAULT] Connected to database (Tenant: ${TENANT_ID}).`);
            await populateBloomFilter();
        })
        .catch(err => console.error('[EMCS VAULT] Connection failed:', err.message));
}

// Internal server-side error logger (Never leaks stack traces to client)
async function logBackendError(source, err, req = null) {
    try {
        await new SystemError({
            tenantId: TENANT_ID,
            source: sanitizeInput(source || 'Secure Storage Layer', 50),
            message: sanitizeInput(err?.message || String(err), 300),
            location: sanitizeInput(req ? `${req.method} ${req.originalUrl}` : 'Internal', 150),
            userOrIp: sanitizeInput(req ? (req.user?.consumerId || req.ip) : 'System', 60)
        }).save();
    } catch (ignore) {}
}

// ===================================================================
// AUTHENTICATION, TENANT ISOLATION & STRICT ANTI-IDOR SHIELD
// ===================================================================
async function authenticateUser(req, res, next) {
    const token = req.cookies.emcs_auth_token;
    if (!token) return res.status(401).json({ success: false, message: 'Authentication required. Please log in.' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        if (decoded.tenantId && decoded.tenantId !== TENANT_ID) {
            res.clearCookie('emcs_auth_token');
            return res.status(403).json({ success: false, message: 'Cross-site token rejected.' });
        }

        const user = await User.findOne({ _id: decoded.userId, tenantId: TENANT_ID });

        if (!user || user.accountStatus === 'deleted' || !user.activeSessions.some(s => s.sessionId === decoded.sessionId)) {
            res.clearCookie('emcs_auth_token');
            return res.status(401).json({ success: false, message: 'Session expired or invalid.' });
        }

        req.user = user;
        req.sessionId = decoded.sessionId;
        next();
    } catch (e) {
        return res.status(403).json({ success: false, message: 'Invalid session credentials.' });
    }
}

// 🔥 STRICT ANTI-IDOR SHIELD: Blocks any URL, Query, or Body Consumer ID Tampering
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
            logBackendError(
                'SECURITY_VIOLATION_IDOR',
                `Blocked cross-account access! Authenticated ${req.user.consumerId} attempted to access ${sanitizeInput(candidate, 20)}`,
                req
            );
            return res.status(403).json({
                success: false,
                message: 'Security Block: Cross-account Consumer ID tampering detected and logged.'
            });
        }
    }
    next();
}

async function authenticateAdmin(req, res, next) {
    const token = req.cookies.emcs_admin_token;
    if (!token) return res.status(401).json({ success: false, message: 'Admin authentication required.' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        if (decoded.tenantId && decoded.tenantId !== TENANT_ID) {
            res.clearCookie('emcs_admin_token');
            return res.status(403).json({ success: false, message: 'Cross-site admin token rejected.' });
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
        await new SystemError({ tenantId: TENANT_ID, source, message, location, userOrIp }).save();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.get('/api/admin/errors', authenticateAdmin, async (req, res) => {
    try {
        const errors = await SystemError.find({ tenantId: TENANT_ID }).sort({ timestamp: -1 }).limit(100);
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
        await SystemError.deleteMany({ tenantId: TENANT_ID });
        res.json({ success: true, message: 'All error logs cleared.' });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// ===================================================================
// USER AUTHENTICATION, REGISTRATION & DUAL RECOVERY ROUTES
// ===================================================================
app.post('/api/auth/register', strictRegisterLimiter, async (req, res) => {
    try {
        if (req.body._bot_honeypot && String(req.body._bot_honeypot).length > 0) {
            return res.status(403).json({ success: false, message: 'Automated registration blocked.' });
        }

        if (req.body.termsAccepted !== true) {
            return res.status(400).json({ success: false, message: 'You must accept the Privacy Policy and Terms & Conditions.' });
        }

        const mobile = sanitizeInput(req.body.mobile, 10);
        const consumerId = sanitizeInput(req.body.consumerId, 12).toUpperCase();
        const name = sanitizeInput(req.body.name, 60);
        const emailValidation = validateStrictEmail(req.body.email);

        if (!emailValidation.valid) {
            return res.status(400).json({ success: false, message: emailValidation.message });
        }
        const email = emailValidation.email;

        const authTypeInput = req.body.authType === 'password' ? 'password' : 'pin';
        const rawCred = req.body.credential !== undefined ? req.body.credential : req.body.pin;
        const credValidation = validateSecurityCredential(authTypeInput, String(rawCred || ''));

        if (!credValidation.valid) {
            return res.status(400).json({ success: false, message: credValidation.message });
        }

        if (!/^[0-9]{10}$/.test(mobile) || !/^[A-Z0-9]{12}$/.test(consumerId) || name.length < 2) {
            return res.status(400).json({ success: false, message: 'Invalid input format. Check 10-digit Mobile and 12-char alphanumeric Consumer ID.' });
        }

        // 🚀 BLOOM FILTER CHECK: Only query DB if Bloom Filter indicates possible match
        if (emcsBloom.test(mobile) || emcsBloom.test(consumerId) || emcsBloom.test(email)) {
            const existing = await User.findOne({
                tenantId: TENANT_ID,
                $or: [{ mobile }, { consumerId }, { email }]
            });
            if (existing) {
                return res.status(400).json({ success: false, message: 'Registration failed: Mobile, Email, or Consumer ID is already registered.' });
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

        // Add to Bloom Filter in memory
        emcsBloom.add(mobile);
        emcsBloom.add(email);
        emcsBloom.add(consumerId);

        res.json({ success: true, message: 'Account created securely.' });
    } catch (e) {
        await logBackendError('Register Route', e, req);
        res.status(500).json({ success: false, message: 'Something went wrong. Please try again later.' });
    }
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const mobile = sanitizeInput(req.body.mobile, 10);
        const rawCred = String(req.body.credential !== undefined ? req.body.credential : (req.body.pin || '')).trim();

        if (!/^[0-9]{10}$/.test(mobile) || rawCred.length < 4 || rawCred.length > 16) {
            return res.status(400).json({ success: false, message: 'Invalid mobile number or security credential.' });
        }

        // 🚀 ANTI-PHANTOM DOS: Reject non-existent mobile numbers in O(1) memory without touching MongoDB
        if (!emcsBloom.test(mobile)) {
            await new Promise(r => setTimeout(r, 90));
            return res.status(401).json({ success: false, message: 'Invalid mobile number or security credential.' });
        }

        const user = await User.findOne({ tenantId: TENANT_ID, mobile });
        if (!user) return res.status(401).json({ success: false, message: 'Invalid mobile number or security credential.' });

        if (user.accountStatus === 'deleted') {
            return res.status(403).json({ success: false, message: 'This account has been deactivated.' });
        }

        if (user.lockUntil && user.lockUntil > Date.now()) {
            const mins = Math.ceil((user.lockUntil - Date.now()) / 60000);
            return res.status(429).json({
                success: false,
                isLocked: true,
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
            return res.status(401).json({ success: false, message: 'Invalid mobile number or security credential.' });
        }

        await User.updateOne(
            { _id: user._id, tenantId: TENANT_ID },
            { $set: { failedLoginAttempts: 0, lockUntil: null } }
        );

        const sessionId = crypto.randomBytes(24).toString('hex');
        user.activeSessions.push({
            sessionId,
            deviceInfo: sanitizeInput(req.headers['user-agent'], 90) || 'Browser Client',
            ipAddress: sanitizeInput(req.ip, 45)
        });

        // Retain last 15 login sessions for forensic audit
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
        await logBackendError('Login Route', e, req);
        res.status(500).json({ success: false, message: 'Something went wrong. Please try again later.' });
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

// Dual Recovery Handler (Supports Consumer ID OR Email ID + New PIN OR Password)
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
            return res.status(400).json({ success: false, message: credCheck.message || 'Invalid recovery details provided.' });
        }

        // 🚀 ANTI-PHANTOM DOS: Check Mobile in Bloom Filter first
        if (!emcsBloom.test(mobile)) {
            await new Promise(r => setTimeout(r, 90));
            return res.status(400).json({ success: false, message: 'Verification failed. Details do not match our records.' });
        }

        const query = { tenantId: TENANT_ID, mobile, accountStatus: 'active' };
        if (recoveryType === 'email') {
            const emailCheck = validateStrictEmail(rawRecoveryVal);
            if (!emailCheck.valid || !emcsBloom.test(emailCheck.email)) {
                return res.status(400).json({ success: false, message: 'Verification failed. Details do not match our records.' });
            }
            query.email = emailCheck.email;
        } else {
            const cid = sanitizeInput(rawRecoveryVal, 12).toUpperCase();
            if (!/^[A-Z0-9]{12}$/.test(cid) || !emcsBloom.test(cid)) {
                return res.status(400).json({ success: false, message: 'Verification failed. Details do not match our records.' });
            }
            query.consumerId = cid;
        }

        const user = await User.findOne(query);
        if (!user || user.name.toLowerCase() !== registeredName) {
            return res.status(400).json({ success: false, message: 'Verification failed. Details do not match our records.' });
        }

        user.authType = credCheck.authType;
        user.credentialHash = await bcrypt.hash(credCheck.credential, 12);
        user.failedLoginAttempts = 0;
        user.lockUntil = null;
        user.activeSessions = []; // Revoke all active sessions on credential reset
        await user.save();

        res.json({ success: true, message: 'Security credentials reset successfully! Please log in.' });
    } catch (e) {
        await logBackendError('Credential Reset Route', e, req);
        res.status(500).json({ success: false, message: 'Something went wrong. Please try again later.' });
    }
}

app.post('/api/auth/verify-and-reset', loginLimiter, handleCredentialReset);
app.post('/api/auth/verify-and-reset-pin', loginLimiter, handleCredentialReset);

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
// USER DATA SYNC & ACCOUNT DELETION (STRICT ANTI-IDOR ENFORCED)
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

// Catch any attempt to pass a consumerId parameter in the URL path (e.g. /api/user/profile/EM1234567890)
app.all('/api/user/:anyRoute/:consumerId', (req, res) => {
    res.status(403).json({
        success: false,
        message: 'Security Block: Direct URL parameter access is prohibited.'
    });
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
                return {
                    id: Number(a.id) || Date.now(),
                    name: sanitizeInput(a.name, 40) || 'Appliance',
                    power: pwr,
                    hours: hrs,
                    monthlyKwh: Number(((pwr * hrs * 30) / 1000).toFixed(2)),
                    state: Boolean(a.state)
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

app.delete('/api/user/delete-account', async (req, res) => {
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
// ADMIN, STAFF RBAC, KYC FORENSICS, CMS & SUPPORT DESK ROUTES
// ===================================================================
app.post('/api/admin/login', loginLimiter, async (req, res) => {
    try {
        const username = sanitizeInput(req.body.username, 40).toLowerCase();
        const password = sanitizeInput(req.body.password, 64);

        if (!username) {
            if (!MASTER_OWNER_KEY) {
                return res.status(503).json({ success: false, message: 'Master Owner key is not configured on the server.' });
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

// 🔥 ADMIN CONSUMER KYC, IP FORENSICS & 24-MONTH BILLING LEDGER ENDPOINT
app.get('/api/admin/user/:consumerId', authenticateAdmin, async (req, res) => {
    try {
        if (req.admin.role !== 'owner' && !req.admin.permissions?.canManageUsers) {
            return res.status(403).json({ success: false, message: 'Forbidden: Insufficient permissions to view KYC.' });
        }

        const cid = sanitizeInput(req.params.consumerId, 12).toUpperCase();
        if (!/^[A-Z0-9]{12}$/.test(cid) || !emcsBloom.test(cid)) {
            return res.status(404).json({ success: false, message: 'Consumer not found in this tenant.' });
        }

        const targetUser = await User.findOne({ tenantId: TENANT_ID, consumerId: cid }, '-credentialHash -pinHash');
        if (!targetUser) {
            return res.status(404).json({ success: false, message: 'Consumer not found in this tenant.' });
        }

        const createdTime = targetUser.createdAt ? new Date(targetUser.createdAt).getTime() : Date.now();
        const monthsActive = Math.max(1, (Date.now() - createdTime) / (1000 * 60 * 60 * 24 * 30));
        let monthlyKwh = 0;
        (targetUser.appliances || []).forEach(a => {
            if (a.state) monthlyKwh += parseFloat(a.monthlyKwh) || 0;
        });
        const lifetimeUsage = (monthsActive * monthlyKwh).toFixed(1);

        // Generate 24-Month (2-Year Legal Retention) Billing & Settlement Ledger
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

            // Slight realistic seasonal variance around active load
            const varianceFactor = 0.92 + ((i % 5) * 0.04);
            const billedUnits = (monthlyKwh * varianceFactor).toFixed(1);
            const fixedCharge = (targetUser.sanctionedLoadKw || 2.0) * 80;
            const billedAmt = Math.round((parseFloat(billedUnits) * 6.85) + (monthlyKwh > 0 ? fixedCharge : 0));

            paymentLedger.push({
                month: monthLabel,
                txnId: `TXN-${deterministicHash}`,
                units: billedUnits,
                amount: billedAmt,
                status: i === 0 && billedAmt > 0 ? 'Current Cycle' : 'Settled'
            });
        }

        res.json({
            success: true,
            user: targetUser,
            lifetimeUsage,
            paymentLedger
        });
    } catch (e) {
        await logBackendError('Admin KYC Route', e, req);
        res.status(500).json({ success: false, message: 'Failed to retrieve KYC details.' });
    }
});

// Staff RBAC Management (Owner Only)
app.get('/api/admin/staff', authenticateAdmin, async (req, res) => {
    if (req.admin.role !== 'owner') return res.status(403).json({ success: false });
    const staffList = await Staff.find({ tenantId: TENANT_ID }, '-passwordHash');
    res.json({ success: true, staff: staffList });
});

app.post('/api/admin/staff', authenticateAdmin, async (req, res) => {
    try {
        if (req.admin.role !== 'owner') return res.status(403).json({ success: false, message: 'Owner privilege required.' });
        const name = sanitizeInput(req.body.name, 50);
        const username = sanitizeInput(req.body.username, 30).toLowerCase();
        const password = sanitizeInput(req.body.password, 64);

        if (!name || !username || password.length < 6) {
            return res.status(400).json({ success: false, message: 'Valid name, username, and password (min 6 chars) required.' });
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

        res.json({ success: true, message: 'Staff account created.' });
    } catch (e) {
        res.status(400).json({ success: false, message: 'Could not create staff account (username may already exist).' });
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
        await logBackendError('CMS Update Route', e, req);
        res.status(500).json({ success: false });
    }
});

// Two-Way User Support Chat Routes (Row-Level Security + Anti-IDOR Enforced)
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
            return res.status(403).json({ success: false, message: 'Forbidden: Insufficient permissions.' });
        }
        const users = await User.find(
            { tenantId: TENANT_ID },
            'name email consumerId mobile sanctionedLoadKw accountStatus createdAt'
        ).sort({ createdAt: -1 });
        res.json({ success: true, threads: users });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.get('/api/support/admin/messages/:cid', authenticateAdmin, requireAdminPermission('canChatSupport'), async (req, res) => {
    try {
        const cid = sanitizeInput(req.params.cid, 12).toUpperCase();
        if (!emcsBloom.test(cid)) return res.json({ success: true, messages: [] });
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
        if (!text || !emcsBloom.test(consumerId)) return res.status(400).json({ success: false });
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
        const errors = await SystemError.find({ tenantId: TENANT_ID });
        res.json({
            exportDate: new Date(),
            tenantId: TENANT_ID,
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

app.listen(PORT, () => console.log(`[EMCS SERVER] Live on port ${PORT} | Tenant: ${TENANT_ID}`));
