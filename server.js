// ===================================================================
// EMCS BACKEND SERVER (server.js) - INDEPENDENT PROJECT
// Features: MongoDB Cloud Sync, Atomic Brute-Force Protection ($inc),
// 24-Hr IP Registration Limit, Anti-Bot Honeypot, 2-Year Soft Delete TTL,
// and Automated Client + Server Error Telemetry for Admin Panel
// ===================================================================

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

// Enable proxy trust so req.ip works properly on Render / cloud hosting
app.set('trust proxy', 1);

const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/emcs_project_db';
const MASTER_OWNER_KEY = process.env.MASTER_OWNER_KEY || 'EMCS_Admin_2026';
const JWT_SECRET = process.env.JWT_SECRET || crypto.createHash('sha256').update(MASTER_OWNER_KEY + '_emcs_jwt_key').digest('hex');

app.use(express.json({ limit: '15kb' }));
app.use(cookieParser());

const allowedOrigins = [
    'http://localhost:3000',
    'http://localhost:5000',
    'http://127.0.0.1:5500',
    'http://localhost:5500',
    process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
    origin: (origin, cb) => (!origin || allowedOrigins.includes(origin)) ? cb(null, true) : cb(new Error('Not allowed by CORS')),
    credentials: true
}));

// Security Headers, CSP & CSRF Check
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; connect-src 'self' http://192.168.* http://10.* http://172.* ws: wss:; img-src 'self' data: blob:;"
    );

    // Flag suspicious proxy headers for stricter rate limits
    if (req.headers['via'] || req.headers['x-proxy-id'] || req.headers['forwarded']) {
        req.isSuspiciousProxy = true;
    }

    // Check custom CSRF header on state-changing API calls
    if (['POST', 'DELETE', 'PUT'].includes(req.method) && req.path.startsWith('/api/')) {
        const csrf = req.headers['x-emcs-csrf'];
        if (csrf !== 'emcs-verified-client') {
            return res.status(403).json({ success: false, message: 'Invalid or missing security header.' });
        }
    }
    next();
});

// Helper to clean string inputs and avoid NoSQL operator injection
const sanitizeInput = (val, max = 150) => {
    if (typeof val === 'string' || typeof val === 'number') {
        return String(val).trim().slice(0, max);
    }
    return '';
};

// Constant-time string comparison for admin password
function safeCompareStrings(a, b) {
    const bufA = Buffer.from(String(a));
    const bufB = Buffer.from(String(b));
    if (bufA.length !== bufB.length) {
        crypto.timingSafeEqual(bufA, bufA);
        return false;
    }
    return crypto.timingSafeEqual(bufA, bufB);
}

// ===================================================================
// IP RATE LIMITERS (WITH PROXY PENALTY & MEMORY CLEANUP)
// ===================================================================
const rateLimits = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of rateLimits.entries()) {
        if (now > v.resetAt) rateLimits.delete(k);
    }
}, 300000); // Clean up expired IP records every 5 mins

function createLimiter(maxReqs, windowMs, customMsg) {
    return (req, res, next) => {
        const key = `${req.ip}_${req.path}`;
        const now = Date.now();
        let rec = rateLimits.get(key) || { count: 0, resetAt: now + windowMs };
        if (now > rec.resetAt) rec = { count: 0, resetAt: now + windowMs };

        // Reduce allowed attempts by half if request comes through a suspicious proxy
        const allowedMax = req.isSuspiciousProxy ? Math.max(1, Math.floor(maxReqs / 2)) : maxReqs;

        rec.count++;
        rateLimits.set(key, rec);

        if (rec.count > allowedMax) {
            return res.status(429).json({
                success: false,
                message: customMsg || 'Too many requests from this IP. Please try again later.'
            });
        }
        next();
    };
}

// Max 3 account registrations per IP address within 24 hours
const strictRegisterLimiter = createLimiter(
    3,
    24 * 60 * 60 * 1000,
    'Registration limit reached: Maximum 3 accounts can be created from a single IP address within 24 hours.'
);

const loginLimiter = createLimiter(8, 15 * 60 * 1000, 'Too many login attempts. Please wait 15 minutes.');
const chatLimiter = createLimiter(15, 60 * 1000, 'Sending messages too fast. Please wait a moment.');
const errorReportLimiter = createLimiter(25, 60 * 1000, 'Error log rate limit reached.');

// Connect to MongoDB
mongoose.connect(MONGO_URI)
    .then(() => console.log('[EMCS DB] Connected to MongoDB successfully.'))
    .catch(err => console.error('[EMCS DB Error]', err.message));

// ===================================================================
// MONGODB SCHEMAS & TTL INDEXES
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
        slabs: [{
            limit: mongoose.Schema.Types.Mixed,
            rate: Number
        }]
    },
    // Soft Delete & 2-Year Auto-Deletion Fields
    accountStatus: { type: String, default: 'active', enum: ['active', 'deleted'] },
    deletionScheduledAt: { type: Date, default: null }
}, { timestamps: true });

// Automatically remove deactivated user accounts 2 years (63,072,000 seconds) after deletionScheduledAt
UserSchema.index({ deletionScheduledAt: 1 }, { expireAfterSeconds: 63072000 });

const StaffSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    name: { type: String, required: true },
    role: { type: String, default: 'staff' },
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
    timestamp: { type: Date, default: Date.now, expires: 2592000 } // Auto-deletes after 30 days
});

const CmsSchema = new mongoose.Schema({
    key: { type: String, default: 'global_cms', unique: true },
    broadcast: { type: String, default: '' },
    about: { type: String, default: 'EMCS is an intelligent energy management and load monitoring platform.' },
    privacy: { type: String, default: 'All user data is encrypted. Deactivated accounts are retained for 2 years for compliance before automatic erasure.' },
    terms: { type: String, default: 'By using EMCS, you agree to fair usage policies and state electricity slab estimation rules.' },
    faqs: {
        type: Array,
        default: [
            { q: 'How is my electricity bill calculated?', a: 'We use official state and private electricity board slab rates, fixed load charges, and electricity duty.' },
            { q: 'What happens when I delete my account?', a: 'Your account is immediately deactivated and automatically erased from the database after 2 years.' }
        ]
    }
});

// Automated Error Telemetry Schema (Stores Website & Server Errors for Admin)
const SystemErrorSchema = new mongoose.Schema({
    timestamp: { type: Date, default: Date.now, expires: 2592000 }, // Auto-cleans logs older than 30 days
    source: { type: String, default: 'Backend Server' },
    message: { type: String, required: true },
    location: { type: String, default: '' },
    userOrIp: { type: String, default: '' }
});

const User = mongoose.model('User', UserSchema);
const Staff = mongoose.model('Staff', StaffSchema);
const SupportMessage = mongoose.model('SupportMessage', SupportMessageSchema);
const CmsConfig = mongoose.model('CmsConfig', CmsSchema);
const SystemError = mongoose.model('SystemError', SystemErrorSchema);

// Helper to record backend exceptions into the Admin Error List
async function logBackendError(source, err, req = null) {
    try {
        await new SystemError({
            source: source || 'Backend Server',
            message: sanitizeInput(err?.message || String(err), 300),
            location: sanitizeInput(req ? `${req.method} ${req.originalUrl}` : 'Server Internal', 150),
            userOrIp: sanitizeInput(req ? (req.user?.consumerId || req.ip) : 'Server', 60)
        }).save();
    } catch (ignore) {}
}

// ===================================================================
// AUTHENTICATION MIDDLEWARES
// ===================================================================
async function authenticateUser(req, res, next) {
    const token = req.cookies.emcs_auth_token;
    if (!token) return res.status(401).json({ success: false, message: 'Please log in first.' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        const user = await User.findById(decoded.userId);

        if (!user || user.accountStatus === 'deleted' || !user.activeSessions.some(s => s.sessionId === decoded.sessionId)) {
            res.clearCookie('emcs_auth_token');
            return res.status(401).json({ success: false, message: 'Session expired or account deactivated.' });
        }

        req.user = user;
        req.sessionId = decoded.sessionId;
        next();
    } catch (e) {
        return res.status(403).json({ success: false, message: 'Invalid session token.' });
    }
}

async function authenticateAdmin(req, res, next) {
    const token = req.cookies.emcs_admin_token;
    if (!token) return res.status(401).json({ success: false, message: 'Admin login required.' });

    try {
        req.admin = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        next();
    } catch (e) {
        return res.status(403).json({ success: false, message: 'Invalid admin token.' });
    }
}

// ===================================================================
// AUTOMATED ERROR REPORTING & ADMIN ERROR LIST ROUTES
// ===================================================================
app.post('/api/errors/report', errorReportLimiter, async (req, res) => {
    try {
        const source = sanitizeInput(req.body.source || 'Website JS', 50);
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
        res.status(500).json({ success: false, message: 'Failed to load error logs.' });
    }
});

app.delete('/api/admin/errors/clear', authenticateAdmin, async (req, res) => {
    try {
        await SystemError.deleteMany({});
        res.json({ success: true, message: 'All error logs cleared.' });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// ===================================================================
// USER AUTH, HONEYPOT, PRIVACY CONSENT & 2-YEAR SOFT DELETE
// ===================================================================
app.post('/api/auth/register', strictRegisterLimiter, async (req, res) => {
    try {
        // 1. Anti-Bot Honeypot Check
        if (req.body._bot_honeypot && String(req.body._bot_honeypot).length > 0) {
            return res.status(403).json({ success: false, message: 'Automated bot registration blocked.' });
        }

        // 2. Mandatory Privacy Policy & Terms Consent Check
        if (req.body.termsAccepted !== true) {
            return res.status(400).json({ success: false, message: 'You must accept the Privacy Policy and Terms & Conditions.' });
        }

        const mobile = sanitizeInput(req.body.mobile, 10);
        const consumerId = sanitizeInput(req.body.consumerId, 12).toUpperCase();
        const pin = sanitizeInput(req.body.pin, 4);
        const name = sanitizeInput(req.body.name, 60);

        if (!/^[0-9]{10}$/.test(mobile) \vert{}\vert{} consumerId.length !== 12 \vert{}\vert{} !/^[0-9]{4}$/.test(pin) || !name) {
            return res.status(400).json({ success: false, message: 'Please enter valid registration details.' });
        }

        const existing = await User.findOne({ $or: [{ mobile }, { consumerId }] });
        if (existing) {
            return res.status(400).json({ success: false, message: 'Mobile number or 12-character Consumer ID is already registered.' });
        }

        const pinHash = await bcrypt.hash(pin, 12);
        await new User({
            mobile,
            consumerId,
            name,
            pinHash,
            termsAccepted: true,
            termsAcceptedAt: new Date()
        }).save();

        res.json({ success: true, message: 'Account created successfully.' });
    } catch (e) {
        await logBackendError('Register Route', e, req);
        res.status(500).json({ success: false, message: 'Server error during registration.' });
    }
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const mobile = sanitizeInput(req.body.mobile, 10);
        const pin = sanitizeInput(req.body.pin, 4);

        const user = await User.findOne({ mobile });
        if (!user) return res.status(400).json({ success: false, message: 'Invalid mobile number or PIN.' });

        // Block Soft-Deleted Accounts
        if (user.accountStatus === 'deleted') {
            return res.status(403).json({
                success: false,
                message: 'This account has been deactivated and is scheduled for permanent deletion.'
            });
        }

        // Check Temporary Lockout
        if (user.lockUntil && user.lockUntil > Date.now()) {
            const mins = Math.ceil((user.lockUntil - Date.now()) / 60000);
            return res.status(429).json({
                success: false,
                isLocked: true,
                message: `Account locked due to multiple failed attempts. Try again in ${mins} minutes.`
            });
        }

        const isMatch = await bcrypt.compare(pin, user.pinHash);
        if (!isMatch) {
            // Atomic $inc update to prevent TOCTOU brute-force race conditions
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
            }
            return res.status(401).json({ success: false, message: 'Invalid mobile number or PIN.' });
        }

        // Reset failed attempts atomically on valid login
        await User.updateOne(
            { _id: user._id },
            { $set: { failedLoginAttempts: 0, lockUntil: null } }
        );

        const sessionId = crypto.randomBytes(24).toString('hex');
        user.activeSessions.push({
            sessionId,
            deviceInfo: sanitizeInput(req.headers['user-agent'], 70),
            ipAddress: req.ip
        });

        if (user.activeSessions.length > 5) {
            user.activeSessions = user.activeSessions.slice(-5);
        }
        await user.save();

        const token = jwt.sign({ userId: user._id, sessionId }, JWT_SECRET, { expiresIn: '7d', algorithm: 'HS256' });

        res.cookie('emcs_auth_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
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
        res.status(500).json({ success: false, message: 'Login error occurred.' });
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

app.post('/api/auth/verify-and-reset-pin', loginLimiter, async (req, res) => {
    try {
        const mobile = sanitizeInput(req.body.mobile, 10);
        const consumerId = sanitizeInput(req.body.consumerId, 12).toUpperCase();
        const registeredName = sanitizeInput(req.body.registeredName, 60).toLowerCase();
        const newPin = sanitizeInput(req.body.newPin, 4);

        const user = await User.findOne({ mobile, consumerId, accountStatus: 'active' });
        if (!user || user.name.toLowerCase() !== registeredName || !/^[0-9]{4}$/.test(newPin)) {
            return res.status(400).json({ success: false, message: 'Verification failed. Details do not match our records.' });
        }

        user.pinHash = await bcrypt.hash(newPin, 12);
        user.failedLoginAttempts = 0;
        user.lockUntil = null;
        user.activeSessions = [];
        await user.save();

        res.json({ success: true, message: 'PIN reset successful! You can now log in.' });
    } catch (e) {
        await logBackendError('PIN Reset Route', e, req);
        res.status(500).json({ success: false, message: 'PIN reset error.' });
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
        res.json({ success: true, message: 'Device logged out successfully.' });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// ===================================================================
// USER CLOUD DATA SYNC & 2-YEAR SOFT DELETE ROUTE
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

app.post('/api/user/sync-cloud', authenticateUser, async (req, res) => {
    try {
        const {
            appliances,
            sanctionedLoadKw,
            budgetThreshold,
            tariffProvider,
            tariffCategory,
            tariffArea,
            customTariff
        } = req.body;

        // Server-side clamping so Inspect Element changes cannot corrupt values
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

        if (sanctionedLoadKw) req.user.sanctionedLoadKw = Math.min(50, Math.max(0.5, Number(sanctionedLoadKw)));
        if (budgetThreshold) req.user.budgetThreshold = Math.min(1000000, Math.max(100, Number(budgetThreshold)));
        if (tariffProvider) req.user.tariffProvider = sanitizeInput(tariffProvider, 30);
        if (tariffCategory) req.user.tariffCategory = sanitizeInput(tariffCategory, 20);
        if (tariffArea) req.user.tariffArea = sanitizeInput(tariffArea, 20);

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
        res.json({ success: true, message: 'Cloud data synced.' });
    } catch (e) {
        await logBackendError('Cloud Sync Route', e, req);
        res.status(500).json({ success: false, message: 'Sync failed.' });
    }
});

// Soft Delete Route (Deactivates immediately, MongoDB TTL erases after 2 years)
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
// ADMIN PANEL, CMS, FAQS & SUPPORT DESK ROUTES
// ===================================================================
app.post('/api/admin/login', loginLimiter, async (req, res) => {
    try {
        const username = sanitizeInput(req.body.username, 40);
        const password = sanitizeInput(req.body.password, 64);

        if (!username && safeCompareStrings(password, MASTER_OWNER_KEY)) {
            const perms = { canManageUsers: true, canChatSupport: true, canEditCMS: true, canDeleteChat: true };
            const token = jwt.sign({ role: 'owner', name: 'Master Owner', permissions: perms }, JWT_SECRET, { expiresIn: '8h', algorithm: 'HS256' });
            res.cookie('emcs_admin_token', token, { httpOnly: true, sameSite: 'lax', maxAge: 28800000 });
            return res.json({ success: true, role: 'owner', name: 'Master Owner', permissions: perms });
        }

        if (username) {
            const staff = await Staff.findOne({ username });
            if (staff && await bcrypt.compare(password, staff.passwordHash)) {
                const token = jwt.sign({ role: 'staff', name: staff.name, permissions: staff.permissions }, JWT_SECRET, { expiresIn: '8h', algorithm: 'HS256' });
                res.cookie('emcs_admin_token', token, { httpOnly: true, sameSite: 'lax', maxAge: 28800000 });
                return res.json({ success: true, role: 'staff', name: staff.name, permissions: staff.permissions });
            }
        }

        res.status(401).json({ success: false, message: 'Invalid Admin credentials.' });
    } catch (e) {
        await logBackendError('Admin Login Route', e, req);
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

app.post('/api/admin/cms', authenticateAdmin, async (req, res) => {
    try {
        if (req.admin.role !== 'owner' && !req.admin.permissions?.canEditCMS) {
            return res.status(403).json({ success: false, message: 'No CMS permission.' });
        }
        const update = {
            broadcast: sanitizeInput(req.body.broadcast, 250),
            about: sanitizeInput(req.body.about, 2000),
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

app.post('/api/support/user/send', authenticateUser, chatLimiter, async (req, res) => {
    try {
        const text = sanitizeInput(req.body.text, 500);
        if (!text) return res.status(400).json({ success: false });
        const msg = await new SupportMessage({ consumerId: req.user.consumerId, sender: 'user', text }).save();
        res.json({ success: true, message: msg });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.get('/api/support/admin/threads', authenticateAdmin, async (req, res) => {
    try {
        const users = await User.find({}, 'name consumerId mobile sanctionedLoadKw accountStatus createdAt');
        res.json({ success: true, threads: users });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.get('/api/support/admin/messages/:cid', authenticateAdmin, async (req, res) => {
    try {
        const cid = sanitizeInput(req.params.cid, 12).toUpperCase();
        const messages = await SupportMessage.find({ consumerId: cid }).sort({ timestamp: 1 });
        res.json({ success: true, messages });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.post('/api/support/admin/reply', authenticateAdmin, async (req, res) => {
    try {
        const consumerId = sanitizeInput(req.body.consumerId, 12).toUpperCase();
        const text = sanitizeInput(req.body.text, 500);
        const msg = await new SupportMessage({ consumerId, sender: 'admin', text }).save();
        res.json({ success: true, message: msg });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.delete('/api/support/chat/clear/:cid', authenticateAdmin, async (req, res) => {
    try {
        if (req.admin.role !== 'owner' && !req.admin.permissions?.canDeleteChat) {
            return res.status(403).json({ success: false });
        }
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

// Serve Static Frontend Files
app.use(express.static(path.join(__dirname)));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// Global Express Unhandled Error Middleware (Logs crashes into Admin Error List)
app.use(async (err, req, res, next) => {
    await logBackendError('Express Unhandled Error', err, req);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
});

app.listen(PORT, () => console.log(`[EMCS SERVER] Running on http://localhost:${PORT}`));
