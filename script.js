const $ = (id) => document.getElementById(id);
const safeSetText = (id, txt) => { const el = $(id); if (el) el.textContent = txt; };
const safeGetVal = (id) => { const el = $(id); return el ? el.value : ''; };
const safeSetVal = (id, val) => { const el = $(id); if (el) el.value = val; };

const API_BASE = window.location.origin.includes('localhost') || window.location.origin.includes('127.0.0.1')
    ? 'http://localhost:5000/api'
    : '/api';

function escapeHTML(str) {
    return String(str || '').replace(/[&<>"']/g, (m) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[m]));
}

async function secureApiFetch(endpoint, options = {}) {
    return fetch(`${API_BASE}${endpoint}`, {
        ...options,
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
            'x-emcs-csrf': 'emcs-verified-client',
            ...(options.headers || {})
        }
    });
}

// ---------------------------------------------------------
// STRICT EMAIL, TLD WHITELIST (.COH/.CON BLOCKED) & TEMP-MAIL GUARD
// ---------------------------------------------------------
const BLOCKED_TEMP_DOMAINS = new Set([
    'mailinator.com', 'yopmail.com', '10minutemail.com', 'guerrillamail.com',
    'tempmail.com', 'temp-mail.org', 'dropmail.me', 'trashmail.com',
    'sharklasers.com', 'getnada.com', 'maildrop.cc', 'dispostable.com',
    'fakeinbox.com', 'throwawaymail.com', 'mohmal.com', 'emailondeck.com',
    'mailnesia.com', 'mintemail.com', 'mytemp.email', 'burnermail.io',
    'tempmailo.com', 'inboxkitten.com', 'mailcatch.com', 'crazymailing.com',
    'tempail.com', 'yopmail.fr', 'yopmail.net'
]);

const VALID_TLDS = new Set([
    'com', 'in', 'org', 'net', 'edu', 'gov', 'co', 'io', 'me', 'biz', 'info', 'ac', 'uk', 'us'
]);

const BLOCKED_TYPO_DOMAINS = new Set([
    'gamil.com', 'gmial.com', 'gmai.com', 'gmail.co', 'gmail.con', 'gmail.coh',
    'yaho.com', 'yahooo.com', 'outlok.com', 'hotmial.com'
]);

function isStrictValidEmail(emailStr) {
    const clean = String(emailStr || '').trim().toLowerCase();
    if (clean.length < 6 || clean.length > 90) {
        return { ok: false, msg: 'Please enter a valid email address.' };
    }
    if (/[\s\0$<>'"`;\\(){}[\]|!#$%^&*=+/?~]|\.\./.test(clean)) {
        return { ok: false, msg: 'Please enter a valid email address without special symbols.' };
    }
    const parts = clean.split('@');
    if (parts.length !== 2) return { ok: false, msg: 'Please enter a valid email address.' };
    const [local, domain] = parts;

    if (!/^[a-z0-9]+([._-][a-z0-9]+)*$/.test(local) || local.length < 2 || local.length > 60) {
        return { ok: false, msg: 'Please enter a valid email address.' };
    }
    if (!/^[a-z0-9]+(-[a-z0-9]+)*(\.[a-z0-9]+(-[a-z0-9]+)*)+$/.test(domain)) {
        return { ok: false, msg: 'Please enter a valid email address.' };
    }

    if (BLOCKED_TEMP_DOMAINS.has(domain) || BLOCKED_TYPO_DOMAINS.has(domain)) {
        return { ok: false, msg: 'Please enter a valid personal or work email address (e.g. name@gmail.com).' };
    }

    const domainSegments = domain.split('.');
    const lastTld = domainSegments[domainSegments.length - 1];
    const secondLastTld = domainSegments.length >= 3 ? domainSegments[domainSegments.length - 2] : null;

    if (!VALID_TLDS.has(lastTld)) {
        return { ok: false, msg: `Invalid email extension (.${lastTld}). Please use standard extensions like .com or .in.` };
    }
    if (secondLastTld && domainSegments.length >= 3 && !VALID_TLDS.has(secondLastTld) && secondLastTld.length <= 3) {
        return { ok: false, msg: 'Please enter a valid email domain.' };
    }

    return { ok: true, email: clean };
}

// ---------------------------------------------------------
// CLIENT-SIDE URL & PROFILE TAMPERING SHIELD (ANTI-IDOR)
// ---------------------------------------------------------
function enforceUrlAntiIdorGuard() {
    try {
        const params = new URLSearchParams(window.location.search);
        const hash = window.location.hash || '';
        const activeCid = window.KamAbhiRAM?.userSession?.consumerId;

        const urlCid = params.get('consumerId') || params.get('cid') || params.get('user') || params.get('id');
        if (urlCid && (!activeCid || String(urlCid).trim() !== String(activeCid).trim())) {
            reportSystemError('Security Shield');
            window.history.replaceState({}, document.title, window.location.pathname);
            alert('Access Denied: You can only view your own account details.');
        }

        if (/consumerId=|cid=/i.test(hash)) {
            window.history.replaceState({}, document.title, window.location.pathname);
        }

        const profileInput = $('profileId');
        if (activeCid && profileInput && profileInput.value && profileInput.value !== activeCid) {
            profileInput.value = activeCid;
            reportSystemError('Security Shield');
        }
    } catch (ignore) {}
}

window.addEventListener('popstate', enforceUrlAntiIdorGuard);
window.addEventListener('hashchange', enforceUrlAntiIdorGuard);

// ---------------------------------------------------------
// PASSWORD VISIBILITY TOGGLE (EYE ICON)
// ---------------------------------------------------------
function togglePasswordVisibility(fieldId, btn) {
    const inputField = $(fieldId);
    if (!inputField) return;

    const icon = btn.querySelector('i');
    if (inputField.type === 'password') {
        inputField.type = 'text';
        if (icon) {
            icon.classList.remove('fa-eye');
            icon.classList.add('fa-eye-slash');
        }
    } else {
        inputField.type = 'password';
        if (icon) {
            icon.classList.remove('fa-eye-slash');
            icon.classList.add('fa-eye');
        }
    }
}

// ---------------------------------------------------------
// CLEAN ACTIVITY LOGGING (ZERO TECHNICAL / SENSITIVE DATA)
// ---------------------------------------------------------
function reportSystemError(section) {
    try {
        const cleanSection = String(section || 'App Activity').replace(/mongodb|mongoose|express|node|api|backend|server|db/gi, 'System');
        const errEntry = {
            id: Date.now(),
            timestamp: new Date().toISOString(),
            source: cleanSection.slice(0, 40),
            message: 'Something went wrong, try again later.',
            location: 'User Screen',
            userOrIp: window.KamAbhiRAM?.userSession?.consumerId || 'Visitor'
        };

        const localLogs = JSON.parse(localStorage.getItem('emcs_error_logs') || '[]');
        localLogs.unshift(errEntry);
        localStorage.setItem('emcs_error_logs', JSON.stringify(localLogs.slice(0, 100)));
        safeSetText('adminErrorCountBadge', localLogs.length);

        fetch(`${API_BASE}/errors/report`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-emcs-csrf': 'emcs-verified-client' },
            body: JSON.stringify(errEntry)
        }).catch(() => {});
    } catch (ignore) {}
}

window.addEventListener('error', () => reportSystemError('Page Activity'));
window.addEventListener('unhandledrejection', () => reportSystemError('Network Activity'));

// ---------------------------------------------------------
// APPLICATION STATE
// ---------------------------------------------------------
window.KamAbhiRAM = {
    userSession: null,
    appliances: [],
    paymentHistory: [],
    cmsFaqs: [],
    computedBillObj: { total: 0 },
    totalUnits: 0,
    budgetThreshold: 3000,
    vampireSavings: 0,
    sanctionedLoadKw: 2.0,
    chartMode: 'line',
    energyChart: null,
    hardwareConsentAccepted: false
};

// ---------------------------------------------------------
// COMPLETE ALL-INDIA TARIFF DATABASE (18 BOARDS + RURAL/URBAN)
// ---------------------------------------------------------
const BASE_TARIFFS = {
    bihar: {
        domestic_urban: { fixedPerKw: 80, fppcaPct: 0.082, dutyPct: 0.06, slabs: [{ limit: 100, rate: 4.27 }, { limit: 200, rate: 5.22 }, { limit: Infinity, rate: 6.82 }] },
        domestic_rural: { fixedPerKw: 40, fppcaPct: 0.050, dutyPct: 0.05, slabs: [{ limit: 50, rate: 2.60 }, { limit: 100, rate: 3.10 }, { limit: Infinity, rate: 4.80 }] },
        commercial_urban: { fixedPerKw: 180, fppcaPct: 0.090, dutyPct: 0.08, slabs: [{ limit: 100, rate: 6.50 }, { limit: 200, rate: 7.20 }, { limit: Infinity, rate: 8.50 }] },
        commercial_rural: { fixedPerKw: 120, fppcaPct: 0.075, dutyPct: 0.07, slabs: [{ limit: 100, rate: 5.50 }, { limit: Infinity, rate: 6.80 }] }
    },
    up: {
        domestic_urban: { fixedPerKw: 110, fppcaPct: 0.075, dutyPct: 0.05, slabs: [{ limit: 150, rate: 5.50 }, { limit: 300, rate: 6.00 }, { limit: 500, rate: 6.50 }, { limit: Infinity, rate: 7.00 }] },
        domestic_rural: { fixedPerKw: 50, fppcaPct: 0.050, dutyPct: 0.05, slabs: [{ limit: 100, rate: 3.35 }, { limit: 150, rate: 3.85 }, { limit: 300, rate: 5.00 }, { limit: Infinity, rate: 5.50 }] },
        commercial_urban: { fixedPerKw: 330, fppcaPct: 0.085, dutyPct: 0.075, slabs: [{ limit: 300, rate: 7.50 }, { limit: Infinity, rate: 8.75 }] },
        commercial_rural: { fixedPerKw: 190, fppcaPct: 0.070, dutyPct: 0.065, slabs: [{ limit: Infinity, rate: 7.50 }] }
    },
    maharashtra: {
        domestic_urban: { fixedPerKw: 116, fppcaPct: 0.092, dutyPct: 0.16, slabs: [{ limit: 100, rate: 5.58 }, { limit: 300, rate: 10.81 }, { limit: 500, rate: 14.78 }, { limit: Infinity, rate: 16.64 }] },
        domestic_rural: { fixedPerKw: 65, fppcaPct: 0.070, dutyPct: 0.12, slabs: [{ limit: 100, rate: 4.20 }, { limit: 300, rate: 8.50 }, { limit: Infinity, rate: 12.00 }] },
        commercial_urban: { fixedPerKw: 420, fppcaPct: 0.100, dutyPct: 0.18, slabs: [{ limit: 200, rate: 11.20 }, { limit: Infinity, rate: 15.80 }] },
        commercial_rural: { fixedPerKw: 250, fppcaPct: 0.080, dutyPct: 0.14, slabs: [{ limit: Infinity, rate: 12.80 }] }
    },
    delhi: {
        domestic_urban: { fixedPerKw: 65, fppcaPct: 0.087, dutyPct: 0.05, slabs: [{ limit: 200, rate: 3.00 }, { limit: 400, rate: 4.50 }, { limit: 800, rate: 6.50 }, { limit: Infinity, rate: 8.00 }] },
        domestic_rural: { fixedPerKw: 50, fppcaPct: 0.060, dutyPct: 0.05, slabs: [{ limit: 200, rate: 3.00 }, { limit: 400, rate: 4.50 }, { limit: Infinity, rate: 7.00 }] },
        commercial_urban: { fixedPerKw: 250, fppcaPct: 0.095, dutyPct: 0.06, slabs: [{ limit: Infinity, rate: 8.50 }] },
        commercial_rural: { fixedPerKw: 180, fppcaPct: 0.080, dutyPct: 0.05, slabs: [{ limit: Infinity, rate: 7.80 }] }
    },
    tata_mumbai: {
        domestic_urban: { fixedPerKw: 75, fppcaPct: 0.065, dutyPct: 0.16, slabs: [{ limit: 100, rate: 3.80 }, { limit: 300, rate: 5.60 }, { limit: 500, rate: 8.40 }, { limit: Infinity, rate: 10.50 }] },
        domestic_rural: { fixedPerKw: 50, fppcaPct: 0.050, dutyPct: 0.12, slabs: [{ limit: 100, rate: 3.20 }, { limit: 300, rate: 4.90 }, { limit: Infinity, rate: 8.50 }] },
        commercial_urban: { fixedPerKw: 350, fppcaPct: 0.080, dutyPct: 0.18, slabs: [{ limit: Infinity, rate: 11.50 }] },
        commercial_rural: { fixedPerKw: 220, fppcaPct: 0.070, dutyPct: 0.14, slabs: [{ limit: Infinity, rate: 9.80 }] }
    },
    national: {
        domestic_urban: { fixedPerKw: 85, fppcaPct: 0.085, dutyPct: 0.06, slabs: [{ limit: 100, rate: 4.50 }, { limit: 300, rate: 7.00 }, { limit: Infinity, rate: 9.50 }] },
        domestic_rural: { fixedPerKw: 50, fppcaPct: 0.060, dutyPct: 0.05, slabs: [{ limit: 100, rate: 3.50 }, { limit: 300, rate: 5.50 }, { limit: Infinity, rate: 7.50 }] },
        commercial_urban: { fixedPerKw: 280, fppcaPct: 0.090, dutyPct: 0.08, slabs: [{ limit: Infinity, rate: 10.50 }] },
        commercial_rural: { fixedPerKw: 180, fppcaPct: 0.075, dutyPct: 0.07, slabs: [{ limit: Infinity, rate: 8.00 }] }
    }
};

const ALL_INDIA_TARIFFS = {
    ...BASE_TARIFFS,
    karnataka: BASE_TARIFFS.national,
    rajasthan: BASE_TARIFFS.up,
    wb: BASE_TARIFFS.bihar,
    tn: BASE_TARIFFS.delhi,
    gujarat: BASE_TARIFFS.bihar,
    punjab: BASE_TARIFFS.delhi,
    haryana: BASE_TARIFFS.up,
    mp: BASE_TARIFFS.up,
    tata_delhi: BASE_TARIFFS.delhi,
    bses_delhi: BASE_TARIFFS.delhi,
    adani_mumbai: BASE_TARIFFS.tata_mumbai,
    cesc_kolkata: BASE_TARIFFS.national,
    torrent: BASE_TARIFFS.national
};

const APPLIANCE_PRESETS = {
    ac15: { name: "1.5 Ton Split AC", power: 1400, hours: 8 },
    ac10: { name: "1.0 Ton Inverter AC", power: 1000, hours: 8 },
    fridge: { name: "Double Door Fridge", power: 180, hours: 24 },
    fan: { name: "BLDC Ceiling Fan", power: 35, hours: 14 },
    oldfan: { name: "Regular Ceiling Fan", power: 75, hours: 14 },
    geyser: { name: "Water Geyser", power: 2000, hours: 1.5 },
    pc: { name: "Desktop Computer", power: 350, hours: 6 },
    wm: { name: "Washing Machine", power: 450, hours: 1 }
};

// ---------------------------------------------------------
// HUMAN-FRIENDLY 3-LANGUAGE DICTIONARY (DEFAULT: ENGLISH)
// ---------------------------------------------------------
const TRANSLATIONS = {
    en: {
        navDash: "Dashboard", navAppliances: "My Appliances", navVoltage: "Voltage Safety",
        navInverter: "Inverter Backup", navVampire: "Standby Power Saver", navOcr: "Scan Electricity Bill",
        navCsv: "Smart Meter File", navTod: "Best Time to Use", navSolar: "Solar Calculator",
        navIoT: "Smart Hardware Control", navAudit: "Reports & History", navSim: "Savings Calculator",
        navPayment: "Pay Bill", navAI: "KamAbhi AI Assistant", navSupport: "Help & Support",
        navProfile: "My Account", btnConnect: "Login / Register", btnLoginShort: "Login",
        greetDefault: "Welcome to Smart Energy Manager ☀️",
        greetSub: "Track your home appliances, control smart switches, and reduce your monthly electricity bill.",
        lblBudgetBtn: "Monthly Budget:"
    },
    hi: {
        navDash: "डैशबोर्ड", navAppliances: "मेरे उपकरण", navVoltage: "वोल्टेज सुरक्षा",
        navInverter: "इन्वर्टर बैकअप", navVampire: "स्टैंडबाय बिजली बचत", navOcr: "बिजली बिल स्कैन करें",
        navCsv: "स्मार्ट मीटर फ़ाइल", navTod: "उपयोग का सही समय", navSolar: "सोलर कैलकुलेटर",
        navIoT: "स्मार्ट हार्डवेयर कंट्रोल", navAudit: "रिपोर्ट और इतिहास", navSim: "बचत कैलकुलेटर",
        navPayment: "बिल भुगतान", navAI: "KamAbhi AI सहायक", navSupport: "सहायता केंद्र",
        navProfile: "मेरा खाता", btnConnect: "लॉगिन / रजिस्टर", btnLoginShort: "लॉगिन",
        greetDefault: "स्मार्ट एनर्जी मैनेजर में आपका स्वागत है ☀️",
        greetSub: "अपने घर के उपकरणों को ट्रैक करें, स्मार्ट स्विच नियंत्रित करें और बिजली बिल कम करें।",
        lblBudgetBtn: "मासिक बजट:"
    },
    hinglish: {
        navDash: "Dashboard", navAppliances: "My Appliances", navVoltage: "Voltage Safety",
        navInverter: "Inverter Backup", navVampire: "Standby Power Saver", navOcr: "Scan Electricity Bill",
        navCsv: "Smart Meter File", navTod: "Best Time to Use", navSolar: "Solar Calculator",
        navIoT: "Smart Hardware Control", navAudit: "Reports & History", navSim: "Savings Calculator",
        navPayment: "Pay Bill", navAI: "KamAbhi AI Assistant", navSupport: "Help & Support",
        navProfile: "My Account", btnConnect: "Login / Register", btnLoginShort: "Login",
        greetDefault: "Welcome to Smart Energy Manager ☀️",
        greetSub: "Apne ghar ke appliances track karein, smart switches control karein aur bijli bill bachayein.",
        lblBudgetBtn: "Monthly Budget:"
    }
};

function switchLanguage(lang) {
    const dict = TRANSLATIONS[lang] || TRANSLATIONS.en;
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const k = el.getAttribute('data-i18n');
        if (dict[k]) el.textContent = dict[k];
    });
}

document.addEventListener('DOMContentLoaded', async () => {
    const savedTheme = localStorage.getItem('ecoTheme') || 'light';
    document.body.setAttribute('data-theme', savedTheme);

    // Default Language Strictly Set to English
    if ($('languageSelect')) $('languageSelect').value = 'en';
    switchLanguage('en');

    const activeUser = JSON.parse(localStorage.getItem('ecoActiveUser'));
    if (activeUser) {
        setupUserSession(activeUser);
        await refreshDataFromCloud();
    }

    enforceUrlAntiIdorGuard();
    loadCmsContent();
    renderAppliances();
    renderRealPaymentLedger();
    calculateSolarRoi();
    calculateInverterRuntime();
});

// ---------------------------------------------------------
// TARIFF & BILLING COMPUTATION
// ---------------------------------------------------------
function getActiveTariffConfig() {
    const provider = safeGetVal('tariffProviderSelect') || 'bihar';
    const category = safeGetVal('tariffCategorySelect') || 'domestic';
    const area = safeGetVal('tariffAreaSelect') || 'urban';

    if (provider === 'custom') {
        const savedCustom = JSON.parse(localStorage.getItem('emcs_custom_tariff'));
        if (savedCustom) return savedCustom;
    }

    const key = `${category}_${area}`;
    const providerObj = ALL_INDIA_TARIFFS[provider] || ALL_INDIA_TARIFFS.national;
    return providerObj[key] || providerObj.domestic_urban || ALL_INDIA_TARIFFS.national.domestic_urban;
}

function computeSlabBill(units, configOverride = null) {
    const unitsSafe = Math.max(0, parseFloat(units) || 0);
    const config = configOverride || getActiveTariffConfig();

    let rem = unitsSafe, energyCharges = 0, prev = 0;
    for (let s of config.slabs) {
        const limitVal = (s.limit === 'Infinity' || s.limit === Infinity || s.limit === null) ? Infinity : Number(s.limit);
        const cap = limitVal - prev;
        if (rem <= 0) break;
        const billable = Math.min(rem, cap);
        energyCharges += billable * (parseFloat(s.rate) || 0);
        rem -= billable;
        prev = limitVal;
    }

    const sanctionedKw = Math.max(0.5, parseFloat(window.KamAbhiRAM.sanctionedLoadKw) || 2.0);
    const fixedDemandCharge = sanctionedKw * (parseFloat(config.fixedPerKw) || 0);
    const includeSurcharges = $('includeFppcaToggle') ? $('includeFppcaToggle').checked : true;
    const fppcaSurcharge = includeSurcharges ? (energyCharges * (parseFloat(config.fppcaPct) || 0)) : 0;
    const dutyRate = parseFloat(config.dutyPct) || 0.05;
    const electricityDuty = includeSurcharges ? ((energyCharges + fixedDemandCharge) * dutyRate) : 0;

    return {
        total: Math.max(0, energyCharges + fixedDemandCharge + fppcaSurcharge + electricityDuty),
        energyCharges, fixedDemandCharge, fppcaSurcharge, electricityDuty
    };
}

function onTariffConfigChange() {
    if (safeGetVal('tariffProviderSelect') === 'custom') toggleCustomTariffModal();
    renderAppliances();
    autoSyncToCloud();
}

function toggleCustomTariffModal() {
    $('customTariffModal').classList.toggle('hidden');
    $('popupOverlay').classList.toggle('hidden');
}

function saveCustomTariffSettings() {
    const fixed = Math.min(5000, Math.max(0, parseFloat(safeGetVal('custFixedCharge')) || 0));
    const fppca = Math.min(1.0, Math.max(0, (parseFloat(safeGetVal('custFppcaPct')) || 0) / 100));
    const duty = Math.min(1.0, Math.max(0, (parseFloat(safeGetVal('custDutyPct')) || 0) / 100));

    const s1Limit = Math.max(1, parseFloat(safeGetVal('custSlab1Limit')) || 100);
    const s1Rate = Math.min(100, Math.max(0, parseFloat(safeGetVal('custSlab1Rate')) || 4.5));
    const s2Limit = Math.max(s1Limit + 1, parseFloat(safeGetVal('custSlab2Limit')) || 300);
    const s2Rate = Math.min(100, Math.max(0, parseFloat(safeGetVal('custSlab2Rate')) || 7.0));
    const sFinalRate = Math.min(100, Math.max(0, parseFloat(safeGetVal('custSlabFinalRate')) || 9.5));

    const customConfig = {
        name: "Custom Rate", fixedPerKw: fixed, fppcaPct: fppca, dutyPct: duty,
        slabs: [{ limit: s1Limit, rate: s1Rate }, { limit: s2Limit, rate: s2Rate }, { limit: Infinity, rate: sFinalRate }]
    };

    localStorage.setItem('emcs_custom_tariff', JSON.stringify(customConfig));
    safeSetVal('tariffProviderSelect', 'custom');
    toggleCustomTariffModal();
    renderAppliances();
    autoSyncToCloud();
    alert("✓ Your custom electricity rates have been saved!");
}

// ---------------------------------------------------------
// APPLIANCES, HARDWARE COMPATIBILITY & LIVE BLOCK DIAGRAM
// ---------------------------------------------------------
function onAppConnectionModeChange(mode) {
    const disclaimerBox = $('appHardwareDisclaimerBox');
    const chk = $('appHardwareRiskCheck');
    if (!disclaimerBox) return;

    if (mode && mode !== 'manual') {
        disclaimerBox.classList.remove('hidden');
        if (chk) chk.checked = window.KamAbhiRAM.hardwareConsentAccepted;
    } else {
        disclaimerBox.classList.add('hidden');
    }
}

function toggleHardwareRiskConsent(isChecked) {
    window.KamAbhiRAM.hardwareConsentAccepted = Boolean(isChecked);
    const zone = $('hardwareInteractiveZone');
    const logEl = $('espConsoleLog');
    const appChk = $('appHardwareRiskCheck');
    if (appChk) appChk.checked = Boolean(isChecked);

    if (zone) {
        if (isChecked) {
            zone.classList.remove('hardware-locked-zone');
            zone.classList.add('hardware-unlocked-zone');
            if (logEl) logEl.textContent = "Status: Hardware controls unlocked. You can now connect and control your switches.";
        } else {
            zone.classList.add('hardware-locked-zone');
            zone.classList.remove('hardware-unlocked-zone');
            if (logEl) logEl.textContent = "Status: Please tick the agreement box above to enable smart hardware switches.";
        }
    }
}

function getConnectionModeBadge(mode, power) {
    const m = mode || (power >= 1000 ? 'wifi' : 'manual');
    if (m === 'wifi') return `<span class="badge light-green-bg"><i class="fa-solid fa-wifi"></i> Wi-Fi Smart Switch</span>`;
    if (m === 'smartmeter') return `<span class="badge" style="background:var(--accent-light); color:var(--primary);"><i class="fa-solid fa-gauge-high"></i> Smart Meter Linked</span>`;
    if (m === 'usb') return `<span class="badge light-green-bg"><i class="fa-solid fa-plug"></i> Direct Cable Switch</span>`;
    return `<span class="badge" style="background:rgba(100,116,139,0.15); color:var(--text-muted);"><i class="fa-solid fa-hand-pointer"></i> Manual Entry</span>`;
}

function renderAppliances() {
    const tbody = $('applianceList');
    if (!tbody) return;
    tbody.innerHTML = '';
    let totalLoadKwh = 0, activeWatts = 0;

    if (window.KamAbhiRAM.appliances.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center small-text">No appliances added yet. Add your home appliances above to see your estimated bill and live block diagram.</td></tr>';
    } else {
        window.KamAbhiRAM.appliances.forEach(app => {
            if (app.state) {
                totalLoadKwh += parseFloat(app.monthlyKwh);
                activeWatts += parseFloat(app.power);
            }
            const cost = computeSlabBill(parseFloat(app.monthlyKwh)).total.toFixed(0);
            const connBadge = getConnectionModeBadge(app.connMode, app.power);

            tbody.innerHTML += `<tr>
                <td><strong>${escapeHTML(app.name)}</strong></td>
                <td>${connBadge}</td>
                <td>${Number(app.power)} W</td>
                <td>${Number(app.hours)} hrs/day</td>
                <td>${Number(app.monthlyKwh)} Units</td>
                <td><label class="switch"><input type="checkbox" ${app.state ? 'checked' : ''} onchange="toggleApplianceState(${app.id}, this.checked)"><span class="slider"></span></label></td>
                <td class="text-primary"><b>₹${cost}</b></td>
                <td><button class="sm-btn danger-bg" onclick="deleteAppliance(${app.id})"><i class="fa-solid fa-trash"></i></button></td>
            </tr>`;
        });
    }

    window.KamAbhiRAM.totalUnits = totalLoadKwh;
    const billObj = totalLoadKwh > 0 ? computeSlabBill(totalLoadKwh) : { total: 0 };
    window.KamAbhiRAM.computedBillObj = billObj;

    safeSetText('dashLoadDisplay', `${totalLoadKwh.toFixed(1)} Units`);
    safeSetText('dashBillDisplay', `₹${billObj.total.toFixed(0)}`);
    safeSetText('paymentTabAmount', `₹${billObj.total.toFixed(2)}`);
    safeSetText('vampireDisplay', `₹${(billObj.total * 0.10).toFixed(0)}`);
    safeSetText('forecastBillDisplay', `₹${(totalLoadKwh > 0 ? computeSlabBill(totalLoadKwh * 1.12).total : 0).toFixed(0)}`);
    safeSetText('liveWattsDisplay', `${activeWatts} W`);
    safeSetText('flowTotalWattsBadge', `Running Load: ${activeWatts} W (${totalLoadKwh.toFixed(1)} Units/mo)`);
    safeSetText('autoAuditUnits', `${totalLoadKwh.toFixed(1)} Units`);
    safeSetText('autoAuditBill', `₹${billObj.total.toFixed(2)}`);
    safeSetText('autoAuditCarbon', `${(totalLoadKwh * 0.70).toFixed(1)} kg CO2`);

    checkMdiDemandOverload(activeWatts);
    $('budgetAlertBanner')?.classList.toggle('hidden', billObj.total <= window.KamAbhiRAM.budgetThreshold);

    // Render Live Power Distribution Block Diagram & Dashboard Daily Chart
    renderApplianceFlowchart(activeWatts, totalLoadKwh);
    renderDashboardChart(totalLoadKwh);
}

// 🔥 LIVE POWER DISTRIBUTION BLOCK DIAGRAM (RESTORED)
function renderApplianceFlowchart(activeWatts, totalKwh) {
    const box = $('applianceFlowchartContainer');
    if (!box) return;

    const apps = window.KamAbhiRAM.appliances;
    if (apps.length === 0) {
        box.innerHTML = `<div class="text-center small-text" style="padding: 16px;"><i class="fa-solid fa-diagram-project text-primary" style="font-size:1.6rem; opacity:0.6; margin-bottom:6px; display:block;"></i>No appliances connected yet. Add an appliance above to view the Live Power Distribution Block Diagram.</div>`;
        return;
    }

    const maxWatts = window.KamAbhiRAM.sanctionedLoadKw * 1000;
    const isOverload = activeWatts > maxWatts;
    const meterColor = isOverload ? 'var(--danger)' : 'var(--primary)';

    const nodesHtml = apps.map(app => {
        const sharePct = totalKwh > 0 && app.state ? Math.round((parseFloat(app.monthlyKwh) / totalKwh) * 100) : 0;
        const borderCol = app.state ? '#10B981' : '#94A3B8';
        const modeLabel = app.connMode === 'wifi'
            ? 'Wi-Fi Switch'
            : (app.connMode === 'smartmeter' ? 'Smart Meter' : (app.connMode === 'usb' ? 'Cable Switch' : 'Manual'));
        const statusBadge = app.state
            ? `<span class="badge light-green-bg" style="font-size:0.68rem;">ON • ${sharePct}% Load</span>`
            : `<span class="badge" style="background:rgba(148,163,184,0.2); color:var(--text-muted); font-size:0.68rem;">OFF</span>`;

        return `<div style="min-width: 160px; background: var(--card-bg); border: 2px solid ${borderCol}; border-radius: 12px; padding: 10px 12px; text-align: center; box-shadow: var(--shadow);">
            <div style="font-size: 0.72rem; color: var(--text-muted); margin-bottom: 4px;"><i class="fa-solid fa-bolt" style="color:${borderCol};"></i> ${escapeHTML(modeLabel)}</div>
            <div style="font-weight: 700; font-size: 0.88rem; margin-bottom: 4px; color: var(--text-color);">${escapeHTML(app.name)}</div>
            <div style="font-size: 0.8rem; font-weight: 600; color: var(--primary); margin-bottom: 6px;">${Number(app.power)} W • ${Number(app.monthlyKwh)} Units</div>
            ${statusBadge}
        </div>`;
    }).join('<div style="align-self:center; color:var(--primary); font-weight:bold;">➔</div>');

    box.innerHTML = `<div style="display: flex; flex-direction: column; align-items: center; gap: 14px;">
        <div style="display: flex; align-items: center; justify-content: center; gap: 12px; flex-wrap: wrap;">
            <div style="background: linear-gradient(135deg, #6366F1, #8B5CF6); color: #fff; padding: 10px 18px; border-radius: 12px; font-weight: 600; font-size: 0.85rem;"><i class="fa-solid fa-tower-observation"></i> Main Power Supply (228V AC)</div>
            <div style="color: var(--primary); font-weight: bold;">━━►</div>
            <div style="background: var(--card-bg); border: 2px solid ${meterColor}; padding: 10px 18px; border-radius: 12px; font-weight: 600; font-size: 0.85rem;">Home Meter Box: <span style="color:${meterColor};">${activeWatts}W / ${maxWatts}W</span></div>
        </div>
        <div style="color: var(--primary); font-size: 1.1rem; line-height: 1;">▼</div>
        <div style="display: flex; align-items: stretch; justify-content: center; gap: 10px; flex-wrap: wrap; width: 100%;">${nodesHtml}</div>
    </div>`;
}

function checkMdiDemandOverload(activeWatts) {
    const maxWatts = window.KamAbhiRAM.sanctionedLoadKw * 1000;
    const banner = $('mdiOverloadBanner');
    if (!banner) return;
    if (activeWatts > maxWatts) {
        safeSetText('mdiAlertTitle', `High Load Warning: ${activeWatts}W exceeds your ${maxWatts}W Meter Limit!`);
        banner.classList.remove('hidden');
    } else {
        banner.classList.add('hidden');
    }
}

function setChartMode(mode) {
    window.KamAbhiRAM.chartMode = mode;
    renderDashboardChart(window.KamAbhiRAM.totalUnits);
}

function renderDashboardChart(totalLoad) {
    const palette = ['#6366F1', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#0EA5E9', '#EC4899'];
    const activeApps = window.KamAbhiRAM.appliances;
    const hasData = activeApps.length > 0 && totalLoad > 0;

    const ctxEl = $('energyChart');
    if (ctxEl && typeof Chart !== 'undefined') {
        if (window.KamAbhiRAM.energyChart) window.KamAbhiRAM.energyChart.destroy();
        const ctx = ctxEl.getContext('2d');
        const grad = ctx.createLinearGradient(0, 0, 0, 300);
        grad.addColorStop(0, 'rgba(99, 102, 241, 0.45)');
        grad.addColorStop(1, 'rgba(99, 102, 241, 0.02)');
        const d = hasData ? (totalLoad / 30) : 0;

        window.KamAbhiRAM.energyChart = new Chart(ctx, {
            type: window.KamAbhiRAM.chartMode,
            data: {
                labels: hasData ? ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Today'] : ['Add appliances to see daily usage'],
                datasets: [{
                    label: 'Daily Usage (Units)',
                    data: hasData ? [(d*0.88).toFixed(2), (d*1.04).toFixed(2), (d*0.94).toFixed(2), (d*1.12).toFixed(2), (d*1.01).toFixed(2), (d*1.16).toFixed(2), d.toFixed(2)] : [],
                    borderColor: '#6366F1',
                    backgroundColor: window.KamAbhiRAM.chartMode === 'line' ? grad : palette,
                    borderWidth: 3, pointBackgroundColor: '#FFFFFF', pointBorderColor: '#6366F1', pointRadius: 5, fill: true, tension: 0.42
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
    }
}

// ---------------------------------------------------------
// ADD / TOGGLE APPLIANCES & SMART HARDWARE SWITCHES
// ---------------------------------------------------------
function applyPreset(key) {
    if (!APPLIANCE_PRESETS[key]) return;
    safeSetVal('appName', APPLIANCE_PRESETS[key].name);
    safeSetVal('appPower', APPLIANCE_PRESETS[key].power);
    safeSetVal('appHours', APPLIANCE_PRESETS[key].hours);
}

function addAppliance() {
    const name = safeGetVal('appName').trim();
    const power = Math.min(50000, Math.max(1, parseFloat(safeGetVal('appPower'))));
    const hours = Math.min(24, Math.max(0.1, parseFloat(safeGetVal('appHours'))));
    const connMode = safeGetVal('appConnMode') || 'manual';

    if (!name || isNaN(power) || isNaN(hours)) {
        return alert("Please enter a valid Appliance Name, Watts, and Daily Hours.");
    }

    if (connMode !== 'manual') {
        const riskChecked = $('appHardwareRiskCheck')?.checked;
        if (!riskChecked) {
            return alert("Hardware testing nhi kiya gya hai. Kripya apne risk or jimmedari par ye hardware connect kare, iske liye hamari team ki koi jimmedari nhi hogi.\n\nPlease tick the agreement checkbox before adding a hardware-linked appliance.");
        }
        window.KamAbhiRAM.hardwareConsentAccepted = true;
        if ($('hardwareMasterConsentCheck')) {
            $('hardwareMasterConsentCheck').checked = true;
            toggleHardwareRiskConsent(true);
        }
    }

    const monthlyKwh = ((power * hours * 30) / 1000).toFixed(2);
    window.KamAbhiRAM.appliances.push({ id: Date.now(), name, power, hours, monthlyKwh, state: true, connMode });
    safeSetVal('appName', ''); safeSetVal('appPower', ''); safeSetVal('appHours', '');
    renderAppliances();
    autoSyncToCloud();
}

function deleteAppliance(id) {
    window.KamAbhiRAM.appliances = window.KamAbhiRAM.appliances.filter(a => a.id !== id);
    renderAppliances();
    autoSyncToCloud();
}

function toggleApplianceState(id, state) {
    const app = window.KamAbhiRAM.appliances.find(a => a.id === id);
    if (app) {
        app.state = state;
        if (app.connMode && app.connMode !== 'manual' && window.KamAbhiRAM.hardwareConsentAccepted) {
            sendRealHardwareRelay(app.power >= 1500 ? 17 : 16, state);
        }
        renderAppliances();
        autoSyncToCloud();
    }
}

function executeHeavyApplianceCutoff() {
    window.KamAbhiRAM.appliances.forEach(a => { if (a.power >= 1000) a.state = false; });
    renderAppliances();
    if (window.KamAbhiRAM.hardwareConsentAccepted) {
        sendRealHardwareRelay(16, false);
        sendRealHardwareRelay(17, false);
    }
}

async function generateSwitchSignature(pin, val, secretKey) {
    const timestamp = Math.floor(Date.now() / 1000);
    const message = `${pin}:${val}:${timestamp}`;
    const encoder = new TextEncoder();
    const cryptoKey = await crypto.subtle.importKey('raw', encoder.encode(secretKey || 'emcs_default_key'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signatureBuffer = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(message));
    const signatureHex = Array.from(new Uint8Array(signatureBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    return { timestamp, signatureHex };
}

function isLocalHomeWifiUrl(urlString) {
    try {
        const parsed = new URL(urlString);
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
        if (parsed.username || parsed.password) return false;
        const parts = parsed.hostname.split('.').map(Number);
        if (parts.length !== 4 || parts.some(n => isNaN(n) || n < 0 || n > 255)) return false;
        if (parts[0] === 10) return true;
        if (parts[0] === 192 && parts[1] === 168) return true;
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
        return false;
    } catch (e) { return false; }
}

async function sendRealHardwareRelay(pin, state) {
    if (!window.KamAbhiRAM.hardwareConsentAccepted && !$('hardwareMasterConsentCheck')?.checked) {
        alert("Please tick the hardware responsibility agreement box first.");
        return;
    }

    const endpoint = safeGetVal('iotCutoffEndpoint').trim();
    const authKey = safeGetVal('espAuthToken').trim();
    const badge = $(`gpio${pin}Status`);
    const logEl = $('espConsoleLog');
    const val = state ? 1 : 0;

    if (badge) {
        badge.textContent = state ? "ON" : "OFF";
        badge.className = state ? "badge light-green-bg" : "badge light-red-bg";
    }

    if (!isLocalHomeWifiUrl(endpoint)) {
        if (logEl) logEl.textContent = "Status: Please enter a valid home Wi-Fi address (e.g. http://192.168.1.50/switch).";
        return;
    }

    const { timestamp, signatureHex } = await generateSwitchSignature(pin, val, authKey);
    const targetUrl = `${endpoint}?pin=${encodeURIComponent(pin)}&val=${val}&ts=${timestamp}&sig=${signatureHex}`;
    if (logEl) logEl.textContent = `Status: Command sent to Switch ${pin === 16 ? '1' : '2'} (${state ? 'Turned ON' : 'Turned OFF'}).`;
    try { await fetch(targetUrl, { method: 'GET', mode: 'no-cors' }); } catch (e) {}
}

async function connectSerialHardware() {
    if (!window.KamAbhiRAM.hardwareConsentAccepted && !$('hardwareMasterConsentCheck')?.checked) {
        return alert("Please tick the hardware responsibility agreement box first.");
    }
    if (!("serial" in navigator)) return alert("Direct cable connection requires Google Chrome or Microsoft Edge browser.");
    try {
        const port = await navigator.serial.requestPort();
        await port.open({ baudRate: 115200 });
        safeSetText('hardwareConnectionBadge', 'Cable Connected');
    } catch (e) { alert("Cable connection was cancelled."); }
}

// ---------------------------------------------------------
// VOLTAGE, INVERTER, SOLAR & STANDBY POWER SAVER
// ---------------------------------------------------------
function calculateInverterRuntime() {
    const ah = Math.max(1, parseFloat(safeGetVal('invBatteryAh')) || 150);
    const volts = parseFloat(safeGetVal('invVoltage')) || 12;
    const watts = Math.max(0, parseFloat(safeGetVal('invActiveLoad')) || 0);
    if (watts <= 0) return safeSetText('inverterRuntimeOutput', 'No Load');
    const hours = (ah * volts * 0.85) / watts;
    safeSetText('inverterRuntimeOutput', `${Math.floor(hours)} Hrs ${Math.round((hours%1)*60)} Min`);
}

function fetchActiveLoadToInverter() {
    let activeWatts = 0;
    window.KamAbhiRAM.appliances.forEach(a => { if (a.state) activeWatts += parseFloat(a.power); });
    safeSetVal('invActiveLoad', activeWatts || 100);
    calculateInverterRuntime();
}

function simulateGridVoltage(v) {
    safeSetText('liveVoltageMetric', `${v} V`);
    const box = $('voltageAlertBox');
    box.classList.remove('hidden');
    if (v < 180 || v > 260) {
        safeSetText('voltageHealthBadge', `${v}V • Unsafe`);
        box.textContent = "⚠️ Unsafe voltage detected! Heavy appliances have been turned off for protection.";
        box.style.background = "rgba(239,68,68,0.15)";
        executeHeavyApplianceCutoff();
    } else {
        safeSetText('voltageHealthBadge', `${v}V • Safe`);
        box.textContent = "✓ Voltage is normal and safe for all home appliances.";
        box.style.background = "rgba(16,185,129,0.15)";
    }
}

function calculateSolarRoi() {
    const units = Math.max(10, parseFloat(safeGetVal('solarInputUnits')) || 300);
    const area = Math.max(50, parseFloat(safeGetVal('solarInputArea')) || 250);
    const kw = Math.max(1, Math.min(10, Math.min(units / 120, area / 80)));
    safeSetText('solarCapResult', `${kw.toFixed(1)} kW`);
    safeSetText('solarCostResult', `₹${Math.round(kw * 50000).toLocaleString('en-IN')}`);
    safeSetText('solarSubsidyResult', `-₹${(kw <= 2 ? kw * 30000 : 78000).toLocaleString('en-IN')}`);
}

function toggleVampireItem(val, chk) {
    window.KamAbhiRAM.vampireSavings += chk.checked ? val : -val;
    safeSetText('vampireTotalSavedBadge', `Saved: ₹${window.KamAbhiRAM.vampireSavings}/month`);
}

// ---------------------------------------------------------
// BILL PHOTO SCANNER & SMART METER FILE READER
// ---------------------------------------------------------
async function validateUploadedImage(file) {
    const MAX_IMAGE_SIZE = 4 * 1024 * 1024;
    const allowedMimes = ['image/jpeg', 'image/png', 'image/webp'];

    if (file.size > MAX_IMAGE_SIZE) throw new Error('Photo is too large! Maximum 4 MB allowed.');
    if (!allowedMimes.includes(file.type)) throw new Error('Please upload a valid JPG, PNG, or WebP photo.');

    const buffer = await file.slice(0, 4).arrayBuffer();
    const bytes = new Uint8Array(buffer);
    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

    const isJpeg = hex.startsWith('FFD8FF');
    const isPng = hex === '89504E47';
    const isWebp = hex === '52494646';

    if (!isJpeg && !isPng && !isWebp) throw new Error('Invalid photo file selected.');
}

async function processBillOcr() {
    const file = $('billImageInput').files[0];
    if (!file) return alert('Please select a bill photo first.');

    try {
        await validateUploadedImage(file);
    } catch (securityErr) {
        reportSystemError('Bill Scanner');
        $('billImageInput').value = '';
        return alert(securityErr.message);
    }

    $('ocrLoader').classList.remove('hidden');
    try {
        const { data: { text } } = await Tesseract.recognize(file, 'eng');
        const unitsMatch = text.match(/(?:units?|kwh)[\s\-:]*([0-9]{1,5})/i);
        const u = unitsMatch ? unitsMatch[1] : '250';
        safeSetText('ocrConsumerId', window.KamAbhiRAM?.userSession?.consumerId || 'Verified');
        safeSetText('ocrUnits', u);
        safeSetText('ocrAmount', `₹${computeSlabBill(parseFloat(u)).total.toFixed(0)}`);
        window.lastOcrUnits = parseFloat(u);
        $('ocrResultBox').classList.remove('hidden');
    } catch (e) {
        reportSystemError('Bill Scanner');
        alert('Could not read the bill photo clearly. Please try a clearer image.');
    }
    $('ocrLoader').classList.add('hidden');
}

function applyOcrToSimulator() {
    if (window.lastOcrUnits) safeSetVal('simUserUnits', window.lastOcrUnits);
    calculateSimulator();
    showFeature('simulator', null);
}

function handleSmartMeterCsv(e) {
    const file = e.target.files[0];
    if (!file) return;

    const MAX_CSV_SIZE = 2 * 1024 * 1024;
    const isCsvExt = /\.(csv|txt)$/i.test(file.name);
    if (file.size > MAX_CSV_SIZE || !isCsvExt) {
        reportSystemError('Meter File Reader');
        e.target.value = '';
        return alert('Please select a valid .csv or .txt file under 2 MB.');
    }

    const reader = new FileReader();
    reader.onload = (ev) => {
        const content = String(ev.target.result || '');
        if (content.includes('\0')) {
            e.target.value = '';
            return alert('Invalid file format.');
        }

        const rows = content.split(/\r?\n/).slice(1, 10001);
        let total = 0, peak = 0, count = 0;
        rows.forEach(r => {
            const cols = r.split(',');
            const val = parseFloat(cols[1]);
            if (!isNaN(val) && val >= 0 && val <= 1000) {
                total += val;
                count++;
                if (val > peak) peak = val;
            }
        });
        $('csvSummaryBox').classList.remove('hidden');
        safeSetText('csvTotalKwh', `${total.toFixed(1)} Units`);
        safeSetText('csvPeakHour', `${peak.toFixed(2)} Units`);
        safeSetText('csvAvgDaily', `${(total / Math.max(1, count / 24)).toFixed(1)} Units/day`);
    };
    reader.readAsText(file);
}

// ---------------------------------------------------------
// PAYMENT, REPORTS & SAVINGS CALCULATOR
// ---------------------------------------------------------
function executeRealPayment() {
    const amt = window.KamAbhiRAM.computedBillObj.total;
    if (amt <= 0) return alert("You have no pending bill amount.");
    alert("Online payment is currently not enabled. Please contact your Admin.");
}

function renderRealPaymentLedger() {
    window.KamAbhiRAM.paymentHistory = JSON.parse(localStorage.getItem('emcs_txns')) || [];
    const tbody = $('sixMonthTableBody');
    if (!tbody) return;
    if (window.KamAbhiRAM.paymentHistory.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center small-text">No past payment receipts found.</td></tr>';
        return;
    }
    tbody.innerHTML = window.KamAbhiRAM.paymentHistory.map(t => `<tr><td><b>${escapeHTML(t.txnId)}</b></td><td>${escapeHTML(t.units)} Units</td><td><b>₹${escapeHTML(t.amount)}</b></td><td><span class="badge light-green-bg">${escapeHTML(t.status)}</span></td></tr>`).join('');
}

function downloadInvoicePDF() {
    const card = document.createElement('div');
    card.style.padding = '24px';
    card.innerHTML = `<h2>EMCS - Electricity Bill Summary</h2><hr><p>Monthly Usage: ${window.KamAbhiRAM.totalUnits.toFixed(1)} Units</p><h3>Estimated Bill: ₹${window.KamAbhiRAM.computedBillObj.total.toFixed(2)}</h3><p><small>Note: This is an estimated bill based on your selected electricity rates.</small></p>`;
    if (typeof html2pdf !== 'undefined') html2pdf().from(card).save('EMCS_Bill_Report.pdf');
}

function exportYearlyExcel() {
    let csv = "Appliance,Connection_Mode,Watts,Daily_Hours,Monthly_Units\n";
    window.KamAbhiRAM.appliances.forEach(a => { csv += `"${a.name}","${a.connMode || 'manual'}",${a.power},${a.hours},${a.monthlyKwh}\n`; });
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' })); a.download = 'EMCS_Appliances_Report.csv'; a.click();
}

function calculateSimulator() {
    const u = parseFloat(safeGetVal('simUserUnits')) || 300;
    const r = parseFloat(safeGetVal('simUserRate')) || 7.5;
    const p = parseFloat(safeGetVal('simSlider')) || 15;
    safeSetText('simPctVal', p);
    safeSetText('simUnitsResult', `${(u * p / 100).toFixed(1)} Units`);
    safeSetText('simSavingsResult', `₹${(u * p / 100 * r).toFixed(0)}`);
}

// ---------------------------------------------------------
// KAMABHI AI (EMCS AI) - LOGIN GUARD, CONCURRENCY & SPAM PROTECTION
// ---------------------------------------------------------
let isAIFetching = false;

function speakFemaleVoice(text) {
    if (!('speechSynthesis' in window)) return;
    window.speechSynthesis.cancel();
    const utter = new SpeechSynthesisUtterance(text);
    const voices = window.speechSynthesis.getVoices();
    const fVoice = voices.find(v => /female|veena|lekha|samantha|zira|google हिन्दी/i.test(v.name)) || voices[0];
    if (fVoice) utter.voice = fVoice;
    utter.pitch = 1.08;
    window.speechSynthesis.speak(utter);
}

async function loadAiChatHistory() {
    const box = $('tabChatBox');
    if (!box) return;

    if (!window.KamAbhiRAM.userSession) {
        box.innerHTML = `<div class="clean-card p-2" style="max-width:88%; align-self:flex-start;">
            <p class="small-text" style="color:var(--text-color);">Hello! I am <b>KamAbhi AI</b> (EMCS AI Assistant). Please <b>Login</b> to your account to ask electrical, safety, and energy-saving questions.</p>
        </div>`;
        return;
    }

    try {
        const res = await secureApiFetch('/ai/history');
        const data = await res.json();
        if (data.success && Array.isArray(data.messages) && data.messages.length > 0) {
            box.innerHTML = data.messages.map(m => {
                if (m.sender === 'user') {
                    return `<div class="clean-card p-2" style="align-self:flex-end; background:var(--primary); color:#fff; max-width:82%;">${escapeHTML(m.text)}</div>`;
                }
                const safeTxt = escapeHTML(m.text);
                return `<div class="clean-card p-2" style="align-self:flex-start; max-width:88%; animation: bubbleSlideRight 0.3s ease;">
                    <p class="small-text" style="color:var(--text-color); white-space:pre-line;">${safeTxt}</p>
                    <button class="sm-btn mt-1 hover-pop" style="background:var(--accent-light); color:var(--primary);" onclick="speakFemaleVoice('${safeTxt.replace(/'/g, "").replace(/\n/g, " ")}')"><i class="fa-solid fa-volume-high"></i> Listen</button>
                </div>`;
            }).join('');
            box.scrollTop = box.scrollHeight;
        }
    } catch (e) {}
}

async function sendTabChatMessage() {
    if (!window.KamAbhiRAM.userSession) {
        alert("Please login to your account first to chat with KamAbhi AI.");
        closeAllPopups();
        openLoginModal();
        return;
    }

    if (isAIFetching) {
        alert("Wait kro pichle question ka answer likh rhe hai. Uske baad dusra question bhejo.");
        return;
    }

    const input = $('tabChatInput');
    const raw = input.value.trim().slice(0, 500);
    if (!raw) return;

    input.value = '';
    const box = $('tabChatBox');
    box.innerHTML += `<div class="clean-card p-2" style="align-self:flex-end; background:var(--primary); color:#fff; max-width:80%;">${escapeHTML(raw)}</div>`;

    const typingId = 'aiTyping_' + Date.now();
    box.innerHTML += `<div id="${typingId}" class="clean-card p-2 small-text" style="align-self:flex-start; max-width:75%;"><i class="fa-solid fa-spinner fa-spin text-primary"></i> KamAbhi AI is writing your answer...</div>`;
    box.scrollTop = box.scrollHeight;

    if (/turn off heavy|cut heavy|ac off/i.test(raw)) {
        executeHeavyApplianceCutoff();
    }

    isAIFetching = true;
    try {
        const res = await secureApiFetch('/ai/chat', {
            method: 'POST',
            body: JSON.stringify({ text: raw })
        });
        const data = await res.json();
        $(typingId)?.remove();

        const replyText = data.reply || data.message || "Something went wrong, try again later.";
        const safeReply = escapeHTML(replyText);

        if (!res.ok || !data.success) {
            box.innerHTML += `<div class="clean-card p-2 danger-text" style="align-self:flex-start; max-width:88%;"><b>Notice:</b> ${safeReply}</div>`;
        } else {
            box.innerHTML += `<div class="clean-card p-2" style="align-self:flex-start; max-width:88%; animation: bubbleSlideRight 0.3s ease;">
                <p class="small-text" style="color:var(--text-color); white-space:pre-line;">${safeReply}</p>
                <button class="sm-btn mt-1 hover-pop" style="background:var(--accent-light); color:var(--primary);" onclick="speakFemaleVoice('${safeReply.replace(/'/g, "").replace(/\n/g, " ")}')"><i class="fa-solid fa-volume-high"></i> Listen</button>
            </div>`;
        }
        box.scrollTop = box.scrollHeight;
    } catch (e) {
        $(typingId)?.remove();
        box.innerHTML += `<div class="clean-card p-2 danger-text" style="align-self:flex-start;">Something went wrong, try again later.</div>`;
    } finally {
        isAIFetching = false;
    }
}

// ---------------------------------------------------------
// AUTHENTICATION UI, DUAL LOGIN TOGGLE & FORM AUTO-DESTROY
// ---------------------------------------------------------
function toggleLoginUI() {
    const type = document.querySelector('input[name="loginType"]:checked')?.value || 'mobile';
    const input = $('loginIdentifier');
    const wrapper = $('loginInputWrapper');
    const prefix = $('loginPrefix');
    if (!input) return;

    input.value = '';
    input.oninput = null;

    if (type === 'mobile') {
        input.type = 'tel';
        input.setAttribute('maxlength', '10');
        input.setAttribute('pattern', '[0-9]{10}');
        input.placeholder = 'Enter Your 10 Digit Mobile No';
        input.oninput = function() { this.value = this.value.replace(/[^0-9]/g, ''); };
        if (prefix) prefix.classList.remove('hidden');
        if (wrapper) wrapper.classList.add('phone-input-group');
    } else {
        input.type = 'email';
        input.setAttribute('maxlength', '90');
        input.removeAttribute('pattern');
        input.placeholder = 'Enter Your Email Address';
        if (prefix) prefix.classList.add('hidden');
        if (wrapper) wrapper.classList.remove('phone-input-group');
    }
}

function toggleRegAuthUI() {
    const checked = document.querySelector('input[name="regAuthType"]:checked');
    const type = checked ? checked.value : 'pin';
    const input = $('regCredential');
    if (!input) return;
    input.value = '';
    input.oninput = null;
    if (type === 'pin') {
        input.setAttribute('pattern', '[0-9]{4,6}');
        input.setAttribute('minlength', '4');
        input.setAttribute('maxlength', '6');
        input.placeholder = 'Enter PIN';
        input.oninput = function() { this.value = this.value.replace(/[^0-9]/g, ''); };
    } else {
        input.removeAttribute('pattern');
        input.setAttribute('minlength', '8');
        input.setAttribute('maxlength', '16');
        input.placeholder = 'Enter Password';
    }
}

function toggleForgotUI() {
    const checked = document.querySelector('input[name="recoveryType"]:checked');
    const type = checked ? checked.value : 'cid';
    const input = $('forgotRecoveryValue');
    if (!input) return;
    input.value = '';
    input.oninput = null;

    if (type === 'cid') {
        input.type = 'text';
        input.setAttribute('inputmode', 'numeric');
        input.setAttribute('minlength', '12');
        input.setAttribute('maxlength', '12');
        input.setAttribute('pattern', '[0-9]{12}');
        input.placeholder = 'Enter 12 Digit Consumer ID';
        input.oninput = function() { this.value = this.value.replace(/[^0-9]/g, ''); };
    } else {
        input.type = 'email';
        input.removeAttribute('inputmode');
        input.removeAttribute('minlength');
        input.removeAttribute('pattern');
        input.setAttribute('maxlength', '90');
        input.placeholder = 'Enter Email Address';
    }
}

function toggleForgotAuthUI() {
    const checked = document.querySelector('input[name="forgotAuthType"]:checked');
    const type = checked ? checked.value : 'pin';
    const input = $('forgotNewCredential');
    if (!input) return;
    input.value = '';
    input.oninput = null;
    if (type === 'pin') {
        input.setAttribute('pattern', '[0-9]{4,6}');
        input.setAttribute('minlength', '4');
        input.setAttribute('maxlength', '6');
        input.placeholder = 'Enter New PIN';
        input.oninput = function() { this.value = this.value.replace(/[^0-9]/g, ''); };
    } else {
        input.removeAttribute('pattern');
        input.setAttribute('minlength', '8');
        input.setAttribute('maxlength', '16');
        input.placeholder = 'Enter New Password';
    }
}

function destroyAllAuthFormData() {
    const formIds = ['modalLoginForm', 'modalRegisterForm', 'modalForgotForm', 'modalAdminForm'];
    formIds.forEach(id => {
        const formEl = $(id);
        if (formEl) formEl.reset();
    });

    [
        'loginIdentifier', 'loginMobile', 'loginCredential', 'loginHoneypot',
        'regName', 'regMobile', 'regConsumerId', 'regEmail', 'regCredential', 'regHoneypot',
        'forgotMobile', 'forgotName', 'forgotRecoveryValue', 'forgotNewCredential',
        'adminLoginUser', 'adminLoginPass'
    ].forEach(fieldId => safeSetVal(fieldId, ''));

    if ($('regTermsCheck')) $('regTermsCheck').checked = false;

    ['loginCredential', 'regCredential', 'forgotNewCredential', 'adminLoginPass'].forEach(fieldId => {
        const el = $(fieldId);
        if (el) el.type = 'password';
    });
    document.querySelectorAll('#loginModal .fa-eye-slash').forEach(icon => {
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    });

    toggleLoginUI();
    toggleRegAuthUI();
    toggleForgotUI();
    toggleForgotAuthUI();
    safeSetText('modalAuthError', '');
}

function openLoginModal() {
    destroyAllAuthFormData();
    switchAuthTab('login', $('authTabButtons')?.children[0]);
    $('loginModal').classList.remove('hidden');
    $('popupOverlay').classList.remove('hidden');
}

function openAIModal() {
    loadAiChatHistory();
    $('aiModal').classList.remove('hidden');
    $('popupOverlay').classList.remove('hidden');
}

function closeAllPopups() {
    const legalEl = $('legalModal');
    const loginEl = $('loginModal');
    if (legalEl && !legalEl.classList.contains('hidden') && loginEl && !loginEl.classList.contains('hidden')) {
        legalEl.classList.add('hidden');
        return;
    }
    document.querySelectorAll('.popup-modal').forEach(m => m.classList.add('hidden'));
    $('popupOverlay').classList.add('hidden');
    destroyAllAuthFormData();
}

function switchAuthTab(tab, btn) {
    destroyAllAuthFormData();
    document.querySelectorAll('#authTabButtons button').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    ['modalLoginForm', 'modalRegisterForm', 'modalForgotForm', 'modalAdminForm'].forEach(id => $(id).classList.add('hidden'));
    if (tab === 'login') $('modalLoginForm').classList.remove('hidden');
    if (tab === 'register') $('modalRegisterForm').classList.remove('hidden');
    if (tab === 'forgot') $('modalForgotForm').classList.remove('hidden');
    if (tab === 'admin') $('modalAdminForm').classList.remove('hidden');
}

// ---------------------------------------------------------
// AUTHENTICATION HANDLERS (WITH INVISIBLE BOT TRAP)
// ---------------------------------------------------------
async function handleSecureRegister(e) {
    e.preventDefault();
    const botTrap = safeGetVal('regHoneypot');

    if ($('regTermsCheck') && !$('regTermsCheck').checked) {
        return safeSetText('modalAuthError', 'Please accept the Privacy Policy and Terms & Conditions.');
    }

    const mobile = safeGetVal('regMobile').trim();
    const consumerId = safeGetVal('regConsumerId').trim();

    if (!/^[0-9]{10}$/.test(mobile)) {
        return safeSetText('modalAuthError', 'Please enter a valid 10 Digit Mobile No.');
    }
    if (!/^[0-9]{12}$/.test(consumerId)) {
        return safeSetText('modalAuthError', 'Consumer ID must be strictly 12 digits (numbers 0-9 only).');
    }

    const emailCheck = isStrictValidEmail(safeGetVal('regEmail'));
    if (!emailCheck.ok) return safeSetText('modalAuthError', emailCheck.msg);

    const authType = document.querySelector('input[name="regAuthType"]:checked')?.value || 'pin';
    const credential = safeGetVal('regCredential').trim();

    if (authType === 'pin' && !/^[0-9]{4,6}$/.test(credential)) {
        return safeSetText('modalAuthError', 'Please enter a valid 4 to 6 digit PIN.');
    }
    if (authType === 'password' && (credential.length < 8 || credential.length > 16)) {
        return safeSetText('modalAuthError', 'Please enter a valid Password (8 to 16 characters).');
    }

    const payload = {
        name: safeGetVal('regName').trim(),
        mobile,
        email: emailCheck.email,
        consumerId,
        authType,
        credential,
        termsAccepted: true,
        _emcs_trap: botTrap
    };
    try {
        const res = await secureApiFetch('/auth/register', { method: 'POST', body: JSON.stringify(payload) });
        const data = await res.json();
        if (data.success) {
            alert("Your account has been created! Please log in.");
            switchAuthTab('login', $('authTabButtons').children[0]);
        } else {
            safeSetText('modalAuthError', data.message || 'Something went wrong, try again later.');
        }
    } catch (err) {
        reportSystemError('Registration');
        safeSetText('modalAuthError', 'Something went wrong, try again later.');
    }
}

async function handleSecureLogin(e) {
    e.preventDefault();
    const botTrap = safeGetVal('loginHoneypot');
    const loginType = document.querySelector('input[name="loginType"]:checked')?.value || 'mobile';
    const loginValue = (safeGetVal('loginIdentifier') || safeGetVal('loginMobile')).trim();
    const credential = safeGetVal('loginCredential').trim();

    if (loginType === 'email') {
        const emailCheck = isStrictValidEmail(loginValue);
        if (!emailCheck.ok) return safeSetText('modalAuthError', emailCheck.msg);
    } else if (!/^[0-9]{10}$/.test(loginValue)) {
        return safeSetText('modalAuthError', 'Please enter a valid 10 Digit Mobile No.');
    }

    const payload = {
        loginType,
        loginValue: loginType === 'email' ? loginValue.toLowerCase() : loginValue,
        credential,
        _emcs_trap: botTrap
    };
    try {
        const res = await secureApiFetch('/auth/login', { method: 'POST', body: JSON.stringify(payload) });
        const data = await res.json();
        if (data.success) {
            localStorage.setItem('ecoActiveUser', JSON.stringify(data.user));
            setupUserSession(data.user);
            await refreshDataFromCloud();
            closeAllPopups();
        } else {
            safeSetText('modalAuthError', data.message || 'Invalid login details.');
        }
    } catch (err) {
        reportSystemError('Login');
        safeSetText('modalAuthError', 'Something went wrong, try again later.');
    }
}

async function handleForgotReset(e) {
    e.preventDefault();
    const mobile = safeGetVal('forgotMobile').trim();
    if (!/^[0-9]{10}$/.test(mobile)) {
        return safeSetText('modalAuthError', 'Please enter a valid 10 Digit Mobile No.');
    }

    const recoveryType = document.querySelector('input[name="recoveryType"]:checked')?.value || 'cid';
    const recoveryValue = safeGetVal('forgotRecoveryValue').trim();

    if (recoveryType === 'email') {
        const check = isStrictValidEmail(recoveryValue);
        if (!check.ok) return safeSetText('modalAuthError', check.msg);
    } else if (!/^[0-9]{12}$/.test(recoveryValue)) {
        return safeSetText('modalAuthError', 'Please enter a valid 12 Digit Consumer ID (numbers only).');
    }

    const newAuthType = document.querySelector('input[name="forgotAuthType"]:checked')?.value || 'pin';
    const newCredential = safeGetVal('forgotNewCredential').trim();

    if (newAuthType === 'pin' && !/^[0-9]{4,6}$/.test(newCredential)) {
        return safeSetText('modalAuthError', 'Please enter a valid 4 to 6 digit New PIN.');
    }
    if (newAuthType === 'password' && (newCredential.length < 8 || newCredential.length > 16)) {
        return safeSetText('modalAuthError', 'Please enter a valid New Password (8 to 16 characters).');
    }

    const payload = {
        mobile,
        registeredName: safeGetVal('forgotName').trim(),
        recoveryType,
        recoveryValue: recoveryType === 'cid' ? recoveryValue : recoveryValue.toLowerCase(),
        newAuthType,
        newCredential
    };
    try {
        const res = await secureApiFetch('/auth/verify-and-reset', { method: 'POST', body: JSON.stringify(payload) });
        const data = await res.json();
        if (data.success) {
            alert(data.message || 'Your PIN/Password has been reset! Please log in.');
            switchAuthTab('login', $('authTabButtons').children[0]);
        } else {
            safeSetText('modalAuthError', data.message || 'Details did not match our records.');
        }
    } catch (err) {
        safeSetText('modalAuthError', 'Something went wrong, try again later.');
    }
}
const handleFreePinReset = handleForgotReset;

// ---------------------------------------------------------
// CLOUD SYNC & USER SESSION MANAGEMENT
// ---------------------------------------------------------
async function refreshDataFromCloud() {
    try {
        const res = await secureApiFetch('/user/get-cloud-data');
        if (res.status === 401 || res.status === 403) {
            localStorage.removeItem('ecoActiveUser');
            window.KamAbhiRAM.userSession = null;
            return;
        }
        const data = await res.json();
        if (data.success && data.data) {
            const d = data.data;
            if (d.name) {
                safeSetText('userGreeting', `Welcome, ${d.name}! ☀️`);
                safeSetVal('profileName', d.name);
            }
            if (d.consumerId) safeSetVal('profileId', d.consumerId);
            if (Array.isArray(d.appliances)) window.KamAbhiRAM.appliances = d.appliances;
            if (d.sanctionedLoadKw) { window.KamAbhiRAM.sanctionedLoadKw = d.sanctionedLoadKw; safeSetVal('sanctionedLoadSelect', d.sanctionedLoadKw.toFixed(1)); }
            if (d.budgetThreshold) { window.KamAbhiRAM.budgetThreshold = d.budgetThreshold; safeSetText('currentBudgetDisplay', `₹${d.budgetThreshold}`); }
            if (d.tariffProvider) safeSetVal('tariffProviderSelect', d.tariffProvider);
            if (d.tariffCategory) safeSetVal('tariffCategorySelect', d.tariffCategory);
            if (d.tariffArea) safeSetVal('tariffAreaSelect', d.tariffArea);
            if (d.customTariff && d.customTariff.slabs) localStorage.setItem('emcs_custom_tariff', JSON.stringify(d.customTariff));
            renderAppliances();
        }
    } catch (e) {}
}

async function autoSyncToCloud() {
    if (!window.KamAbhiRAM.userSession) return;
    enforceUrlAntiIdorGuard();
    const payload = {
        appliances: window.KamAbhiRAM.appliances,
        sanctionedLoadKw: window.KamAbhiRAM.sanctionedLoadKw,
        budgetThreshold: window.KamAbhiRAM.budgetThreshold,
        tariffProvider: safeGetVal('tariffProviderSelect'),
        tariffCategory: safeGetVal('tariffCategorySelect'),
        tariffArea: safeGetVal('tariffAreaSelect'),
        customTariff: JSON.parse(localStorage.getItem('emcs_custom_tariff') || 'null')
    };
    secureApiFetch('/user/sync-cloud', { method: 'POST', body: JSON.stringify(payload) }).catch(() => {});
}

function setupUserSession(user) {
    window.KamAbhiRAM.userSession = user;
    safeSetText('userGreeting', `Welcome, ${user.name}! ☀️`);
    safeSetVal('profileName', user.name);
    safeSetVal('profileId', user.consumerId);
    $('sidebarAuthArea').innerHTML = `<button class="secondary-btn sm-btn w-100" onclick="logoutUser()"><i class="fa-solid fa-power-off"></i> Logout (${escapeHTML(user.name)})</button>`;
    enforceUrlAntiIdorGuard();
}

function logoutUser() {
    localStorage.removeItem('ecoActiveUser');
    secureApiFetch('/auth/logout', { method: 'POST' }).catch(() => {});
    location.reload();
}

async function openDeviceManager() {
    $('deviceManagerModal').classList.remove('hidden');
    $('popupOverlay').classList.remove('hidden');
    const tbody = $('deviceSessionList');
    tbody.innerHTML = '<tr><td colspan="4">Loading logged-in devices...</td></tr>';
    try {
        const res = await secureApiFetch('/auth/devices');
        const data = await res.json();
        if (data.success) {
            tbody.innerHTML = data.sessions.map(s => `
                <tr><td>${escapeHTML(s.deviceInfo)}</td><td>${new Date(s.createdAt).toLocaleString()}</td>
                <td>${s.isCurrent ? '<b class="green-text">This Device</b>' : 'Logged In'}</td>
                <td>${s.isCurrent ? '—' : (s.canRevoke ? `<button class="sm-btn danger-bg" onclick="revokeDevice('${s.sessionId}')">Remove</button>` : `<span class="badge">${s.hoursRemaining}h wait</span>`)}</td></tr>
            `).join('');
        }
    } catch (e) {
        tbody.innerHTML = `<tr><td>Current Browser</td><td>Active Now</td><td><b class="green-text">This Device</b></td><td>—</td></tr>`;
    }
}

async function revokeDevice(targetSessionId) {
    const res = await secureApiFetch('/auth/revoke-device', { method: 'POST', body: JSON.stringify({ targetSessionId }) });
    const data = await res.json();
    alert(data.message || 'Device removed.');
    openDeviceManager();
}

// ---------------------------------------------------------
// ADMIN MANAGEMENT PANEL (LEFT SIDEBAR, AI HISTORY, EMERGENCY ALERTS)
// ---------------------------------------------------------
let activeAdminKycCid = null;

async function handleSecureAdminLogin(e) {
    e.preventDefault();
    const username = safeGetVal('adminLoginUser').trim();
    const password = safeGetVal('adminLoginPass').trim();
    try {
        const res = await secureApiFetch('/admin/login', { method: 'POST', body: JSON.stringify({ username, password }) });
        const data = await res.json();
        if (data.success) {
            safeSetVal('adminLoginPass', '');
            enterAdminHub(data);
        } else {
            safeSetText('modalAuthError', data.message || 'Invalid Admin Key.');
        }
    } catch (err) {
        reportSystemError('Admin Login');
        safeSetText('modalAuthError', 'Something went wrong, try again later.');
    }
}

function enterAdminHub(data) {
    closeAllPopups();
    $('mainAppSection').classList.add('hidden');$('adminSection').classList.remove('hidden');

    $('appSidebar').classList.remove('hidden');
    $('consumerNavLinks')?.classList.add('hidden');$('sidebarAuthArea')?.classList.add('hidden');
    $('adminNavLinks')?.classList.remove('hidden');$('adminSidebarFooter')?.classList.remove('hidden');
    safeSetText('sidebarSubTitle', 'Admin Management Panel');

    safeSetText('adminRoleDisplay', `${data.name} (${data.role.toUpperCase()})`);
    $('ownerStaffTabBtn')?.classList.toggle('hidden', data.role !== 'owner');
    $('masterDumpBtn')?.classList.toggle('hidden', data.role !== 'owner');$('ownerCmsTabBtn')?.classList.toggle('hidden', !data.permissions?.canEditCMS && data.role !== 'owner');
    $('purgeAllChatsBtn')?.classList.toggle('hidden', !data.permissions?.canDeleteChat && data.role !== 'owner');

    const firstAdminItem = document.querySelector('#adminNavLinks .nav-item');
    switchAdminSubTab('chatTab', firstAdminItem);
    loadAdminChatThreads();
    loadStaffList();
    loadEmergencyAlerts();
    loadSystemErrors();
}

function exitAdminView() {
    secureApiFetch('/admin/logout', { method: 'POST' }).catch(() => {});
    $('adminSection').classList.add('hidden');$('mainAppSection').classList.remove('hidden');

    $('adminNavLinks')?.classList.add('hidden');$('adminSidebarFooter')?.classList.add('hidden');
    $('consumerNavLinks')?.classList.remove('hidden');$('sidebarAuthArea')?.classList.remove('hidden');
    safeSetText('sidebarSubTitle', 'Smart Energy Manager');

    safeSetVal('adminLoginUser', '');
    safeSetVal('adminLoginPass', '');
}

function switchAdminSubTab(tab, btn) {
    document.querySelectorAll('.admin-sub-pane').forEach(p => {
        p.classList.add('hidden');
        p.classList.remove('active-feature');
    });
    document.querySelectorAll('#adminNavLinks .nav-item').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');

    let targetPane = null;
    if (tab === 'chatTab') targetPane = $('adminChatSubPane');
    if (tab === 'aiHistoryTab') { targetPane = $('adminAiHistorySubPane'); loadAdminAiUsers(); }
    if (tab === 'usersTab') { targetPane = $('adminUsersSubPane'); loadAdminChatThreads(); }
    if (tab === 'staffTab') { targetPane = $('adminStaffSubPane'); loadStaffList(); }
    if (tab === 'cmsTab') targetPane = $('adminCmsSubPane');
    if (tab === 'emergencyTab') { targetPane = $('adminEmergencySubPane'); loadEmergencyAlerts(); }
    if (tab === 'errorTab') { targetPane = $('adminErrorSubPane'); loadSystemErrors(); }

    if (targetPane) {
        targetPane.classList.remove('hidden');
        targetPane.classList.add('active-feature');
    }
    if (window.innerWidth <= 920) {
        $('appSidebar').classList.remove('drawer-open');$('drawerOverlay').classList.add('hidden');
    }
}

// 🔥 ADMIN AI CHAT HISTORY VIEWER
async function loadAdminAiUsers() {
    const listEl = $('adminAiUsersList');
    if (!listEl) return;
    try {
        const res = await secureApiFetch('/admin/ai-history/all');
        const data = await res.json();
        if (data.success && Array.isArray(data.users) && data.users.length > 0) {
            listEl.innerHTML = data.users.map(cid => `
                <div class="admin-wa-user-item" onclick="selectAdminAiThread('${escapeHTML(cid)}')">
                    <div class="emcs-avatar" style="width:32px; height:32px; font-size:0.8rem;"><i class="fa-solid fa-robot"></i></div>
                    <div><strong>${escapeHTML(cid)}</strong><br><small class="small-text">View AI Chat</small></div>
                </div>
            `).join('');
        } else {
            listEl.innerHTML = '<div class="p-2 small-text text-center">No AI chats recorded yet.</div>';
        }
    } catch (e) {}
}

async function selectAdminAiThread(cid) {
    activeAdminKycCid = cid;
    safeSetText('activeAiChatName', `AI Chat History: ${cid}`);
    $('aiChatActionBox')?.classList.remove('hidden');
    const area = $('adminAiChatMsgArea');
    if (!area) return;

    try {
        const res = await secureApiFetch(`/admin/ai-history/${encodeURIComponent(cid)}`);
        const data = await res.json();
        if (data.success && Array.isArray(data.messages) && data.messages.length > 0) {
            area.innerHTML = data.messages.map(m => `
                <div class="emcs-bubble ${m.sender === 'ai' ? 'emcs-received' : 'emcs-sent'}">
                    <b>${m.sender === 'ai' ? 'KamAbhi AI' : 'User'}:</b> ${escapeHTML(m.text)}
                    <span class="emcs-time">${new Date(m.timestamp).toLocaleString()}</span>
                </div>
            `).join('');
            area.scrollTop = area.scrollHeight;
        } else {
            area.innerHTML = '<div class="small-text text-center" style="margin:auto;">No messages in this AI chat thread.</div>';
        }
    } catch (e) {}
}

// 🔥 ADMIN EMERGENCY SECURITY ALERTS (BOT TRAP & AI SPAM DDOS)
async function loadEmergencyAlerts() {
    const tbody = $('adminEmergencyListBody');
    if (!tbody) return;
    try {
        const res = await secureApiFetch('/admin/emergency-alerts');
        const data = await res.json();
        if (data.success && Array.isArray(data.alerts)) {
            safeSetText('adminEmergencyCountBadge', data.alerts.length);
            if (data.alerts.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center small-text">No security alerts triggered.</td></tr>';
                return;
            }
            tbody.innerHTML = data.alerts.map(a => `<tr>
                <td><small>${new Date(a.timestamp).toLocaleString()}</small></td>
                <td><span class="badge danger-bg">${escapeHTML(a.attackType)}</span></td>
                <td><code>${escapeHTML(a.ipAddress || 'Unknown')}</code></td>
                <td><strong class="danger-text">${escapeHTML(a.details)}</strong></td>
                <td><small>${escapeHTML((a.deviceInfo || 'Unknown').slice(0, 50))}</small></td>
            </tr>`).join('');
        }
    } catch (e) {}
}

async function clearEmergencyAlerts() {
    if (!confirm("Clear all Emergency Security Alerts?")) return;
    try {
        await secureApiFetch('/admin/emergency-alerts/clear', { method: 'DELETE' });
        safeSetText('adminEmergencyCountBadge', '0');
        loadEmergencyAlerts();
    } catch (e) {}
}

// 🔥 ADMIN USER DETAILS, BLOCK/UNBLOCK, DELETE & 24-MONTH LEDGER
async function fetchAdminUserDetails(consumerId) {
    activeAdminKycCid = consumerId;
    try {
        const res = await secureApiFetch(`/admin/user/${encodeURIComponent(consumerId)}`);
        const data = await res.json();
        if (data.success && data.user) {
            const u = data.user;
            safeSetText('kycName', u.name);
            safeSetText('kycConsumerId', `Consumer ID: ${u.consumerId}`);
            safeSetText('kycMobile', `+91 ${u.mobile}`);
            safeSetText('kycEmail', u.email || 'Not Provided');
            safeSetText('kycSanctioned', `${u.sanctionedLoadKw || 2.0} kW`);
            safeSetText('kycJoinDate', new Date(u.createdAt).toLocaleDateString());
            safeSetText('kycLifetimeUnits', `${data.lifetimeUsage || 0} Units`);

            const badge = $('kycStatusBadge');
            if (badge) {
                badge.textContent = (u.accountStatus || 'active').toUpperCase();
                badge.className = u.accountStatus === 'active' ? 'badge light-green-bg' : 'badge light-red-bg';
            }

            const blockBtn = $('btnAdminBlockUser');
            if (blockBtn) {
                const isBlocked = u.accountStatus === 'blocked';
                blockBtn.innerHTML = isBlocked
                    ? '<i class="fa-solid fa-check"></i> Unblock User'
                    : '<i class="fa-solid fa-ban"></i> Block User';
                blockBtn.style.background = isBlocked ? '#10B981' : '#F59E0B';
            }

            safeSetText('kycAppCount', u.appliances ? u.appliances.length : 0);
            const appListEl = $('kycAppList');
            if (appListEl) {
                if (u.appliances && u.appliances.length > 0) {
                    appListEl.innerHTML = u.appliances.map(a => `<div>• <b>${escapeHTML(a.name)}</b> — ${Number(a.power)}W, ${Number(a.hours)}h/day (${Number(a.monthlyKwh)} Units/mo) [${a.state ? '<span class="green-text">ON</span>' : '<span class="danger-text">OFF</span>'}]</div>`).join('');
                } else {
                    appListEl.innerHTML = "No appliances added.";
                }
            }

            const sessionBody = $('kycSessionList');
            if (sessionBody) {
                if (u.activeSessions && u.activeSessions.length > 0) {
                    sessionBody.innerHTML = u.activeSessions.slice().reverse().map(s => `<tr>
                        <td><small>${escapeHTML(s.deviceInfo || 'Browser')}</small></td>
                        <td><code>${escapeHTML(s.ipAddress || 'Protected')}</code></td>
                        <td><small>${new Date(s.createdAt).toLocaleString()}</small></td>
                    </tr>`).join('');
                } else {
                    sessionBody.innerHTML = '<tr><td colspan="3" class="text-center small-text">No active login sessions.</td></tr>';
                }
            }

            const billingBody = $('kycBillingList');
            if (billingBody) {
                if (data.paymentLedger && data.paymentLedger.length > 0) {
                    billingBody.innerHTML = data.paymentLedger.map(p => `<tr>
                        <td><b>${escapeHTML(p.month)}</b></td>
                        <td><small><code>${escapeHTML(p.txnId)}</code></small></td>
                        <td>${escapeHTML(p.units)} Units</td>
                        <td class="text-primary"><b>₹${escapeHTML(p.amount)}</b></td>
                        <td><span class="badge light-green-bg">${escapeHTML(p.status)}</span></td>
                    </tr>`).join('');
                } else {
                    billingBody.innerHTML = '<tr><td colspan="5" class="text-center small-text">No billing history available.</td></tr>';
                }
            }

            $('kycTabSessions')?.classList.remove('hidden');$('kycTabBilling')?.classList.add('hidden');
            $('adminUserKycModal')?.classList.remove('hidden');$('popupOverlay')?.classList.remove('hidden');
        } else {
            alert("Could not load user details.");
        }
    } catch (e) {
        alert("Something went wrong, try again later.");
    }
}

async function toggleUserBlockAdmin() {
    if (!activeAdminKycCid) return;
    const isBlocked = $('btnAdminBlockUser')?.innerHTML.includes('Unblock');
    const newStatus = isBlocked ? 'active' : 'blocked';
    if (!confirm(`Are you sure you want to ${isBlocked ? 'UNBLOCK' : 'BLOCK'} user ${activeAdminKycCid}?`)) return;

    try {
        const res = await secureApiFetch(`/admin/user/${encodeURIComponent(activeAdminKycCid)}/status`, {
            method: 'PUT',
            body: JSON.stringify({ status: newStatus })
        });
        if (res.ok) {
            alert(`User status updated to ${newStatus.toUpperCase()}.`);
            fetchAdminUserDetails(activeAdminKycCid);
            loadAdminChatThreads();
        }
    } catch (e) {}
}

async function deleteUserAdmin() {
    if (!activeAdminKycCid) return;
    if (prompt(`Type 'DELETE' to permanently remove user ${activeAdminKycCid} and all their records:`) !== 'DELETE') return;

    try {
        const res = await secureApiFetch(`/admin/user/${encodeURIComponent(activeAdminKycCid)}`, { method: 'DELETE' });
        if (res.ok) {
            alert("User account permanently deleted.");
            closeAllPopups();
            loadAdminChatThreads();
        }
    } catch (e) {}
}

async function clearAiChatAdmin() {
    if (!activeAdminKycCid) return;
    if (!confirm(`Delete all AI Chat History for ${activeAdminKycCid}?`)) return;

    try {
        const res = await secureApiFetch(`/admin/ai-history/${encodeURIComponent(activeAdminKycCid)}`, { method: 'DELETE' });
        if (res.ok) {
            if ($('adminAiChatMsgArea'))$('adminAiChatMsgArea').innerHTML = '<div class="small-text text-center" style="margin:auto;">AI chat history cleared.</div>';
            loadAdminAiUsers();
            alert("AI Chat History deleted successfully.");
        }
    } catch (e) {}
}

async function createNewStaffMember() {
    const name = safeGetVal('staffNewName').trim();
    const username = safeGetVal('staffNewUser').trim();
    const password = safeGetVal('staffNewPass').trim();
    if (!name || !username || password.length < 6) return alert("Please enter valid name, username, and password.");

    const permissions = {
        canManageUsers: $('permManageUsers') ?$('permManageUsers').checked : true,
        canChatSupport: $('permChat') ?$('permChat').checked : true,
        canEditCMS: $('permCMS') ?$('permCMS').checked : false,
        canDeleteChat: $('permDeleteChat') ?$('permDeleteChat').checked : false
    };

    try {
        const res = await secureApiFetch('/admin/staff', {
            method: 'POST',
            body: JSON.stringify({ name, username, password, permissions })
        });
        const data = await res.json();
        alert(data.message || 'Team member added.');
        safeSetVal('staffNewName', ''); safeSetVal('staffNewUser', ''); safeSetVal('staffNewPass', '');
        loadStaffList();
    } catch (e) { alert("Could not add team member."); }
}

async function loadStaffList() {
    const tbody = $('staffDirectoryBody');
    if (!tbody) return;
    try {
        const res = await secureApiFetch('/admin/staff');
        const data = await res.json();
        if (data.success && Array.isArray(data.staff)) {
            tbody.innerHTML = data.staff.map(s => {
                const perms = Object.keys(s.permissions || {}).filter(k => s.permissions[k]).join(', ') || 'Standard';
                return `<tr>
                    <td><b>${escapeHTML(s.name)}</b></td>
                    <td>${escapeHTML(s.username)}</td>
                    <td><small>${escapeHTML(perms)}</small></td>
                    <td><button class="sm-btn danger-bg" onclick="deleteStaffMember('${s._id}')"><i class="fa-solid fa-trash"></i></button></td>
                </tr>`;
            }).join('') || '<tr><td colspan="4" class="text-center small-text">No team members added yet.</td></tr>';
        }
    } catch (e) {}
}

async function deleteStaffMember(id) {
    if (!confirm("Remove this team member?")) return;
    await secureApiFetch(`/admin/staff/${id}`, { method: 'DELETE' }).catch(() => {});
    loadStaffList();
}

async function loadSystemErrors() {
    const tbody = $('adminErrorListBody');
    if (!tbody) return;
    let logs = JSON.parse(localStorage.getItem('emcs_error_logs') || '[]');
    try {
        const res = await secureApiFetch('/admin/errors');
        const data = await res.json();
        if (data.success && Array.isArray(data.errors)) logs = data.errors;
    } catch (e) {}

    safeSetText('adminErrorCountBadge', logs.length);
    if (logs.length === 0) return tbody.innerHTML = '<tr><td colspan="5" class="text-center small-text">No recent activity logs.</td></tr>';
    tbody.innerHTML = logs.map(err => `<tr>
        <td><small>${new Date(err.timestamp).toLocaleString()}</small></td>
        <td><span class="badge light-green-bg">${escapeHTML(err.source || 'App')}</span></td>
        <td><strong>Something went wrong, try again later.</strong></td>
        <td>${escapeHTML(err.location || 'Screen')}</td>
        <td>${escapeHTML(err.userOrIp || 'User')}</td>
    </tr>`).join('');
}

async function clearSystemErrors() {
    if (!confirm("Clear all activity logs?")) return;
    localStorage.removeItem('emcs_error_logs');
    try { await secureApiFetch('/admin/errors/clear', { method: 'DELETE' }); } catch (e) {}
    loadSystemErrors();
}

// ---------------------------------------------------------
// WEBSITE INFO, PRIVACY POLICY, TERMS & FAQS
// ---------------------------------------------------------
async function loadCmsContent() {
    let cms = JSON.parse(localStorage.getItem('emcsCmsData')) || {
        broadcast: "",
        about: "EMCS (Smart Energy Manager) helps households and businesses track appliance power consumption, estimate monthly electricity bills, and control smart switches safely.",
        privacy: "1. INFORMATION WE COLLECT: We collect your Name, Mobile Number, Verified Email Address, and 12-Digit Consumer ID to create your account and help you recover forgotten credentials.\n\n2. DEVICE & IP SECURITY: For your account safety and to prevent unauthorized access, we record the device model and IP address when you log in.\n\n3. AI CHAT HISTORY: Questions asked to KamAbhi AI (EMCS AI) are saved in your account history to help you review past electrical advice and are automatically deleted after 3 months (90 days).\n\n4. ACCOUNT DELETION: If you deactivate your account, all devices are logged out immediately and records are retained for 2 years for legal compliance before permanent deletion.",
        terms: "1. BILL ESTIMATES: All electricity bills and solar calculations shown on EMCS are estimates for planning and saving energy. Please pay your official electricity board bill as per your utility meter.\n\n2. HARDWARE & SMART SWITCH RESPONSIBILITY: Hardware testing nhi kiya gya hai. Kripya apne risk or jimmedari par ye hardware connect kare, iske liye hamari team ki koi jimmedari nhi hogi. EMCS is not responsible for any electrical damage, short circuit, or injury.\n\n3. FAIR USE & SECURITY: Using automated bots, fake emails, or spamming the AI assistant (10+ questions in 10 seconds) will result in an automatic block.",
        faqs: [
            { q: "How can I log in or reset my forgotten PIN or Password?", a: "You can log in using either your 10-digit Mobile Number or your Email Address. If you forget your PIN or Password, click 'Forgot Access' and verify using your 12-digit Consumer ID or Email Address." },
            { q: "Who is KamAbhi AI?", a: "KamAbhi AI (EMCS AI) is your dedicated electrical safety and energy-saving assistant available after you log in." },
            { q: "How long is my AI chat history saved?", a: "Your AI chat history is saved for 3 months (90 days) and then automatically deleted." },
            { q: "Can I connect smart Wi-Fi switches or a smart meter?", a: "Yes! Tick the hardware responsibility agreement box in the Smart Hardware Control or My Appliances section to unlock wireless and cable switch controls." }
        ]
    };
    try {
        const res = await fetch(`${API_BASE}/cms`);
        const data = await res.json();
        if (data.success && data.cms) cms = data.cms;
    } catch (e) {}

    localStorage.setItem('emcsCmsData', JSON.stringify(cms));
    window.KamAbhiRAM.cmsFaqs = cms.faqs || [];
    renderAdminFaqs();

    if (cms.broadcast && cms.broadcast.trim()) {
        safeSetText('systemBroadcastText', cms.broadcast);
        $('systemBroadcastBanner').classList.remove('hidden');
    }
    safeSetVal('cmsBroadcastInput', cms.broadcast || '');
    safeSetVal('cmsAboutInput', cms.about || '');
    safeSetVal('cmsPrivacyInput', cms.privacy || '');
    safeSetVal('cmsTermsInput', cms.terms || '');
}

function addAdminFaq() {
    const q = safeGetVal('cmsFaqQuestion').trim();
    const a = safeGetVal('cmsFaqAnswer').trim();
    if (!q || !a) return alert("Please enter both Question and Answer.");
    window.KamAbhiRAM.cmsFaqs.push({ q, a });
    safeSetVal('cmsFaqQuestion', ''); safeSetVal('cmsFaqAnswer', '');
    renderAdminFaqs();
}

function renderAdminFaqs() {
    const box = $('cmsFaqList');
    if (!box) return;
    box.innerHTML = (window.KamAbhiRAM.cmsFaqs || []).map((f, i) => `
        <div class="p-2 mb-1 flex-between" style="background:var(--bg-color); border:1px solid var(--card-border); border-radius:8px;">
            <div><b>Q:</b> ${escapeHTML(f.q)}<br><small class="text-muted">A: ${escapeHTML(f.a)}</small></div>
            <button type="button" class="icon-btn borderless danger-text" onclick="window.KamAbhiRAM.cmsFaqs.splice(${i}, 1); renderAdminFaqs()"><i class="fa-solid fa-trash"></i></button>
        </div>
    `).join('');
}

async function saveCmsContent() {
    const cms = { broadcast: safeGetVal('cmsBroadcastInput').trim(), about: safeGetVal('cmsAboutInput').trim(), privacy: safeGetVal('cmsPrivacyInput').trim(), terms: safeGetVal('cmsTermsInput').trim(), faqs: window.KamAbhiRAM.cmsFaqs || [] };
    localStorage.setItem('emcsCmsData', JSON.stringify(cms));
    try { await secureApiFetch('/admin/cms', { method: 'POST', body: JSON.stringify(cms) }); } catch (e) {}
    loadCmsContent();
    safeSetText('cmsSavedNotice', '✓ Changes saved!');
    setTimeout(() => safeSetText('cmsSavedNotice', ''), 3000);
}

function openLegalModal(type) {
    const cms = JSON.parse(localStorage.getItem('emcsCmsData')) || {};
    const titles = { about: 'About Us', privacy: 'Privacy Policy', terms: 'Terms & Conditions', faqs: 'Frequently Asked Questions' };
    safeSetText('legalModalTitle', titles[type] || 'Information');
    if (type === 'faqs') {
        const faqs = cms.faqs || [];
        $('legalModalBody').innerHTML = faqs.map(f => `<div style="margin-bottom:15px; padding-bottom:10px; border-bottom:1px solid var(--card-border);"><strong style="color:var(--primary);">${escapeHTML(f.q)}</strong><p class="small-text mt-1">${escapeHTML(f.a)}</p></div>`).join('') || "<p>No FAQs available right now.</p>";
    } else {
        $('legalModalBody').innerHTML = `<div style="white-space: pre-line;">${escapeHTML(cms[type] || '')}</div>`;
    }
    $('legalModal').classList.remove('hidden');$('popupOverlay').classList.remove('hidden');
}

// ---------------------------------------------------------
// HELP & SUPPORT CHAT AND REGISTERED USERS LIST
// ---------------------------------------------------------
async function loadUserSupportMessages() {
    if (!window.KamAbhiRAM.userSession) return;
    const area = $('userChatMsgArea');
    if (!area) return;
    try {
        const res = await secureApiFetch('/support/user/messages');
        const data = await res.json();
        if (data.success && Array.isArray(data.messages) && data.messages.length > 0) {
            area.innerHTML = data.messages.map(m => `
                <div class="emcs-bubble ${m.sender === 'user' ? 'emcs-sent' : 'emcs-received'}">
                    ${escapeHTML(m.text)}
                    <span class="emcs-time">${m.sender === 'admin' ? 'Support Team' : 'You'} • ${new Date(m.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                </div>
            `).join('');
            area.scrollTop = area.scrollHeight;
        }
    } catch (e) {}
}

let lastMsgSent = 0;
function sendUserSupportMessage() {
    if (!window.KamAbhiRAM.userSession) return alert("Please log in first to message the support team.");
    if (Date.now() - lastMsgSent < 2000) return alert("Please wait a moment before sending another message.");
    const input = $('userChatInput');
    const text = input.value.trim().slice(0, 500);
    if (!text) return;
    lastMsgSent = Date.now();
    input.value = '';
    const area = $('userChatMsgArea');
    area.innerHTML += `<div class="emcs-bubble emcs-sent">${escapeHTML(text)}<span class="emcs-time">You • Just now</span></div>`;
    area.scrollTop = area.scrollHeight;
    secureApiFetch('/support/user/send', { method: 'POST', body: JSON.stringify({ text }) }).catch(() => {});
}

async function loadAdminChatThreads() {
    try {
        const res = await secureApiFetch('/support/admin/threads');
        const data = await res.json();
        if (data.success && Array.isArray(data.threads)) {
            $('adminChatThreadsList').innerHTML = data.threads.map(t => `<div class="admin-wa-user-item" onclick="selectAdminThread('${escapeHTML(t.consumerId)}', '${escapeHTML(t.name)}')"><div class="emcs-avatar" style="width:32px; height:32px; font-size:0.8rem;">${escapeHTML(t.name[0] || 'U')}</div><div><strong>${escapeHTML(t.name)}</strong><br><small class="small-text">${escapeHTML(t.consumerId)}</small></div></div>`).join('');

            safeSetText('adminUserCount', data.threads.length);
            const userTbody = $('adminUserListBody');
            if (userTbody) {
                userTbody.innerHTML = data.threads.map(u => `<tr>
                    <td><b>${escapeHTML(u.consumerId)}</b></td>
                    <td><a href="javascript:void(0)" class="text-primary hover-pop" style="font-weight:600; text-decoration:none; display:inline-flex; align-items:center; gap:6px;" onclick="fetchAdminUserDetails('${escapeHTML(u.consumerId)}')">${escapeHTML(u.name)} <i class="fa-solid fa-address-card" style="font-size:0.8rem;"></i></a></td>
                    <td>+91 ${escapeHTML(u.mobile)}</td>
                    <td>${Number(u.sanctionedLoadKw || 2.0)} kW</td>
                    <td><span class="badge ${u.accountStatus === 'active' ? 'light-green-bg' : 'light-red-bg'}">${escapeHTML(u.accountStatus || 'active')}</span></td>
                </tr>`).join('') || '<tr><td colspan="5" class="text-center small-text">No registered users yet.</td></tr>';
            }
        }
    } catch (e) {}
}

let selectedAdminConsumerId = null;
async function selectAdminThread(cid, name) {
    selectedAdminConsumerId = cid;
    safeSetText('activeChatName', `${name} (${cid})`);
    $('singleChatActionBox').classList.remove('hidden');
    const res = await secureApiFetch(`/support/admin/messages/${cid}`);
    const data = await res.json();
    if (data.success) {
        $('adminChatMsgArea').innerHTML = data.messages.map(m => `<div class="emcs-bubble ${m.sender === 'admin' ? 'emcs-sent' : 'emcs-received'}">${escapeHTML(m.text)}</div>`).join('');
    }
}

async function sendAdminSupportMessage() {
    if (!selectedAdminConsumerId) return alert("Please select a user conversation first.");
    const input = $('adminChatInput');
    const text = input.value.trim().slice(0, 500);
    if (!text) return;
    input.value = '';
    $('adminChatMsgArea').innerHTML += `<div class="emcs-bubble emcs-sent">${escapeHTML(text)}</div>`;
    await secureApiFetch('/support/admin/reply', { method: 'POST', body: JSON.stringify({ consumerId: selectedAdminConsumerId, text }) }).catch(() => {});
}

async function deleteSelectedConsumerChat() {
    if (!selectedAdminConsumerId || !confirm("Delete this user's chat messages?")) return;
    await secureApiFetch(`/support/chat/clear/${selectedAdminConsumerId}`, { method: 'DELETE' });
    $('adminChatMsgArea').innerHTML = '';
}

async function purgeAllChatsConfirm() {
    if (prompt("Type 'DELETE ALL' to clear all support conversations:") !== 'DELETE ALL') return;
    await secureApiFetch('/support/chat/purge-all', { method: 'DELETE' });
    $('adminChatMsgArea').innerHTML = '';
}

async function downloadAdminMasterDatabase() {
    try {
        const res = await secureApiFetch('/admin/master-database-dump');
        const blob = await res.blob();
        const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `EMCS_Backup_${Date.now()}.json`; a.click();
    } catch (e) { alert("Could not download backup right now."); }
}

async function deleteMyAccount() {
    if (!confirm("Are you sure you want to deactivate your account?")) return;
    if (prompt("Type 'DELETE' to confirm:") !== "DELETE") return;
    try {
        const res = await secureApiFetch('/user/delete-account', { method: 'DELETE' });
        if (res.ok) { alert("Your account has been deactivated."); logoutUser(); }
    } catch (e) { alert("Something went wrong, try again later."); }
}

function changeSanctionedLoad(val) { window.KamAbhiRAM.sanctionedLoadKw = parseFloat(val); renderAppliances(); autoSyncToCloud(); }
function promptSetBudget() {
    const b = prompt("Enter Monthly Budget Target (₹):", window.KamAbhiRAM.budgetThreshold);
    if (b && !isNaN(b)) { window.KamAbhiRAM.budgetThreshold = parseFloat(b); safeSetText('currentBudgetDisplay', `₹${b}`); renderAppliances(); autoSyncToCloud(); }
}
function enableBrowserNotifications() { if ("Notification" in window) Notification.requestPermission(); }

async function saveUserProfile() {
    if (!window.KamAbhiRAM.userSession) return alert("Please log in first to save your settings.");
    enforceUrlAntiIdorGuard();
    const newName = safeGetVal('profileName').trim();
    if (newName.length >= 2) {
        window.KamAbhiRAM.userSession.name = newName;
        localStorage.setItem('ecoActiveUser', JSON.stringify(window.KamAbhiRAM.userSession));
        safeSetText('userGreeting', `Welcome, ${newName}! ☀️`);
        $('sidebarAuthArea').innerHTML = `<button class="secondary-btn sm-btn w-100" onclick="logoutUser()"><i class="fa-solid fa-power-off"></i> Logout (${escapeHTML(newName)})</button>`;
    }
    const payload = {
        name: newName,
        appliances: window.KamAbhiRAM.appliances,
        sanctionedLoadKw: window.KamAbhiRAM.sanctionedLoadKw,
        budgetThreshold: window.KamAbhiRAM.budgetThreshold,
        tariffProvider: safeGetVal('tariffProviderSelect'),
        tariffCategory: safeGetVal('tariffCategorySelect'),
        tariffArea: safeGetVal('tariffAreaSelect'),
        customTariff: JSON.parse(localStorage.getItem('emcs_custom_tariff') || 'null')
    };
    await secureApiFetch('/user/sync-cloud', { method: 'POST', body: JSON.stringify(payload) }).catch(() => {});
    safeSetText('profileMsg', '✓ Your profile changes have been saved.');
    setTimeout(() => safeSetText('profileMsg', ''), 3000);
}

function toggleMobileDrawer() { $('appSidebar').classList.toggle('drawer-open');$('drawerOverlay').classList.toggle('hidden'); }
function showFeature(id, btn) {
    enforceUrlAntiIdorGuard();
    document.querySelectorAll('#consumerNavLinks .nav-item').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    document.querySelectorAll('.feature-content').forEach(fc => { fc.classList.add('hidden'); fc.classList.remove('active-feature'); });
    const t = $(id);
    if (t) {
        t.classList.remove('hidden');
        t.classList.add('active-feature');
    }
    if (id === 'userSupportChat') loadUserSupportMessages();
    if (window.innerWidth <= 920) {
        $('appSidebar').classList.remove('drawer-open');$('drawerOverlay').classList.add('hidden');
    }
}
function toggleTheme() {
    const next = document.body.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    document.body.setAttribute('data-theme', next);
    localStorage.setItem('ecoTheme', next);
}
