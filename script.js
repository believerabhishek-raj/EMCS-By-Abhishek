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

function getClientTelemetry() {
    return {
        screen: `${window.screen?.width || 0}x${window.screen?.height || 0}`,
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
        platform: navigator.platform || ''
    };
}

// ---------------------------------------------------------
// SILENT EMAIL & TEMP-MAIL VALIDATOR
// ---------------------------------------------------------
const BLOCKED_TEMP_DOMAINS = new Set([
    'mailinator.com', 'yopmail.com', '10minutemail.com', 'guerrillamail.com',
    'tempmail.com', 'temp-mail.org', 'dropmail.me', 'trashmail.com',
    'sharklasers.com', 'getnada.com', 'maildrop.cc', 'dispostable.com',
    'fakeinbox.com', 'throwawaymail.com', 'mohmal.com', 'emailondeck.com',
    'mailnesia.com', 'mintemail.com', 'mytemp.email', 'burnermail.io',
    'tempmailo.com', 'inboxkitten.com', 'mailcatch.com', 'crazymailing.com'
]);

function isStrictValidEmail(emailStr) {
    const clean = String(emailStr || '').trim().toLowerCase();
    if (clean.length < 6 || clean.length > 90) return { ok: false, msg: 'Please enter a valid email address.' };
    if (/[\s\0$<>'"`;\\(){}[\]|!#$%^&*=+/?~]|\.\./.test(clean)) {
        return { ok: false, msg: 'Please enter a valid email address.' };
    }
    const parts = clean.split('@');
    if (parts.length !== 2) return { ok: false, msg: 'Please enter a valid email address.' };
    const [local, domain] = parts;
    if (!/^[a-z0-9]+([._-][a-z0-9]+)*$/.test(local) || !/^[a-z0-9]+(-[a-z0-9]+)*(\.[a-z0-9]+(-[a-z0-9]+)*)+$/.test(domain)) {
        return { ok: false, msg: 'Please enter a valid email address.' };
    }
    if (BLOCKED_TEMP_DOMAINS.has(domain)) {
        return { ok: false, msg: 'Please use a standard personal or work email address.' };
    }
    return { ok: true, email: clean };
}

// ---------------------------------------------------------
// CLIENT URL & PROFILE TAMPER GUARD (ANTI-IDOR)
// ---------------------------------------------------------
function enforceUrlAntiIdorGuard() {
    try {
        const params = new URLSearchParams(window.location.search);
        const hash = window.location.hash || '';
        const activeCid = window.KamAbhiRAM?.userSession?.consumerId;

        const urlCid = params.get('consumerId') || params.get('cid') || params.get('user') || params.get('id');
        if (urlCid && (!activeCid || urlCid.toUpperCase() !== activeCid.toUpperCase())) {
            reportSystemError('Security', 'Something went wrong, try again later.', 'URL');
            window.history.replaceState({}, document.title, window.location.pathname);
            alert('Access denied: You cannot open another consumer ID via the URL.');
        }

        if (/consumerId=|cid=/i.test(hash)) {
            window.history.replaceState({}, document.title, window.location.pathname);
        }

        const profileInput = $('profileId');
        if (activeCid && profileInput && profileInput.value && profileInput.value !== activeCid) {
            profileInput.value = activeCid;
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
        if (icon) { icon.classList.remove('fa-eye'); icon.classList.add('fa-eye-slash'); }
    } else {
        inputField.type = 'password';
        if (icon) { icon.classList.remove('fa-eye-slash'); icon.classList.add('fa-eye'); }
    }
}

// ---------------------------------------------------------
// CLEAN ACTIVITY LOGGER (NO TECHNICAL OR BACKEND DETAILS)
// ---------------------------------------------------------
function reportSystemError() {
    try {
        const errEntry = {
            id: Date.now(),
            timestamp: new Date().toISOString(),
            source: 'App Notice',
            message: 'Something went wrong, try again later.',
            location: 'Protected',
            userOrIp: window.KamAbhiRAM?.userSession?.consumerId || 'Visitor'
        };
        const localLogs = JSON.parse(localStorage.getItem('emcs_error_logs') || '[]');
        localLogs.unshift(errEntry);
        localStorage.setItem('emcs_error_logs', JSON.stringify(localLogs.slice(0, 50)));
        safeSetText('adminErrorCountBadge', localLogs.length);

        fetch(`${API_BASE}/errors/report`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-emcs-csrf': 'emcs-verified-client' },
            body: JSON.stringify({ message: 'Something went wrong, try again later.' })
        }).catch(() => {});
    } catch (ignore) {}
}

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
    hardwareConsentAccepted: false,
    chartMode: 'line',
    energyChart: null
};

// ---------------------------------------------------------
// COMPLETE ALL-INDIA TARIFF DATABASE (18 BOARDS)
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
        navInverter: "इन्वर्टर बैकअप", navVampire: "स्टैंडबाय बिजली बचत", navOcr: "बिल फोटो स्कैन",
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
        greetSub: "Apne ghar ke appliances track karein, smart switches control karein aur monthly bill kam karein.",
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

    // Default language set to English
    safeSetVal('languageSelect', 'en');
    switchLanguage('en');
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
// APPLIANCES & HARDWARE COMPATIBILITY (NO 2D/FLOWGRAPH IN APPLIANCE TAB)
// ---------------------------------------------------------
function onAppConnectionModeChange(mode) {
    const box = $('appHardwareDisclaimerBox');
    if (!box) return;
    if (mode !== 'manual') {
        box.classList.remove('hidden');
    } else {
        box.classList.add('hidden');
    }
}

function getConnectionModeBadge(connMode) {
    if (connMode === 'wifi') return `<span class="badge light-green-bg"><i class="fa-solid fa-wifi"></i> Wi-Fi Switch</span>`;
    if (connMode === 'smartmeter') return `<span class="badge" style="background:var(--accent-light); color:var(--primary);"><i class="fa-solid fa-gauge-high"></i> Smart Meter</span>`;
    if (connMode === 'usb') return `<span class="badge light-green-bg"><i class="fa-solid fa-usb"></i> Cable Switch</span>`;
    return `<span class="badge" style="background:rgba(148,163,184,0.18); color:var(--text-muted);">Manual</span>`;
}

function renderAppliances() {
    const tbody = $('applianceList');
    if (!tbody) return;
    tbody.innerHTML = '';
    let totalLoadKwh = 0, activeWatts = 0;

    if (window.KamAbhiRAM.appliances.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center small-text">No appliances added yet. Add your first appliance above.</td></tr>';
    } else {
        window.KamAbhiRAM.appliances.forEach(app => {
            if (app.state) {
                totalLoadKwh += parseFloat(app.monthlyKwh);
                activeWatts += parseFloat(app.power);
            }
            const cost = computeSlabBill(parseFloat(app.monthlyKwh)).total.toFixed(0);
            tbody.innerHTML += `<tr>
                <td><strong>${escapeHTML(app.name)}</strong></td>
                <td>${getConnectionModeBadge(app.connMode)}</td>
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

    renderDashboardChart(totalLoadKwh);
}

function checkMdiDemandOverload(activeWatts) {
    const maxWatts = window.KamAbhiRAM.sanctionedLoadKw * 1000;
    const banner = $('mdiOverloadBanner');
    if (!banner) return;
    if (activeWatts > maxWatts) {
        safeSetText('mdiAlertTitle', `High Load Warning: ${activeWatts}W exceeds your ${maxWatts}W meter limit!`);
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
    const hasData = window.KamAbhiRAM.appliances.length > 0 && totalLoad > 0;
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
                labels: hasData ? ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Today'] : ['Add appliances to view usage'],
                datasets: [{
                    label: 'Daily Usage (Units)',
                    data: hasData ? [(d*0.88).toFixed(2), (d*1.04).toFixed(2), (d*0.94).toFixed(2), (d*1.12).toFixed(2), (d*1.01).toFixed(2), (d*1.16).toFixed(2), d.toFixed(2)] : [],
                    borderColor: '#6366F1', backgroundColor: window.KamAbhiRAM.chartMode === 'line' ? grad : palette,
                    borderWidth: 3, pointBackgroundColor: '#FFFFFF', pointBorderColor: '#6366F1', pointRadius: 5, fill: true, tension: 0.42
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
    }
}

// ---------------------------------------------------------
// APPLIANCE CRUD & HARDWARE RISK CONSENT LOCK
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
        return alert("Please enter Appliance Name, Watts, and Daily Hours.");
    }

    // Require Hardware Responsibility Consent if linking with hardware
    if (connMode !== 'manual') {
        const riskChecked = $('appHardwareRiskCheck')?.checked;
        if (!riskChecked) {
            return alert("Hardware testing nhi kiya gya hai. Kripya pehle responsibility tick-box par tick karein.");
        }
        window.KamAbhiRAM.hardwareConsentAccepted = true;
        if ($('hardwareMasterConsentCheck')) {
            $('hardwareMasterConsentCheck').checked = true;
            toggleHardwareRiskConsent(true);
        }
    }

    const monthlyKwh = ((power * hours * 30) / 1000).toFixed(2);
    window.KamAbhiRAM.appliances.push({ id: Date.now(), name, power, hours, monthlyKwh, connMode, state: true });
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
        if (app.connMode === 'wifi' && window.KamAbhiRAM.hardwareConsentAccepted) {
            sendRealHardwareRelay(app.power >= 1000 ? 16 : 17, state);
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

function toggleHardwareRiskConsent(accepted) {
    window.KamAbhiRAM.hardwareConsentAccepted = Boolean(accepted);
    const zone = $('hardwareInteractiveZone');
    const logEl = $('espConsoleLog');
    if (zone) {
        zone.className = accepted ? 'hardware-unlocked-zone' : 'hardware-locked-zone';
    }
    if (logEl) {
        logEl.textContent = accepted
            ? "Status: Hardware controls unlocked. You can now connect your Wi-Fi switch or USB cable."
            : "Status: Please tick the agreement box above to enable smart hardware switches.";
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

function isStrictPrivateLanUrl(urlString) {
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
    if (!window.KamAbhiRAM.hardwareConsentAccepted) {
        alert("Hardware testing nhi kiya gya hai. Kripya pehle responsibility tick-box par tick karein.");
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

    if (!isStrictPrivateLanUrl(endpoint)) {
        if (logEl) logEl.textContent = "Status: Please enter a valid local Wi-Fi switch address (e.g. http://192.168.1.50/switch).";
        return;
    }

    const { timestamp, signatureHex } = await generateSwitchSignature(pin, val, authKey);
    const targetUrl = `${endpoint}?pin=${encodeURIComponent(pin)}&val=${val}&ts=${timestamp}&sig=${signatureHex}`;
    if (logEl) logEl.textContent = `Status: Command sent to Switch ${pin === 16 ? '1' : '2'} (${state ? 'ON' : 'OFF'}).`;
    try { await fetch(targetUrl, { method: 'GET', mode: 'no-cors' }); } catch (e) {}
}

async function connectSerialHardware() {
    if (!window.KamAbhiRAM.hardwareConsentAccepted) {
        return alert("Hardware testing nhi kiya gya hai. Kripya pehle responsibility tick-box par tick karein.");
    }
    if (!("serial" in navigator)) return alert("Direct cable connection requires Chrome or Edge browser.");
    try {
        const port = await navigator.serial.requestPort();
        await port.open({ baudRate: 115200 });
        safeSetText('hardwareConnectionBadge', 'Cable Connected');
    } catch (e) { alert("Cable connection cancelled."); }
}

// ---------------------------------------------------------
// VOLTAGE, INVERTER, SOLAR & STANDBY POWER
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
    safeSetVal('invActiveLoad', activeWatts);
    calculateInverterRuntime();
}

function simulateGridVoltage(v) {
    safeSetText('liveVoltageMetric', `${v} V`);
    const box = $('voltageAlertBox');
    box.classList.remove('hidden');
    if (v < 180 || v > 260) {
        safeSetText('voltageHealthBadge', `${v}V • Unsafe`);
        box.textContent = "⚠️ Unsafe voltage detected! Heavy appliances have been turned OFF for safety.";
        box.style.background = "rgba(239,68,68,0.15)";
        executeHeavyApplianceCutoff();
    } else {
        safeSetText('voltageHealthBadge', `${v}V • Safe`);
        box.textContent = "✓ Voltage is normal and safe for all appliances.";
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
    if (file.size > MAX_IMAGE_SIZE) throw new Error('File too large! Maximum 4 MB allowed.');
    if (!allowedMimes.includes(file.type)) throw new Error('Only JPG, PNG, and WebP photos are allowed.');

    const buffer = await file.slice(0, 4).arrayBuffer();
    const bytes = new Uint8Array(buffer);
    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    if (!hex.startsWith('FFD8FF') && hex !== '89504E47' && hex !== '52494646') {
        throw new Error('Invalid image file.');
    }
}

async function processBillOcr() {
    const file = $('billImageInput').files[0];
    if (!file) return alert('Please choose a bill photo first.');

    try {
        await validateUploadedImage(file);
    } catch (securityErr) {
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
        alert('Could not read the photo clearly. Please try a clearer image.');
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
    if (file.size > 2 * 1024 * 1024 || !/\.(csv|txt)$/i.test(file.name)) {
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
                total += val; count++;
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
    if (amt <= 0) return alert("No pending bill amount.");
    alert("Online payment is currently not enabled. Please contact your Administrator.");
}

function renderRealPaymentLedger() {
    window.KamAbhiRAM.paymentHistory = JSON.parse(localStorage.getItem('emcs_txns')) || [];
    const tbody = $('sixMonthTableBody');
    if (!tbody) return;
    if (window.KamAbhiRAM.paymentHistory.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center small-text">No past payment records.</td></tr>';
        return;
    }
    tbody.innerHTML = window.KamAbhiRAM.paymentHistory.map(t => `<tr><td><b>${escapeHTML(t.txnId)}</b></td><td>${escapeHTML(t.units)} Units</td><td><b>₹${escapeHTML(t.amount)}</b></td><td><span class="badge light-green-bg">${escapeHTML(t.status)}</span></td></tr>`).join('');
}

function downloadInvoicePDF() {
    const card = document.createElement('div');
    card.style.padding = '24px';
    card.innerHTML = `<h2>EMCS - Monthly Electricity Bill Summary</h2><hr><p>Monthly Usage: ${window.KamAbhiRAM.totalUnits.toFixed(1)} Units</p><h3>Estimated Amount: ₹${window.KamAbhiRAM.computedBillObj.total.toFixed(2)}</h3><p><small>Note: This is an estimated calculation based on standard tariff slabs.</small></p>`;
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
// 🔥 KAMABHI AI (EMCS AI) - LOGIN-ONLY, SINGLE-QUESTION LOCK & VOICE
// ---------------------------------------------------------
let isWaitingForAiAnswer = false;

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
        box.innerHTML = `<div class="clean-card p-2" style="max-width:90%; align-self:flex-start;">
            <p class="small-text" style="color:var(--text-color);">Hello! I am <b>KamAbhi AI (EMCS AI)</b>, your electrical safety and energy saving assistant. Please <b>Log In</b> first to ask questions.</p>
        </div>`;
        return;
    }

    try {
        const res = await secureApiFetch('/ai/history');
        const data = await res.json();
        if (data.success && Array.isArray(data.messages) && data.messages.length > 0) {
            box.innerHTML = data.messages.map(m => {
                if (m.sender === 'user') {
                    return `<div class="clean-card p-2" style="align-self:flex-end; background:var(--primary); color:#fff; max-width:82%;"><p class="small-text" style="color:#fff;">${escapeHTML(m.text)}</p></div>`;
                }
                const safeTxt = escapeHTML(m.text);
                return `<div class="clean-card p-2" style="align-self:flex-start; max-width:88%;"><p class="small-text" style="color:var(--text-color);">${safeTxt}</p><button class="sm-btn mt-1" style="background:var(--accent-light); color:var(--primary);" onclick="speakFemaleVoice('${safeTxt.replace(/'/g, "")}')"><i class="fa-solid fa-volume-high"></i> Listen</button></div>`;
            }).join('');
            box.scrollTop = box.scrollHeight;
        }
    } catch (e) {}
}

async function sendTabChatMessage() {
    // 1. Login Required Check
    if (!window.KamAbhiRAM.userSession) {
        alert("Please log in to your account first to use KamAbhi AI.");
        closeAllPopups();
        openLoginModal();
        return;
    }

    const box = $('tabChatBox');

    // 2. Single Question Concurrency Lock (Ignore new question while previous is being answered)
    if (isWaitingForAiAnswer) {
        box.innerHTML += `<div class="clean-card p-2" style="align-self:center; background:rgba(245,158,11,0.14); border:1px solid var(--warning); max-width:90%;"><p class="small-text" style="color:var(--text-color); font-weight:600;">⏳ Wait kro pichle question ka answer likh rhe hai. Uske baad dusra question bhejo.</p></div>`;
        box.scrollTop = box.scrollHeight;
        return;
    }

    const input = $('tabChatInput');
    const raw = input.value.trim().slice(0, 500);
    if (!raw) return;
    input.value = '';

    box.innerHTML += `<div class="clean-card p-2" style="align-self:flex-end; background:var(--primary); color:#fff; max-width:82%;"><p class="small-text" style="color:#fff;">${escapeHTML(raw)}</p></div>`;
    box.scrollTop = box.scrollHeight;

    isWaitingForAiAnswer = true;
    try {
        const res = await secureApiFetch('/ai/chat', {
            method: 'POST',
            body: JSON.stringify({ text: raw })
        });
        const data = await res.json();
        const replyText = escapeHTML(data.reply || 'Something went wrong, try again later.');

        if (!res.ok || !data.success) {
            box.innerHTML += `<div class="clean-card p-2" style="align-self:center; border:1px solid var(--danger); max-width:88%;"><p class="small-text danger-text"><b>${replyText}</b></p></div>`;
        } else {
            box.innerHTML += `<div class="clean-card p-2" style="align-self:flex-start; max-width:88%;"><p class="small-text" style="color:var(--text-color);">${replyText}</p><button class="sm-btn mt-1" style="background:var(--accent-light); color:var(--primary);" onclick="speakFemaleVoice('${replyText.replace(/'/g, "")}')"><i class="fa-solid fa-volume-high"></i> Listen</button></div>`;
        }
        box.scrollTop = box.scrollHeight;
    } catch (e) {
        box.innerHTML += `<div class="clean-card p-2" style="align-self:flex-start;"><p class="small-text danger-text">Something went wrong, try again later.</p></div>`;
    } finally {
        isWaitingForAiAnswer = false;
    }
}

// ---------------------------------------------------------
// AUTHENTICATION UI, FORM AUTO-DESTROY & MODALS
// ---------------------------------------------------------
function destroyAllAuthFormData() {
    ['modalLoginForm', 'modalRegisterForm', 'modalForgotForm', 'modalAdminForm'].forEach(id => {
        const formEl = $(id);
        if (formEl) formEl.reset();
    });

    [
        'loginMobile', 'loginCredential', 'loginHoneypot',
        'regName', 'regMobile', 'regConsumerId', 'regEmail', 'regCredential', 'regHoneypot',
        'forgotMobile', 'forgotName', 'forgotRecoveryValue', 'forgotNewCredential',
        'adminLoginUser', 'adminLoginPass'
    ].forEach(fieldId => safeSetVal(fieldId, ''));

    if ($('regTermsCheck'))$('regTermsCheck').checked = false;

    ['loginCredential', 'regCredential', 'forgotNewCredential', 'adminLoginPass'].forEach(fieldId => {
        const el = $(fieldId);
        if (el) el.type = 'password';
    });
    document.querySelectorAll('#loginModal .fa-eye-slash').forEach(icon => {
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    });

    toggleRegAuthUI();
    toggleForgotUI();
    toggleForgotAuthUI();
    safeSetText('modalAuthError', '');
}

function openLoginModal() {
    destroyAllAuthFormData();
    switchAuthTab('login', $('authTabButtons')?.children[0]);
    $('loginModal').classList.remove('hidden');$('popupOverlay').classList.remove('hidden');
}

function openAIModal() {
    loadAiChatHistory();
    $('aiModal').classList.remove('hidden');$('popupOverlay').classList.remove('hidden');
}

function toggleRegAuthUI() {
    const checked = document.querySelector('input[name="regAuthType"]:checked');
    const type = checked ? checked.value : 'pin';
    const input = $('regCredential');
    if (!input) return;
    input.value = '';
    if (type === 'pin') {
        input.setAttribute('pattern', '[0-9]{4,6}');
        input.setAttribute('minlength', '4');
        input.setAttribute('maxlength', '6');
        input.placeholder = 'Enter PIN';
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
    if (type === 'cid') {
        input.type = 'text';
        input.setAttribute('minlength', '12');
        input.setAttribute('maxlength', '12');
        input.placeholder = 'Enter Consumer ID';
        input.style.textTransform = 'uppercase';
    } else {
        input.type = 'email';
        input.removeAttribute('minlength');
        input.setAttribute('maxlength', '100');
        input.placeholder = 'Enter Email Address';
        input.style.textTransform = 'none';
    }
}

function toggleForgotAuthUI() {
    const checked = document.querySelector('input[name="forgotAuthType"]:checked');
    const type = checked ? checked.value : 'pin';
    const input = $('forgotNewCredential');
    if (!input) return;
    input.value = '';
    if (type === 'pin') {
        input.setAttribute('pattern', '[0-9]{4,6}');
        input.setAttribute('minlength', '4');
        input.setAttribute('maxlength', '6');
        input.placeholder = 'Enter New PIN';
    } else {
        input.removeAttribute('pattern');
        input.setAttribute('minlength', '8');
        input.setAttribute('maxlength', '16');
        input.placeholder = 'Enter New Password';
    }
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
// AUTHENTICATION HANDLERS (WITH INVISIBLE BOT TRAP TELEMETRY)
// ---------------------------------------------------------
async function handleSecureRegister(e) {
    e.preventDefault();
    if ($('regTermsCheck') && !$('regTermsCheck').checked) {
        return safeSetText('modalAuthError', 'Please accept the Privacy Policy and Terms & Conditions.');
    }

    const emailCheck = isStrictValidEmail(safeGetVal('regEmail'));
    if (!emailCheck.ok) return safeSetText('modalAuthError', emailCheck.msg);

    const authType = document.querySelector('input[name="regAuthType"]:checked')?.value || 'pin';
    const credential = safeGetVal('regCredential').trim();

    if (authType === 'pin' && !/^[0-9]{4,6}$/.test(credential)) {
        return safeSetText('modalAuthError', 'Invalid PIN.');
    }
    if (authType === 'password' && (credential.length < 8 || credential.length > 16)) {
        return safeSetText('modalAuthError', 'Invalid Password.');
    }

    const payload = {
        name: safeGetVal('regName').trim(),
        mobile: safeGetVal('regMobile').trim(),
        email: emailCheck.email,
        consumerId: safeGetVal('regConsumerId').trim().toUpperCase(),
        authType,
        credential,
        termsAccepted: true,
        _emcs_trap: safeGetVal('regHoneypot'),
        _clientMeta: getClientTelemetry()
    };
    try {
        const res = await secureApiFetch('/auth/register', { method: 'POST', body: JSON.stringify(payload) });
        const data = await res.json();
        if (data.success) {
            alert("Account created successfully! Please log in.");
            switchAuthTab('login', $('authTabButtons').children[0]);
        } else {
            safeSetText('modalAuthError', data.message || 'Something went wrong, try again later.');
        }
    } catch (err) {
        safeSetText('modalAuthError', 'Something went wrong, try again later.');
    }
}

async function handleSecureLogin(e) {
    e.preventDefault();
    const payload = {
        mobile: safeGetVal('loginMobile').trim(),
        credential: safeGetVal('loginCredential').trim(),
        _emcs_trap: safeGetVal('loginHoneypot'),
        _clientMeta: getClientTelemetry()
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
            safeSetText('modalAuthError', data.message || 'Something went wrong, try again later.');
        }
    } catch (err) {
        safeSetText('modalAuthError', 'Something went wrong, try again later.');
    }
}

async function handleForgotReset(e) {
    e.preventDefault();
    const recoveryType = document.querySelector('input[name="recoveryType"]:checked')?.value || 'cid';
    const recoveryValue = safeGetVal('forgotRecoveryValue').trim();

    if (recoveryType === 'email') {
        const check = isStrictValidEmail(recoveryValue);
        if (!check.ok) return safeSetText('modalAuthError', check.msg);
    } else if (!/^[A-Za-z0-9]{12}$/.test(recoveryValue)) {
        return safeSetText('modalAuthError', 'Please enter a valid Consumer ID.');
    }

    const newAuthType = document.querySelector('input[name="forgotAuthType"]:checked')?.value || 'pin';
    const newCredential = safeGetVal('forgotNewCredential').trim();

    if (newAuthType === 'pin' && !/^[0-9]{4,6}$/.test(newCredential)) {
        return safeSetText('modalAuthError', 'Invalid PIN.');
    }
    if (newAuthType === 'password' && (newCredential.length < 8 || newCredential.length > 16)) {
        return safeSetText('modalAuthError', 'Invalid Password.');
    }

    const payload = {
        mobile: safeGetVal('forgotMobile').trim(),
        registeredName: safeGetVal('forgotName').trim(),
        recoveryType,
        recoveryValue: recoveryType === 'cid' ? recoveryValue.toUpperCase() : recoveryValue.toLowerCase(),
        newAuthType,
        newCredential
    };
    try {
        const res = await secureApiFetch('/auth/verify-and-reset', { method: 'POST', body: JSON.stringify(payload) });
        const data = await res.json();
        if (data.success) {
            alert(data.message);
            switchAuthTab('login', $('authTabButtons').children[0]);
        } else {
            safeSetText('modalAuthError', data.message || 'Something went wrong, try again later.');
        }
    } catch (err) {
        safeSetText('modalAuthError', 'Something went wrong, try again later.');
    }
}

// ---------------------------------------------------------
// CLOUD SYNC & SESSION MANAGEMENT
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
    $('deviceManagerModal').classList.remove('hidden');$('popupOverlay').classList.remove('hidden');
    const tbody = $('deviceSessionList');
    tbody.innerHTML = '<tr><td colspan="4">Loading logged-in devices...</td></tr>';
    try {
        const res = await secureApiFetch('/auth/devices');
        const data = await res.json();
        if (data.success) {
            tbody.innerHTML = data.sessions.map(s => `
                <tr><td>${escapeHTML(s.deviceInfo)}</td><td>${new Date(s.createdAt).toLocaleString()}</td>
                <td>${s.isCurrent ? '<b class="green-text">This Device</b>' : 'Active'}</td>
                <td>${s.isCurrent ? '—' : (s.canRevoke ? `<button class="sm-btn danger-bg" onclick="revokeDevice('${s.sessionId}')">Logout</button>` : `<span class="badge">${s.hoursRemaining}h wait</span>`)}</td></tr>
            `).join('');
        }
    } catch (e) {
        tbody.innerHTML = `<tr><td>Current Browser</td><td>Active Now</td><td><b class="green-text">This Device</b></td><td>—</td></tr>`;
    }
}

async function revokeDevice(targetSessionId) {
    const res = await secureApiFetch('/auth/revoke-device', { method: 'POST', body: JSON.stringify({ targetSessionId }) });
    const data = await res.json();
    alert(data.message);
    openDeviceManager();
}

// ---------------------------------------------------------
// ADMIN PANEL, USER BLOCK/DELETE, AI HISTORY & EMERGENCY ALERTS
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
            safeSetText('modalAuthError', data.message || 'Invalid access key.');
        }
    } catch (err) {
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
        p.classList.add
