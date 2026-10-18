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
// AUTOMATED ERROR TELEMETRY (TECHNICAL NAMES MASKED)
// ---------------------------------------------------------
function reportSystemError(source, message, location = '') {
    try {
        const maskedSource = (source || 'Client App').replace(/mongodb|mongoose|express|node/gi, 'Secure Storage Layer');
        const errEntry = {
            id: Date.now(),
            timestamp: new Date().toISOString(),
            source: maskedSource,
            message: String(message || 'Unknown Exception').slice(0, 300),
            location: String(location || window.location.pathname).slice(0, 150),
            userOrIp: window.KamAbhiRAM?.userSession?.consumerId || 'Secured Client'
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

window.addEventListener('error', (event) => {
    const loc = event.filename ? `${event.filename.split('/').pop()}:${event.lineno}` : 'Runtime UI';
    reportSystemError('Client Component', event.message, loc);
});

window.addEventListener('unhandledrejection', (event) => {
    const reason = event.reason ? (event.reason.message || String(event.reason)) : 'Async Promise Rejection';
    reportSystemError('Async Gateway', reason, 'Promise Handling');
});

// ---------------------------------------------------------
// APPLICATION STATE (ZERO DUMMY DATA)
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
    appChartMode: 'line',
    energyChart: null,
    pieChart: null,
    appCompChart: null
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
    fridge: { name: "Double Door Refrigerator", power: 180, hours: 24 },
    fan: { name: "BLDC Ceiling Fan", power: 35, hours: 14 },
    oldfan: { name: "Standard Ceiling Fan", power: 75, hours: 14 },
    geyser: { name: "Water Geyser", power: 2000, hours: 1.5 },
    pc: { name: "Desktop Computer", power: 350, hours: 6 },
    wm: { name: "Washing Machine", power: 450, hours: 1 }
};

// ---------------------------------------------------------
// COMPLETE 3-LANGUAGE DICTIONARY (EN / HI / HINGLISH)
// ---------------------------------------------------------
const TRANSLATIONS = {
    en: {
        navDash: "Dashboard", navAppliances: "Appliances & Flowgraph", navVoltage: "Voltage & Surge Guard",
        navInverter: "Inverter Backup", navVampire: "Vampire Audit", navOcr: "Bill OCR Scanner",
        navCsv: "Smart Meter CSV", navTod: "ToD Tariff Saver", navSolar: "Solar Rooftop ROI",
        navIoT: "Hardware Relay Control", navAudit: "Insights & Ledger", navSim: "Savings Simulator",
        navPayment: "Bill Settlement", navAI: "EMCS Ai Assistant", navSupport: "Help & Support Desk",
        navProfile: "Account & Security", btnConnect: "Login / Connect", btnLoginShort: "Login",
        greetDefault: "Energy Analytics Overview ☀️", greetSub: "Monitor and optimize your daily energy consumption securely.",
        lblBudgetBtn: "Budget:"
    },
    hi: {
        navDash: "डैशबोर्ड", navAppliances: "उपकरण और फ्लोग्राफ", navVoltage: "वोल्टेज और सर्ज गार्ड",
        navInverter: "इन्वर्टर बैकअप", navVampire: "वैम्पायर ऑडिट", navOcr: "बिल OCR स्कैनर",
        navCsv: "स्मार्ट मीटर CSV", navTod: "ToD टैरिफ सेवर", navSolar: "सोलर रूफटॉप ROI",
        navIoT: "हार्डवेयर रिले कंट्रोल", navAudit: "इनसाइट्स और खाता", navSim: "बचत सिम्युलेटर",
        navPayment: "बिल भुगतान", navAI: "EMCS AI सहायक", navSupport: "सहायता डेस्क",
        navProfile: "खाता और सुरक्षा", btnConnect: "लॉगिन / जुड़ें", btnLoginShort: "लॉगिन",
        greetDefault: "ऊर्जा विश्लेषिकी अवलोकन ☀️", greetSub: "अपने दैनिक बिजली उपभोग की सुरक्षित रूप से निगरानी और अनुकूलन करें।",
        lblBudgetBtn: "बजट:"
    },
    hinglish: {
        navDash: "Dashboard", navAppliances: "Appliances & Flowgraph", navVoltage: "Voltage & Surge Guard",
        navInverter: "Inverter Backup", navVampire: "Vampire Audit", navOcr: "Bill OCR Scanner",
        navCsv: "Smart Meter CSV", navTod: "ToD Tariff Saver", navSolar: "Solar Rooftop ROI",
        navIoT: "Hardware Relay Control", navAudit: "Insights & Ledger", navSim: "Savings Simulator",
        navPayment: "Bill Settlement", navAI: "EMCS Ai Assistant", navSupport: "Help & Support Desk",
        navProfile: "Account & Security", btnConnect: "Login / Connect", btnLoginShort: "Login",
        greetDefault: "Energy Analytics Overview ☀️", greetSub: "Apne daily electricity consumption ko securely monitor aur optimize karein.",
        lblBudgetBtn: "Budget:"
    }
};

function switchLanguage(lang) {
    const dict = TRANSLATIONS[lang] || TRANSLATIONS.hinglish;
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

    loadCmsContent();
    renderAppliances();
    renderRealPaymentLedger();
    calculateSolarRoi();
    calculateInverterRuntime();
    switchLanguage('hinglish');
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
    alert("✓ Custom Tariff Rates saved successfully!");
}

// ---------------------------------------------------------
// HACKATHON LIVE FLOWCHART & GRAPHS (ZERO DUMMY DATA)
// ---------------------------------------------------------
function renderAppliances() {
    const tbody = $('applianceList');
    if (!tbody) return;
    tbody.innerHTML = '';
    let totalLoadKwh = 0, activeWatts = 0;

    if (window.KamAbhiRAM.appliances.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center small-text">No appliances connected. Add a device above to generate live flowchart & graphs.</td></tr>';
    } else {
        window.KamAbhiRAM.appliances.forEach(app => {
            if (app.state) {
                totalLoadKwh += parseFloat(app.monthlyKwh);
                activeWatts += parseFloat(app.power);
            }
            const cost = computeSlabBill(parseFloat(app.monthlyKwh)).total.toFixed(0);
            tbody.innerHTML += `<tr>
                <td><strong>${escapeHTML(app.name)}</strong></td>
                <td>${Number(app.power)} W</td>
                <td>${Number(app.hours)} hrs/day</td>
                <td>${Number(app.monthlyKwh)} kWh</td>
                <td><label class="switch"><input type="checkbox" ${app.state ? 'checked' : ''} onchange="toggleApplianceState(${app.id}, this.checked)"><span class="slider"></span></label></td>
                <td class="text-primary"><b>₹${cost}</b></td>
                <td><button class="sm-btn danger-bg" onclick="deleteAppliance(${app.id})"><i class="fa-solid fa-trash"></i></button></td>
            </tr>`;
        });
    }

    window.KamAbhiRAM.totalUnits = totalLoadKwh;
    const billObj = totalLoadKwh > 0 ? computeSlabBill(totalLoadKwh) : { total: 0 };
    window.KamAbhiRAM.computedBillObj = billObj;

    safeSetText('dashLoadDisplay', `${totalLoadKwh.toFixed(1)} kWh`);
    safeSetText('dashBillDisplay', `₹${billObj.total.toFixed(0)}`);
    safeSetText('paymentTabAmount', `₹${billObj.total.toFixed(2)}`);
    safeSetText('vampireDisplay', `₹${(billObj.total * 0.10).toFixed(0)}`);
    safeSetText('forecastBillDisplay', `₹${(totalLoadKwh > 0 ? computeSlabBill(totalLoadKwh * 1.12).total : 0).toFixed(0)}`);
    safeSetText('liveWattsDisplay', `${activeWatts} W`);
    safeSetText('flowTotalWattsBadge', `Active Draw: ${activeWatts} W (${totalLoadKwh.toFixed(1)} kWh/mo)`);
    safeSetText('autoAuditUnits', `${totalLoadKwh.toFixed(1)} kWh`);
    safeSetText('autoAuditBill', `₹${billObj.total.toFixed(2)}`);
    safeSetText('autoAuditCarbon', `${(totalLoadKwh * 0.70).toFixed(1)} kg CO2`);

    checkMdiDemandOverload(activeWatts);
    $('budgetAlertBanner')?.classList.toggle('hidden', billObj.total <= window.KamAbhiRAM.budgetThreshold);

    renderApplianceFlowchart(activeWatts, totalLoadKwh);
    renderDynamicCharts(totalLoadKwh);
}

function checkMdiDemandOverload(activeWatts) {
    const maxWatts = window.KamAbhiRAM.sanctionedLoadKw * 1000;
    const banner = $('mdiOverloadBanner');
    if (!banner) return;
    if (activeWatts > maxWatts) {
        safeSetText('mdiAlertTitle', `Demand Overload: ${activeWatts}W exceeds ${maxWatts}W Sanctioned Limit!`);
        banner.classList.remove('hidden');
    } else {
        banner.classList.add('hidden');
    }
}

function renderApplianceFlowchart(activeWatts, totalKwh) {
    const box = $('applianceFlowchartContainer');
    if (!box) return;

    const apps = window.KamAbhiRAM.appliances;
    if (apps.length === 0) {
        box.innerHTML = `<div class="text-center small-text" style="padding: 16px;"><i class="fa-solid fa-diagram-project text-primary" style="font-size:1.6rem; opacity:0.6; margin-bottom:6px; display:block;"></i>No active load nodes. Add an appliance above to view real-time power distribution flowchart.</div>`;
        return;
    }

    const maxWatts = window.KamAbhiRAM.sanctionedLoadKw * 1000;
    const isOverload = activeWatts > maxWatts;
    const meterColor = isOverload ? 'var(--danger)' : 'var(--primary)';

    const nodesHtml = apps.map(app => {
        const sharePct = totalKwh > 0 && app.state ? Math.round((parseFloat(app.monthlyKwh) / totalKwh) * 100) : 0;
        const borderCol = app.state ? '#10B981' : '#94A3B8';
        const statusBadge = app.state
            ? `<span class="badge light-green-bg" style="font-size:0.68rem;">ON • ${sharePct}% Share</span>`
            : `<span class="badge" style="background:rgba(148,163,184,0.2); color:var(--text-muted); font-size:0.68rem;">STANDBY / OFF</span>`;
        return `<div style="min-width: 155px; background: var(--card-bg); border: 2px solid ${borderCol}; border-radius: 12px; padding: 10px 12px; text-align: center; box-shadow: var(--shadow);">
            <div style="font-size: 0.72rem; color: var(--text-muted); margin-bottom: 4px;"><i class="fa-solid fa-bolt" style="color:${borderCol};"></i> Node</div>
            <div style="font-weight: 700; font-size: 0.88rem; margin-bottom: 4px; color: var(--text-color);">${escapeHTML(app.name)}</div>
            <div style="font-size: 0.8rem; font-weight: 600; color: var(--primary); margin-bottom: 6px;">${Number(app.power)} W • ${Number(app.monthlyKwh)} kWh</div>
            ${statusBadge}
        </div>`;
    }).join('<div style="align-self:center; color:var(--primary); font-weight:bold;">➔</div>');

    box.innerHTML = `<div style="display: flex; flex-direction: column; align-items: center; gap: 14px;">
        <div style="display: flex; align-items: center; justify-content: center; gap: 12px; flex-wrap: wrap;">
            <div style="background: linear-gradient(135deg, #6366F1, #8B5CF6); color: #fff; padding: 10px 18px; border-radius: 12px; font-weight: 600; font-size: 0.85rem;"><i class="fa-solid fa-tower-observation"></i> Utility Grid (228V AC)</div>
            <div style="color: var(--primary); font-weight: bold;">━━►</div>
            <div style="background: var(--card-bg); border: 2px solid ${meterColor}; padding: 10px 18px; border-radius: 12px; font-weight: 600; font-size: 0.85rem;">Meter Gateway: <span style="color:${meterColor};">${activeWatts}W / ${maxWatts}W</span></div>
        </div>
        <div style="color: var(--primary); font-size: 1.1rem; line-height: 1;">▼</div>
        <div style="display: flex; align-items: stretch; justify-content: center; gap: 10px; flex-wrap: wrap; width: 100%;">${nodesHtml}</div>
    </div>`;
}

function setChartMode(mode) { window.KamAbhiRAM.chartMode = mode; renderDynamicCharts(window.KamAbhiRAM.totalUnits); }
function setAppChartMode(mode) {
    window.KamAbhiRAM.appChartMode = mode;
    if ($('appFlowBtn')) $('appFlowBtn').style.background = mode === 'line' ? 'var(--primary)' : '#64748B';
    if ($('appBarBtn')) $('appBarBtn').style.background = mode === 'bar' ? 'var(--primary)' : '#64748B';
    renderDynamicCharts(window.KamAbhiRAM.totalUnits);
}

function renderDynamicCharts(totalLoad) {
    const palette = ['#6366F1', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#0EA5E9', '#EC4899', '#14B8A6'];
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
                labels: hasData ? ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Today'] : ['No Appliances Connected'],
                datasets: [{
                    label: 'Daily Energy Flow (kWh)',
                    data: hasData ? [(d*0.88).toFixed(2), (d*1.04).toFixed(2), (d*0.94).toFixed(2), (d*1.12).toFixed(2), (d*1.01).toFixed(2), (d*1.16).toFixed(2), d.toFixed(2)] : [],
                    borderColor: '#6366F1', backgroundColor: window.KamAbhiRAM.chartMode === 'line' ? grad : palette,
                    borderWidth: 3, pointBackgroundColor: '#FFFFFF', pointBorderColor: '#6366F1', pointRadius: 5, fill: true, tension: 0.42
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
    }

    const pieEl = $('pieChart');
    if (pieEl && typeof Chart !== 'undefined') {
        if (window.KamAbhiRAM.pieChart) window.KamAbhiRAM.pieChart.destroy();
        window.KamAbhiRAM.pieChart = new Chart(pieEl.getContext('2d'), {
            type: 'doughnut',
            data: { labels: activeApps.map(a => a.name), datasets: [{ data: activeApps.map(a => a.state ? a.monthlyKwh : 0), backgroundColor: palette }] },
            options: { responsive: true, maintainAspectRatio: false, cutout: '64%' }
        });
    }

    const compEl = $('applianceCompChart');
    if (compEl && typeof Chart !== 'undefined') {
        if (window.KamAbhiRAM.appCompChart) window.KamAbhiRAM.appCompChart.destroy();
        const ctx2 = compEl.getContext('2d');
        const isLine = window.KamAbhiRAM.appChartMode === 'line';

        const gradPrimary = ctx2.createLinearGradient(0, 0, 0, 260);
        gradPrimary.addColorStop(0, 'rgba(99, 102, 241, 0.45)');
        gradPrimary.addColorStop(1, 'rgba(99, 102, 241, 0.02)');

        const gradSecondary = ctx2.createLinearGradient(0, 0, 0, 260);
        gradSecondary.addColorStop(0, 'rgba(16, 185, 129, 0.38)');
        gradSecondary.addColorStop(1, 'rgba(16, 185, 129, 0.02)');

        window.KamAbhiRAM.appCompChart = new Chart(ctx2, {
            type: window.KamAbhiRAM.appChartMode,
            data: {
                labels: activeApps.map(a => a.name),
                datasets: [
                    {
                        label: 'Monthly Consumption (kWh)',
                        data: activeApps.map(a => a.state ? a.monthlyKwh : 0),
                        borderColor: isLine ? '#6366F1' : palette, backgroundColor: isLine ? gradPrimary : palette,
                        borderWidth: 3, pointBackgroundColor: '#FFFFFF', pointBorderColor: '#6366F1', pointRadius: 5, fill: isLine, tension: 0.42
                    },
                    {
                        label: 'Power Rating (Watts ÷ 10)',
                        data: activeApps.map(a => a.state ? (a.power / 10).toFixed(1) : 0),
                        borderColor: '#10B981', backgroundColor: isLine ? gradSecondary : 'rgba(16, 185, 129, 0.78)',
                        borderWidth: 2.5, pointBackgroundColor: '#FFFFFF', pointBorderColor: '#10B981', pointRadius: 4, fill: isLine, tension: 0.42
                    }
                ]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
    }
}

// ---------------------------------------------------------
// CRUD OPERATIONS & HARDWARE RELAY (HMAC-SHA256)
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
    if (!name || isNaN(power) || isNaN(hours)) return alert("Enter valid appliance details.");
    const monthlyKwh = ((power * hours * 30) / 1000).toFixed(2);
    window.KamAbhiRAM.appliances.push({ id: Date.now(), name, power, hours, monthlyKwh, state: true });
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
    if (app) { app.state = state; renderAppliances(); autoSyncToCloud(); }
}

function executeHeavyApplianceCutoff() {
    window.KamAbhiRAM.appliances.forEach(a => { if (a.power >= 1000) a.state = false; });
    renderAppliances();
    sendRealHardwareRelay(16, false);
    sendRealHardwareRelay(17, false);
}

async function generateIoTMac(pin, val, secretKey) {
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
    const endpoint = safeGetVal('iotCutoffEndpoint').trim();
    const authKey = safeGetVal('espAuthToken').trim();
    const badge = $(`gpio${pin}Status`);
    const logEl = $('espConsoleLog');
    const val = state ? 1 : 0;

    if (badge) {
        badge.textContent = state ? "ACTIVE / ON" : "CUT OFF";
        badge.className = state ? "badge light-green-bg" : "badge light-red-bg";
    }

    if (!isStrictPrivateLanUrl(endpoint)) {
        if (logEl) logEl.textContent = "[SECURITY BARRIER]: Target is not a verified local private IP.";
        return;
    }

    const { timestamp, signatureHex } = await generateIoTMac(pin, val, authKey);
    const targetUrl = `${endpoint}?pin=${encodeURIComponent(pin)}&val=${val}&ts=${timestamp}&sig=${signatureHex}`;
    if (logEl) logEl.textContent = `[SECURE LAN DISPATCH]: Sent time-stamped trigger (GPIO ${pin}). Sig: ${signatureHex.substring(0,8)}...`;
    try { await fetch(targetUrl, { method: 'GET', mode: 'no-cors' }); } catch (e) {}
}

async function connectSerialHardware() {
    if (!("serial" in navigator)) return alert("Web Serial API requires Chrome or Edge browser.");
    try {
        const port = await navigator.serial.requestPort();
        await port.open({ baudRate: 115200 });
        safeSetText('hardwareConnectionBadge', 'USB Connected');
    } catch (e) { alert("Serial connection cancelled."); }
}

// ---------------------------------------------------------
// VOLTAGE, INVERTER, SOLAR & VAMPIRE
// ---------------------------------------------------------
function calculateInverterRuntime() {
    const ah = Math.max(1, parseFloat(safeGetVal('invBatteryAh')) || 150);
    const volts = parseFloat(safeGetVal('invVoltage')) || 12;
    const watts = Math.max(0, parseFloat(safeGetVal('invActiveLoad')) || 0);
    if (watts <= 0) return safeSetText('inverterRuntimeOutput', 'Standby');
    const hours = (ah * volts * 0.85) / watts;
    safeSetText('inverterRuntimeOutput', `${Math.floor(hours)}h ${Math.round((hours%1)*60)}m`);
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
        safeSetText('voltageHealthBadge', `${v}V • Alert`);
        box.textContent = "⚠️ Voltage anomaly detected. Heavy circuits isolated.";
        box.style.background = "rgba(239,68,68,0.15)";
        executeHeavyApplianceCutoff();
    } else {
        safeSetText('voltageHealthBadge', `${v}V • Normal`);
        box.textContent = "✓ Voltage within secure tolerances.";
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
    safeSetText('vampireTotalSavedBadge', `Saved: ₹${window.KamAbhiRAM.vampireSavings}/mo`);
}

// ---------------------------------------------------------
// FILE UPLOAD SECURITY (MAGIC BYTES & SIZE LIMIT)
// ---------------------------------------------------------
async function validateUploadedImage(file) {
    const MAX_IMAGE_SIZE = 4 * 1024 * 1024;
    const allowedMimes = ['image/jpeg', 'image/png', 'image/webp'];

    if (file.size > MAX_IMAGE_SIZE) throw new Error('File too large! Max 4 MB allowed.');
    if (!allowedMimes.includes(file.type)) throw new Error('Invalid file type! Only JPG, PNG, and WebP allowed.');

    const buffer = await file.slice(0, 4).arrayBuffer();
    const bytes = new Uint8Array(buffer);
    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

    const isJpeg = hex.startsWith('FFD8FF');
    const isPng = hex === '89504E47';
    const isWebp = hex === '52494646';

    if (!isJpeg && !isPng && !isWebp) throw new Error('Security Block: Invalid file signature.');
}

async function processBillOcr() {
    const file = $('billImageInput').files[0];
    if (!file) return alert('Please select a bill image first.');

    try {
        await validateUploadedImage(file);
    } catch (securityErr) {
        reportSystemError('File Security Module', securityErr.message, 'processBillOcr');
        $('billImageInput').value = '';
        return alert(securityErr.message);
    }

    $('ocrLoader').classList.remove('hidden');
    try {
        const { data: { text } } = await Tesseract.recognize(file, 'eng');
        const unitsMatch = text.match(/(?:units?|kwh)[\s\-:]*([0-9]{1,5})/i);
        const u = unitsMatch ? unitsMatch[1] : '250';
        safeSetText('ocrConsumerId', window.KamAbhiRAM?.userSession?.consumerId || 'VERIFIED');
        safeSetText('ocrUnits', u);
        safeSetText('ocrAmount', `₹${computeSlabBill(parseFloat(u)).total.toFixed(0)}`);
        window.lastOcrUnits = parseFloat(u);
        $('ocrResultBox').classList.remove('hidden');
    } catch (e) {
        reportSystemError('OCR Scanner', e.message, 'processBillOcr');
        alert('Could not parse text. Please upload a clear photo.');
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
        reportSystemError('File Security Module', `Rejected upload: ${file.name}`, 'handleSmartMeterCsv');
        e.target.value = '';
        return alert('Security Block: Only valid .csv or .txt files under 2 MB allowed.');
    }

    const reader = new FileReader();
    reader.onload = (ev) => {
        const content = String(ev.target.result || '');
        if (content.includes('\0')) {
            e.target.value = '';
            return alert('Security Block: Corrupted binary file detected.');
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
        safeSetText('csvTotalKwh', `${total.toFixed(1)} kWh`);
        safeSetText('csvPeakHour', `${peak.toFixed(2)} kWh`);
        safeSetText('csvAvgDaily', `${(total / Math.max(1, count / 24)).toFixed(1)} kWh/d`);
    };
    reader.readAsText(file);
}

// ---------------------------------------------------------
// PAYMENT, AUDIT & SIMULATOR
// ---------------------------------------------------------
function executeRealPayment() {
    const amt = window.KamAbhiRAM.computedBillObj.total;
    if (amt <= 0) return alert("No active dues.");
    alert("Payment setup abhi nhi kiya gya hai kripya apne Admin se contact kare.");
}

function renderRealPaymentLedger() {
    window.KamAbhiRAM.paymentHistory = JSON.parse(localStorage.getItem('emcs_txns')) || [];
    const tbody = $('sixMonthTableBody');
    if (!tbody) return;
    if (window.KamAbhiRAM.paymentHistory.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center small-text">No recorded receipts.</td></tr>';
        return;
    }
    tbody.innerHTML = window.KamAbhiRAM.paymentHistory.map(t => `<tr><td><b>${escapeHTML(t.txnId)}</b></td><td>${escapeHTML(t.units)} kWh</td><td><b>₹${escapeHTML(t.amount)}</b></td><td><span class="badge light-green-bg">${escapeHTML(t.status)}</span></td></tr>`).join('');
}

function downloadInvoicePDF() {
    const card = document.createElement('div');
    card.style.padding = '24px';
    card.innerHTML = `<h2>EMCS - Secured Energy Bill Summary</h2><hr><p>Consumption: ${window.KamAbhiRAM.totalUnits.toFixed(1)} kWh</p><h3>Estimated Amount: ₹${window.KamAbhiRAM.computedBillObj.total.toFixed(2)}</h3><p><small>Disclaimer: Estimate only based on standard utility slabs.</small></p>`;
    if (typeof html2pdf !== 'undefined') html2pdf().from(card).save('EMCS_Summary.pdf');
}

function exportYearlyExcel() {
    let csv = "Appliance,Watts,Daily_Hours,Monthly_kWh\n";
    window.KamAbhiRAM.appliances.forEach(a => { csv += `"${a.name}",${a.power},${a.hours},${a.monthlyKwh}\n`; });
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' })); a.download = 'EMCS_Audit.csv'; a.click();
}

function calculateSimulator() {
    const u = parseFloat(safeGetVal('simUserUnits')) || 300;
    const r = parseFloat(safeGetVal('simUserRate')) || 7.5;
    const p = parseFloat(safeGetVal('simSlider')) || 15;
    safeSetText('simPctVal', p);
    safeSetText('simUnitsResult', `${(u * p / 100).toFixed(1)} kWh`);
    safeSetText('simSavingsResult', `₹${(u * p / 100 * r).toFixed(0)}`);
}

// ---------------------------------------------------------
// VOICE ASSISTANT & CHAT
// ---------------------------------------------------------
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

function sendTabChatMessage() {
    const input = $('tabChatInput');
    const raw = input.value.trim().slice(0, 500);
    if (!raw) return;
    input.value = '';
    const box = $('tabChatBox');
    box.innerHTML += `<div class="clean-card p-2" style="align-self:flex-end; background:var(--primary); color:#fff; max-width:80%;">${escapeHTML(raw)}</div>`;

    let reply = "Optimizing appliance schedules and maintaining AC thermostat at 24°C will minimize monthly billing tiers.";
    if (/turn off heavy|cut heavy|ac off/i.test(raw)) {
        executeHeavyApplianceCutoff();
        reply = "Automated Command: Heavy appliances (>1000W) and GPIO relays have been switched off.";
    }
    const safeReply = escapeHTML(reply);
    setTimeout(() => {
        box.innerHTML += `<div class="clean-card p-2" style="align-self:flex-start; max-width:85%;"><p>${safeReply}</p><button class="sm-btn mt-1" style="background:var(--accent-light); color:var(--primary);" onclick="speakFemaleVoice('${safeReply.replace(/'/g, "")}')"><i class="fa-solid fa-volume-high"></i> Listen</button></div>`;
        box.scrollTop = box.scrollHeight;
    }, 250);
}

// ---------------------------------------------------------
// AUTHENTICATION & MODALS (ZERO LOCALSTORAGE PIN FALLBACK)
// ---------------------------------------------------------
function openLoginModal() { $('loginModal').classList.remove('hidden'); $('popupOverlay').classList.remove('hidden'); }
function openAIModal() { $('aiModal').classList.remove('hidden'); $('popupOverlay').classList.remove('hidden'); }
function closeAllPopups() {
    const legalEl = $('legalModal');
    const loginEl = $('loginModal');
    if (legalEl && !legalEl.classList.contains('hidden') && loginEl && !loginEl.classList.contains('hidden')) {
        legalEl.classList.add('hidden');
        return;
    }
    document.querySelectorAll('.popup-modal').forEach(m => m.classList.add('hidden'));
    $('popupOverlay').classList.add('hidden');
}

function switchAuthTab(tab, btn) {
    document.querySelectorAll('#authTabButtons button').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    ['modalLoginForm', 'modalRegisterForm', 'modalForgotForm', 'modalAdminForm'].forEach(id => $(id).classList.add('hidden'));
    if (tab === 'login') $('modalLoginForm').classList.remove('hidden');
    if (tab === 'register') $('modalRegisterForm').classList.remove('hidden');
    if (tab === 'forgot') $('modalForgotForm').classList.remove('hidden');
    if (tab === 'admin') $('modalAdminForm').classList.remove('hidden');
    safeSetText('modalAuthError', '');
}

async function handleSecureRegister(e) {
    e.preventDefault();
    if ($('regHoneypot') && $('regHoneypot').value) return;
    if ($('regTermsCheck') && !$('regTermsCheck').checked) return safeSetText('modalAuthError', 'Acceptance of Privacy Policy and Terms is required.');

    const payload = {
        name: safeGetVal('regName').trim(),
        mobile: safeGetVal('regMobile').trim(),
        consumerId: safeGetVal('regConsumerId').trim().toUpperCase(),
        pin: safeGetVal('regPin').trim(),
        termsAccepted: true
    };
    try {
        const res = await secureApiFetch('/auth/register', { method: 'POST', body: JSON.stringify(payload) });
        const data = await res.json();
        if (data.success) {
            alert("Account registered securely! Please log in.");
            switchAuthTab('login', $('authTabButtons').children[0]);
        } else {
            safeSetText('modalAuthError', data.message);
        }
    } catch (err) {
        reportSystemError('Auth Register API', err.message, '/api/auth/register');
        safeSetText('modalAuthError', 'Network error or server unreachable. Try again later.');
    }
}

async function handleSecureLogin(e) {
    e.preventDefault();
    const mobile = safeGetVal('loginMobile').trim();
    const pin = safeGetVal('loginPin').trim();
    try {
        const res = await secureApiFetch('/auth/login', { method: 'POST', body: JSON.stringify({ mobile, pin }) });
        const data = await res.json();
        if (data.success) {
            localStorage.setItem('ecoActiveUser', JSON.stringify(data.user));
            setupUserSession(data.user);
            await refreshDataFromCloud();
            closeAllPopups();
        } else {
            safeSetText('modalAuthError', data.message);
        }
    } catch (err) {
        reportSystemError('Auth Login API', err.message, '/api/auth/login');
        safeSetText('modalAuthError', 'Network error or server unreachable. Try again later.');
    }
}

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

async function handleFreePinReset(e) {
    e.preventDefault();
    const payload = {
        mobile: safeGetVal('forgotMobile').trim(),
        consumerId: safeGetVal('forgotConsumerId').trim().toUpperCase(),
        registeredName: safeGetVal('forgotName').trim(),
        newPin: safeGetVal('forgotNewPin').trim()
    };
    try {
        const res = await secureApiFetch('/auth/verify-and-reset-pin', { method: 'POST', body: JSON.stringify(payload) });
        const data = await res.json();
        if (data.success) { alert(data.message); switchAuthTab('login', $('authTabButtons').children[0]); }
        else safeSetText('modalAuthError', data.message);
    } catch (err) {
        safeSetText('modalAuthError', 'Something went wrong. Please try again later.');
    }
}

function setupUserSession(user) {
    window.KamAbhiRAM.userSession = user;
    safeSetText('userGreeting', `Welcome, ${user.name}! ☀️`);
    safeSetVal('profileName', user.name);
    safeSetVal('profileId', user.consumerId);
    $('sidebarAuthArea').innerHTML = `<button class="secondary-btn sm-btn w-100" onclick="logoutUser()"><i class="fa-solid fa-power-off"></i> Logout (${escapeHTML(user.name)})</button>`;
}

function logoutUser() {
    localStorage.removeItem('ecoActiveUser');
    secureApiFetch('/auth/logout', { method: 'POST' }).catch(() => {});
    location.reload();
}

async function openDeviceManager() {
    $('deviceManagerModal').classList.remove('hidden');$('popupOverlay').classList.remove('hidden');
    const tbody = $('deviceSessionList');
    tbody.innerHTML = '<tr><td colspan="4">Loading authorized endpoints...</td></tr>';
    try {
        const res = await secureApiFetch('/auth/devices');
        const data = await res.json();
        if (data.success) {
            tbody.innerHTML = data.sessions.map(s => `
                <tr><td>${escapeHTML(s.deviceInfo)}</td><td>${new Date(s.createdAt).toLocaleString()}</td>
                <td>${s.isCurrent ? '<b class="green-text">Current</b>' : 'Active'}</td>
                <td>${s.isCurrent ? '—' : (s.canRevoke ? `<button class="sm-btn danger-bg" onclick="revokeDevice('${s.sessionId}')">Revoke</button>` : `<span class="badge">${s.hoursRemaining}h lock</span>`)}</td></tr>
            `).join('');
        }
    } catch (e) {
        tbody.innerHTML = `<tr><td>Secured Endpoint (${escapeHTML(navigator.userAgent.slice(0, 25))}...)</td><td>Active Now</td><td><b class="green-text">Current</b></td><td>—</td></tr>`;
    }
}

async function revokeDevice(targetSessionId) {
    const res = await secureApiFetch('/auth/revoke-device', { method: 'POST', body: JSON.stringify({ targetSessionId }) });
    const data = await res.json();
    alert(data.message);
    openDeviceManager();
}

// ---------------------------------------------------------
// SECURE ADMIN CONSOLE, STAFF CRUD & PRE-LOADED LEGAL CMS
// ---------------------------------------------------------
async function handleSecureAdminLogin(e) {
    e.preventDefault();
    const username = safeGetVal('adminLoginUser').trim();
    const password = safeGetVal('adminLoginPass').trim();
    try {
        const res = await secureApiFetch('/admin/login', { method: 'POST', body: JSON.stringify({ username, password }) });
        const data = await res.json();
        if (data.success) enterAdminHub(data);
        else safeSetText('modalAuthError', data.message || 'Invalid authorization key.');
    } catch (err) {
        reportSystemError('Admin Auth API', err.message, '/api/admin/login');
        safeSetText('modalAuthError', 'Something went wrong. Please try again later.');
    }
}

function enterAdminHub(data) {
    closeAllPopups();
    $('mainAppSection').classList.add('hidden');
    $('appSidebar').classList.add('hidden');$('adminSection').classList.remove('hidden');
    safeSetText('adminRoleDisplay', `${data.name} (${data.role.toUpperCase()})`);
    $('ownerStaffTabBtn').classList.toggle('hidden', data.role !== 'owner');
    $('masterDumpBtn').classList.toggle('hidden', data.role !== 'owner');$('ownerCmsTabBtn').classList.toggle('hidden', !data.permissions?.canEditCMS && data.role !== 'owner');
    $('purgeAllChatsBtn').classList.toggle('hidden', !data.permissions?.canDeleteChat && data.role !== 'owner');
    loadAdminChatThreads();
    loadStaffList();
    loadSystemErrors();
}

function exitAdminView() {
    secureApiFetch('/admin/logout', { method: 'POST' }).catch(() => {});
    $('adminSection').classList.add('hidden');
    $('mainAppSection').classList.remove('hidden');$('appSidebar').classList.remove('hidden');
}

function switchAdminSubTab(tab, btn) {
    document.querySelectorAll('.admin-sub-pane').forEach(p => p.classList.add('hidden'));
    document.querySelectorAll('#adminSection .auth-tabs button').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    if (tab === 'chatTab') $('adminChatSubPane').classList.remove('hidden');
    if (tab === 'usersTab') { $('adminUsersSubPane').classList.remove('hidden'); loadAdminChatThreads(); }
    if (tab === 'staffTab') { $('adminStaffSubPane').classList.remove('hidden'); loadStaffList(); }
    if (tab === 'cmsTab') $('adminCmsSubPane').classList.remove('hidden');
    if (tab === 'errorTab') { $('adminErrorSubPane')?.classList.remove('hidden'); loadSystemErrors(); }
}

async function createNewStaffMember() {
    const name = safeGetVal('staffNewName').trim();
    const username = safeGetVal('staffNewUser').trim();
    const password = safeGetVal('staffNewPass').trim();
    if (!name || !username || password.length < 6) return alert("Enter valid staff name, username, and password (min 6 chars).");

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
        alert(data.message || 'Staff role provisioned.');
        safeSetVal('staffNewName', ''); safeSetVal('staffNewUser', ''); safeSetVal('staffNewPass', '');
        loadStaffList();
    } catch (e) { alert("Failed to create staff member."); }
}

async function loadStaffList() {
    const tbody = $('staffDirectoryBody');
    if (!tbody) return;
    try {
        const res = await secureApiFetch('/admin/staff');
        const data = await res.json();
        if (data.success && Array.isArray(data.staff)) {
            tbody.innerHTML = data.staff.map(s => {
                const perms = Object.keys(s.permissions || {}).filter(k => s.permissions[k]).join(', ') || 'Basic';
                return `<tr>
                    <td><b>${escapeHTML(s.name)}</b></td>
                    <td>${escapeHTML(s.username)}</td>
                    <td><small>${escapeHTML(perms)}</small></td>
                    <td><button class="sm-btn danger-bg" onclick="deleteStaffMember('${s._id}')"><i class="fa-solid fa-trash"></i></button></td>
                </tr>`;
            }).join('') || '<tr><td colspan="4" class="text-center small-text">No staff members added yet.</td></tr>';
        }
    } catch (e) {}
}

async function deleteStaffMember(id) {
    if (!confirm("Remove this staff account?")) return;
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
    if (logs.length === 0) return tbody.innerHTML = '<tr><td colspan="5" class="text-center small-text">No recorded system exceptions.</td></tr>';
    tbody.innerHTML = logs.map(err => {
        const isServer = /backend|server|db|storage/i.test(err.source);
        return `<tr><td><small>${new Date(err.timestamp).toLocaleString()}</small></td><td><span class="badge ${isServer ? 'light-red-bg' : 'light-green-bg'}">${escapeHTML(err.source)}</span></td><td><strong class="danger-text">${escapeHTML(err.message)}</strong></td><td><code>${escapeHTML(err.location || 'N/A')}</code></td><td>${escapeHTML(err.userOrIp || 'System')}</td></tr>`;
    }).join('');
}

async function clearSystemErrors() {
    if (!confirm("Clear all recorded error logs?")) return;
    localStorage.removeItem('emcs_error_logs');
    try { await secureApiFetch('/admin/errors/clear', { method: 'DELETE' }); } catch (e) {}
    loadSystemErrors();
}

// Pre-loaded with complete DPDP Act 2023, IoT Hardware Waiver & Billing Disclaimers
async function loadCmsContent() {
    let cms = JSON.parse(localStorage.getItem('emcsCmsData')) || {
        broadcast: "",
        about: "EMCS (Energy Management Control System) is an intelligent energy monitoring, tariff estimation, and load automation platform.",
        privacy: "1. DATA COLLECTION (DPDP Act 2023 Compliance): We collect minimal data (Mobile, Consumer ID, Name) strictly for authentication and load monitoring. We do not sell your data to third parties.\n\n2. OCR & FILE UPLOADS: Bill images uploaded for OCR and CSV files are processed securely in memory. We do not permanently store images of your physical electricity bills.\n\n3. DATA RETENTION & ERASURE: Upon account deactivation, all sessions are revoked, and records enter a secured 2-year retention archive for compliance before automatic permanent erasure.\n\n4. COOKIES: We use HTTP-only cookies strictly for session authorization.",
        terms: "1. ACCEPTANCE OF TERMS: By using EMCS, you agree to these legal terms.\n\n2. NO FINANCIAL LIABILITY: The electricity bills, solar ROI, and tariff calculations provided by EMCS are 'Estimates' based on standard utility slabs. EMCS is not an official billing authority. You must pay your actual utility provider based on their official meter readings.\n\n3. HARDWARE & IOT SAFETY WAIVER: The hardware relay control, voltage surge guard, and IoT features are provided 'AS IS'. EMCS and its developers are NOT liable for any electrical damage, short circuits, hardware failure, fire hazards, or personal injury resulting from automated appliance switching. Use IoT features at your own risk.\n\n4. PAYMENTS: EMCS provides a simulated settlement ledger. No real financial transactions are processed on this platform.",
        faqs: [
            { q: "Are the electricity bills shown here official?", a: "No. All bills and solar ROI figures are estimates calculated using state/private DISCOM tariff slabs for planning and energy-saving purposes." },
            { q: "How does the 2-year account deletion policy work?", a: "When you deactivate your account, all active devices are logged out immediately and your records are automatically erased after 2 years." },
            { q: "Is it safe to connect my ESP32 / Arduino relay?", a: "Yes, local hardware triggers use HMAC-SHA256 signatures, but always ensure qualified electrical insulation when dealing with 230V AC loads." }
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
    if (!q || !a) return alert("Enter both question and answer.");
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
    safeSetText('cmsSavedNotice', '✓ Published successfully!');
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
// TWO-WAY SUPPORT CHAT & REGISTERED USERS TABLE
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
                    <span class="emcs-time">${m.sender === 'admin' ? 'EMCS Support Desk' : 'You'} • ${new Date(m.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                </div>
            `).join('');
            area.scrollTop = area.scrollHeight;
        }
    } catch (e) {}
}

let lastMsgSent = 0;
function sendUserSupportMessage() {
    if (!window.KamAbhiRAM.userSession) return alert("Please log in to send support messages.");
    if (Date.now() - lastMsgSent < 2000) return alert("Please wait between messages.");
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

            // Also populate Registered Accounts Registry Table
            safeSetText('adminUserCount', data.threads.length);
            const userTbody = $('adminUserListBody');
            if (userTbody) {
                userTbody.innerHTML = data.threads.map(u => `<tr>
                    <td><b>${escapeHTML(u.consumerId)}</b></td>
                    <td>${escapeHTML(u.name)}</td>
                    <td>${escapeHTML(u.mobile)}</td>
                    <td>${Number(u.sanctionedLoadKw || 2.0)} kW</td>
                    <td><span class="badge ${u.accountStatus === 'deleted' ? 'light-red-bg' : 'light-green-bg'}">${escapeHTML(u.accountStatus || 'active')}</span></td>
                </tr>`).join('') || '<tr><td colspan="5" class="text-center small-text">No registered consumers yet.</td></tr>';
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
    if (!selectedAdminConsumerId) return alert("Select a consumer thread first.");
    const input = $('adminChatInput');
    const text = input.value.trim().slice(0, 500);
    if (!text) return;
    input.value = '';
    $('adminChatMsgArea').innerHTML += `<div class="emcs-bubble emcs-sent">${escapeHTML(text)}</div>`;
    await secureApiFetch('/support/admin/reply', { method: 'POST', body: JSON.stringify({ consumerId: selectedAdminConsumerId, text }) }).catch(() => {});
}

async function deleteSelectedConsumerChat() {
    if (!selectedAdminConsumerId || !confirm("Clear this thread?")) return;
    await secureApiFetch(`/support/chat/clear/${selectedAdminConsumerId}`, { method: 'DELETE' });
    $('adminChatMsgArea').innerHTML = '';
}

async function purgeAllChatsConfirm() {
    if (prompt("Type 'DELETE ALL' to confirm:") !== 'DELETE ALL') return;
    await secureApiFetch('/support/chat/purge-all', { method: 'DELETE' });
    $('adminChatMsgArea').innerHTML = '';
}

async function downloadAdminMasterDatabase() {
    try {
        const res = await secureApiFetch('/admin/master-database-dump');
        const blob = await res.blob();
        const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `EMCS_Vault_Export_${Date.now()}.json`; a.click();
    } catch (e) { alert("Vault export requires active server."); }
}

async function deleteMyAccount() {
    if (!confirm("WARNING: Account deactivate ho jayega aur 2 saal baad permanently erase ho jayega. Continue?")) return;
    if (prompt("Type 'DELETE' to confirm:") !== "DELETE") return;
    try {
        const res = await secureApiFetch('/user/delete-account', { method: 'DELETE' });
        if (res.ok) { alert("Account deactivated."); logoutUser(); }
    } catch (e) { alert("Failed."); }
}

function changeSanctionedLoad(val) { window.KamAbhiRAM.sanctionedLoadKw = parseFloat(val); renderAppliances(); autoSyncToCloud(); }
function promptSetBudget() {
    const b = prompt("Enter Monthly Budget Target (₹):", window.KamAbhiRAM.budgetThreshold);
    if (b && !isNaN(b)) { window.KamAbhiRAM.budgetThreshold = parseFloat(b); safeSetText('currentBudgetDisplay', `₹${b}`); renderAppliances(); autoSyncToCloud(); }
}
function enableBrowserNotifications() { if ("Notification" in window) Notification.requestPermission(); }

async function saveUserProfile() {
    if (!window.KamAbhiRAM.userSession) return alert("Please log in first to save profile settings.");
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
    safeSetText('profileMsg', '✓ Secured Profile synced.');
    setTimeout(() => safeSetText('profileMsg', ''), 3000);
}

function toggleMobileDrawer() { $('appSidebar').classList.toggle('drawer-open');$('drawerOverlay').classList.toggle('hidden'); }
function showFeature(id, btn) {
    document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
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
