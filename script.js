window.KamAbhiRAM = {
    userSession: null,
    adminSession: null,
    cmsData: {
        siteName: 'EMCS',
        broadcastBanner: '',
        heroHeading: 'Smart Energy Control & Bill Optimizer',
        heroSubtext: 'Real-time load monitoring, progressive tariff slab alerts, and AI bill reduction.',
        themeColors: { primary: '#6366f1', accent: '#10b981' },
        featureSwitches: {
            gridSafety: true,
            inverter: true,
            vampire: true,
            tod: true,
            solar: true,
            iot: true
        },
        liveTariffs: {
            slabs: [
                { min: 0, max: 100, rate: 5.5 },
                { min: 101, max: 200, rate: 6.5 },
                { min: 201, max: 300, rate: 7.5 },
                { min: 301, max: 999999, rate: 8.5 }
            ],
            fixedCharge: 120,
            taxPercent: 5
        },
        paymentConfig: { enabled: true, apiKey: '' }
    },
    guestAppliances: [
        { name: '1.5 Ton Split AC', power: 1500, hours: 6 },
        { name: 'Double Door Refrigerator', power: 200, hours: 24 },
        { name: 'Ceiling Fan (x2)', power: 150, hours: 14 },
        { name: 'Smart LED TV 55"', power: 110, hours: 5 }
    ],
    adminUsersCache: [],
    adminIdleTimer: null
};

// ============================================================================
// 🛠️ 2. SAFE DOM HELPERS & XSS SANITIZERS
// ============================================================================
const $ = (id) => document.getElementById(id);

function safeSetText(id, text) {
    const el = $(id);
    if (el) el.innerText = text;
}

function escapeHTML(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function enforceUrlAntiIdorGuard() {
    if (window.location.search && /consumerId|token|password|secret/i.test(window.location.search)) {
        window.history.replaceState(null, document.title, window.location.pathname);
    }
}

// ============================================================================
// 🔍 3. SPA ROUTING MAPS & DYNAMIC SEO ENGINE (User Side)
// ============================================================================
const APP_ROUTES = {
    '/home': 'dashboard',
    '/appliances': 'appliances',
    '/calculators': 'quickCalcs',
    '/standby-saver': 'vampireCheck',
    '/inverter-backup': 'inverterAssistant',
    '/solar-calculator': 'solarRoi',
    '/smart-hardware': 'iotControl',
    '/voltage-safety': 'gridSafety',
    '/best-time-to-use': 'todOptimizer',
    '/reports': 'audit',
    '/savings-calculator': 'simulator',
    '/pay-bill': 'payment',
    '/support': 'userSupportChat',
    '/profile': 'profile'
};

const REVERSE_APP_ROUTES = Object.fromEntries(
    Object.entries(APP_ROUTES).map(([path, id]) => [id, path])
);

const AUTH_ROUTES = {
    '/login': 'login',
    '/register': 'register',
    '/admin-login': 'admin'
};

const ADMIN_ROUTES = {
    '/admin': 'overviewTab',
    '/admin/users': 'usersTab',
    '/admin/cms': 'adminCmsSubPane',
    '/admin/support': 'supportTab',
    '/admin/staff': 'staffTab',
    '/admin/logs': 'logsTab'
};

const SEO_DATA = {
    'dashboard': { title: 'Dashboard | EMCS', desc: 'Track your home appliances, control smart switches, and reduce your monthly electricity bill.' },
    'appliances': { title: 'My Appliances | EMCS', desc: 'Manage your connected home appliances and track their daily power consumption and monthly costs.' },
    'quickCalcs': { title: 'Instant Electrical Calculators | EMCS', desc: 'Use our generic power estimator and Ohm\'s Law helper for instant electrical calculations.' },
    'vampireCheck': { title: 'Standby Power Saver | EMCS', desc: 'Discover how much money you are losing to vampire power from appliances left plugged in.' },
    'inverterAssistant': { title: 'Inverter Backup Calculator | EMCS', desc: 'Calculate your inverter runtime and battery backup based on your live connected load.' },
    'solarRoi': { title: 'Solar Calculator | EMCS', desc: 'Estimate the ROI, total cost, and benefits of installing a solar panel system for your home.' },
    'iotControl': { title: 'Smart Hardware Control | EMCS', desc: 'Remotely control your WiFi smart switches and IoT devices directly from your EMCS dashboard.' },
    'gridSafety': { title: 'Voltage & Grid Safety | EMCS', desc: 'Monitor live grid voltage and protect your valuable appliances from electrical faults.' },
    'todOptimizer': { title: 'Time of Day Optimizer | EMCS', desc: 'Optimize your heavy appliance usage based on Time-of-Day (ToD) electricity rates to save money.' },
    'audit': { title: 'Energy Reports & Graphs | EMCS', desc: 'Visualize your daily power consumption trends with dynamic 2D and Flowgraph charts.' },
    'simulator': { title: 'Savings Simulator | EMCS', desc: 'Simulate different appliance usage scenarios to see how much money you can save.' },
    'payment': { title: 'Pay Electricity Bill | EMCS', desc: 'Securely pay your monthly electricity and EMCS bills online via Razorpay or Stripe.' },
    'userSupportChat': { title: 'Customer Support | EMCS', desc: 'Get help and chat with EMCS AI Advisor or our customer support team for your electrical queries.' },
    'profile': { title: 'My Account & Security | EMCS', desc: 'Manage your EMCS account security, linked devices, and personal profile details.' }
};

function updateDynamicSEO(featureId) {
    const seo = SEO_DATA[featureId];
    if (!seo) return;
    const siteName = window.KamAbhiRAM?.cmsData?.siteName || 'EMCS';
    const formattedTitle = seo.title.replace('EMCS', siteName);

    document.title = formattedTitle;
    if ($('seoTitle'))$('seoTitle').innerText = formattedTitle;
    if ($('seoDescription'))$('seoDescription').setAttribute('content', seo.desc);
    if ($('seoOgTitle'))$('seoOgTitle').setAttribute('content', formattedTitle);
    if ($('seoOgDesc'))$('seoOgDesc').setAttribute('content', seo.desc);
    if ($('seoTwTitle'))$('seoTwTitle').setAttribute('content', formattedTitle);
    if ($('seoTwDesc'))$('seoTwDesc').setAttribute('content', seo.desc);
}

// ============================================================================
// 🚦 4. CENTRAL ROUTER (With Freemium Lock & Admin Kill-Switch Enforcer)
// ============================================================================
function handleCentralRouting(path, isInitialLoad = false) {
    enforceUrlAntiIdorGuard();

    const isUserLoggedIn = !!window.KamAbhiRAM.userSession;
    const isAdminLoggedIn = !!window.KamAbhiRAM.adminSession;

    // 1. Admin Routes Guard
    if (ADMIN_ROUTES[path]) {
        if (isAdminLoggedIn) {
            closeAllPopups(false);
            switchAdminSubTab(ADMIN_ROUTES[path], null, !isInitialLoad);
        } else {
            openLoginModal('admin', !isInitialLoad);
        }
        return;
    }

    // 2. Auth Modal Routes Guard
    if (AUTH_ROUTES[path]) {
        if (isUserLoggedIn && (path === '/login' || path === '/register')) {
            showFeature('dashboard', null, true);
        } else {
            openLoginModal(AUTH_ROUTES[path], !isInitialLoad);
        }
        return;
    }

    // 3. Consumer Feature Routes + Kill-Switch + Freemium Guard
    if (APP_ROUTES[path]) {
        const featureId = APP_ROUTES[path];

        // Check God-Mode Kill-Switch
        const sw = window.KamAbhiRAM?.cmsData?.featureSwitches || {};
        const switchMap = {
            'gridSafety': sw.gridSafety,
            'inverterAssistant': sw.inverter,
            'vampireCheck': sw.vampire,
            'todOptimizer': sw.tod,
            'solarRoi': sw.solar,
            'iotControl': sw.iot
        };

        if (featureId in switchMap && switchMap[featureId] === false) {
            alert('⚠️ This module is currently disabled for maintenance by the administration.');
            showFeature('dashboard', null, true);
            return;
        }

        // 7 Public Freemium Routes (Allowed without login for preview)
        const publicRoutes = [
            '/home',
            '/appliances',
            '/calculators',
            '/standby-saver',
            '/inverter-backup',
            '/solar-calculator',
            '/smart-hardware'
        ];

        if (!publicRoutes.includes(path) && !isUserLoggedIn) {
            openLoginModal('login', true);
            return;
        }

        closeAllPopups(false);
        showFeature(featureId, null, !isInitialLoad);
        return;
    }

    // 4. Fallback for "/" or Unknown Path
    closeAllPopups(false);
    if (isAdminLoggedIn && path.startsWith('/admin')) {
        switchAdminSubTab('overviewTab', null, true);
    } else {
        showFeature('dashboard', null, false);
        if (isInitialLoad) window.history.replaceState(null, document.title, '/home');
    }
}

function showFeature(id, btn = null, updateUrl = true) {
    enforceUrlAntiIdorGuard();

    const isUserLoggedIn = !!window.KamAbhiRAM.userSession;
    const targetPath = REVERSE_APP_ROUTES[id] || '/home';

    // Check Kill-Switch before switching tab
    const sw = window.KamAbhiRAM?.cmsData?.featureSwitches || {};
    const switchMap = {
        'gridSafety': sw.gridSafety,
        'inverterAssistant': sw.inverter,
        'vampireCheck': sw.vampire,
        'todOptimizer': sw.tod,
        'solarRoi': sw.solar,
        'iotControl': sw.iot
    };

    if (id in switchMap && switchMap[id] === false) {
        alert('⚠️ This feature is temporarily disabled by Admin.');
        return;
    }

    // Check Freemium Guard when clicking protected sidebar items
    const publicIds = ['dashboard', 'appliances', 'quickCalcs', 'vampireCheck', 'inverterAssistant', 'solarRoi', 'iotControl'];
    if (!publicIds.includes(id) && !isUserLoggedIn) {
        openLoginModal('login', true);
        return;
    }

    // Hide all consumer feature panes
    document.querySelectorAll('#consumerSection .feature-content').forEach(el => {
        el.classList.add('hidden');
        el.classList.remove('active-feature');
    });

    const targetEl = $(id);
    if (targetEl) {
        targetEl.classList.remove('hidden');
        targetEl.classList.add('active-feature');
    }

    // Highlight Sidebar Item
    document.querySelectorAll('#consumerNavLinks .nav-item').forEach(li => li.classList.remove('active'));
    if (btn) {
        btn.classList.add('active');
    } else {
        const autoNav = document.querySelector(`#consumerNavLinks .nav-item[onclick*="'${id}'"]`);
        if (autoNav) autoNav.classList.add('active');
    }

    if (updateUrl && window.location.pathname !== targetPath) {
        window.history.pushState({ featureId: id }, document.title, targetPath);
    }

    // 🔥 Trigger Dynamic SEO & Module-Specific Engines
    updateDynamicSEO(id);

    if (id === 'dashboard' || id === 'appliances') renderAppliancesAndBill();
    if (id === 'quickCalcs') calcGenericEstimator();
    if (id === 'vampireCheck') analyzeStandbyPower();
    if (id === 'inverterAssistant') calculateInverterBackup();
    if (id === 'solarRoi') calculateSolarRoi();
    if (id === 'todOptimizer') calculateTodSavings();
    if (id === 'audit') renderUsageChart();
    if (id === 'simulator') runSavingsSimulator();
    if (id === 'payment') updatePaymentTabInfo();
    if (id === 'userSupportChat') loadUserSupportMessages();
    if (id === 'profile') renderUserProfile();
}

window.addEventListener('popstate', () => {
    handleCentralRouting(window.location.pathname, true);
});

// ============================================================================
// 🔐 5. AUTHENTICATION MODALS & SESSION HANDLERS
// ============================================================================
function openLoginModal(mode = 'login', updateUrl = true) {
    const overlay = $('authModalOverlay');
    if (overlay) overlay.classList.remove('hidden');
    switchAuthMode(mode, updateUrl);
}

function closeAllPopups(restoreUrl = true) {
    if ($('authModalOverlay'))$('authModalOverlay').classList.add('hidden');
    if (restoreUrl && ['/login', '/register', '/admin-login'].includes(window.location.pathname)) {
        window.history.pushState(null, document.title, '/home');
    }
}

function switchAuthMode(mode, updateUrl = false) {
    if ($('loginPane'))$('loginPane').classList.add('hidden');
    if ($('registerPane'))$('registerPane').classList.add('hidden');
    if ($('adminLoginPane'))$('adminLoginPane').classList.add('hidden');
    if ($('userAuthTabs'))$('userAuthTabs').classList.remove('hidden');

    if ($('tabBtnLogin'))$('tabBtnLogin').classList.remove('active');
    if ($('tabBtnRegister'))$('tabBtnRegister').classList.remove('active');

    if (mode === 'login') {
        if ($('loginPane'))$('loginPane').classList.remove('hidden');
        if ($('tabBtnLogin'))$('tabBtnLogin').classList.add('active');
        safeSetText('authModalTitle', 'Consumer Secure Login');
        if (updateUrl) window.history.pushState(null, document.title, '/login');
    } else if (mode === 'register') {
        if ($('registerPane'))$('registerPane').classList.remove('hidden');
        if ($('tabBtnRegister'))$('tabBtnRegister').classList.add('active');
        safeSetText('authModalTitle', 'New Consumer Registration');
        if (updateUrl) window.history.pushState(null, document.title, '/register');
    } else if (mode === 'admin') {
        if ($('adminLoginPane'))$('adminLoginPane').classList.remove('hidden');
        if ($('userAuthTabs'))$('userAuthTabs').classList.add('hidden');
        safeSetText('authModalTitle', 'Command Hub Authorization');
        if (updateUrl) window.history.pushState(null, document.title, '/admin-login');
    }
}

function toggleLoginInputType() {
    const type = $('loginTypeSelect')?.value || 'mobile';
    const label = $('loginValueLabel');
    const input = $('loginIdentifier');
    if (type === 'email') {
        if (label) label.innerText = 'Registered Email ID';
        if (input) input.placeholder = 'Enter your registered email';
    } else {
        if (label) label.innerText = 'Mobile Number';
        if (input) input.placeholder = 'Enter 10-digit mobile number';
    }
}

async function submitConsumerRegistration() {
    const name = $('regName')?.value?.trim();
    const mobile = $('regMobile')?.value?.trim();
    const state = $('regState')?.value || 'BR';
    const email = $('regEmail')?.value?.trim();
    const sanctionedKw = Number($('regSanctionedKw')?.value) || 2;
    const credential = $('regCredential')?.value;
    const honeypot = $('website_url_trap')?.value || '';

    if (!name || !mobile || !email || !credential) {
        return alert('Please fill all registration fields.');
    }

    try {
        const res = await fetch('/api/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, mobile, email, state, sanctionedKw, credential, honeypot })
        });
        const data = await res.json();
        if (!data.success) return alert(data.message || 'Registration failed.');

        setLoggedInUser(data.user);
        closeAllPopups(false);
        showFeature('dashboard', null, true);
        alert(`🎉 Welcome ${data.user.name}! Your Consumer ID is ${data.user.consumerId}`);
    } catch (e) {
        alert('Server connection error during registration.');
    }
}

async function submitConsumerLogin() {
    const identifier = $('loginIdentifier')?.value?.trim();
    const credential = $('loginCredential')?.value;
    const honeypot = $('website_url_trap')?.value || '';

    if (!identifier || !credential) {
        return alert('Please enter your login ID and password.');
    }

    try {
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ identifier, credential, honeypot })
        });
        const data = await res.json();
        if (!data.success) return alert(data.message || 'Login failed.');

        setLoggedInUser(data.user);
        closeAllPopups(false);
        showFeature('dashboard', null, true);
    } catch (e) {
        alert('Network error during login.');
    }
}

function setLoggedInUser(userObj) {
    window.KamAbhiRAM.userSession = userObj;
    if ($('guestAuthButtons'))$('guestAuthButtons').classList.add('hidden');
    if ($('userProfileBadge'))$('userProfileBadge').classList.remove('hidden');
    safeSetText('navConsumerName', userObj.name || userObj.consumerId);
    safeSetText('dashConsumerIdBadge', `ID: ${userObj.consumerId}`);
    safeSetText('dashStateLabel', `${userObj.state || 'BR'} Domestic Grid`);

    // Sync IoT Relay checkboxes from user's saved state
    if (userObj.iotStates) {
        ['1', '2', '3', '4'].forEach(nodeId => {
            const cb = $(`iotRelay${nodeId}`);
            if (cb) cb.checked = Boolean(userObj.iotStates[nodeId]);
        });
    }

    renderAppliancesAndBill();
    analyzeStandbyPower();
}

async function logoutConsumer() {
    try {
        await fetch('/api/auth/logout', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ allDevices: false })
        });
    } catch (e) {}
    window.KamAbhiRAM.userSession = null;
    if ($('guestAuthButtons'))$('guestAuthButtons').classList.remove('hidden');
    if ($('userProfileBadge'))$('userProfileBadge').classList.add('hidden');
    safeSetText('dashConsumerIdBadge', 'Freemium Preview Mode');
    showFeature('dashboard', null, true);
}

async function logoutAllDevices() {
    if (!confirm('Revoke all logged-in devices and sessions immediately?')) return;
    try {
        await fetch('/api/auth/logout', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ allDevices: true })
        });
    } catch (e) {}
    window.KamAbhiRAM.userSession = null;
    window.location.href = '/home';
}

// ============================================================================
// 🔌 6. APPLIANCE MANAGER, PROGRESSIVE SLAB BILLING & STANDBY POWER SAVER
// ============================================================================
function getActiveAppliancesList() {
    if (window.KamAbhiRAM.userSession && Array.isArray(window.KamAbhiRAM.userSession.appliances)) {
        return window.KamAbhiRAM.userSession.appliances;
    }
    return window.KamAbhiRAM.guestAppliances;
}

function getActiveTariffConfig() {
    return window.KamAbhiRAM?.cmsData?.liveTariffs || {
        slabs: [
            { min: 0, max: 100, rate: 5.5 },
            { min: 101, max: 200, rate: 6.5 },
            { min: 201, max: 300, rate: 7.5 },
            { min: 301, max: 999999, rate: 8.5 }
        ],
        fixedCharge: 120,
        taxPercent: 5
    };
}

function calculateProgressiveBill(monthlyUnits) {
    const tariff = getActiveTariffConfig();
    const slabs = tariff.slabs || [];
    let energyCharge = 0;
    let marginalRate = slabs[0]?.rate || 6.5;

    if (monthlyUnits > 0) {
        let remaining = monthlyUnits;
        for (const slab of slabs) {
            const slabCapacity = slab.max - slab.min + (slab.min === 0 ? 0 : 1);
            const unitsInSlab = Math.min(remaining, slabCapacity);
            if (unitsInSlab > 0) {
                energyCharge += unitsInSlab * slab.rate;
                marginalRate = slab.rate;
                remaining -= unitsInSlab;
            }
            if (remaining <= 0) break;
        }
    }

    const fixed = Number(tariff.fixedCharge) || 120;
    const taxPct = Number(tariff.taxPercent) || 5;
    const subtotal = energyCharge + fixed;
    const totalBill = subtotal + (subtotal * (taxPct / 100));

    return {
        totalBill: Math.round(totalBill),
        marginalRate,
        fixed
    };
}

function applyQuickPreset() {
    const val = $('quickPresetSelect')?.value;
    if (!val) return;
    const [name, watts, hours] = val.split('|');
    if ($('dashAppName'))$('dashAppName').value = name || '';
    if ($('dashAppWatts'))$('dashAppWatts').value = watts || '';
    if ($('dashAppHours'))$('dashAppHours').value = hours || '';
}

function addApplianceFromDash() {
    const name = $('dashAppName')?.value?.trim();
    const power = parseFloat($('dashAppWatts')?.value);
    const hours = parseFloat($('dashAppHours')?.value);

    if (!name || isNaN(power) || power <= 0 || isNaN(hours) || hours <= 0 || hours > 24) {
        return alert('Please enter a valid Appliance Name, Wattage, and Daily Hours (0.1 - 24).');
    }

    const list = getActiveAppliancesList();
    list.push({ name, power, hours });

    if ($('dashAppName'))$('dashAppName').value = '';
    if ($('dashAppWatts'))$('dashAppWatts').value = '';
    if ($('dashAppHours'))$('dashAppHours').value = '';
    if ($('quickPresetSelect'))$('quickPresetSelect').value = '';

    renderAppliancesAndBill();
    analyzeStandbyPower();
    if (window.KamAbhiRAM.userSession) saveAppliancesToCloud(true);
}

function addApplianceFromTab() {
    const name = $('appTabName')?.value?.trim();
    const power = parseFloat($('appTabWatts')?.value);
    const hours = parseFloat($('appTabHours')?.value);

    if (!name || isNaN(power) || power <= 0 || isNaN(hours) || hours <= 0 || hours > 24) {
        return alert('Please enter valid appliance details.');
    }

    const list = getActiveAppliancesList();
    list.push({ name, power, hours });

    if ($('appTabName'))$('appTabName').value = '';
    if ($('appTabWatts'))$('appTabWatts').value = '';
    if ($('appTabHours'))$('appTabHours').value = '';

    renderAppliancesAndBill();
    analyzeStandbyPower();
    if (window.KamAbhiRAM.userSession) saveAppliancesToCloud(true);
}

function removeApplianceItem(index) {
    const list = getActiveAppliancesList();
    list.splice(index, 1);
    renderAppliancesAndBill();
    analyzeStandbyPower();
    if (window.KamAbhiRAM.userSession) saveAppliancesToCloud(true);
}

function clearAllAppliances() {
    if (!confirm('Clear all appliances from your load list?')) return;
    if (window.KamAbhiRAM.userSession) {
        window.KamAbhiRAM.userSession.appliances = [];
        saveAppliancesToCloud(true);
    } else {
        window.KamAbhiRAM.guestAppliances = [];
    }
    renderAppliancesAndBill();
    analyzeStandbyPower();
}

async function saveAppliancesToCloud(silent = false) {
    if (!window.KamAbhiRAM.userSession) {
        return openLoginModal('login', true);
    }
    try {
        const res = await fetch('/api/user/appliances', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ appliances: window.KamAbhiRAM.userSession.appliances })
        });
        const data = await res.json();
        if (data.success && !silent) {
            alert('☁️ Appliances synced to your cloud account!');
        }
    } catch (e) {
        if (!silent) alert('Failed to sync appliances.');
    }
}

function renderAppliancesAndBill() {
    const apps = getActiveAppliancesList();
    let totalWatts = 0;
    let dailyWh = 0;

    apps.forEach(a => {
        const w = parseFloat(a.power) || 0;
        const h = parseFloat(a.hours) || 0;
        totalWatts += w;
        dailyWh += (w * h);
    });

    const dailyKwh = dailyWh / 1000;
    const monthlyUnits = dailyKwh * 30;
    const billObj = calculateProgressiveBill(monthlyUnits);

    // Update Dashboard KPIs
    safeSetText('dashMonthlyUnits', `${monthlyUnits.toFixed(1)} kWh`);
    safeSetText('dashDailyUnitsSub', `${dailyKwh.toFixed(2)} kWh / day`);
    safeSetText('dashMonthlyBill', `₹${billObj.totalBill.toLocaleString('en-IN')}`);
    safeSetText('dashTotalWatts', `${totalWatts} W`);
    safeSetText('dashAppCountSub', `${apps.length} Active Appliances`);
    safeSetText('dashQuickCount', String(apps.length));
    safeSetText('dashCurrentRate', `₹${billObj.marginalRate.toFixed(2)}/u`);

    if (monthlyUnits > 300) {
        safeSetText('dashSlabStatusSub', 'Slab 4 (Peak Penalty)');
        safeSetText('slabAlertBadge', 'High Slab Alert');
    } else if (monthlyUnits > 200) {
        safeSetText('dashSlabStatusSub', 'Slab 3 (Moderate)');
        safeSetText('slabAlertBadge', 'Moderate Zone');
    } else {
        safeSetText('dashSlabStatusSub', 'Slab 1-2 (Optimal)');
        safeSetText('slabAlertBadge', 'Safe Zone');
    }

    // Render Appliances Table in #applianceListContainer
    const container = $('applianceListContainer');
    if (!container) return;

    if (apps.length === 0) {
        container.innerHTML = `<div class="text-center p-4 small-text text-muted sub-box">No appliances added yet. Add your home appliances above!</div>`;
        return;
    }

    let html = `<table class="data-table"><thead><tr><th>Appliance</th><th>Power (W)</th><th>Usage/Day</th><th>Monthly Units</th><th>Est. Cost/Mo</th><th>Action</th></tr></thead><tbody>`;
    apps.forEach((app, idx) => {
        const mUnits = ((parseFloat(app.power) || 0) * (parseFloat(app.hours) || 0) * 30) / 1000;
        const mCost = Math.round(mUnits * billObj.marginalRate);
        html += `
            <tr>
                <td><strong>${escapeHTML(app.name)}</strong></td>
                <td class="mono-text">${Number(app.power)} W</td>
                <td class="mono-text">${Number(app.hours)} hrs</td>
                <td class="mono-text text-primary">${mUnits.toFixed(1)} kWh</td>
                <td class="mono-text danger-text">₹${mCost}</td>
                <td><button class="danger-btn sm-btn" onclick="removeApplianceItem(${idx})"><i class="fa-solid fa-trash"></i></button></td>
            </tr>
        `;
    });
    html += `</tbody></table>`;
    container.innerHTML = html;
}
// ============================================================================
// 👻 7. STANDBY POWER SAVER (Vampire Draw Synced With Real Appliances)
// ============================================================================
function analyzeStandbyPower() {
    const listEl = $('vampireAppList');
    const unitsEl = $('vampWastedUnits');
    const costEl = $('vampWastedCost');
    if (!listEl) return;

    const apps = getActiveAppliancesList();
    if (!apps || apps.length === 0) {
        listEl.innerHTML = `<div class="text-center p-4 small-text text-muted sub-box">No appliances added yet. Add appliances in Dashboard to calculate vampire standby draw!</div>`;
        if (unitsEl) unitsEl.innerText = '0.0 Units';
        if (costEl) costEl.innerText = '₹0 / mo';
        return;
    }

    let totalMonthlyWastedUnits = 0;
    const tariff = getActiveTariffConfig();
    const avgRate = tariff.slabs[0]?.rate || 6.5;
    let html = '';

    apps.forEach(app => {
        const pwr = parseFloat(app.power) || 0;
        const activeHrs = parseFloat(app.hours) || 0;
        const standbyHrs = Math.max(0, 24 - activeHrs);

        // Standby rule: Appliances in standby draw ~2% of operating wattage (capped between 0.5W and 12W)
        let standbyWatts = pwr * 0.02;
        if (standbyWatts < 0.5) standbyWatts = 0.5;
        if (standbyWatts > 12) standbyWatts = 12;
        if (pwr === 0) standbyWatts = 0;

        const monthlyWastedUnits = (standbyWatts * standbyHrs * 30) / 1000;
        totalMonthlyWastedUnits += monthlyWastedUnits;

        html += `
            <div class="sub-box flex-between mb-2" style="border-color: rgba(239, 68, 68, 0.25);">
                <div>
                    <strong><i class="fa-solid fa-plug text-warning" style="margin-right:6px;"></i> ${escapeHTML(app.name)}</strong>
                    <p class="small-text text-muted mt-1">Active: <span class="green-text">${activeHrs}h</span> | Standby: <span class="danger-text">${standbyHrs}h / day</span></p>
                </div>
                <div class="text-right">
                    <strong class="danger-text mono-text">${monthlyWastedUnits.toFixed(1)} Units/mo</strong>
                    <p class="small-text text-muted mt-1">Standby Draw: ${standbyWatts.toFixed(1)} W</p>
                </div>
            </div>
        `;
    });

    listEl.innerHTML = html;
    if (unitsEl) unitsEl.innerText = `${totalMonthlyWastedUnits.toFixed(1)} Units`;
    if (costEl) costEl.innerText = `₹${Math.round(totalMonthlyWastedUnits * avgRate)} / mo`;
}

// ============================================================================
// 🧮 8. INSTANT ELECTRICAL CALCULATORS (Client RAM Based - Zero Server Delay)
// ============================================================================
function calcGenericEstimator() {
    const w = parseFloat($('calcPwr')?.value) || 0;
    const h = parseFloat($('calcHrs')?.value) || 0;
    const r = parseFloat($('calcRate')?.value) || 0;

    const dailyKwh = (w * h) / 1000;
    const monthlyKwh = dailyKwh * 30;
    const monthlyCost = monthlyKwh * r;

    safeSetText('calcDailyRes', `${dailyKwh.toFixed(2)} kWh`);
    safeSetText('calcMonthlyRes', `${monthlyKwh.toFixed(2)} kWh`);
    safeSetText('calcCostRes', `₹${monthlyCost.toFixed(2)}`);
}

function solveOhmsLaw() {
    const vInput = $('calcV');
    const iInput = $('calcI');
    const rInput = $('calcR');

    const v = parseFloat(vInput?.value);
    const i = parseFloat(iInput?.value);
    const r = parseFloat(rInput?.value);

    let filledCount = 0;
    if (!isNaN(v)) filledCount++;
    if (!isNaN(i)) filledCount++;
    if (!isNaN(r)) filledCount++;

    if (filledCount !== 2) {
        return alert('Please fill exactly 2 fields to solve for the 3rd.');
    }

    if (!isNaN(v) && !isNaN(i) && isNaN(r)) {
        if (i === 0) return alert('Current cannot be zero.');
        rInput.value = (v / i).toFixed(2);
    } else if (!isNaN(v) && isNaN(i) && !isNaN(r)) {
        if (r === 0) return alert('Resistance cannot be zero.');
        iInput.value = (v / r).toFixed(2);
    } else if (isNaN(v) && !isNaN(i) && !isNaN(r)) {
        vInput.value = (i * r).toFixed(2);
    }
}

function resetOhmsLaw() {
    if ($('calcV'))$('calcV').value = '';
    if ($('calcI'))$('calcI').value = '';
    if ($('calcR'))$('calcR').value = '';
}

// ============================================================================
// 🔋 9. INVERTER, SOLAR, ToD & VOLTAGE SAFETY COMPUTERS
// ============================================================================
function calculateInverterBackup() {
    const ah = parseFloat($('invAh')?.value) || 150;
    const v = parseFloat($('invVolts')?.value) || 12;
    let loadW = parseFloat($('invLoadWatts')?.value) || 300;

    const totalWh = ah * v;
    const usableWh = totalWh * 0.8; // 80% Depth of Discharge & Inverter efficiency
    const hours = loadW > 0 ? (usableWh / loadW) : 0;

    safeSetText('invResultHours', `${hours.toFixed(1)} Hours`);
    safeSetText('invUsableWh', `${Math.round(usableWh).toLocaleString('en-IN')} Wh`);
}

function syncInverterWithAppliances() {
    const apps = getActiveAppliancesList();
    let totalW = 0;
    apps.forEach(a => totalW += (parseFloat(a.power) || 0));
    if (totalW > 0 && $('invLoadWatts')) {$('invLoadWatts').value = totalW;
        calculateInverterBackup();
        alert(`Synced total appliance load (${totalW}W) to Inverter calculator.`);
    } else {
        alert('No active appliance load found.');
    }
}

function calculateSolarRoi() {
    const bill = parseFloat($('solarBillInput')?.value) || 3000;
    const annualBill = bill * 12;

    // Estimate solar plant sizing (approx ₹1000 monthly bill = 1 kW plant generating ~120 units)
    const kw = Math.max(1, Math.round((bill / 1000) * 10) / 10);
    const grossCost = kw * 55000;
    const pmSubsidy = kw <= 3 ? (kw * 18000) : 78000;
    const netCost = Math.max(25000, grossCost - pmSubsidy);
    const annualSavings = Math.round(annualBill * 0.82); // 82% bill offset
    const paybackYears = netCost / (annualSavings || 1);

    safeSetText('solarKwRes', `${kw} kW`);
    safeSetText('solarCostRes', `₹${Math.round(netCost).toLocaleString('en-IN')}`);
    safeSetText('solarSaveRes', `₹${annualSavings.toLocaleString('en-IN')}/yr`);
    safeSetText('solarPaybackRes', `${paybackYears.toFixed(1)} Yrs`);
}

function evaluateCustomVoltage() {
    const volt = parseFloat($('manualVoltInput')?.value) || 230;
    const statusEl = $('gridSurgeStatus');
    const actionEl = $('gridRelayActionText');

    if (!statusEl) return;

    if (volt < 190) {
        statusEl.className = 'danger-text mt-1 mono-text';
        statusEl.innerText = 'LOW VOLTAGE (BROWNOUT)';
        if (actionEl) actionEl.innerText = '⚠️ Compressor Auto-Cut Engaged';
    } else if (volt > 255) {
        statusEl.className = 'danger-text mt-1 mono-text';
        statusEl.innerText = 'HIGH VOLTAGE SURGE';
        if (actionEl) actionEl.innerText = '🚨 MOV Surge Protector Triggered';
    } else {
        statusEl.className = 'green-text mt-1 mono-text';
        statusEl.innerText = 'SAFE';
        if (actionEl) actionEl.innerText = '🟢 Normal Grid Operation';
    }
}

function simulateGridVoltageTest() {
    const testVolts = [232, 182, 240, 262, 228];
    const rand = testVolts[Math.floor(Math.random() * testVolts.length)];
    if ($('manualVoltInput'))$('manualVoltInput').value = rand;
    evaluateCustomVoltage();
}

function calculateTodSavings() {
    const w = parseFloat($('todShiftWatts')?.value) || 2000;
    const h = parseFloat($('todShiftHours')?.value) || 2;
    const tariff = getActiveTariffConfig();
    const rate = tariff.slabs[0]?.rate || 6.5;

    const monthlySaved = ((w * h * 30) / 1000) * rate * 0.15; // 15% solar off-peak rebate
    if ($('todMonthlySavedRes')) {$('todMonthlySavedRes').value = `₹${Math.round(monthlySaved)} / Month`;
    }
}

// ============================================================================
// 📊 10. CHART.JS DYNAMIC 2D BAR & FLOWGRAPH ENGINE
// ============================================================================
let usageChartInstance = null;
let currentChartType = 'bar'; // Default 2D Bar

function toggleChartType(btnEl) {
    currentChartType = currentChartType === 'bar' ? 'line' : 'bar';
    if (btnEl) {
        btnEl.innerHTML = currentChartType === 'bar'
            ? '<i class="fa-solid fa-wave-square"></i> Switch to Flowgraph'
            : '<i class="fa-solid fa-chart-column"></i> Switch to 2D Bar';
    }
    renderUsageChart();
}

function renderUsageChart() {
    const ctx = $('usageChart');
    if (!ctx) return;

    if (usageChartInstance) usageChartInstance.destroy();

    const apps = getActiveAppliancesList();
    let dailyWh = 0;
    let maxApp = { name: 'None', watts: 0 };

    apps.forEach(a => {
        const w = parseFloat(a.power) || 0;
        const h = parseFloat(a.hours) || 0;
        const wh = w * h;
        dailyWh += wh;
        if (wh > maxApp.watts) {
            maxApp.name = a.name;
            maxApp.watts = wh;
        }
    });

    const baseKwh = dailyWh / 1000;
    const monthlyUnits = baseKwh * 30;
    const carbonKg = monthlyUnits * 0.82; // 0.82 kg CO2 per kWh (India Grid Average)

    safeSetText('reportTotalUnits', `${monthlyUnits.toFixed(1)} Units`);
    safeSetText('reportMaxApp', maxApp.name);
    safeSetText('reportCarbonKg', `${carbonKg.toFixed(1)} kg CO₂`);

    const labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const dataPoints = labels.map(() => {
        const fluctuation = baseKwh * (0.85 + (Math.random() * 0.3));
        return Number((fluctuation > 0 ? fluctuation : 0.5).toFixed(2));
    });

    const primaryColor = getComputedStyle(document.documentElement).getPropertyValue('--primary').trim() || '#6366f1';

    usageChartInstance = new Chart(ctx, {
        type: currentChartType,
        data: {
            labels: labels,
            datasets: [{
                label: 'Daily Energy Consumption (kWh)',
                data: dataPoints,
                backgroundColor: currentChartType === 'bar' ? primaryColor : 'rgba(99, 102, 241, 0.18)',
                borderColor: primaryColor,
                borderWidth: 2,
                tension: 0.38,
                fill: currentChartType === 'line'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.06)' } },
                x: { grid: { display: false } }
            }
        }
    });
}

// ============================================================================
// 📈 11. SAVINGS SIMULATOR & PAYMENT GATEWAY
// ============================================================================
function runSavingsSimulator() {
    const hoursCut = parseFloat($('simHoursCut')?.value) || 2;
    const acTemp = parseFloat($('simAcTemp')?.value) || 24;
    const tariff = getActiveTariffConfig();
    const rate = tariff.slabs[0]?.rate || 6.5;

    // Assume 1500W AC/Heavy Load baseline
    const monthlySavedUnits = (1500 * hoursCut * 30) / 1000;
    const tempBonusMultiplier = 1 + Math.max(0, (acTemp - 22) * 0.05);
    const totalMonthlySaved = monthlySavedUnits * tempBonusMultiplier;
    const annualSaved = totalMonthlySaved * 12 * rate;

    safeSetText('simMonthlySavings', `₹${Math.round(totalMonthlySaved * rate)} / mo`);
    safeSetText('simAnnualSavings', `₹${Math.round(annualSaved).toLocaleString('en-IN')} / yr`);
    if ($('simHoursCutLabel'))$('simHoursCutLabel').innerText = `${hoursCut} Hours / Day`;
    if ($('simAcTempLabel'))$('simAcTempLabel').innerText = `${acTemp} °C`;
}

function updatePaymentTabInfo() {
    const apps = getActiveAppliancesList();
    let totalWh = 0;
    apps.forEach(a => totalWh += (parseFloat(a.power) || 0) * (parseFloat(a.hours) || 0));
    const monthlyUnits = (totalWh * 30) / 1000;
    const billObj = calculateProgressiveBill(monthlyUnits);

    safeSetText('payConsumerId', window.KamAbhiRAM.userSession?.consumerId || 'Guest Preview');
    safeSetText('payTotalUnits', `${monthlyUnits.toFixed(1)} kWh`);
    safeSetText('payBillAmount', `₹${billObj.totalBill.toLocaleString('en-IN')}`);
    loadPaymentHistory();
}

async function initiateBillPayment() {
    if (!window.KamAbhiRAM.userSession) {
        return openLoginModal('login', true);
    }
    const apps = getActiveAppliancesList();
    let totalWh = 0;
    apps.forEach(a => totalWh += (parseFloat(a.power) || 0) * (parseFloat(a.hours) || 0));
    const monthlyUnits = (totalWh * 30) / 1000;
    const billObj = calculateProgressiveBill(monthlyUnits);
    const method = $('paymentMethodSelect')?.value || 'UPI';

    if (billObj.totalBill <= 0) {
        return alert('Payable amount is ₹0. Add appliances to generate a bill.');
    }

    try {
        const res = await fetch('/api/user/pay-bill', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ amount: billObj.totalBill, unitsBilled: monthlyUnits, method })
        });
        const data = await res.json();
        if (!data.success) return alert(data.message || 'Payment failed.');

        alert(`✅ Payment Successful! Transaction ID: ${data.receipt.txnId}`);
        loadPaymentHistory();
    } catch (e) {
        alert('Payment gateway timeout.');
    }
}

async function loadPaymentHistory() {
    if (!window.KamAbhiRAM.userSession) return;
    try {
        const res = await fetch('/api/user/payments');
        const data = await res.json();
        const container = $('paymentHistoryContainer');
        if (!container || !data.success) return;

        if (data.receipts.length === 0) {
            container.innerHTML = `<p class="small-text text-muted">No past receipts found.</p>`;
            return;
        }

        let html = `<table class="data-table"><thead><tr><th>Txn ID</th><th>Amount</th><th>Method</th><th>Date</th></tr></thead><tbody>`;
        data.receipts.forEach(r => {
            const dt = new Date(r.createdAt).toLocaleDateString();
            html += `<tr><td class="mono-text">${r.txnId}</td><td class="mono-text green-text">₹${r.amount}</td><td>${r.method}</td><td>${dt}</td></tr>`;
        });
        html += `</tbody></table>`;
        container.innerHTML = html;
    } catch (e) {}
}

// ============================================================================
// 💬 12. AI ADVISOR & SUPPORT CHAT HUB
// ============================================================================
async function loadUserSupportMessages() {
    if (!window.KamAbhiRAM.userSession) {
        return;
    }
    try {
        const res = await fetch('/api/user/support');
        const data = await res.json();
        const box = $('chatMessagesBox');
        if (!box || !data.success) return;

        if (data.messages.length === 0) {
            box.innerHTML = `<div class="p-2 sub-box small-text text-muted">Start a conversation with our AI Energy Advisor.</div>`;
            return;
        }

        let html = '';
        data.messages.forEach(m => {
            const isUser = m.sender === 'user';
            const bg = isUser ? 'rgba(99, 102, 241, 0.12)' : 'rgba(16, 185, 129, 0.12)';
            const border = isUser ? 'var(--primary)' : 'var(--accent)';
            const title = isUser ? 'You' : (m.sender === 'ai' ? 'EMCS AI Advisor' : 'Grid Admin');
            html += `
                <div class="p-2 mb-2 sub-box" style="background:${bg}; border-left:3px solid ${border};">
                    <strong class="small-text">${title}</strong>
                    <p class="small-text mt-1">${escapeHTML(m.text)}</p>
                </div>
            `;
        });
        box.innerHTML = html;
        box.scrollTop = box.scrollHeight;
    } catch (e) {}
}

async function sendUserSupportMessage() {
    if (!window.KamAbhiRAM.userSession) {
        return openLoginModal('login', true);
    }
    const input = $('supportChatInput');
    const text = input?.value?.trim();
    if (!text) return;

    if (input) input.value = '';

    // Optimistic UI Append
    const box = $('chatMessagesBox');
    if (box) {
        box.innerHTML += `
            <div class="p-2 mb-2 sub-box" style="background:rgba(99, 102, 241, 0.12); border-left:3px solid var(--primary);">
                <strong class="small-text">You</strong>
                <p class="small-text mt-1">${escapeHTML(text)}</p>
            </div>
        `;
        box.scrollTop = box.scrollHeight;
    }

    try {
        const res = await fetch('/api/user/support', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text })
        });
        const data = await res.json();
        if (data.success) {
            loadUserSupportMessages();
        }
    } catch (e) {
        alert('Failed to send message.');
    }
}

function renderUserProfile() {
    const u = window.KamAbhiRAM.userSession;
    if (!u) return;
    safeSetText('profCid', u.consumerId);
    safeSetText('profName', u.name);
    safeSetText('profMobile', u.mobile);
    safeSetText('profEmailState', `${u.email} (${u.state} Grid)`);

    const list = $('activeSessionsList');
    if (list && Array.isArray(u.activeSessions)) {
        let html = '';
        u.activeSessions.forEach((s) => {
            const dt = new Date(s.lastActive || Date.now()).toLocaleString();
            html += `<div class="sub-box mb-1 flex-between"><span>💻 ${escapeHTML(s.deviceLabel || 'Browser')} (${s.ip || 'IP'})</span><span class="small-text text-muted">${dt}</span></div>`;
        });
        list.innerHTML = html;
    }
}

async function toggleSmartRelay(nodeId, checkboxEl) {
    if (!window.KamAbhiRAM.userSession) {
        checkboxEl.checked = !checkboxEl.checked;
        return openLoginModal('login', true);
    }
    const state = checkboxEl.checked;
    try {
        const res = await fetch('/api/user/iot-toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nodeId, state })
        });
        const data = await res.json();
        if (!data.success) {
            checkboxEl.checked = !state;
            alert('Hardware relay toggle failed.');
        }
    } catch (e) {
        checkboxEl.checked = !state;
    }
}

// ============================================================================
// 🛡️ 13. GOD-MODE ADMIN & STAFF COMMAND HUB CONTROLLER
// ============================================================================
async function submitAdminLogin() {
    const username = $('adminUsernameInput')?.value?.trim();
    const password = $('adminPasswordInput')?.value;
    const honeypot = $('website_url_trap')?.value || '';

    if (!username || !password) {
        return alert('Enter admin username and security key.');
    }

    try {
        const res = await fetch('/api/admin/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, honeypot })
        });
        const data = await res.json();
        if (!data.success) return alert(data.message || 'Admin authorization failed.');

        window.KamAbhiRAM.adminSession = data.admin;
        closeAllPopups(false);
        if ($('consumerSection'))$('consumerSection').classList.add('hidden');
        if ($('adminSection'))$('adminSection').classList.remove('hidden');

        switchAdminSubTab('overviewTab', null, true);
        alert(`🛡️ Welcome ${data.admin.username} (${data.admin.role}) to Command Hub!`);
    } catch (e) {
        alert('Admin authentication network error.');
    }
}

async function logoutAdmin() {
    try {
        await fetch('/api/admin/logout', { method: 'POST' });
    } catch (e) {}
    window.KamAbhiRAM.adminSession = null;
    if ($('adminSection'))$('adminSection').classList.add('hidden');
    if ($('consumerSection'))$('consumerSection').classList.remove('hidden');
    window.history.pushState(null, document.title, '/home');
}

function switchAdminSubTab(subId, btnEl = null, updateUrl = true) {
    document.querySelectorAll('.admin-sub-pane').forEach(el => el.classList.add('hidden'));
    const t = $(subId);
    if (t) t.classList.remove('hidden');

    document.querySelectorAll('#adminSection .sidebar .nav-item').forEach(li => li.classList.remove('active'));
    if (btnEl) {
        btnEl.classList.add('active');
    } else {
        const auto = document.querySelector(`#adminSection .sidebar .nav-item[onclick*="'${subId}'"]`);
        if (auto) auto.classList.add('active');
    }

    const pathMap = {
        'overviewTab': '/admin',
        'usersTab': '/admin/users',
        'adminCmsSubPane': '/admin/cms',
        'supportTab': '/admin/support',
        'staffTab': '/admin/staff',
        'logsTab': '/admin/logs'
    };

    const targetPath = pathMap[subId] || '/admin';
    if (updateUrl && window.location.pathname !== targetPath) {
        window.history.pushState({ adminSub: subId }, document.title, targetPath);
    }

    if (subId === 'overviewTab') refreshAdminOverview();
    if (subId === 'usersTab') loadAdminUsersList();
    if (subId === 'adminCmsSubPane') loadAdminCmsData();
    if (subId === 'supportTab') loadAdminSupportTickets();
    if (subId === 'staffTab') loadAdminStaffList();
    if (subId === 'logsTab') loadAdminSecurityLogs();
}

async function refreshAdminOverview() {
    try {
        const res = await fetch('/api/admin/overview');
        const data = await res.json();
        if (data.success) {
            safeSetText('admTotalUsers', data.stats.totalUsers);
            safeSetText('admActiveUsers', data.stats.activeUsers);
            safeSetText('admPendingTickets', data.stats.pendingTickets);
            safeSetText('admTotalErrors', data.stats.totalErrors);
            if ($('adminRoleBadge'))$('adminRoleBadge').innerText = data.adminProfile.role;
        }
    } catch (e) {}
}

async function loadAdminUsersList() {
    try {
        const res = await fetch('/api/admin/users');
        const data = await res.json();
        if (!data.success) return;
        window.KamAbhiRAM.adminUsersCache = data.users;
        renderAdminUsersTable(data.users);
    } catch (e) {}
}

function renderAdminUsersTable(users) {
    const tbody = $('adminUsersTableBody');
    if (!tbody) return;

    if (users.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted p-3">No consumers registered yet.</td></tr>`;
        return;
    }

    let html = '';
    users.forEach(u => {
        const appCount = Array.isArray(u.appliances) ? u.appliances.length : 0;
        const isSuspended = u.accountStatus === 'suspended';
        const statusBadge = isSuspended ? `<span class="badge-pill danger-text">Suspended</span>` : `<span class="badge-pill green-text">Active</span>`;
        const actionBtn = isSuspended
            ? `<button class="success-btn sm-btn" onclick="toggleUserStatus('${u.consumerId}', 'active')">Unsuspend</button>`
            : `<button class="danger-btn sm-btn" onclick="toggleUserStatus('${u.consumerId}', 'suspended')">Suspend</button>`;

        html += `
            <tr>
                <td class="mono-text"><strong>${u.consumerId}</strong></td>
                <td>${escapeHTML(u.name)}<br><small class="text-muted">${escapeHTML(u.mobile)}</small></td>
                <td>${escapeHTML(u.state)}</td>
                <td class="mono-text">${appCount} items</td>
                <td>${statusBadge}</td>
                <td>${actionBtn}</td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
}

function filterAdminUsersTable() {
    const q = $('adminUserSearchInput')?.value?.toLowerCase() || '';
    const filtered = window.KamAbhiRAM.adminUsersCache.filter(u =>
        u.consumerId.toLowerCase().includes(q) ||
        u.name.toLowerCase().includes(q) ||
        u.mobile.includes(q) ||
        u.email.toLowerCase().includes(q)
    );
    renderAdminUsersTable(filtered);
}

async function toggleUserStatus(consumerId, status) {
    try {
        const res = await fetch(`/api/admin/users/${consumerId}/status`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status })
        });
        const data = await res.json();
        if (data.success) {
            loadAdminUsersList();
        }
    } catch (e) {
        alert('Failed to update user status.');
    }
}

async function loadAdminCmsData() {
    try {
        const res = await fetch('/api/admin/cms-full');
        const data = await res.json();
        if (!data.success || !data.cms) return;

        const c = data.cms;
        window.KamAbhiRAM.cmsData = c;

        if ($('cmsSiteNameInput'))$('cmsSiteNameInput').value = c.siteName || 'EMCS';
        if ($('cmsBroadcastInput'))$('cmsBroadcastInput').value = c.broadcastBanner || '';
        if ($('cmsHeroHeadingInput'))$('cmsHeroHeadingInput').value = c.heroHeading || '';
        if ($('cmsHeroSubtextInput'))$('cmsHeroSubtextInput').value = c.heroSubtext || '';
        if ($('cmsPrimaryColor'))$('cmsPrimaryColor').value = c.themeColors?.primary || '#6366f1';
        if ($('cmsAccentColor'))$('cmsAccentColor').value = c.themeColors?.accent || '#10b981';

        const sw = c.featureSwitches || {};
        if ($('cmsSwGrid'))$('cmsSwGrid').checked = sw.gridSafety !== false;
        if ($('cmsSwInverter'))$('cmsSwInverter').checked = sw.inverter !== false;
        if ($('cmsSwVampire'))$('cmsSwVampire').checked = sw.vampire !== false;
        if ($('cmsSwTod'))$('cmsSwTod').checked = sw.tod !== false;
        if ($('cmsSwSolar'))$('cmsSwSolar').checked = sw.solar !== false;
        if ($('cmsSwIot'))$('cmsSwIot').checked = sw.iot !== false;

        const slabs = c.liveTariffs?.slabs || [];
        if ($('cmsSlab1Rate'))$('cmsSlab1Rate').value = slabs[0]?.rate || 5.5;
        if ($('cmsSlab2Rate'))$('cmsSlab2Rate').value = slabs[1]?.rate || 6.5;
        if ($('cmsSlab3Rate'))$('cmsSlab3Rate').value = slabs[2]?.rate || 7.5;
        if ($('cmsSlab4Rate'))$('cmsSlab4Rate').value = slabs[3]?.rate || 8.5;
        if ($('cmsFixedChargeInput'))$('cmsFixedChargeInput').value = c.liveTariffs?.fixedCharge || 120;
        if ($('cmsTaxPercentInput'))$('cmsTaxPercentInput').value = c.liveTariffs?.taxPercent || 5;

        if ($('cmsPaymentEnabled'))$('cmsPaymentEnabled').value = String(c.paymentConfig?.enabled ?? true);
        if ($('cmsPaymentKey'))$('cmsPaymentKey').value = c.paymentConfig?.apiKey || '';
        if ($('cmsPaymentSecret'))$('cmsPaymentSecret').value = ''; // Blank until explicitly updated
        if ($('cmsAiPromptInput'))$('cmsAiPromptInput').value = c.aiPrompt || '';
    } catch (e) {}
}

async function saveCmsContent() {
    try {
        const payload = {
            siteName: $('cmsSiteNameInput')?.value,
            broadcastBanner: $('cmsBroadcastInput')?.value,
            heroHeading: $('cmsHeroHeadingInput')?.value,
            heroSubtext: $('cmsHeroSubtextInput')?.value,
            themeColors: {
                primary: $('cmsPrimaryColor')?.value || '#6366f1',
                accent: $('cmsAccentColor')?.value || '#10b981'
            },
            featureSwitches: {
                gridSafety: $('cmsSwGrid')?.checked ?? true,
                inverter: $('cmsSwInverter')?.checked ?? true,
                vampire: $('cmsSwVampire')?.checked ?? true,
                tod: $('cmsSwTod')?.checked ?? true,
                solar: $('cmsSwSolar')?.checked ?? true,
                iot: $('cmsSwIot')?.checked ?? true
            },
            liveTariffs: {
                slabs: [
                    { min: 0, max: 100, rate: parseFloat($('cmsSlab1Rate')?.value) \vert{}\vert{} 5.5 }, { min: 101, max: 200, rate: parseFloat($('cmsSlab2Rate')?.value) || 6.5 },
                    { min: 201, max: 300, rate: parseFloat($('cmsSlab3Rate')?.value) \vert{}\vert{} 7.5 }, { min: 301, max: 999999, rate: parseFloat($('cmsSlab4Rate')?.value) || 8.5 }
                ],
                fixedCharge: parseFloat($('cmsFixedChargeInput')?.value) || 120,
                taxPercent: parseFloat($('cmsTaxPercentInput')?.value) || 5
            },
            paymentConfig: {
                enabled: $('cmsPaymentEnabled')?.value === 'true',
                apiKey: $('cmsPaymentKey')?.value?.trim(),
                apiSecret: $('cmsPaymentSecret')?.value?.trim()
            },
            aiPrompt: $('cmsAiPromptInput')?.value
        };

        const res = await fetch('/api/admin/cms', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!data.success) return alert(data.message || 'Failed to save CMS.');

        applyFrontendCmsSync(data.cms);
        alert('🚀 God-Mode CMS and Live Tariffs successfully published!');
    } catch (e) {
        alert('Network error while saving CMS.');
    }
}

async function loadAdminSupportTickets() {
    try {
        const res = await fetch('/api/admin/support');
        const data = await res.json();
        const container = $('adminSupportList');
        if (!container || !data.success) return;

        if (data.tickets.length === 0) {
            container.innerHTML = `<p class="text-center text-muted small-text p-3">No active support tickets.</p>`;
            return;
        }

        let html = '';
        data.tickets.forEach(t => {
            const isResolved = t.status === 'resolved';
            const badge = isResolved ? `<span class="badge-pill green-text">Resolved</span>` : `<span class="badge-pill warning-text">Open</span>`;
            let msgLog = '';
            if (Array.isArray(t.messages)) {
                t.messages.forEach(m => {
                    msgLog += `<div class="small-text mb-1"><strong>[${m.sender.toUpperCase()}]:</strong> ${escapeHTML(m.text)}</div>`;
                });
            }

            html += `
                <div class="sub-box mb-3">
                    <div class="flex-between mb-2">
                        <div><strong>Consumer: ${t.consumerName} (${t.consumerId})</strong></div>
                        <div>${badge}</div>
                    </div>
                    <div class="p-2 mb-2" style="background:var(--bg-color); border-radius:6px; max-height:160px; overflow-y:auto;">
                        ${msgLog}
                    </div>
                    <div style="display:flex; gap:8px;">
                        <input type="text" id="adminReplyText_${t.consumerId}" placeholder="Type engineer reply...">
                        <button class="primary-btn sm-btn" onclick="sendAdminSupportReply('${t.consumerId}', false)">Reply</button>
                        <button class="success-btn sm-btn" onclick="sendAdminSupportReply('${t.consumerId}', true)">Resolve</button>
                    </div>
                </div>
            `;
        });
        container.innerHTML = html;
    } catch (e) {}
}

async function sendAdminSupportReply(consumerId, resolveTicket) {
    const textInput = $(`adminReplyText_${consumerId}`);
    const text = textInput?.value?.trim();
    if (!text && !resolveTicket) return;

    try {
        const res = await fetch(`/api/admin/support/${consumerId}/reply`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text, resolveTicket })
        });
        const data = await res.json();
        if (data.success) {
            if (textInput) textInput.value = '';
            loadAdminSupportTickets();
        }
    } catch (e) {
        alert('Failed to send reply.');
    }
}

async function loadAdminStaffList() {
    try {
        const res = await fetch('/api/admin/staff');
        const data = await res.json();
        const container = $('adminStaffListContainer');
        if (!container || !data.success) return;

        if (data.staffList.length === 0) {
            container.innerHTML = `<p class="small-text text-muted">No staff operators created yet.</p>`;
            return;
        }

        let html = `<table class="data-table"><thead><tr><th>Username</th><th>Role Title</th><th>Permissions</th><th>Action</th></tr></thead><tbody>`;
        data.staffList.forEach(st => {
            const perms = Object.entries(st.permissions || {}).filter(([k, v]) => v).map(([k]) => k).join(', ') || 'None';
            html += `
                <tr>
                    <td class="mono-text"><strong>${escapeHTML(st.username)}</strong></td>
                    <td>${escapeHTML(st.roleTitle)}</td>
                    <td class="small-text text-muted">${perms}</td>
                    <td><button class="danger-btn sm-btn" onclick="deleteStaffAccount('${st._id}')"><i class="fa-solid fa-trash"></i></button></td>
                </tr>
            `;
        });
        html += `</tbody></table>`;
        container.innerHTML = html;
    } catch (e) {}
}

async function createNewStaffAccount() {
    const username = $('newStaffUsername')?.value?.trim();
    const password = $('newStaffPassword')?.value;
    const roleTitle = $('newStaffRoleTitle')?.value?.trim() || 'Operator';
    const permissions = {
        manageUsers: $('permManageUsers')?.checked,
        manageCms: $('permManageCms')?.checked,
        manageSupport: $('permManageSupport')?.checked,
        viewLogs: $('permViewLogs')?.checked
    };

    if (!username || !password || password.length < 6) {
        return alert('Enter username and 6+ character password.');
    }

    try {
        const res = await fetch('/api/admin/staff', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, roleTitle, permissions })
        });
        const data = await res.json();
        if (!data.success) return alert(data.message || 'Failed to create staff.');

        if ($('newStaffUsername'))$('newStaffUsername').value = '';
        if ($('newStaffPassword'))$('newStaffPassword').value = '';
        loadAdminStaffList();
        alert(`✅ Staff operator '${username}' created successfully!`);
    } catch (e) {
        alert('Network error while creating staff.');
    }
}

async function deleteStaffAccount(id) {
    if (!confirm('Revoke and delete this staff account?')) return;
    try {
        await fetch(`/api/admin/staff/${id}`, { method: 'DELETE' });
        loadAdminStaffList();
    } catch (e) {}
}

async function loadAdminSecurityLogs() {
    try {
        const res = await fetch('/api/admin/logs');
        const data = await res.json();
        const container = $('adminLogsContainer');
        if (!container || !data.success) return;

        if (data.logs.length === 0) {
            container.innerHTML = `<p class="text-center text-muted small-text p-3">Audit log is clean. No security threats detected.</p>`;
            return;
        }

        let html = `<table class="data-table"><thead><tr><th>Timestamp</th><th>Source</th><th>Location</th><th>IP / User</th><th>Message</th></tr></thead><tbody>`;
        data.logs.forEach(l => {
            const dt = new Date(l.createdAt).toLocaleString();
            html += `
                <tr>
                    <td class="small-text text-muted">${dt}</td>
                    <td><strong>${escapeHTML(l.source)}</strong></td>
                    <td class="mono-text">${escapeHTML(l.location)}</td>
                    <td class="mono-text">${escapeHTML(l.userOrIp)}</td>
                    <td class="small-text">${escapeHTML(l.message)}</td>
                </tr>
            `;
        });
        html += `</tbody></table>`;
        container.innerHTML = html;
    } catch (e) {}
}

async function clearAdminSecurityLogs() {
    if (!confirm('Purge all security audit logs?')) return;
    try {
        await fetch('/api/admin/logs', { method: 'DELETE' });
        loadAdminSecurityLogs();
    } catch (e) {}
}

// ============================================================================
// 🌍 14. INITIAL BOOTSTRAP & CLOCK SYNC
// ============================================================================
async function initializeEmcsApp() {
    enforceUrlAntiIdorGuard();

    // 1. Fetch Global CMS Settings & Theme Colors
    try {
        const res = await fetch('/api/cms');
        const data = await res.json();
        if (data.success && data.cms) {
            applyFrontendCmsSync(data.cms);
        }
    } catch (e) {}

    // 2. Check Existing User Session
    try {
        const res = await fetch('/api/auth/me');
        const data = await res.json();
        if (data.success && data.user) {
            setLoggedInUser(data.user);
        }
    } catch (e) {}

    // 3. Setup Clock & Route Handler
    setInterval(() => {
        const clockEl = $('liveClock');
        if (clockEl) {
            clockEl.innerText = new Date().toLocaleTimeString();
        }
    }, 1000);

    // Initial Routing Load based on browser URL pathname
    handleCentralRouting(window.location.pathname, true);
}

function applyFrontendCmsSync(cms) {
    window.KamAbhiRAM.cmsData = cms;

    if (cms.siteName) {
        safeSetText('cmsBrandTitle', cms.siteName);
    }
    if (cms.broadcastBanner && cms.broadcastBanner.trim() !== '') {
        safeSetText('broadcastText', cms.broadcastBanner);
        if ($('globalBroadcastBanner'))$('globalBroadcastBanner').classList.remove('hidden');
    } else {
        if ($('globalBroadcastBanner'))$('globalBroadcastBanner').classList.add('hidden');
    }

    if (cms.heroHeading) safeSetText('cmsHeroHeading', cms.heroHeading);
    if (cms.heroSubtext) safeSetText('cmsHeroSubtext', cms.heroSubtext);

    // Apply Dynamic Theme Colors to CSS Root
    if (cms.themeColors) {
        if (cms.themeColors.primary) document.documentElement.style.setProperty('--primary', cms.themeColors.primary);
        if (cms.themeColors.accent) document.documentElement.style.setProperty('--accent', cms.themeColors.accent);
    }

    // Update Slab Text on Dashboard
    const slabs = cms.liveTariffs?.slabs || [];
    if (slabs[0]) safeSetText('slabRate1Text', `₹${slabs[0].rate.toFixed(2)} / kWh`);
    if (slabs[1]) safeSetText('slabRate2Text', `₹${slabs[1].rate.toFixed(2)} / kWh`);
    if (slabs[2]) safeSetText('slabRate3Text', `₹${slabs[2].rate.toFixed(2)} / kWh`);
    if (slabs[3]) safeSetText('slabRate4Text', `₹${slabs[3].rate.toFixed(2)} / kWh`);
}

function toggleTheme() {
    const body = document.body;
    if (body.classList.contains('dark-theme')) {
        body.classList.remove('dark-theme');
        body.classList.add('light-theme');
    } else {
        body.classList.remove('light-theme');
        body.classList.add('dark-theme');
    }
}

// Run bootstrap on DOM ready
document.addEventListener('DOMContentLoaded', initializeEmcsApp);
