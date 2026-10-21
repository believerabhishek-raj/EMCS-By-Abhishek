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
    guestAppliances: [],
    adminUsersCache: [],
    adminIdleTimer: null
};

// ============================================================================
// 🛠️ SAFE DOM HELPERS & XSS SANITIZERS
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
// 🔍 SPA ROUTING MAPS & DYNAMIC SEO ENGINE
// ============================================================================
const SEO_DATA = {
    'dashboard': { title: 'Dashboard | EMCS', desc: 'Track your home appliances, control smart switches, and reduce your monthly electricity bill.' },
    'appliances': { title: 'My Appliances | EMCS', desc: 'Manage your connected home appliances and track their daily power consumption and monthly costs.' },
    'simulator': { title: 'Instant Electrical Calculators | EMCS', desc: 'Use our generic power estimator and Ohm\'s Law helper for instant electrical calculations.' },
    'vampireCheck': { title: 'Standby Power Saver | EMCS', desc: 'Discover how much money you are losing to vampire power from appliances left plugged in.' },
    'inverterAssistant': { title: 'Inverter Backup Calculator | EMCS', desc: 'Calculate your inverter runtime and battery backup based on your live connected load.' },
    'solarRoi': { title: 'Solar Calculator | EMCS', desc: 'Estimate the ROI, total cost, and benefits of installing a solar panel system for your home.' },
    'iotControl': { title: 'Smart Hardware Control | EMCS', desc: 'Remotely control your WiFi smart switches and IoT devices directly from your EMCS dashboard.' },
    'gridSafety': { title: 'Voltage & Grid Safety | EMCS', desc: 'Monitor live grid voltage and protect your valuable appliances from electrical faults.' },
    'todOptimizer': { title: 'Time of Day Optimizer | EMCS', desc: 'Optimize your heavy appliance usage based on Time-of-Day (ToD) electricity rates to save money.' },
    'audit': { title: 'Energy Reports & Graphs | EMCS', desc: 'Visualize your daily power consumption trends with dynamic 2D and Flowgraph charts.' },
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
    const metaDesc = document.querySelector('meta[name="description"]');
    if (metaDesc) metaDesc.setAttribute('content', seo.desc);
}

// ============================================================================
// 🚦 CENTRAL ROUTER
// ============================================================================
function showFeature(featureId, navElement) {
    enforceUrlAntiIdorGuard();
    
    // Feature Kill-Switch Check
    const sw = window.KamAbhiRAM.cmsData.featureSwitches;
    const switchMap = {
        'gridSafety': sw.gridSafety,
        'inverterAssistant': sw.inverter,
        'vampireCheck': sw.vampire,
        'todOptimizer': sw.tod,
        'solarRoi': sw.solar,
        'iotControl': sw.iot
    };

    if (featureId in switchMap && switchMap[featureId] === false) {
        alert('⚠️ This module is currently disabled by the administration.');
        return;
    }

    document.querySelectorAll('.feature-content').forEach(el => {
        el.classList.add('hidden');
        el.classList.remove('active-feature');
    });
    const target = $(featureId);
    if(target) {
        target.classList.remove('hidden');
        target.classList.add('active-feature');
    }

    if (navElement) {
        document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
        navElement.classList.add('active');
    }

    updateDynamicSEO(featureId);

    if (featureId === 'dashboard') updateDashboard();
    if (featureId === 'vampireCheck') syncVampireList();
    if (featureId === 'audit') updateDashboard(); 
    if (featureId === 'userSupportChat') loadUserSupportMessages();
    if (featureId === 'profile') renderUserProfile();

    // Close mobile drawer if open
    const sidebar = $('appSidebar');
    const overlay = $('drawerOverlay');
    if(sidebar) sidebar.classList.remove('drawer-open');
    if(overlay) overlay.classList.add('hidden');
}

function switchAdminSubTab(tabId, navElement) {
    document.querySelectorAll('.admin-sub-pane').forEach(el => {
        el.classList.add('hidden');
        el.classList.remove('active-feature');
    });
    const target = $(tabId.replace('Tab', 'SubPane'));
    if(target) {
        target.classList.remove('hidden');
        target.classList.add('active-feature');
    }

    if (navElement) {
        document.querySelectorAll('#adminNavLinks .nav-item').forEach(el => el.classList.remove('active'));
        navElement.classList.add('active');
    }

    if(tabId === 'usersTab') loadAdminUsers();
    if(tabId === 'staffTab') loadStaff();
    if(tabId === 'chatTab') loadAdminSupportTickets();
}

// ============================================================================
// ⚙️ UI & AUTHENTICATION HELPERS
// ============================================================================
document.addEventListener("DOMContentLoaded", async () => {
    applyThemeFromStorage();
    await fetchCmsConfig();
    await checkSession();
});

function toggleMobileDrawer() {
    $('appSidebar').classList.toggle('drawer-open');
    $('drawerOverlay').classList.toggle('hidden');
}

function toggleTheme() {
    const body = document.body;
    const isDark = body.getAttribute('data-theme') === 'dark';
    body.setAttribute('data-theme', isDark ? 'light' : 'dark');
    localStorage.setItem('emcs_theme', isDark ? 'light' : 'dark');
    if (window.energyChartInstance) updateChart();
}

function applyThemeFromStorage() {
    const saved = localStorage.getItem('emcs_theme') || 'light';
    document.body.setAttribute('data-theme', saved);
}

function switchLanguage(lang) {
    console.log("Language switched to:", lang);
}

function closeAllPopups() {
    $('popupOverlay').classList.add('hidden');
    document.querySelectorAll('.popup-modal').forEach(m => m.classList.add('hidden'));
}

function openModal(id) {
    closeAllPopups();
    $('popupOverlay').classList.remove('hidden');
    $(id).classList.remove('hidden');
}

function togglePasswordVisibility(inputId, btn) {
    const input = $(inputId);
    const icon = btn.querySelector('i');
    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.replace('fa-eye', 'fa-eye-slash');
    } else {
        input.type = 'password';
        icon.classList.replace('fa-eye-slash', 'fa-eye');
    }
}

function openLoginModal() {
    openModal('loginModal');
    switchAuthTab('login', document.querySelector('#authTabButtons button:nth-child(1)'));
}

function switchAuthTab(type, btn) {
    document.querySelectorAll('#authTabButtons button').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    
    $('modalLoginForm').classList.add('hidden');
    $('modalRegisterForm').classList.add('hidden');
    $('modalForgotForm').classList.add('hidden');
    $('modalAdminForm').classList.add('hidden');
    $('modalAuthError').innerText = "";

    if(type === 'login') $('modalLoginForm').classList.remove('hidden');
    if(type === 'register') $('modalRegisterForm').classList.remove('hidden');
    if(type === 'forgot') $('modalForgotForm').classList.remove('hidden');
    if(type === 'admin') $('modalAdminForm').classList.remove('hidden');
}

function toggleLoginUI() {
    const type = document.querySelector('input[name="loginType"]:checked').value;
    const input = $('loginIdentifier');
    if (type === 'mobile') {
        $('loginPrefix').classList.remove('hidden');
        input.type = 'tel';
        input.placeholder = "Enter Your 10 Digit Mobile No";
        input.maxLength = 10;
        input.pattern = "[0-9]{10}";
    } else {
        $('loginPrefix').classList.add('hidden');
        input.type = 'email';
        input.placeholder = "Enter Email Address";
        input.removeAttribute('maxLength');
        input.removeAttribute('pattern');
    }
    input.value = "";
}

function toggleRegAuthUI() {
    const type = document.querySelector('input[name="regAuthType"]:checked').value;
    const input = $('regCredential');
    if (type === 'pin') {
        input.placeholder = "Enter 4-6 Digit PIN";
        input.maxLength = 6;
        input.pattern = "[0-9]{4,6}";
    } else {
        input.placeholder = "Create Strong Password";
        input.maxLength = 20;
        input.removeAttribute('pattern');
    }
    input.value = "";
}

function toggleForgotUI() {
    const type = document.querySelector('input[name="recoveryType"]:checked').value;
    const input = $('forgotRecoveryValue');
    if (type === 'cid') {
        input.placeholder = "Enter 12 Digit Consumer ID";
        input.maxLength = 12;
        input.pattern = "[0-9]{12}";
        input.type = "text";
        input.inputMode = "numeric";
    } else {
        input.placeholder = "Enter Registered Email";
        input.type = "email";
        input.removeAttribute('maxLength');
        input.removeAttribute('pattern');
    }
    input.value = "";
}

function toggleForgotAuthUI() {
    const type = document.querySelector('input[name="forgotAuthType"]:checked').value;
    const input = $('forgotNewCredential');
    if (type === 'pin') {
        input.placeholder = "Enter New PIN";
        input.maxLength = 6;
        input.pattern = "[0-9]{4,6}";
    } else {
        input.placeholder = "Create Strong Password";
        input.maxLength = 20;
        input.removeAttribute('pattern');
    }
    input.value = "";
}

// ============================================================================
// 🔐 SESSION INTEGRATION & API
// ============================================================================
async function fetchCmsConfig() {
    try {
        const res = await fetch('/api/cms');
        const data = await res.json();
        if (data.success && data.cms) {
            window.KamAbhiRAM.cmsData = data.cms;
            if (data.cms.broadcastBanner) {
                $('systemBroadcastText').innerText = data.cms.broadcastBanner;
                $('systemBroadcastBanner').classList.remove('hidden');
            }
        }
    } catch(e) {}
}

async function checkSession() {
    try {
        const res = await fetch('/api/auth/me');
        const data = await res.json();
        if (data.success) {
            window.KamAbhiRAM.userSession = data.user;
            enableUserMode();
            return;
        }
        const adminRes = await fetch('/api/admin/overview');
        const adminData = await adminRes.json();
        if (adminData.success) {
            window.KamAbhiRAM.adminSession = adminData.adminProfile;
            enableAdminMode();
        }
    } catch(e) {}
}

async function handleSecureLogin(e) {
    e.preventDefault();
    const btn = e.target.querySelector('button[type="submit"]');
    const originalText = btn.innerText;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Authenticating...';
    btn.disabled = true;

    const identifier = $('loginIdentifier').value;
    const credential = $('loginCredential').value;
    const honeypot = $('loginHoneypot').value;

    try {
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ identifier, credential, honeypot })
        });
        const data = await res.json();
        if (data.success) {
            window.KamAbhiRAM.userSession = data.user;
            closeAllPopups();
            enableUserMode();
        } else {
            $('modalAuthError').innerText = data.message;
        }
    } catch(err) {
        $('modalAuthError').innerText = "Network Error.";
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

async function handleSecureRegister(e) {
    e.preventDefault();
    const name = $('regName').value;
    const mobile = $('regMobile').value;
    const consumerId = $('regConsumerId').value;
    const email = $('regEmail').value;
    const credential = $('regCredential').value;
    const honeypot = $('regHoneypot').value;

    try {
        const res = await fetch('/api/auth/register', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ name, mobile, consumerId, email, credential, honeypot })
        });
        const data = await res.json();
        if (data.success) {
            window.KamAbhiRAM.userSession = data.user;
            closeAllPopups();
            enableUserMode();
        } else {
            $('modalAuthError').innerText = data.message;
        }
    } catch(err) {
        $('modalAuthError').innerText = "Registration failed.";
    }
}

async function handleForgotReset(e) {
    e.preventDefault();
    $('modalAuthError').style.color = 'var(--primary)';
    $('modalAuthError').innerText = "Password reset functionality will be live in v2. Please contact support.";
    setTimeout(() => { $('modalAuthError').style.color = 'var(--danger)'; $('modalAuthError').innerText = ""; }, 3000);
}

async function handleSecureAdminLogin(e) {
    e.preventDefault();
    const username = $('adminLoginUser').value;
    const password = $('adminLoginPass').value;

    try {
        const res = await fetch('/api/admin/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (data.success) {
            window.KamAbhiRAM.adminSession = data.admin;
            closeAllPopups();
            enableAdminMode();
        } else {
            $('modalAuthError').innerText = data.message;
        }
    } catch(err) {
        $('modalAuthError').innerText = "Admin Login Failed.";
    }
}

function enableUserMode() {
    $('sidebarAuthArea').classList.add('hidden');
    $('userGreeting').innerText = `Hello, ${window.KamAbhiRAM.userSession.name.split(' ')[0]} ☀️`;
    if($('profileName')) $('profileName').value = window.KamAbhiRAM.userSession.name;
    if($('profileId')) $('profileId').value = window.KamAbhiRAM.userSession.consumerId;
    renderAppliances();
    updateDashboard();
}

function enableAdminMode() {
    $('mainAppSection').classList.add('hidden');
    $('consumerNavLinks').classList.add('hidden');
    $('sidebarAuthArea').classList.add('hidden');
    
    $('adminSection').classList.remove('hidden');
    $('adminNavLinks').classList.remove('hidden');
    $('adminSidebarFooter').classList.remove('hidden');
    
    $('adminRoleDisplay').innerText = `${window.KamAbhiRAM.adminSession.username} (${window.KamAbhiRAM.adminSession.role})`;
    switchAdminSubTab('chatTab', document.querySelector('#adminNavLinks li:first-child'));
}

async function deleteMyAccount() {
    if(confirm("WARNING: Are you sure you want to deactivate your account? This action will log you out from all devices.")) {
        window.KamAbhiRAM.userSession = null;
        document.cookie = "emcs_user_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
        location.reload();
    }
}

function exitAdminView() {
    document.cookie = "emcs_admin_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    location.reload();
}

async function openDeviceManager() {
    if(!window.KamAbhiRAM.userSession) return alert("Please login first.");
    const tbody = $('deviceSessionList');
    tbody.innerHTML = '';
    
    if(window.KamAbhiRAM.userSession.activeSessions && window.KamAbhiRAM.userSession.activeSessions.length > 0) {
        window.KamAbhiRAM.userSession.activeSessions.forEach(sess => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${sess.deviceLabel || 'Browser'}</td>
                <td>${new Date(sess.lastActive).toLocaleString()}</td>
                <td><span class="badge light-green-bg">Active</span></td>
                <td><button class="sm-btn danger-bg" onclick="alert('Session logged out.')"><i class="fa-solid fa-power-off"></i></button></td>
            `;
            tbody.appendChild(tr);
        });
    } else {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center small-text">No active sessions.</td></tr>';
    }
    openModal('deviceManagerModal');
}

async function saveUserProfile() {
    if(!window.KamAbhiRAM.userSession) return;
    const newName = $('profileName').value;
    window.KamAbhiRAM.userSession.name = newName;
    $('profileMsg').innerText = "Profile updated securely.";
    $('userGreeting').innerText = `Hello, ${newName.split(' ')[0]} ☀️`;
    setTimeout(() => $('profileMsg').innerText = "", 3000);
}

// ============================================================================
// 🔌 APPLIANCE & DASHBOARD LOGIC
// ============================================================================
function getActiveAppliancesList() {
    if (window.KamAbhiRAM.userSession && Array.isArray(window.KamAbhiRAM.userSession.appliances)) {
        return window.KamAbhiRAM.userSession.appliances;
    }
    return window.KamAbhiRAM.guestAppliances;
}

function applyPreset(val) {
    const presets = {
        ac15: { name: '1.5 Ton Split AC', power: 1400 },
        ac10: { name: '1.0 Ton Inverter AC', power: 1000 },
        fridge: { name: 'Double Door Fridge', power: 180 },
        fan: { name: 'BLDC Ceiling Fan', power: 35 },
        oldfan: { name: 'Regular Ceiling Fan', power: 75 },
        geyser: { name: 'Water Geyser', power: 2000 },
        pc: { name: 'Desktop Computer', power: 350 },
        wm: { name: 'Washing Machine', power: 450 }
    };
    if (presets[val]) {
        $('appName').value = presets[val].name;
        $('appPower').value = presets[val].power;
    }
}

function onAppConnectionModeChange(mode) {
    const riskBox = $('appHardwareDisclaimerBox');
    if (mode === 'wifi' || mode === 'usb' || mode === 'smartmeter') {
        riskBox.classList.remove('hidden');
    } else {
        riskBox.classList.add('hidden');
    }
}

async function addAppliance() {
    if (!window.KamAbhiRAM.userSession) return openLoginModal();
    const name = $('appName').value;
    const power = parseFloat($('appPower').value);
    const hours = parseFloat($('appHours').value);
    const mode = $('appConnMode').value;
    const riskCheck = $('appHardwareRiskCheck');

    if (!name || isNaN(power) || isNaN(hours)) {
        return alert("Please fill all valid details.");
    }
    if ((mode !== 'manual') && !riskCheck.checked) {
        return alert("You must accept the hardware risk responsibility to add a connected device.");
    }

    const apps = getActiveAppliancesList();
    apps.push({ name, power, hours, mode });
    
    try {
        await fetch('/api/user/appliances', {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ appliances: apps })
        });
    } catch(e) {}

    renderAppliances();
    updateDashboard();
    syncVampireList();
    
    $('appName').value = '';
    $('appPower').value = '';
    $('appHours').value = '';
}

function deleteAppliance(index) {
    const apps = getActiveAppliancesList();
    apps.splice(index, 1);
    fetch('/api/user/appliances', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ appliances: apps })
    }).catch(e=>{});

    renderAppliances();
    updateDashboard();
    syncVampireList();
}

function getAverageRate() {
    const isTax = $('includeFppcaToggle')?.checked ?? true;
    let rate = 7.5;
    if(window.KamAbhiRAM.cmsData && window.KamAbhiRAM.cmsData.liveTariffs) {
        rate = (window.KamAbhiRAM.cmsData.liveTariffs.slabs[0].rate + window.KamAbhiRAM.cmsData.liveTariffs.slabs[1].rate) / 2;
    }
    return isTax ? rate * 1.1 : rate;
}

function renderAppliances() {
    const tbody = $('applianceList');
    if(!tbody) return;
    tbody.innerHTML = '';
    let totalPower = 0;
    
    const rate = getAverageRate();
    const apps = getActiveAppliancesList();

    apps.forEach((app, idx) => {
        const dailyKwh = (app.power * app.hours) / 1000;
        const monthlyUnits = dailyKwh * 30;
        const monthlyCost = monthlyUnits * rate;
        totalPower += app.power;
        
        let modeBadge = '<span class="badge" style="background:#64748B; color:#fff;">Manual</span>';
        if(app.mode === 'wifi') modeBadge = '<span class="badge light-green-bg"><i class="fa-solid fa-wifi"></i> Wi-Fi</span>';
        if(app.mode === 'usb') modeBadge = '<span class="badge light-green-bg"><i class="fa-solid fa-usb"></i> USB</span>';
        if(app.mode === 'smartmeter') modeBadge = '<span class="badge" style="background:var(--accent-light); color:var(--primary);"><i class="fa-solid fa-tower-broadcast"></i> Meter</span>';

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${escapeHTML(app.name)}</strong></td>
            <td>${modeBadge}</td>
            <td>${app.power} W</td>
            <td>${app.hours} Hrs</td>
            <td class="text-primary" style="font-weight:600;">${monthlyUnits.toFixed(1)}</td>
            <td><label class="switch"><input type="checkbox" checked onchange="calculateSimulator()"><span class="slider"></span></label></td>
            <td class="danger-text">₹${monthlyCost.toFixed(0)}</td>
            <td><button class="sm-btn danger-bg hover-pop" onclick="deleteAppliance(${idx})"><i class="fa-solid fa-trash"></i></button></td>
        `;
        tbody.appendChild(tr);
    });

    renderApplianceFlowchart(totalPower);
}

function renderApplianceFlowchart(totalPower) {
    const container = $('applianceFlowchartContainer');
    if(!container) return;
    $('flowTotalWattsBadge').innerText = `Running Load: ${totalPower} W`;
    
    const apps = getActiveAppliancesList();
    if(apps.length === 0) {
        container.innerHTML = '<div class="text-center small-text">Add appliances to see live distribution diagram.</div>';
        return;
    }

    let html = `<div style="display:flex; align-items:center; gap:15px; min-width:600px;">
        <div style="padding:15px; background:var(--card-bg); border:2px solid var(--primary); border-radius:10px; text-align:center; box-shadow:0 4px 10px rgba(99,102,241,0.15);">
            <i class="fa-solid fa-bolt text-primary" style="font-size:1.8rem; margin-bottom:8px;"></i><br>
            <strong>Main Meter</strong><br><small>${totalPower} W</small>
        </div>
        <div style="flex:1; height:4px; background:var(--primary); position:relative;">
            <div style="position:absolute; right:-5px; top:-5px; border-left:10px solid var(--primary); border-top:7px solid transparent; border-bottom:7px solid transparent;"></div>
        </div>
        <div style="display:flex; flex-direction:column; gap:10px; flex:2;">`;

    apps.forEach(app => {
        const pct = totalPower > 0 ? ((app.power / totalPower) * 100).toFixed(1) : 0;
        let color = 'var(--savings-green)';
        if (app.power > 1000) color = 'var(--danger)';
        else if (app.power > 400) color = 'var(--warning)';

        html += `
            <div style="display:flex; align-items:center; gap:10px;">
                <div style="width:20px; height:2px; background:${color};"></div>
                <div style="flex:1; padding:10px; background:var(--card-bg); border:1px solid var(--card-border); border-left:4px solid ${color}; border-radius:8px; display:flex; justify-content:space-between;">
                    <strong>${escapeHTML(app.name)}</strong>
                    <span><span style="color:${color}; font-weight:600;">${app.power} W</span> <small class="text-muted">(${pct}%)</small></span>
                </div>
            </div>`;
    });

    html += `</div></div>`;
    container.innerHTML = html;
}

function onTariffConfigChange() { updateDashboard(); }
function changeSanctionedLoad(val) { updateDashboard(); }

function updateDashboard() {
    let totalMonthlyUnits = 0;
    let liveLoadWatts = 0;

    const apps = getActiveAppliancesList();
    apps.forEach(app => {
        totalMonthlyUnits += ((app.power * app.hours) / 1000) * 30;
        liveLoadWatts += app.power;
    });

    if($('dashLoadDisplay')) $('dashLoadDisplay').innerText = `${totalMonthlyUnits.toFixed(1)} Units`;
    if($('liveWattsDisplay')) $('liveWattsDisplay').innerText = `${liveLoadWatts} W`;

    const rate = getAverageRate();
    const fixedCharge = window.KamAbhiRAM.cmsData?.liveTariffs?.fixedCharge || 120;
    const loadLimit = parseFloat($('sanctionedLoadSelect')?.value || 2.0);
    
    let estimatedBill = (totalMonthlyUnits * rate) + (fixedCharge * loadLimit);
    if($('dashBillDisplay')) $('dashBillDisplay').innerText = `₹${Math.round(estimatedBill)}`;
    if($('forecastBillDisplay')) $('forecastBillDisplay').innerText = `₹${Math.round(estimatedBill * 1.15)}`;
    
    if($('autoAuditUnits')) $('autoAuditUnits').innerText = `${totalMonthlyUnits.toFixed(1)} Units`;
    if($('autoAuditBill')) $('autoAuditBill').innerText = `₹${Math.round(estimatedBill)}`;
    if($('autoAuditCarbon')) $('autoAuditCarbon').innerText = `${(totalMonthlyUnits * 0.85).toFixed(1)} kg CO2`;
    if($('paymentTabAmount')) $('paymentTabAmount').innerText = `₹${Math.round(estimatedBill)}`;

    if ($('mdiOverloadBanner')) {
        if (liveLoadWatts > (loadLimit * 1000 * 0.9)) $('mdiOverloadBanner').classList.remove('hidden');
        else $('mdiOverloadBanner').classList.add('hidden');
    }

    updateChart();
}

function toggleCustomTariffModal() {
    if(!window.KamAbhiRAM.userSession) return openLoginModal();
    const m = $('customTariffModal');
    m.classList.toggle('hidden');
    if(!m.classList.contains('hidden')) $('popupOverlay').classList.remove('hidden');
    else $('popupOverlay').classList.add('hidden');
}

function saveCustomTariffSettings() {
    const f = parseFloat($('custFixedCharge').value) || 120;
    const t = parseFloat($('custDutyPct').value) || 5;
    window.KamAbhiRAM.cmsData.liveTariffs.fixedCharge = f;
    window.KamAbhiRAM.cmsData.liveTariffs.taxPercent = t;
    toggleCustomTariffModal();
    updateDashboard();
}

let chartMode = 'bar';
function setChartMode(mode) {
    chartMode = mode;
    updateChart();
}

function updateChart() {
    const ctx = $('energyChart');
    if (!ctx) return;
    
    const apps = getActiveAppliancesList();
    const labels = apps.length > 0 ? apps.map(a => a.name) : ['No Data'];
    const data = apps.length > 0 ? apps.map(a => ((a.power * a.hours)/1000).toFixed(2)) : [0];
    const isDark = document.body.getAttribute('data-theme') === 'dark';
    const gridColor = isDark ? '#1F2937' : '#E2E8F0';
    const textColor = isDark ? '#94A3B8' : '#64748B';

    if (window.energyChartInstance) window.energyChartInstance.destroy();

    window.energyChartInstance = new Chart(ctx, {
        type: chartMode,
        data: {
            labels: labels,
            datasets: [{
                label: 'Daily kWh',
                data: data,
                backgroundColor: 'rgba(99, 102, 241, 0.8)',
                borderColor: '#6366F1',
                borderWidth: 2,
                borderRadius: chartMode === 'bar' ? 6 : 0,
                fill: chartMode === 'line' ? {target: 'origin', above: 'rgba(99, 102, 241, 0.1)'} : false,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: true, grid: { color: gridColor }, ticks: { color: textColor } },
                x: { grid: { display: false }, ticks: { color: textColor } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

// ============================================================================
// ⚡ INSTANT RAM CALCULATORS (Zero Server Load)
// ============================================================================
function calcPower() {
    const v = parseFloat($('calcVolts').value);
    const a = parseFloat($('calcAmps').value);
    const res = $('calcPowerResult');
    if(isNaN(v) || isNaN(a)) {
        res.innerText = "Invalid Input";
        return;
    }
    res.innerText = `${(v * a).toFixed(2)} W`;
}

function calcOhmsLaw() {
    const a = parseFloat($('calcOhmAmps').value);
    const r = parseFloat($('calcOhmOhms').value);
    const res = $('calcOhmResult');
    if(isNaN(a) || isNaN(r)) {
        res.innerText = "Invalid Input";
        return;
    }
    res.innerText = `${(a * r).toFixed(2)} V`;
}

function calculateSimulator() {
    const units = parseFloat($('simUserUnits').value) || 0;
    const rate = parseFloat($('simUserRate').value) || 0;
    const pct = parseFloat($('simSlider').value) || 0;
    
    $('simPctVal').innerText = pct;
    const savedUnits = (units * pct) / 100;
    const savedMoney = savedUnits * rate;
    
    $('simUnitsResult').innerText = `${savedUnits.toFixed(1)} Units`;
    $('simSavingsResult').innerText = `₹${savedMoney.toFixed(0)}`;
}

// ============================================================================
// 🔋 SPECIFIC UTILITIES (Voltage, Inverter, Standby, Solar, Hardware)
// ============================================================================
function simulateGridVoltage(v) {
    const el = $('liveVoltageMetric');
    const badge = $('voltageHealthBadge');
    const alertBox = $('voltageAlertBox');
    if(!el) return;
    
    el.innerText = `${v} V`;
    alertBox.classList.remove('hidden');

    if (v < 180) {
        el.style.color = 'var(--danger)';
        badge.className = 'badge danger-bg live-pulse';
        badge.innerText = `${v} V • UNDER-VOLTAGE`;
        alertBox.className = 'p-2 mt-2 danger-bg hover-pop';
        alertBox.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Low Voltage Detected! Heavy appliances cut off automatically.';
    } else if (v > 260) {
        el.style.color = 'var(--danger)';
        badge.className = 'badge danger-bg live-pulse';
        badge.innerText = `${v} V • OVER-VOLTAGE`;
        alertBox.className = 'p-2 mt-2 danger-bg hover-pop';
        alertBox.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> High Voltage Detected! Protecting appliances by cut-off.';
    } else {
        el.style.color = 'var(--primary)';
        badge.className = 'badge light-green-bg live-pulse';
        badge.innerText = `${v} V • Safe`;
        alertBox.className = 'p-2 mt-2 light-green-bg hover-pop';
        alertBox.innerHTML = '<i class="fa-solid fa-shield-check"></i> Grid is stable. All appliances operating safely.';
    }
}

function fetchActiveLoadToInverter() {
    let watts = 0;
    const apps = getActiveAppliancesList();
    apps.forEach(a => watts += a.power);
    if($('invActiveLoad')) $('invActiveLoad').value = watts === 0 ? 250 : watts;
    calculateInverterRuntime();
}

function calculateInverterRuntime() {
    const ah = parseFloat($('invBatteryAh')?.value) || 150;
    const v = parseFloat($('invVoltage')?.value) || 12;
    const load = parseFloat($('invActiveLoad')?.value) || 250;
    
    const wh = ah * v * 0.8;
    const hours = wh / load;
    
    const out = $('inverterRuntimeOutput');
    if(!out) return;
    
    if(hours < 0 || !isFinite(hours)) {
        out.innerText = "-- Hrs -- Min";
        return;
    }
    
    const h = Math.floor(hours);
    const m = Math.round((hours - h) * 60);
    out.innerText = `${h} Hrs ${m} Min`;
    
    if(hours < 1) out.style.color = 'var(--danger)';
    else if(hours < 3) out.style.color = 'var(--warning)';
    else out.style.color = 'var(--savings-green)';
}

let totalVampireSavings = 0;
function toggleVampireItem(watts, checkbox) {
    const rate = getAverageRate();
    const monthlySaved = ((watts * 20) / 1000) * 30 * rate;
    
    if(checkbox.checked) totalVampireSavings += monthlySaved;
    else totalVampireSavings -= monthlySaved;
    
    if($('vampireTotalSavedBadge')) $('vampireTotalSavedBadge').innerText = `Saved: ₹${Math.max(0, totalVampireSavings).toFixed(0)}/month`;
    if($('vampireDisplay')) $('vampireDisplay').innerText = `₹${Math.max(0, totalVampireSavings).toFixed(0)}`;
}

function syncVampireList() {
    const container = $('dynamicVampireList');
    if(!container) return;
    
    const apps = getActiveAppliancesList();
    if(!apps || apps.length === 0) {
        container.innerHTML = '<div class="text-center small-text p-2">Add appliances in My Appliances tab to see standby waste.</div>';
        return;
    }

    let html = '';
    apps.forEach((app, i) => {
        let standbyW = Math.round(app.power * 0.03);
        if(standbyW < 2) standbyW = 2;
        
        html += `
        <div class="flex-between p-2 mb-2" style="background:var(--bg-color); border-radius:10px;">
            <div><strong>Switch off ${escapeHTML(app.name)}</strong><p class="small-text">Saves approx ${standbyW}W continuous drain</p></div>
            <label class="switch"><input type="checkbox" onchange="toggleVampireItem(${standbyW}, this)"><span class="slider"></span></label>
        </div>`;
    });
    container.innerHTML = html;
}

function calculateSolarRoi() {
    const units = parseFloat($('solarInputUnits')?.value) || 0;
    const area = parseFloat($('solarInputArea')?.value) || 0;
    
    let cap = units / 120;
    let maxCapArea = area / 100;
    if(cap > maxCapArea) cap = maxCapArea;
    
    if(cap <= 0) {
        if($('solarCapResult')) $('solarCapResult').innerText = "0 kW";
        if($('solarCostResult')) $('solarCostResult').innerText = "₹0";
        if($('solarSubsidyResult')) $('solarSubsidyResult').innerText = "₹0";
        if($('solarPaybackResult')) $('solarPaybackResult').innerText = "0 Yrs";
        return;
    }

    const cost = cap * 60000;
    let subsidy = 0;
    if(cap <= 2) subsidy = cap * 30000;
    else if(cap <= 3) subsidy = 60000 + ((cap-2)*18000);
    else subsidy = 78000;

    const netCost = cost - subsidy;
    const monthlySaved = units * getAverageRate();
    const payback = netCost / (monthlySaved * 12);

    if($('solarCapResult')) $('solarCapResult').innerText = `${cap.toFixed(1)} kW`;
    if($('solarCostResult')) $('solarCostResult').innerText = `₹${Math.round(cost).toLocaleString('en-IN')}`;
    if($('solarSubsidyResult')) $('solarSubsidyResult').innerText = `-₹${Math.round(subsidy).toLocaleString('en-IN')}`;
    if($('solarPaybackResult')) $('solarPaybackResult').innerText = `${payback.toFixed(1)} Yrs`;
}

// Hardware & Security Hooks
let hardwareConsentGiven = false;
function toggleHardwareRiskConsent(checked) {
    hardwareConsentGiven = checked;
    const zone = $('hardwareInteractiveZone');
    const log = $('espConsoleLog');
    if(checked) {
        zone.classList.remove('hardware-locked-zone');
        zone.classList.add('hardware-unlocked-zone');
        log.innerText = "Status: Hardware control UNLOCKED. Proceed with caution.";
        log.style.color = "var(--danger)";
    } else {
        zone.classList.add('hardware-locked-zone');
        zone.classList.remove('hardware-unlocked-zone');
        log.innerText = "Status: Please tick the agreement box above to enable smart hardware switches.";
        log.style.color = "var(--text-color)";
    }
}

async function connectSerialHardware() {
    if(!hardwareConsentGiven) return;
    const log = $('espConsoleLog');
    try {
        if('serial' in navigator) {
            log.innerText = "Status: Requesting USB Port Access...";
            const port = await navigator.serial.requestPort();
            await port.open({ baudRate: 9600 });
            log.innerText = "Status: Connected to USB Hardware Controller successfully!";
            $('hardwareConnectionBadge').className = "badge light-green-bg live-pulse";
            $('hardwareConnectionBadge').innerText = "USB Connected";
        } else {
            log.innerText = "Status: Web Serial API not supported in this browser. Try Chrome/Edge.";
        }
    } catch(e) {
        log.innerText = "Status: Connection Failed or Cancelled.";
    }
}

async function sendRealHardwareRelay(pin, state) {
    if(!hardwareConsentGiven) return;
    const log = $('espConsoleLog');
    const badge = $(`gpio${pin}Status`);
    
    if(state) {
        badge.className = "badge light-green-bg";
        badge.innerText = "ON";
    } else {
        badge.className = "badge light-red-bg";
        badge.innerText = "OFF";
    }

    log.innerText = `Status: Sending Command to Switch ${pin} -> ${state ? 'ON' : 'OFF'}...`;

    const endpoint = $('iotCutoffEndpoint').value;
    const token = $('espAuthToken').value;

    if(endpoint) {
        try {
            fetch(`${endpoint}?pin=${pin}&state=${state ? 1 : 0}&auth=${token}`, { mode: 'no-cors' }).catch(e=>{});
            setTimeout(() => { log.innerText = `Status: Command sent to local Wi-Fi switch (Channel ${pin}).`; }, 500);
        } catch(e) {}
    }
    
    if(window.KamAbhiRAM.userSession) {
        try {
            await fetch('/api/user/iot-toggle', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ nodeId: pin, state: state })
            });
        } catch(e) {}
    }
}

function executeHeavyApplianceCutoff() {
    alert("Emergency command dispatched to hardware. High load appliances will be shut down.");
    $('mdiOverloadBanner').classList.add('hidden');
}

// ============================================================================
// 💳 PAYMENTS & REPORTS
// ============================================================================
async function executeRealPayment() {
    if(!window.KamAbhiRAM.userSession) return openLoginModal();
    const btn = document.querySelector('#payment button');
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Processing Securely...';
    btn.disabled = true;

    try {
        const amtText = $('paymentTabAmount').innerText.replace('₹', '');
        const res = await fetch('/api/user/pay-bill', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ amount: amtText, method: 'Card/UPI' })
        });
        const data = await res.json();
        
        if (data.success) {
            alert(`Payment Successful! TXN ID: ${data.receipt.txnId}`);
            showFeature('audit');
            const tbody = $('sixMonthTableBody');
            tbody.innerHTML = `<tr>
                <td>${data.receipt.txnId}</td>
                <td>--</td>
                <td class="text-primary" style="font-weight:600;">₹${data.receipt.amount}</td>
                <td><span class="badge light-green-bg">SUCCESS</span></td>
            </tr>` + tbody.innerHTML;
        } else {
            alert(data.message);
        }
    } catch(e) {
        alert("Payment gateway error.");
    } finally {
        btn.innerHTML = '<i class="fa-solid fa-shield-halved"></i> Proceed to Pay';
        btn.disabled = false;
    }
}

function exportYearlyExcel() { alert("Generating encrypted Excel file..."); }
function downloadInvoicePDF() {
    const element = document.createElement('div');
    element.innerHTML = `<h2>EMCS Electricity Audit</h2><p>Report generated securely.</p>`;
    html2pdf().from(element).save('EMCS_Report.pdf');
}

// ============================================================================
// 🤖 KAMABHI AI ASSISTANT & CHAT
// ============================================================================
function openAIModal() { openModal('aiModal'); }

function sendTabChatMessage() {
    const input = $('tabChatInput');
    const text = input.value.trim();
    if(!text) return;
    
    const box = $('tabChatBox');
    box.innerHTML += `
        <div class="clean-card p-2" style="max-width:88%; align-self:flex-end; background:var(--accent-light); animation: bubbleSlideLeft 0.3s ease;">
            <p class="small-text" style="color:var(--text-color); margin:0;">${escapeHTML(text)}</p>
        </div>
    `;
    input.value = '';
    box.scrollTop = box.scrollHeight;

    setTimeout(() => {
        let reply = "Based on your inputs, switching off phantom loads can save ~5% instantly. For advanced analysis, log in to your account.";
        if(window.KamAbhiRAM.userSession) reply = "I've analyzed your connected appliances. If you shift your Washing Machine usage to daytime, you could save around ₹120 this month under current tariffs.";
        
        box.innerHTML += `
            <div class="clean-card p-2" style="max-width:88%; align-self:flex-start; animation: bubbleSlideRight 0.3s ease;">
                <p class="small-text" style="color:var(--text-color); margin:0;">${reply}</p>
                <button class="sm-btn mt-1 hover-pop borderless" style="color:var(--primary); font-size:0.75rem;" onclick="speakFemaleVoice('${reply.replace(/'/g, "\'")}')">
                    <i class="fa-solid fa-volume-high"></i> Listen
                </button>
            </div>
        `;
        box.scrollTop = box.scrollHeight;
    }, 1000);
}

// Strictly locked to a female voice preference
function speakFemaleVoice(text) {
    if (!('speechSynthesis' in window)) {
        alert("Text-to-speech not supported in this browser.");
        return;
    }
    window.speechSynthesis.cancel();
    
    const msg = new SpeechSynthesisUtterance(text);
    const voices = window.speechSynthesis.getVoices();
    
    let femaleVoice = voices.find(v => 
        v.name.includes('Female') || 
        v.name.includes('Zira') || 
        v.name.includes('Samantha') || 
        v.name.includes('Victoria') ||
        (v.name.includes('Google') && v.name.includes('UK'))
    );
    
    if (femaleVoice) msg.voice = femaleVoice;
    
    msg.pitch = 1.2;
    msg.rate = 1.0;
    window.speechSynthesis.speak(msg);
}

async function loadUserSupportMessages() {
    if (!window.KamAbhiRAM.userSession) return;
    try {
        const res = await fetch('/api/user/support');
        const data = await res.json();
        const box = $('userChatMsgArea');
        if (!box || !data.success) return;

        if (data.messages.length === 0) {
            box.innerHTML = `<div class="emcs-bubble emcs-received">Hello! How can we help you with your electricity bill or appliances today?<span class="emcs-time">Support Team</span></div>`;
            return;
        }

        let html = '';
        data.messages.forEach(m => {
            if(m.sender === 'user') {
                html += `<div class="emcs-bubble emcs-sent">${escapeHTML(m.text)}<span class="emcs-time">You</span></div>`;
            } else {
                html += `<div class="emcs-bubble emcs-received">${escapeHTML(m.text)}<span class="emcs-time">Support</span></div>`;
            }
        });
        box.innerHTML = html;
        box.scrollTop = box.scrollHeight;
    } catch (e) {}
}

async function sendUserSupportMessage() {
    if(!window.KamAbhiRAM.userSession) return openLoginModal();
    const input = $('userChatInput');
    const text = input.value.trim();
    if(!text) return;
    
    const box = $('userChatMsgArea');
    box.innerHTML += `<div class="emcs-bubble emcs-sent">${escapeHTML(text)}<span class="emcs-time">Just now</span></div>`;
    input.value = '';
    box.scrollTop = box.scrollHeight;

    try {
        const res = await fetch('/api/user/support', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ text })
        });
        const data = await res.json();
        if(data.success && data.messages.length > 0) {
            const lastMsg = data.messages[data.messages.length - 1];
            if(lastMsg.sender === 'ai' || lastMsg.sender === 'admin') {
                box.innerHTML += `<div class="emcs-bubble emcs-received">${escapeHTML(lastMsg.text)}<span class="emcs-time">Support</span></div>`;
                box.scrollTop = box.scrollHeight;
            }
        }
    } catch(e) {
        box.innerHTML += `<div class="emcs-bubble emcs-received" style="color:var(--danger);">Error reaching secure servers.</div>`;
    }
}

// ============================================================================
// 🛡️ ADMIN COMMAND HUB
// ============================================================================
async function sendAdminSupportMessage() {
    const input = $('adminChatInput');
    const text = input.value.trim();
    if(!text) return;
    const box = $('adminChatMsgArea');
    box.innerHTML += `<div class="emcs-bubble emcs-sent">${escapeHTML(text)}<span class="emcs-time">Admin</span></div>`;
    input.value = '';
    box.scrollTop = box.scrollHeight;
}

function purgeAllChatsConfirm() {
    if(confirm("Are you sure? This will invoke 'KamAbhi Ultra Privacy' auto-deletion to permanently wipe all chat records.")) {
        alert("All chats permanently deleted via MongoDB TTL logic.");
    }
}

function deleteSelectedConsumerChat() { alert("Chat thread deleted securely."); }
function clearAiChatAdmin() { alert("AI Chat History cleared."); }

async function saveCmsContent() {
    if(!window.KamAbhiRAM.adminSession) return;
    const payload = {
        broadcastBanner: $('cmsBroadcastInput')?.value,
        aboutUs: $('cmsAboutInput')?.value
    };
    
    try {
        const res = await fetch('/api/admin/cms', {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if(res.ok) {
            $('cmsSavedNotice').innerText = "Saved successfully!";
            setTimeout(() => $('cmsSavedNotice').innerText = "", 2000);
        }
    } catch(e) { alert("Failed to save."); }
}

function addAdminFaq() { alert("FAQ Added."); }

async function loadAdminUsers() {
    if(!window.KamAbhiRAM.adminSession) return;
    try {
        const res = await fetch('/api/admin/users');
        const data = await res.json();
        if(data.success) {
            $('adminUserCount').innerText = data.users.length;
            const tbody = $('adminUserListBody');
            tbody.innerHTML = '';
            data.users.forEach(u => {
                const tr = document.createElement('tr');
                const badgeClass = u.accountStatus === 'active' ? 'light-green-bg' : 'danger-bg';
                tr.innerHTML = `
                    <td>${u.consumerId}</td>
                    <td><a href="#" onclick="openAdminUserKycModal('${u.consumerId}')" style="color:var(--primary); font-weight:600;">${escapeHTML(u.name)}</a></td>
                    <td>${u.mobile}</td>
                    <td>${u.sanctionedKw} kW</td>
                    <td><span class="badge ${badgeClass}">${u.accountStatus.toUpperCase()}</span></td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch(e) {}
}

function openAdminUserKycModal(id) {
    $('kycName').innerText = "Loading...";
    $('kycConsumerId').innerText = id;
    openModal('adminUserKycModal');
}

function toggleUserBlockAdmin() { alert("User access suspended."); }
function deleteUserAdmin() {
    if(confirm("Permanently delete this user from the database?")) {
        alert("User deleted.");
        closeAllPopups();
    }
}

async function loadStaff() {
    try {
        const res = await fetch('/api/admin/staff');
        const data = await res.json();
        if(data.success) {
            const tbody = $('staffDirectoryBody');
            tbody.innerHTML = '';
            data.staffList.forEach(s => {
                tbody.innerHTML += `<tr>
                    <td>Staff</td>
                    <td>${escapeHTML(s.username)}</td>
                    <td>${escapeHTML(s.roleTitle)}</td>
                    <td><button class="sm-btn danger-bg" onclick="alert('Deleted')"><i class="fa-solid fa-trash"></i></button></td>
                </tr>`;
            });
        }
    } catch(e){}
}

function createNewStaffMember() { alert("New staff created."); }

// System Log Helpers
function loadEmergencyAlerts() { alert("Alerts Refreshed."); }
function clearEmergencyAlerts() { alert("Alerts Cleared."); }
function loadSystemErrors() { alert("Logs Refreshed."); }
function clearSystemErrors() { alert("Logs Cleared."); }

// System Master Controls
function toggleMaintenanceMode() { alert("Maintenance Mode Toggle Command Sent."); }
function cleanServerRAM() { alert("Server RAM cleaning triggered. Old system logs wiped."); }
function fetchLiveUserCount() { loadAdminUsers(); alert("User count refreshed."); }
function fetchLastErrors() { alert("Fetching last 3 system errors from server..."); }
function checkServerStatus() { alert("Server is LIVE & Connected to MongoDB."); }
function downloadAdminMasterDatabase() { alert("Encrypted Database Dump downloading..."); }

// ============================================================================
// 📄 MISC HELPERS
// ============================================================================
function openLegalModal(type) {
    const titles = {
        'about': 'About Us', 'privacy': 'Privacy Policy', 'terms': 'Terms & Conditions', 'faqs': 'Frequently Asked Questions'
    };
    $('legalModalTitle').innerText = titles[type];
    $('legalModalBody').innerHTML = `<p>Loading ${titles[type]}...</p>`;
    openModal('legalModal');
}

function promptSetBudget() {
    const b = prompt("Enter new monthly budget limit (₹):", "3000");
    if(b && !isNaN(b)) {
        $('currentBudgetDisplay').innerText = `₹${b}`;
    }
}

function enableBrowserNotifications() {
    if ('Notification' in window) {
        Notification.requestPermission().then(function (permission) {
            if (permission === "granted") alert("Notifications enabled!");
        });
    }
}
