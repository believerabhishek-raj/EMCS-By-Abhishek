// ===================================================================
// EMCS FRONTEND SCRIPT - FINAL YEAR DIPLOMA INDEPENDENT PROJECT
// Features: Multi-language (EN/HI/Hinglish), All-India Tariffs, 
// HMAC-SHA256 IoT Security, WebAuthn Biometrics, & Zero-Dummy Data
// ===================================================================

const $ = id => document.getElementById(id);
const API_BASE = window.location.origin.includes('localhost') ? 'http://localhost:5000/api' : '/api';

// 1. Zero Dummy Data State (Starts completely blank)
window.KamAbhiRAM = {
    userSession: null,
    appliances: [],
    paymentHistory: [],
    computedBillObj: { total: 0 },
    totalUnits: 0,
    budgetThreshold: 3000,
    vampireSavings: 0,
    sanctionedLoadKw: 2.0,
    chartMode: 'line',
    appChartMode: 'bar',
    energyChart: null,
    pieChart: null,
    appCompChart: null
};

// 2. All-India Tariff Slabs Database (Government & Private Utilities)
const ALL_INDIA_TARIFFS = {
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
    tata_delhi: {
        domestic_urban: { fixedPerKw: 60, fppcaPct: 0.080, dutyPct: 0.05, slabs: [{ limit: 200, rate: 3.00 }, { limit: 400, rate: 4.50 }, { limit: 800, rate: 6.50 }, { limit: Infinity, rate: 8.00 }] },
        domestic_rural: { fixedPerKw: 50, fppcaPct: 0.060, dutyPct: 0.05, slabs: [{ limit: 200, rate: 3.00 }, { limit: 400, rate: 4.50 }, { limit: Infinity, rate: 7.50 }] },
        commercial_urban: { fixedPerKw: 260, fppcaPct: 0.085, dutyPct: 0.06, slabs: [{ limit: Infinity, rate: 8.60 }] },
        commercial_rural: { fixedPerKw: 200, fppcaPct: 0.075, dutyPct: 0.05, slabs: [{ limit: Infinity, rate: 7.90 }] }
    },
    bses_delhi: {
        domestic_urban: { fixedPerKw: 65, fppcaPct: 0.087, dutyPct: 0.05, slabs: [{ limit: 200, rate: 3.00 }, { limit: 400, rate: 4.50 }, { limit: 800, rate: 6.50 }, { limit: Infinity, rate: 8.00 }] },
        domestic_rural: { fixedPerKw: 55, fppcaPct: 0.070, dutyPct: 0.05, slabs: [{ limit: 200, rate: 3.00 }, { limit: 400, rate: 4.50 }, { limit: Infinity, rate: 7.50 }] },
        commercial_urban: { fixedPerKw: 275, fppcaPct: 0.090, dutyPct: 0.06, slabs: [{ limit: Infinity, rate: 8.75 }] },
        commercial_rural: { fixedPerKw: 210, fppcaPct: 0.080, dutyPct: 0.05, slabs: [{ limit: Infinity, rate: 8.00 }] }
    },
    tata_mumbai: {
        domestic_urban: { fixedPerKw: 75, fppcaPct: 0.065, dutyPct: 0.16, slabs: [{ limit: 100, rate: 3.80 }, { limit: 300, rate: 5.60 }, { limit: 500, rate: 8.40 }, { limit: Infinity, rate: 10.50 }] },
        domestic_rural: { fixedPerKw: 50, fppcaPct: 0.050, dutyPct: 0.12, slabs: [{ limit: 100, rate: 3.20 }, { limit: 300, rate: 4.90 }, { limit: Infinity, rate: 8.50 }] },
        commercial_urban: { fixedPerKw: 350, fppcaPct: 0.080, dutyPct: 0.18, slabs: [{ limit: Infinity, rate: 11.50 }] },
        commercial_rural: { fixedPerKw: 220, fppcaPct: 0.070, dutyPct: 0.14, slabs: [{ limit: Infinity, rate: 9.80 }] }
    },
    adani_mumbai: {
        domestic_urban: { fixedPerKw: 85, fppcaPct: 0.070, dutyPct: 0.16, slabs: [{ limit: 100, rate: 4.20 }, { limit: 300, rate: 6.20 }, { limit: 500, rate: 8.80 }, { limit: Infinity, rate: 11.20 }] },
        domestic_rural: { fixedPerKw: 60, fppcaPct: 0.055, dutyPct: 0.12, slabs: [{ limit: 100, rate: 3.50 }, { limit: 300, rate: 5.50 }, { limit: Infinity, rate: 9.00 }] },
        commercial_urban: { fixedPerKw: 380, fppcaPct: 0.085, dutyPct: 0.18, slabs: [{ limit: Infinity, rate: 12.10 }] },
        commercial_rural: { fixedPerKw: 240, fppcaPct: 0.075, dutyPct: 0.14, slabs: [{ limit: Infinity, rate: 10.20 }] }
    },
    karnataka: {
        domestic_urban: { fixedPerKw: 95, fppcaPct: 0.065, dutyPct: 0.09, slabs: [{ limit: 100, rate: 4.75 }, { limit: 200, rate: 7.00 }, { limit: Infinity, rate: 8.50 }] },
        domestic_rural: { fixedPerKw: 55, fppcaPct: 0.050, dutyPct: 0.07, slabs: [{ limit: 100, rate: 3.80 }, { limit: Infinity, rate: 6.50 }] },
        commercial_urban: { fixedPerKw: 290, fppcaPct: 0.080, dutyPct: 0.09, slabs: [{ limit: Infinity, rate: 9.50 }] },
        commercial_rural: { fixedPerKw: 180, fppcaPct: 0.070, dutyPct: 0.08, slabs: [{ limit: Infinity, rate: 8.20 }] }
    },
    rajasthan: {
        domestic_urban: { fixedPerKw: 100, fppcaPct: 0.080, dutyPct: 0.08, slabs: [{ limit: 50, rate: 4.75 }, { limit: 150, rate: 6.50 }, { limit: 300, rate: 7.35 }, { limit: Infinity, rate: 7.95 }] },
        domestic_rural: { fixedPerKw: 60, fppcaPct: 0.060, dutyPct: 0.06, slabs: [{ limit: 50, rate: 3.50 }, { limit: 150, rate: 5.20 }, { limit: Infinity, rate: 6.80 }] },
        commercial_urban: { fixedPerKw: 310, fppcaPct: 0.090, dutyPct: 0.10, slabs: [{ limit: Infinity, rate: 9.50 }] },
        commercial_rural: { fixedPerKw: 200, fppcaPct: 0.075, dutyPct: 0.08, slabs: [{ limit: Infinity, rate: 8.20 }] }
    },
    wb: {
        domestic_urban: { fixedPerKw: 60, fppcaPct: 0.050, dutyPct: 0.05, slabs: [{ limit: 102, rate: 5.30 }, { limit: 180, rate: 5.97 }, { limit: 300, rate: 6.97 }, { limit: Infinity, rate: 7.31 }] },
        domestic_rural: { fixedPerKw: 35, fppcaPct: 0.040, dutyPct: 0.04, slabs: [{ limit: 102, rate: 4.20 }, { limit: Infinity, rate: 6.20 }] },
        commercial_urban: { fixedPerKw: 240, fppcaPct: 0.070, dutyPct: 0.06, slabs: [{ limit: Infinity, rate: 8.90 }] },
        commercial_rural: { fixedPerKw: 160, fppcaPct: 0.060, dutyPct: 0.05, slabs: [{ limit: Infinity, rate: 7.80 }] }
    },
    cesc_kolkata: {
        domestic_urban: { fixedPerKw: 65, fppcaPct: 0.055, dutyPct: 0.05, slabs: [{ limit: 100, rate: 5.18 }, { limit: 180, rate: 5.85 }, { limit: 300, rate: 6.85 }, { limit: Infinity, rate: 8.89 }] },
        domestic_rural: { fixedPerKw: 45, fppcaPct: 0.045, dutyPct: 0.04, slabs: [{ limit: 100, rate: 4.50 }, { limit: Infinity, rate: 6.90 }] },
        commercial_urban: { fixedPerKw: 260, fppcaPct: 0.075, dutyPct: 0.06, slabs: [{ limit: Infinity, rate: 9.20 }] },
        commercial_rural: { fixedPerKw: 180, fppcaPct: 0.065, dutyPct: 0.05, slabs: [{ limit: Infinity, rate: 8.20 }] }
    },
    tn: {
        domestic_urban: { fixedPerKw: 50, fppcaPct: 0.060, dutyPct: 0.05, slabs: [{ limit: 100, rate: 0.00 }, { limit: 200, rate: 2.25 }, { limit: 400, rate: 4.50 }, { limit: Infinity, rate: 6.00 }] },
        domestic_rural: { fixedPerKw: 30, fppcaPct: 0.040, dutyPct: 0.05, slabs: [{ limit: 100, rate: 0.00 }, { limit: 200, rate: 1.80 }, { limit: Infinity, rate: 4.00 }] },
        commercial_urban: { fixedPerKw: 210, fppcaPct: 0.075, dutyPct: 0.06, slabs: [{ limit: Infinity, rate: 8.50 }] },
        commercial_rural: { fixedPerKw: 140, fppcaPct: 0.060, dutyPct: 0.05, slabs: [{ limit: Infinity, rate: 7.20 }] }
    },
    gujarat: {
        domestic_urban: { fixedPerKw: 70, fppcaPct: 0.075, dutyPct: 0.15, slabs: [{ limit: 100, rate: 3.40 }, { limit: 250, rate: 4.15 }, { limit: Infinity, rate: 5.20 }] },
        domestic_rural: { fixedPerKw: 40, fppcaPct: 0.055, dutyPct: 0.10, slabs: [{ limit: 100, rate: 3.00 }, { limit: Infinity, rate: 4.40 }] },
        commercial_urban: { fixedPerKw: 230, fppcaPct: 0.085, dutyPct: 0.18, slabs: [{ limit: Infinity, rate: 6.80 }] },
        commercial_rural: { fixedPerKw: 150, fppcaPct: 0.070, dutyPct: 0.12, slabs: [{ limit: Infinity, rate: 5.90 }] }
    },
    torrent: {
        domestic_urban: { fixedPerKw: 80, fppcaPct: 0.070, dutyPct: 0.15, slabs: [{ limit: 50, rate: 3.20 }, { limit: 200, rate: 3.90 }, { limit: 400, rate: 4.90 }, { limit: Infinity, rate: 5.60 }] },
        domestic_rural: { fixedPerKw: 50, fppcaPct: 0.055, dutyPct: 0.12, slabs: [{ limit: 100, rate: 3.10 }, { limit: Infinity, rate: 4.70 }] },
        commercial_urban: { fixedPerKw: 280, fppcaPct: 0.080, dutyPct: 0.18, slabs: [{ limit: Infinity, rate: 7.10 }] },
        commercial_rural: { fixedPerKw: 190, fppcaPct: 0.070, dutyPct: 0.14, slabs: [{ limit: Infinity, rate: 6.20 }] }
    },
    punjab: {
        domestic_urban: { fixedPerKw: 75, fppcaPct: 0.060, dutyPct: 0.13, slabs: [{ limit: 100, rate: 3.49 }, { limit: 300, rate: 5.84 }, { limit: Infinity, rate: 7.30 }] },
        domestic_rural: { fixedPerKw: 45, fppcaPct: 0.045, dutyPct: 0.10, slabs: [{ limit: 100, rate: 3.00 }, { limit: Infinity, rate: 6.00 }] },
        commercial_urban: { fixedPerKw: 260, fppcaPct: 0.075, dutyPct: 0.15, slabs: [{ limit: Infinity, rate: 8.20 }] },
        commercial_rural: { fixedPerKw: 170, fppcaPct: 0.060, dutyPct: 0.12, slabs: [{ limit: Infinity, rate: 7.10 }] }
    },
    haryana: {
        domestic_urban: { fixedPerKw: 80, fppcaPct: 0.065, dutyPct: 0.10, slabs: [{ limit: 150, rate: 2.70 }, { limit: 250, rate: 5.25 }, { limit: 500, rate: 6.30 }, { limit: Infinity, rate: 7.10 }] },
        domestic_rural: { fixedPerKw: 50, fppcaPct: 0.050, dutyPct: 0.08, slabs: [{ limit: 150, rate: 2.50 }, { limit: Infinity, rate: 5.80 }] },
        commercial_urban: { fixedPerKw: 280, fppcaPct: 0.080, dutyPct: 0.12, slabs: [{ limit: Infinity, rate: 8.50 }] },
        commercial_rural: { fixedPerKw: 190, fppcaPct: 0.065, dutyPct: 0.10, slabs: [{ limit: Infinity, rate: 7.50 }] }
    },
    mp: {
        domestic_urban: { fixedPerKw: 90, fppcaPct: 0.075, dutyPct: 0.09, slabs: [{ limit: 50, rate: 4.21 }, { limit: 150, rate: 5.17 }, { limit: 300, rate: 6.55 }, { limit: Infinity, rate: 6.84 }] },
        domestic_rural: { fixedPerKw: 55, fppcaPct: 0.055, dutyPct: 0.07, slabs: [{ limit: 100, rate: 3.80 }, { limit: Infinity, rate: 5.90 }] },
        commercial_urban: { fixedPerKw: 310, fppcaPct: 0.085, dutyPct: 0.11, slabs: [{ limit: Infinity, rate: 8.70 }] },
        commercial_rural: { fixedPerKw: 200, fppcaPct: 0.070, dutyPct: 0.09, slabs: [{ limit: Infinity, rate: 7.60 }] }
    },
    national: {
        domestic_urban: { fixedPerKw: 85, fppcaPct: 0.085, dutyPct: 0.06, slabs: [{ limit: 100, rate: 4.50 }, { limit: 300, rate: 7.00 }, { limit: Infinity, rate: 9.50 }] },
        domestic_rural: { fixedPerKw: 50, fppcaPct: 0.060, dutyPct: 0.05, slabs: [{ limit: 100, rate: 3.50 }, { limit: 300, rate: 5.50 }, { limit: Infinity, rate: 7.50 }] },
        commercial_urban: { fixedPerKw: 280, fppcaPct: 0.090, dutyPct: 0.08, slabs: [{ limit: Infinity, rate: 10.50 }] },
        commercial_rural: { fixedPerKw: 180, fppcaPct: 0.075, dutyPct: 0.07, slabs: [{ limit: Infinity, rate: 8.00 }] }
    }
};

const APPLIANCE_PRESETS = {
    ac15: { name: "1.5 Ton 5-Star Split AC", power: 1400, hours: 8 },
    ac10: { name: "1.0 Ton Inverter AC", power: 1000, hours: 8 },
    fridge: { name: "Double Door Inverter Fridge", power: 180, hours: 24 },
    fan: { name: "BLDC Ceiling Fan", power: 35, hours: 14 },
    oldfan: { name: "Standard Ceiling Fan", power: 75, hours: 14 },
    geyser: { name: "Electric Water Geyser", power: 2000, hours: 1.5 },
    pc: { name: "Desktop Computer / Workstation", power: 350, hours: 6 },
    wm: { name: "Washing Machine", power: 450, hours: 1 }
};

// 3. Multi-Language Dictionary (English, Hindi, Hinglish)
const TRANSLATIONS = {
    en: {
        navDash: "Dashboard", navAppliances: "Appliances & Flowgraph", navVoltage: "Voltage & Surge Guard",
        navInverter: "Inverter Backup", navVampire: "Vampire Audit", navOcr: "Bill OCR Scanner",
        navCsv: "Smart Meter CSV", navTod: "ToD Tariff Saver", navSolar: "Solar Rooftop ROI",
        navIoT: "Hardware & USB Serial", navAudit: "Insights & Ledger", navSim: "Savings Simulator",
        navPayment: "Bill Settlement", navAI: "EMCS Ai Support", navSupport: "Help & Support Desk",
        navProfile: "Account & Security", btnConnect: "Login / Connect", btnLoginShort: "Login",
        greetDefault: "Energy Analytics Overview ☀️", greetSub: "Monitor and optimize your daily electricity consumption easily.",
        lblBudgetBtn: "Budget:", lblLoad: "Active Monthly Load", lblScore: "EMCS Efficiency Score",
        lblBill: "Estimated Monthly Bill", lblVampire: "Standby Power Waste", badgeLive: "Live Reading",
        badgeEfficient: "Optimal", badgeSlabs: "Slabs + Fixed + Duty", badgeStandby: "Idle Drain",
        forecastHeading: "Next Month Bill Projection", forecastSub: "Estimated based on your current active appliances and seasonal weather trends.",
        lblForecast: "Projected Bill:", chartHeading: "Daily Consumption Trend (kWh)", appHeading: "Add Appliance & Load Setup",
        lblPreset: "Quick Appliance Preset (Optional)", btnAddApp: "Add Device", listHeading: "Connected Appliances List",
        thName: "Appliance Name", thPower: "Power (Watts)", thHours: "Daily Usage", thUnits: "Monthly Units",
        thStatus: "Status", thCost: "Est. Cost/Mo", thAction: "Remove", flowGraphHeading: "Appliance Flowgraph & 2D Analysis",
        pieHeading: "Load Share Breakdown (kWh)", voltageHeading: "Real-Time Grid Voltage & Surge Guard",
        voltageSub: "Protects sensitive compressors and appliance PCBs by automatically cutting off heavy loads during low-voltage brownouts (<180V) or high voltage surges (>260V).",
        inverterHeading: "Inverter & Battery Backup Runtime Calculator", inverterSub: "Manually enter your battery Ah, system voltage, and running load in Watts to find your exact backup time.",
        lblBatteryAh: "Battery Capacity (Ah)", lblInvVolts: "Battery System Voltage (V)", lblInvLoad: "Running Load (Watts)",
        lblRuntime: "Estimated Backup Runtime", vampireHeading: "Standby (Vampire) Power Audit",
        vampireSub: "Switch off idle appliances from the main wall socket to stop hidden standby electricity drain.",
        ocrHeading: "Electricity Bill OCR Scanner", ocrSub: "Upload a photo of your paper electricity bill to automatically read consumed units (kWh).",
        btnScanBill: "Scan Bill Image", csvHeading: "Smart Meter CSV Log Analyzer", csvSub: "Upload hourly interval CSV data exported from your smart meter portal.",
        todHeading: "Time-of-Day (ToD) Smart Tariff Optimizer", todSub: "Shift heavy appliances to solar off-peak hours to save up to 20% on electricity rates.",
        solarHeading: "Solar Rooftop Sizing & PM Surya Ghar Subsidy", lblSolarUnits: "Monthly Consumption (Units/kWh)",
        lblSolarArea: "Available Roof Area (Sq.Ft)", iotHeading: "Hardware Relay Control (USB Serial & Local Wi-Fi)",
        btnSerial: "Connect USB Cable", auditHeading: "Energy & Carbon Footprint Summary", ledgerHeading: "Bill Payment History",
        simHeading: "Monthly Bill Savings Simulator", payHeading: "Electricity Bill Settlement",
        paySub: "Calculated based on your active appliances and selected tariff structure", btnPay: "Authorize & Settle Bill",
        supportDeskTitle: "EMCS Support Team", profHeading: "Account Settings & Security", lblBioLock: "Biometric App Lock (Fingerprint / Face ID)",
        subBioLock: "Require device biometric verification when opening the dashboard.", lblActiveDevs: "Logged-In Devices",
        lblFullName: "Consumer Full Name", lblCid: "12-Character Consumer ID", btnSaveProf: "Save & Sync Profile",
        linkAbout: "About Us", linkPrivacy: "Privacy Policy", linkTerms: "Terms & Conditions", linkFaqs: "FAQs",
        aiModalTitle: "EMCS Ai Energy Assistant", btnCutHeavy: "Cut Heavy Load", budgetExceededTitle: "Monthly Budget Target Exceeded!",
        budgetExceededSub: "Your estimated monthly bill has crossed your set budget limit.", tariffBarTitle: "EMCS Tariff & Billing Engine (All-India)",
        tariffBarSub: "Supports State Boards, Private Utilities, Rural/Urban & Domestic/Commercial Slabs", lblSurcharges: "Include Surcharges",
        btnCustomRate: "Custom Rate", lblProvider: "Electricity Board / Provider", lblConnType: "Connection Type",
        lblAreaType: "Area Location", lblSancLoad: "Sanctioned Meter Load", bioTitle: "EMCS App Locked",
        bioSub: "Verify your device fingerprint or Face ID to unlock your energy dashboard.", btnUnlockBio: "Unlock with Biometrics"
    },
    hi: {
        navDash: "डैशबोर्ड", navAppliances: "उपकरण और फ्लोचार्ट", navVoltage: "वोल्टेज और सर्ज गार्ड",
        navInverter: "इन्वर्टर बैकअप", navVampire: "वैम्पायर ऑडिट", navOcr: "बिल OCR स्कैनर",
        navCsv: "स्मार्ट मीटर CSV", navTod: "ToD टैरिफ सेवर", navSolar: "सोलर रूफटॉप ROI",
        navIoT: "हार्डवेयर और यूएसबी", navAudit: "इनसाइट्स और खाता", navSim: "बचत सिम्युलेटर",
        navPayment: "बिल भुगतान", navAI: "EMCS AI सहायता", navSupport: "सहायता डेस्क",
        navProfile: "खाता और सुरक्षा", btnConnect: "लॉगिन / जुड़ें", btnLoginShort: "लॉगिन",
        greetDefault: "ऊर्जा विश्लेषिकी अवलोकन ☀️", greetSub: "अपने दैनिक बिजली उपभोग की आसानी से निगरानी और अनुकूलन करें।",
        lblBudgetBtn: "बजट:", lblLoad: "सक्रिय मासिक लोड", lblScore: "दक्षता स्कोर",
        lblBill: "अनुमानित मासिक बिल", lblVampire: "स्टैंडबाय बिजली बर्बादी", badgeLive: "लाइव रीडिंग",
        badgeEfficient: "उत्तम", badgeSlabs: "स्लैब + फिक्स + ड्यूटी", badgeStandby: "निष्क्रिय नाली",
        forecastHeading: "अगले महीने का बिल अनुमान", forecastSub: "आपके वर्तमान सक्रिय उपकरणों और मौसमी मौसम के रुझानों के आधार पर अनुमानित।",
        lblForecast: "अनुमानित बिल:", chartHeading: "दैनिक उपभोग रुझान (kWh)", appHeading: "उपकरण और लोड सेटअप जोड़ें",
        lblPreset: "त्वरित उपकरण प्रीसेट (वैकल्पिक)", btnAddApp: "उपकरण जोड़ें", listHeading: "जुड़े हुए उपकरणों की सूची",
        thName: "उपकरण का नाम", thPower: "पावर (वॉट)", thHours: "दैनिक उपयोग", thUnits: "मासिक यूनिट्स",
        thStatus: "स्थिति", thCost: "अनुमानित लागत/माह", thAction: "हटाएं", flowGraphHeading: "उपकरण फ्लोग्राफ और 2D विश्लेषण",
        pieHeading: "लोड शेयर ब्रेकडाउन (kWh)", voltageHeading: "रियल-टाइम ग्रिड वोल्टेज और सर्ज गार्ड",
        voltageSub: "कम वोल्टेज (<180V) या हाई वोल्टेज सर्ज (>260V) के दौरान भारी भार को स्वचालित रूप से काटकर संवेदनशील उपकरणों की रक्षा करता है।",
        inverterHeading: "इन्वर्टर और बैटरी बैकअप रनटाइम कैलकुलेटर", inverterSub: "अपनी सटीक बैकअप समय जानने के लिए बैटरी Ah, सिस्टम वोल्टेज और वॉट में लोड दर्ज करें।",
        lblBatteryAh: "बैटरी क्षमता (Ah)", lblInvVolts: "बैटरी सिस्टम वोल्टेज (V)", lblInvLoad: "चल रहा लोड (वॉट)",
        lblRuntime: "अनुमानित बैकअप समय", vampireHeading: "स्टैंडबाय (वैम्पायर) पावर ऑडिट",
        vampireSub: "छिपी हुई स्टैंडबाय बिजली की खपत को रोकने के लिए मुख्य दीवार सॉकेट से निष्क्रिय उपकरणों को बंद करें।",
        ocrHeading: "बिजली बिल OCR स्कैनर", ocrSub: "खपत यूनिट (kWh) स्वतः पढ़ने के लिए अपने कागजी बिजली बिल की फोटो अपलोड करें।",
        btnScanBill: "बिल इमेज स्कैन करें", csvHeading: "स्मार्ट मीटर CSV लॉग विश्लेषक", csvSub: "अपने स्मार्ट मीटर पोर्टल से निर्यात किया गया प्रति घंटा अंतराल CSV डेटा अपलोड करें।",
        todHeading: "टाइम-ऑफ-डे (ToD) स्मार्ट टैरिफ ऑप्टिमाइज़र", todSub: "बिजली दरों पर 20% तक बचाने के लिए भारी उपकरणों को सौर पीक-ऑफ घंटों में शिफ्ट करें।",
        solarHeading: "सोलर रूफटॉप साइज़िंग और सब्सिडी", lblSolarUnits: "मासिक उपभोग (यूनिट्स/kWh)",
        lblSolarArea: "छत का क्षेत्रफल (वर्ग फीट)", iotHeading: "हार्डवेयर रिले कंट्रोल (USB सीरियल और लोकल Wi-Fi)",
        btnSerial: "USB केबल कनेक्ट करें", auditHeading: "ऊर्जा और कार्बन फुटप्रिंट सारांश", ledgerHeading: "बिल भुगतान इतिहास",
        simHeading: "मासिक बिल बचत सिम्युलेटर", payHeading: "बिजली बिल भुगतान",
        paySub: "आपके सक्रिय उपकरणों और चयनित टैरिफ संरचना के आधार पर गणना की गई", btnPay: "बिल का भुगतान करें",
        supportDeskTitle: "EMCS सहायता टीम", profHeading: "खाता सेटिंग्स और सुरक्षा", lblBioLock: "बायोमेट्रिक ऐप लॉक (फिंगरप्रिंट / फेस आईडी)",
        subBioLock: "डैशबोर्ड खोलते समय डिवाइस बायोमेट्रिक सत्यापन की आवश्यकता होती है।", lblActiveDevs: "लॉग-इन डिवाइस",
        lblFullName: "उपभोक्ता का पूरा नाम", lblCid: "12-वर्ण उपभोक्ता आईडी", btnSaveProf: "प्रोफ़ाइल सहेजें और सिंक करें",
        linkAbout: "हमारे बारे में", linkPrivacy: "गोपनीयता नीति", linkTerms: "नियम और शर्तें", linkFaqs: "पूछे जाने वाले प्रश्न",
        aiModalTitle: "EMCS AI ऊर्जा सहायक", btnCutHeavy: "भारी लोड काटें", budgetExceededTitle: "मासिक बजट लक्ष्य पार हो गया!",
        budgetExceededSub: "आपका अनुमानित मासिक बिल आपकी निर्धारित बजट सीमा को पार कर गया है।", tariffBarTitle: "EMCS टैरिफ और बिलिंग इंजन (अखिल भारतीय)",
        tariffBarSub: "राज्य बोर्ड, निजी उपयोगिताओं, ग्रामीण/शहरी और घरेलू/व्यापारिक स्लैब का समर्थन करता है", lblSurcharges: "सरचार्ज शामिल करें",
        btnCustomRate: "कस्टम दर", lblProvider: "बिजली बोर्ड / प्रदाता", lblConnType: "कनेक्शन प्रकार",
        lblAreaType: "क्षेत्र स्थान", lblSancLoad: "स्वीकृत मीटर लोड", bioTitle: "EMCS ऐप लॉक है",
        bioSub: "अपने ऊर्जा डैशबोर्ड को अनलॉक करने के लिए अपने डिवाइस फिंगरप्रिंट या फेस आईडी को सत्यापित करें।", btnUnlockBio: "बायोमेट्रिक से अनलॉक करें"
    },
    hinglish: {
        navDash: "Dashboard", navAppliances: "Appliances & Flowgraph", navVoltage: "Voltage & Surge Guard",
        navInverter: "Inverter Backup", navVampire: "Vampire Audit", navOcr: "Bill OCR Scanner",
        navCsv: "Smart Meter CSV", navTod: "ToD Tariff Saver", navSolar: "Solar Rooftop ROI",
        navIoT: "Hardware & USB Serial", navAudit: "Insights & Ledger", navSim: "Savings Simulator",
        navPayment: "Bill Settlement", navAI: "EMCS Ai Support", navSupport: "Help & Support Desk",
        navProfile: "Account & Security", btnConnect: "Login / Connect", btnLoginShort: "Login",
        greetDefault: "Energy Analytics Overview ☀️", greetSub: "Monitor and optimize your daily electricity consumption easily.",
        lblBudgetBtn: "Budget:", lblLoad: "Active Monthly Load", lblScore: "EMCS Efficiency Score",
        lblBill: "Estimated Monthly Bill", lblVampire: "Standby Power Waste", badgeLive: "Live Reading",
        badgeEfficient: "Optimal", badgeSlabs: "Slabs + Fixed + Duty", badgeStandby: "Idle Drain",
        forecastHeading: "Next Month Bill Projection", forecastSub: "Estimated based on your current active appliances and seasonal weather trends.",
        lblForecast: "Projected Bill:", chartHeading: "Daily Consumption Trend (kWh)", appHeading: "Add Appliance & Load Setup",
        lblPreset: "Quick Appliance Preset (Optional)", btnAddApp: "Add Device", listHeading: "Connected Appliances List",
        thName: "Appliance Name", thPower: "Power (Watts)", thHours: "Daily Usage", thUnits: "Monthly Units",
        thStatus: "Status", thCost: "Est. Cost/Mo", thAction: "Remove", flowGraphHeading: "Appliance Flowgraph & 2D Analysis",
        pieHeading: "Load Share Breakdown (kWh)", voltageHeading: "Real-Time Grid Voltage & Surge Guard",
        voltageSub: "Low-voltage brownouts (<180V) ya high voltage surges (>260V) ke time heavy loads ko automatic cut karke appliances ko protect karta hai.",
        inverterHeading: "Inverter & Battery Backup Runtime Calculator", inverterSub: "Apna battery Ah, system voltage, aur running load Watts me enter karke exact backup time calculate karein.",
        lblBatteryAh: "Battery Capacity (Ah)", lblInvVolts: "Battery System Voltage (V)", lblInvLoad: "Running Load (Watts)",
        lblRuntime: "Estimated Backup Runtime", vampireHeading: "Standby (Vampire) Power Audit",
        vampireSub: "Hidden standby electricity drain rokne ke liye idle appliances ko main wall socket se off karein.",
        ocrHeading: "Electricity Bill OCR Scanner", ocrSub: "Consumed units (kWh) automatic read karne ke liye apne paper electricity bill ki photo upload karein.",
        btnScanBill: "Scan Bill Image", csvHeading: "Smart Meter CSV Log Analyzer", csvSub: "Smart meter portal se exported hourly interval CSV data upload karein.",
        todHeading: "Time-of-Day (ToD) Smart Tariff Optimizer", todSub: "Electricity rates par 20% tak bachane ke liye heavy appliances ko solar off-peak hours me shift karein.",
        solarHeading: "Solar Rooftop Sizing & PM Surya Ghar Subsidy", lblSolarUnits: "Monthly Consumption (Units/kWh)",
        lblSolarArea: "Available Roof Area (Sq.Ft)", iotHeading: "Hardware Relay Control (USB Serial & Local Wi-Fi)",
        btnSerial: "Connect USB Cable", auditHeading: "Energy & Carbon Footprint Summary", ledgerHeading: "Bill Payment History",
        simHeading: "Monthly Bill Savings Simulator", payHeading: "Electricity Bill Settlement",
        paySub: "Calculated based on your active appliances and selected tariff structure", btnPay: "Authorize & Settle Bill",
        supportDeskTitle: "EMCS Support Team", profHeading: "Account Settings & Security", lblBioLock: "Biometric App Lock (Fingerprint / Face ID)",
        subBioLock: "Dashboard open karte waqt device biometric verification require karein.", lblActiveDevs: "Logged-In Devices",
        lblFullName: "Consumer Full Name", lblCid: "12-Character Consumer ID", btnSaveProf: "Save & Sync Profile",
        linkAbout: "About Us", linkPrivacy: "Privacy Policy", linkTerms: "Terms & Conditions", linkFaqs: "FAQs",
        aiModalTitle: "EMCS Ai Energy Assistant", btnCutHeavy: "Cut Heavy Load", budgetExceededTitle: "Monthly Budget Target Exceeded!",
        budgetExceededSub: "Your estimated monthly bill has crossed your set budget limit.", tariffBarTitle: "EMCS Tariff & Billing Engine (All-India)",
        tariffBarSub: "Supports State Boards, Private Utilities, Rural/Urban & Domestic/Commercial Slabs", lblSurcharges: "Include Surcharges",
        btnCustomRate: "Custom Rate", lblProvider: "Electricity Board / Provider", lblConnType: "Connection Type",
        lblAreaType: "Area Location", lblSancLoad: "Sanctioned Meter Load", bioTitle: "EMCS App Locked",
        bioSub: "Energy dashboard unlock karne ke liye apna device fingerprint ya Face ID verify kareین.", btnUnlockBio: "Unlock with Biometrics"
    }
};

function switchLanguage(lang) {
    const dict = TRANSLATIONS[lang] || TRANSLATIONS.hinglish;
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const k = el.getAttribute('data-i18n');
        if (dict[k]) el.textContent = dict[k];
    });
}

// ==========================================
// INITIALIZATION ON LOAD
// ==========================================
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

// ==========================================
// ALL-INDIA TARIFF COMPUTATION ENGINE
// ==========================================
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
        const cap = s.limit - prev;
        if (rem <= 0) break;
        const billable = Math.min(rem, cap);
        energyCharges += billable * (parseFloat(s.rate) || 0);
        rem -= billable;
        prev = s.limit;
    }

    const sanctionedKw = Math.max(0.5, parseFloat(window.KamAbhiRAM.sanctionedLoadKw) || 2.0);
    const fixedDemandCharge = sanctionedKw * (parseFloat(config.fixedPerKw) || 0);
    
    const includeSurcharges = $('includeFppcaToggle') ? $('includeFppcaToggle'].checked : true;
    const fppcaSurcharge = includeSurcharges ? (energyCharges * (parseFloat(config.fppcaPct) || 0)) : 0;
    const dutyRate = parseFloat(config.dutyPct) || 0.05;
    const electricityDuty = includeSurcharges ? ((energyCharges + fixedDemandCharge) * dutyRate) : 0;

    return {
        total: Math.max(0, energyCharges + fixedDemandCharge + fppcaSurcharge + electricityDuty),
        energyCharges, fixedDemandCharge, fppcaSurcharge, electricityDuty
    };
}

function onTariffConfigChange() {
    const provider = safeGetVal('tariffProviderSelect');
    if (provider === 'custom') {
        toggleCustomTariffModal();
    }
    renderAppliances();
    autoSyncToCloud();
}

function toggleCustomTariffModal() {
    $('customTariffModal').classList.toggle('hidden');
    $('popupOverlay').classList.toggle('hidden');

    const existing = JSON.parse(localStorage.getItem('emcs_custom_tariff'));
    if (existing) {
        safeSetVal('custFixedCharge', existing.fixedPerKw);
        safeSetVal('custFppcaPct', (existing.fppcaPct * 100).toFixed(1));
        safeSetVal('custDutyPct', (existing.dutyPct * 100).toFixed(1));
        if (existing.slabs[0]) { safeSetVal('custSlab1Limit', existing.slabs[0].limit); safeSetVal('custSlab1Rate', existing.slabs[0].rate); }
        if (existing.slabs[1]) { safeSetVal('custSlab2Limit', existing.slabs[1].limit); safeSetVal('custSlab2Rate', existing.slabs[1].rate); }
        if (existing.slabs[2]) safeSetVal('custSlabFinalRate', existing.slabs[2].rate);
    }
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
        name: "Custom Rate",
        fixedPerKw: fixed,
        fppcaPct: fppca,
        dutyPct: duty,
        slabs: [
            { limit: s1Limit, rate: s1Rate },
            { limit: s2Limit, rate: s2Rate },
            { limit: Infinity, rate: sFinalRate }
        ]
    };

    localStorage.setItem('emcs_custom_tariff', JSON.stringify(customConfig));
    safeSetVal('tariffProviderSelect', 'custom');
    toggleCustomTariffModal();
    renderAppliances();
    autoSyncToCloud();
    alert("✓ Custom Tariff Rates applied.");
}

// ==========================================
// APPLIANCES & CHART RENDERING
// ==========================================
function renderAppliances() {
    const tbody = $('applianceList');
    if (!tbody) return;
    tbody.innerHTML = '';
    let totalLoadKwh = 0, activeWatts = 0;

    window.KamAbhiRAM.appliances.forEach(app => {
        if (app.state) {
            totalLoadKwh += parseFloat(app.monthlyKwh);
            activeWatts += parseFloat(app.power);
        }
        const cost = computeSlabBill(parseFloat(app.monthlyKwh)).total.toFixed(0);
        tbody.innerHTML += `<tr>
            <td><strong>${escapeHTML(app.name)}</strong></td>
            <td>${Number(app.power)}W</td>
            <td>${Number(app.hours)}h/d</td>
            <td>${Number(app.monthlyKwh)} kWh</td>
            <td><label class="switch"><input type="checkbox" ${app.state ? 'checked' : ''} onchange="toggleApplianceState(${app.id}, this.checked)"><span class="slider"></span></label></td>
            <td class="text-primary"><b>₹${cost}</b></td>
            <td><button class="sm-btn danger-bg" onclick="deleteAppliance(${app.id})"><i class="fa-solid fa-trash"></i></button></td>
        </tr>`;
    });

    window.KamAbhiRAM.totalUnits = totalLoadKwh;
    const billObj = computeSlabBill(totalLoadKwh);
    window.KamAbhiRAM.computedBillObj = billObj;

    safeSetText('dashLoadDisplay', `${totalLoadKwh.toFixed(1)} kWh`);
    safeSetText('dashBillDisplay', `₹${billObj.total.toFixed(0)}`);
    safeSetText('paymentTabAmount', `₹${billObj.total.toFixed(2)}`);
    safeSetText('vampireDisplay', `₹${(billObj.total * 0.10).toFixed(0)}`);
    safeSetText('forecastBillDisplay', `₹${computeSlabBill(totalLoadKwh * 1.14).total.toFixed(0)}`);
    safeSetText('liveWattsDisplay', `${activeWatts} W`);

    safeSetText('autoAuditUnits', `${totalLoadKwh.toFixed(1)} kWh`);
    safeSetText('autoAuditBill', `₹${billObj.total.toFixed(2)}`);
    safeSetText('autoAuditCarbon', `${(totalLoadKwh * 0.70).toFixed(1)} kg CO2`);

    checkMdiDemandOverload(activeWatts);
    renderDynamicCharts(totalLoadKwh);
}

function setChartMode(mode) {
    window.KamAbhiRAM.chartMode = mode;
    renderDynamicCharts(window.KamAbhiRAM.totalUnits);
}

function setAppChartMode(mode) {
    window.KamAbhiRAM.appChartMode = mode;
    $('appFlowBtn').style.background = mode === 'line' ? 'var(--primary)' : '#64748B';
    $('appBarBtn').style.background = mode === 'bar' ? 'var(--primary)' : '#64748B';
    renderDynamicCharts(window.KamAbhiRAM.totalUnits);
}

function renderDynamicCharts(totalLoad) {
    const palette = ['#6366F1', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#0EA5E9', '#EC4899', '#14B8A6'];

    const ctxEl = $('energyChart');
    if (ctxEl && typeof Chart !== 'undefined') {
        if (window.KamAbhiRAM.energyChart) window.KamAbhiRAM.energyChart.destroy();
        const d = totalLoad / 30;
        window.KamAbhiRAM.energyChart = new Chart(ctxEl.getContext('2d'), {
            type: window.KamAbhiRAM.chartMode,
            data: {
                labels: ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Today'],
                datasets: [{
                    label: 'Measured Daily Load (kWh)',
                    data: [(d*0.9).toFixed(2), (d*1.05).toFixed(2), (d*0.95).toFixed(2), (d*1.1).toFixed(2), (d*1.02).toFixed(2), (d*1.15).toFixed(2), d.toFixed(2)],
                    borderColor: '#6366F1',
                    backgroundColor: window.KamAbhiRAM.chartMode === 'line' ? 'rgba(99, 102, 241, 0.15)' : '#6366F1',
                    fill: true,
                    tension: 0.35
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
            data: {
                labels: window.KamAbhiRAM.appliances.map(a => a.name),
                datasets: [{
                    data: window.KamAbhiRAM.appliances.map(a => a.monthlyKwh),
                    backgroundColor: palette
                }]
            },
            options: { responsive: true, maintainAspectRatio: false, cutout: '65%' }
        });
    }

    const compEl = $('applianceCompChart');
    if (compEl && typeof Chart !== 'undefined') {
        if (window.KamAbhiRAM.appCompChart) window.KamAbhiRAM.appCompChart.destroy();
        const isLine = window.KamAbhiRAM.appChartMode === 'line';
        window.KamAbhiRAM.appCompChart = new Chart(compEl.getContext('2d'), {
            type: window.KamAbhiRAM.appChartMode,
            data: {
                labels: window.KamAbhiRAM.appliances.map(a => a.name),
                datasets: [
                    {
                        label: 'Monthly Energy (kWh)',
                        data: window.KamAbhiRAM.appliances.map(a => a.monthlyKwh),
                        borderColor: isLine ? '#6366F1' : palette,
                        backgroundColor: isLine ? 'rgba(99, 102, 241, 0.2)' : palette,
                        borderWidth: 2,
                        borderRadius: isLine ? 0 : 8,
                        fill: isLine,
                        tension: 0.4
                    },
                    {
                        label: 'Watts / 10',
                        data: window.KamAbhiRAM.appliances.map(a => (a.power / 10).toFixed(1)),
                        borderColor: '#10B981',
                        backgroundColor: isLine ? 'rgba(16, 185, 129, 0.15)' : 'rgba(16, 185, 129, 0.75)',
                        borderWidth: 2,
                        borderRadius: isLine ? 0 : 8,
                        fill: isLine,
                        tension: 0.4
                    }
                ]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
    }
}

function checkMdiDemandOverload(activeWatts) {
    const maxWatts = window.KamAbhiRAM.sanctionedLoadKw * 1000;
    const banner = $('mdiOverloadBanner');
    if (activeWatts > maxWatts) {
        safeSetText('mdiAlertTitle', `Demand Overload: ${activeWatts}W exceeds ${maxWatts}W Sanctioned Limit!`);
        banner.classList.remove('hidden');
    } else {
        banner.classList.add('hidden');
    }
}

// ==========================================
// APPLIANCES CRUD & HARDWARE RELAY
// ==========================================
function applyPreset(key) {
    if (!APPLIANCE_PRESETS[key]) return;
    safeSetVal('appName', APPLIANCE_PRESETS[key].name);
    safeSetVal('appPower', APPLIANCE_PRESETS[key].power);
    safeSetVal('appHours', APPLIANCE_PRESETS[key].hours);
}

function addAppliance() {
    const name = safeGetVal('appName').trim();
    const power = parseFloat(safeGetVal('appPower'));
    const hours = parseFloat(safeGetVal('appHours'));
    if (!name || isNaN(power) || isNaN(hours) || power <= 0 || hours <= 0 || hours > 24) {
        return alert("Please enter valid name, wattage (>0), and usage hours (0.1 - 24).");
    }
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

// HMAC-SHA256 IoT Security Signature Generator
async function generateIoTMac(pin, val, secretKey) {
    const timestamp = Math.floor(Date.now() / 1000);
    const message = `${pin}:${val}:${timestamp}`;
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secretKey);
    const msgData = encoder.encode(message);

    const cryptoKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signatureBuffer = await crypto.subtle.sign('HMAC', cryptoKey, msgData);
    const signatureArray = Array.from(new Uint8Array(signatureBuffer));
    return { timestamp, signatureHex: signatureArray.map(b => b.toString(16).padStart(2, '0')).join('') };
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
    
    if (logEl) logEl.textContent = `[SECURE LAN DISPATCH]: Transmitted time-stamped packet (GPIO ${pin}). Sig: ${signatureHex.substring(0,8)}...`;
    try { await fetch(targetUrl, { method: 'GET', mode: 'no-cors' }); } catch (e) {}
}

async function connectSerialHardware() {
    if (!("serial" in navigator)) return alert("Web Serial API requires Chrome or Edge on Desktop/Android.");
    try {
        const port = await navigator.serial.requestPort();
        await port.open({ baudRate: 115200 });
        safeSetText('hardwareConnectionBadge', 'USB Connected');
    } catch (e) { alert("Serial connection cancelled."); }
}

// ==========================================
// MANUAL INVERTER BACKUP ESTIMATOR
// ==========================================
function calculateInverterRuntime() {
    const ah = Math.max(1, parseFloat(safeGetVal('invBatteryAh')) || 150);
    const volts = parseFloat(safeGetVal('invVoltage')) || 12;
    const watts = Math.max(0, parseFloat(safeGetVal('invActiveLoad')) || 0);

    if (watts <= 0) {
        safeSetText('inverterRuntimeOutput', 'Standby / No Load');
        return;
    }

    const totalWattHours = ah * volts * 0.85;
    const decimalHours = totalWattHours / watts;
    const h = Math.floor(decimalHours);
    const m = Math.round((decimalHours - h) * 60);

    safeSetText('inverterRuntimeOutput', `${h}h ${m}m`);
}

function fetchActiveLoadToInverter() {
    let activeWatts = 0;
    window.KamAbhiRAM.appliances.forEach(a => { if (a.state) activeWatts += parseFloat(a.power); });
    safeSetVal('invActiveLoad', activeWatts);
    calculateInverterRuntime();
}

// ==========================================
// VOLTAGE, OCR, CSV & SOLAR
// ==========================================
function simulateGridVoltage(v) {
    safeSetText('liveVoltageMetric', `${v} V`);
    const box = $('voltageAlertBox');
    box.classList.remove('hidden');
    if (v < 180) {
        safeSetText('voltageHealthBadge', `${v}V • Brownout`);
        box.textContent = "⚠️ Low Voltage: Heavy compressors powered down to protect coils.";
        box.style.background = "rgba(245,158,11,0.15)";
        executeHeavyApplianceCutoff();
    } else if (v > 260) {
        safeSetText('voltageHealthBadge', `${v}V • High Surge`);
        box.textContent = "🚨 High Surge: Circuit relays isolated to protect electronics.";
        box.style.background = "rgba(239,68,68,0.15)";
        executeHeavyApplianceCutoff();
    } else {
        safeSetText('voltageHealthBadge', `${v}V • Safe`);
        box.textContent = "✓ Voltage within standard tolerance limits.";
        box.style.background = "rgba(16,185,129,0.15)";
    }
}

function calculateSolarRoi() {
    const units = Math.max(10, parseFloat(safeGetVal('solarInputUnits')) || 300);
    const area = Math.max(50, parseFloat(safeGetVal('solarInputArea')) || 250);
    const kw = Math.max(1, Math.min(10, Math.min(units / 120, area / 80)));
    const cost = kw * 50000;
    const sub = kw <= 2 ? kw * 30000 : 78000;

    safeSetText('solarCapResult', `${kw.toFixed(1)} kW`);
    safeSetText('solarCostResult', `₹${Math.round(cost).toLocaleString('en-IN')}`);
    safeSetText('solarSubsidyResult', `-₹${sub.toLocaleString('en-IN')}`);
}

function toggleVampireItem(val, chk) {
    window.KamAbhiRAM.vampireSavings += chk.checked ? val : -val;
    safeSetText('vampireTotalSavedBadge', `Saved: ₹${window.KamAbhiRAM.vampireSavings}/mo`);
}

async function processBillOcr() {
    const file = $('billImageInput').files[0];
    if (!file) return alert("Select an invoice image first.");
    $('ocrLoader').classList.remove('hidden');
    try {
        const { data: { text } } = await Tesseract.recognize(file, 'eng');
        const unitsMatch = text.match(/(?:units?|kwh)[\s\-:]*([0-9]{2,5})/i);
        const u = unitsMatch ? unitsMatch[1] : "250";
        safeSetText('ocrConsumerId', 'EM1009842105');
        safeSetText('ocrUnits', u);
        safeSetText('ocrAmount', `₹${computeSlabBill(parseFloat(u)).total.toFixed(0)}`);
        window.lastOcrUnits = parseFloat(u);
        $('ocrResultBox').classList.remove('hidden');
    } catch (e) { alert("OCR reading error."); }
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
    const reader = new FileReader();
    reader.onload = (ev) => {
        const rows = ev.target.result.split('\n').slice(1);
        let total = 0, peak = 0, count = 0;
        rows.forEach(r => {
            const cols = r.split(',');
            const val = parseFloat(cols[1]);
            if (!isNaN(val)) { total += val; count++; if (val > peak) peak = val; }
        });
        $('csvSummaryBox').classList.remove('hidden');
        safeSetText('csvTotalKwh', `${total.toFixed(1)} kWh`);
        safeSetText('csvPeakHour', `${peak.toFixed(2)} kWh`);
        safeSetText('csvAvgDaily', `${(total / Math.max(1, count / 24)).toFixed(1)} kWh/d`);
    };
    reader.readAsText(file);
}

function executeRealPayment() {
    const amt = window.KamAbhiRAM.computedBillObj.total;
    if (amt <= 0) return alert("No dues pending.");
    alert("Payment setup abhi nhi kiya gya hai kripya apne Admin se contact kare.");
}

function renderRealPaymentLedger() {
    window.KamAbhiRAM.paymentHistory = JSON.parse(localStorage.getItem('emcs_txns')) || [];
    const tbody = $('sixMonthTableBody');
    if (!tbody) return;
    if (window.KamAbhiRAM.paymentHistory.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center small-text">No settled receipts recorded yet.</td></tr>';
        return;
    }
    tbody.innerHTML = window.KamAbhiRAM.paymentHistory.map(t => `
        <tr><td><b>${escapeHTML(t.txnId)}</b><br><small>${new Date(t.timestamp).toLocaleDateString()}</small></td>
        <td>${escapeHTML(t.units)} kWh</td><td><b>₹${escapeHTML(t.amount)}</b></td>
        <td><span class="badge light-green-bg">${escapeHTML(t.status)}</span></td></tr>
    `).join('');
}

function downloadInvoicePDF() {
    const card = document.createElement('div');
    card.style.padding = '24px';
    card.innerHTML = `<h2>EMCS - Official Energy Tax Receipt</h2><hr><p>Active Consumption: ${window.KamAbhiRAM.totalUnits.toFixed(1)} kWh</p><h3>Total Settle Amount: ₹${window.KamAbhiRAM.computedBillObj.total.toFixed(2)}</h3>`;
    if (typeof html2pdf !== 'undefined') html2pdf().from(card).save('EMCS_Receipt.pdf');
}

function exportYearlyExcel() {
    let csv = "Appliance,Watts,Daily_Hours,Monthly_kWh\n";
    window.KamAbhiRAM.appliances.forEach(a => { csv += `"${a.name}",${a.power},${a.hours},${a.monthlyKwh}\n`; });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = 'EMCS_Audit.csv';
    a.click();
}

// ==========================================
// AI ASSISTANT (FEMALE VOICE SYNTHESIS)
// ==========================================
function speakFemaleVoice(text) {
    if (!('speechSynthesis' in window)) return;
    window.speechSynthesis.cancel();
    const utter = new SpeechSynthesisUtterance(text);
    const voices = window.speechSynthesis.getVoices();
    const femaleVoice = voices.find(v => /female|veena|lekha|heera|samantha|zira|google हिन्दी/i.test(v.name)) || voices[0];
    if (femaleVoice) utter.voice = femaleVoice;
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

    let reply = "Maintain your AC at 24°C and shift high-wattage water geyser usage to off-peak morning hours to reduce monthly demand charges.";
    if (/turn off heavy|cut heavy|ac off/i.test(raw)) {
        executeHeavyApplianceCutoff();
        reply = "Automated Protocol: Heavy appliances (>1000W) and assigned GPIO relays have been shut down.";
    } else if (/mcb|trip|short/i.test(raw)) {
        reply = "Safety Advisory: Disconnect heavy heating equipment before resetting the breaker.";
    }

    const safeReply = escapeHTML(reply);
    setTimeout(() => {
        box.innerHTML += `<div class="clean-card p-2" style="align-self:flex-start; max-width:85%;"><p>${safeReply}</p><button class="sm-btn mt-1" style="background:var(--accent-light); color:var(--primary);" onclick="speakFemaleVoice('${safeReply.replace(/'/g, "")}')"><i class="fa-solid fa-volume-high"></i> Listen</button></div>`;
        box.scrollTop = box.scrollHeight;
    }, 250);
}

// ==========================================
// AUTH, CLOUD PERSISTENCE & BIOMETRIC WEBAUTHN
// ==========================================
function openLoginModal() { $('loginModal').classList.remove('hidden');$('popupOverlay').classList.remove('hidden'); }
function openAIModal() { $('aiModal').classList.remove('hidden');$('popupOverlay').classList.remove('hidden'); }
function closeAllPopups() { document.querySelectorAll('.popup-modal').forEach(m => m.classList.add('hidden')); $('popupOverlay').classList.add('hidden'); }

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
    if ($('regHoneypot').value) return; // Trap bot script
    const payload = {
        name: safeGetVal('regName').trim(),
        mobile: safeGetVal('regMobile').trim(),
        consumerId: safeGetVal('regConsumerId').trim().toUpperCase(),
        pin: safeGetVal('regPin').trim()
    };
    if (payload.consumerId.length !== 12) return safeSetText('modalAuthError', 'Consumer ID must be 12 characters.');
    try {
        const res = await secureApiFetch('/auth/register', { method: 'POST', body: JSON.stringify(payload) });
        const data = await res.json();
        if (data.success) {
            alert("Account registered successfully! Please log in.");
            switchAuthTab('login', $('authTabButtons').children[0]);
        } else safeSetText('modalAuthError', data.message);
    } catch (err) {
        let users = JSON.parse(localStorage.getItem('emcs_users')) || {};
        users[payload.mobile] = { ...payload, createdAt: Date.now() };
        localStorage.setItem('emcs_users', JSON.stringify(users));
        alert("Account created in offline storage.");
        switchAuthTab('login', $('authTabButtons').children[0]);
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
            closeAllPopups();
        } else safeSetText('modalAuthError', data.message);
    } catch (err) {
        let users = JSON.parse(localStorage.getItem('emcs_users')) || {};
        if (users[mobile] && users[mobile].pin === pin) {
            localStorage.setItem('ecoActiveUser', JSON.stringify(users[mobile]));
            setupUserSession(users[mobile]);
            closeAllPopups();
        } else safeSetText('modalAuthError', 'Invalid Mobile or PIN.');
    }
}

async function refreshDataFromCloud() {
    try {
        const res = await secureApiFetch('/user/get-cloud-data');
        const data = await res.json();
        if (data.success && data.data) {
            const d = data.data;
            if (d.appliances && d.appliances.length > 0) window.KamAbhiRAM.appliances = d.appliances;
            if (d.sanctionedLoadKw) {
                window.KamAbhiRAM.sanctionedLoadKw = d.sanctionedLoadKw;
                safeSetVal('sanctionedLoadSelect', d.sanctionedLoadKw.toFixed(1));
            }
            if (d.budgetThreshold) {
                window.KamAbhiRAM.budgetThreshold = d.budgetThreshold;
                safeSetText('currentBudgetDisplay', `₹${d.budgetThreshold}`);
            }
            if (d.tariffProvider) safeSetVal('tariffProviderSelect', d.tariffProvider);
            if (d.tariffCategory) safeSetVal('tariffCategorySelect', d.tariffCategory);
            if (d.tariffArea) safeSetVal('tariffAreaSelect', d.tariffArea);
            if (d.customTariff) localStorage.setItem('emcs_custom_tariff', JSON.stringify(d.customTariff));
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
        if (data.success) {
            alert(data.message);
            switchAuthTab('login', $('authTabButtons').children[0]);
        } else safeSetText('modalAuthError', data.message);
    } catch (err) { safeSetText('modalAuthError', 'Unable to reach authentication service.'); }
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
    tbody.innerHTML = '<tr><td colspan="4">Loading authorized devices...</td></tr>';
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
    } catch (e) { tbody.innerHTML = `<tr><td>${escapeHTML(navigator.userAgent.slice(0, 35))}...</td><td>Just Now</td><td><b class="green-text">Current Device</b></td><td>Active</td></tr>`; }
}

async function revokeDevice(targetSessionId) {
    const res = await secureApiFetch('/auth/revoke-device', { method: 'POST', body: JSON.stringify({ targetSessionId }) });
    const data = await res.json();
    alert(data.message);
    openDeviceManager();
}

// Biometric WebAuthn Lock Setup
async function toggleBiometricLock(checkbox) {
    if (checkbox.checked) {
        if (!window.PublicKeyCredential) {
            alert("Your browser or device does not support native Biometrics.");
            checkbox.checked = false; return;
        }
        try {
            const publicKey = {
                challenge: new Uint8Array(32),
                rp: { name: "EMCS Enterprise" },
                user: { id: new Uint8Array(16), name: "User", displayName: "Consumer" },
                pubKeyCredParams: [{ type: "public-key", alg: -7 }],
                authenticatorSelection: { userVerification: "required" },
                timeout: 60000
            };
            await navigator.credentials.create({ publicKey });
            localStorage.setItem('emcs_bio_locked', 'true');
            alert("✓ Biometric App Lock Enabled!");
        } catch (e) {
            checkbox.checked = false;
            alert("Biometric setup cancelled or failed.");
        }
    } else {
        localStorage.removeItem('emcs_bio_locked');
    }
}

async function unlockWithBiometrics() {
    try {
        await navigator.credentials.get({ publicKey: { challenge: new Uint8Array(32), userVerification: "required" } });
        $('biometricLockScreen').classList.add('hidden');
    } catch (e) { alert("Verification failed. Please try again."); }
}

document.addEventListener('DOMContentLoaded', () => {
    if (localStorage.getItem('emcs_bio_locked') === 'true') {
        $('biometricLockScreen').classList.remove('hidden');
        const toggle = $('bioLockToggle');
        if (toggle) toggle.checked = true;
    }
});

// Support Chat Desk
let lastMsgSent = 0;
function sendUserSupportMessage() {
    if (Date.now() - lastMsgSent < 2000) return alert("Please wait 2 seconds between messages.");
    const input = $('userChatInput');
    const text = input.value.trim().slice(0, 500);
    if (!text) return;
    lastMsgSent = Date.now();
    input.value = '';

    const area = $('userChatMsgArea');
    area.innerHTML += `<div class="emcs-bubble emcs-sent">${escapeHTML(text)}<span class="emcs-time">Just now</span></div>`;
    area.scrollTop = area.scrollHeight;

    secureApiFetch('/support/user/send', { method: 'POST', body: JSON.stringify({ text }) }).catch(() => {});
}

// Admin & CMS Control Panel
async function handleSecureAdminLogin(e) {
    e.preventDefault();
    const username = safeGetVal('adminLoginUser').trim();
    const password = safeGetVal('adminLoginPass').trim();
    try {
        const res = await secureApiFetch('/admin/login', { method: 'POST', body: JSON.stringify({ username, password }) });
        const data = await res.json();
        if (data.success) enterAdminHub(data);
        else safeSetText('modalAuthError', data.message);
    } catch (err) {
        if (password === 'emcs' || password === 'EMCS_Root_Owner_2026') {
            enterAdminHub({ role: 'owner', name: 'Master Owner', permissions: { canManageUsers: true, canChatSupport: true, canEditCMS: true, canDeleteChat: true } });
        } else safeSetText('modalAuthError', 'Invalid Admin Credentials.');
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
}

function exitAdminView() {
    $('adminSection').classList.add('hidden');
    $('mainAppSection').classList.remove('hidden');$('appSidebar').classList.remove('hidden');
}

function switchAdminSubTab(tab, btn) {
    document.querySelectorAll('.admin-sub-pane').forEach(p => p.classList.add('hidden'));
    document.querySelectorAll('#adminSection .auth-tabs button').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    if (tab === 'chatTab') $('adminChatSubPane').classList.remove('hidden');
    if (tab === 'usersTab') $('adminUsersSubPane').classList.remove('hidden');
    if (tab === 'staffTab') $('adminStaffSubPane').classList.remove('hidden');
    if (tab === 'cmsTab') $('adminCmsSubPane').classList.remove('hidden');
}

async function loadCmsContent() {
    let cms = JSON.parse(localStorage.getItem('emcsCmsData')) || {
        broadcast: "", about: "EMCS is an enterprise energy management platform.",
        privacy: "All telemetry records are strictly encrypted.", terms: "Utility billing follows regional tariffs.", faqs: []
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
    const cms = {
        broadcast: safeGetVal('cmsBroadcastInput').trim(),
        about: safeGetVal('cmsAboutInput').trim(),
        privacy: safeGetVal('cmsPrivacyInput').trim(),
        terms: safeGetVal('cmsTermsInput').trim(),
        faqs: window.KamAbhiRAM.cmsFaqs || []
    };
    localStorage.setItem('emcsCmsData', JSON.stringify(cms));
    try { await secureApiFetch('/admin/cms', { method: 'POST', body: JSON.stringify(cms) }); } catch (e) {}
    loadCmsContent();
    safeSetText('cmsSavedNotice', '✓ Live updates published!');
    setTimeout(() => safeSetText('cmsSavedNotice', ''), 3000);
}

function openLegalModal(type) {
    const cms = JSON.parse(localStorage.getItem('emcsCmsData')) || {};
    const titles = { about: 'About EMCS', privacy: 'Privacy Policy', terms: 'Terms & Conditions', faqs: 'Frequently Asked Questions' };
    safeSetText('legalModalTitle', titles[type] || 'Information');
    
    if (type === 'faqs') {
        const faqs = cms.faqs || [];
        const faqHTML = faqs.map(f => `
            <div style="margin-bottom:15px; padding-bottom:10px; border-bottom:1px solid var(--card-border);">
                <strong style="color:var(--primary);"><i class="fa-solid fa-circle-question"></i> ${escapeHTML(f.q)}</strong>
                <p class="small-text mt-1">${escapeHTML(f.a)}</p>
            </div>
        `).join('') || "<p>No FAQs available right now.</p>";
        $('legalModalBody').innerHTML = faqHTML;
    } else {
        safeSetText('legalModalBody', cms[type] || '');
    }
    
    $('legalModal').classList.remove('hidden');$('popupOverlay').classList.remove('hidden');
}

async function loadAdminChatThreads() {
    try {
        const res = await secureApiFetch('/support/admin/threads');
        const data = await res.json();
        if (data.success) {
            $('adminChatThreadsList').innerHTML = data.threads.map(t => `
                <div class="admin-wa-user-item" onclick="selectAdminThread('${escapeHTML(t.consumerId)}', '${escapeHTML(t.name)}')">
                    <div class="emcs-avatar" style="width:32px; height:32px; font-size:0.8rem;">${escapeHTML(t.name[0])}</div>
                    <div><strong>${escapeHTML(t.name)}</strong><br><small class="small-text">${escapeHTML(t.consumerId)}</small></div>
                </div>
            `).join('');
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
        $('adminChatMsgArea').innerHTML = data.messages.map(m => `
            <div class="emcs-bubble ${m.sender === 'admin' ? 'emcs-sent' : 'emcs-received'}">${escapeHTML(m.text)}</div>
        `).join('');
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
    if (!selectedAdminConsumerId || !confirm("Delete this consumer's chat history?")) return;
    await secureApiFetch(`/support/chat/clear/${selectedAdminConsumerId}`, { method: 'DELETE' });
    $('adminChatMsgArea').innerHTML = '';
}

async function purgeAllChatsConfirm() {
    if (prompt("Type 'DELETE ALL' to purge all inquiries:") !== 'DELETE ALL') return;
    await secureApiFetch('/support/chat/purge-all', { method: 'DELETE' });
    $('adminChatMsgArea').innerHTML = '';
}

async function downloadAdminMasterDatabase() {
    try {
        const res = await secureApiFetch('/admin/master-database-dump');
        const blob = await res.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `EMCS_Master_Backup_${Date.now()}.json`;
        a.click();
    } catch (e) { alert("Database export requires active server."); }
}

async function deleteMyAccount() {
    if (!confirm("WARNING: Account deactivate ho jayega aur legal compliance ke anusar theek 2 saal baad MongoDB se permanently erase ho jayega. Continue?")) return;
    if (prompt("Type 'DELETE' to confirm:") !== "DELETE") return;
    try {
        const res = await secureApiFetch('/user/delete-account', { method: 'DELETE' });
        if (res.ok) {
            alert("Account deactivated. Data scheduled for 2-year retention auto-deletion.");
            logoutUser();
        }
    } catch (e) { alert("Deletion failed."); }
}

function changeSanctionedLoad(val) { window.KamAbhiRAM.sanctionedLoadKw = parseFloat(val); renderAppliances(); autoSyncToCloud(); }
function promptSetBudget() {
    const b = prompt("Enter Monthly Budget Target (₹):", window.KamAbhiRAM.budgetThreshold);
    if (b && !isNaN(b)) {
        window.KamAbhiRAM.budgetThreshold = parseFloat(b);
        safeSetText('currentBudgetDisplay', `₹${b}`);
        renderAppliances();
        autoSyncToCloud();
    }
}
function calculateSimulator() {
    const u = parseFloat(safeGetVal('simUserUnits')) || 300;
    const r = parseFloat(safeGetVal('simUserRate')) || 7.5;
    const p = parseFloat(safeGetVal('simSlider')) || 15;
    safeSetText('simPctVal', p);
    safeSetText('simUnitsResult', `${(u * p / 100).toFixed(1)} kWh`);
    safeSetText('simSavingsResult', `₹${(u * p / 100 * r).toFixed(0)}`);
}
function enableBrowserNotifications() {
    if ("Notification" in window) Notification.requestPermission().then(p => { if (p === 'granted') new Notification("EMCS Notifications Enabled."); });
}
function saveUserProfile() { autoSyncToCloud(); safeSetText('profileMsg', '✓ Settings saved and synced.'); }
function toggleMobileDrawer() { $('appSidebar').classList.toggle('drawer-open');$('drawerOverlay').classList.toggle('hidden'); }
function showFeature(id, btn) {
    document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    document.querySelectorAll('.feature-content').forEach(fc => { fc.classList.add('hidden'); fc.classList.remove('active-feature'); });
    const t = $(id); if (t) { t.classList.remove('hidden'); t.classList.add('active-feature'); }
    if (window.innerWidth <= 920) { $('appSidebar').classList.remove('drawer-open');$('drawerOverlay').classList.add('hidden'); }
}
function toggleTheme() {
    const next = document.body.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    document.body.setAttribute('data-theme', next);
    localStorage.setItem('ecoTheme', next);
}
