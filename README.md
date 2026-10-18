⚡ EMCS — Energy Management Control System

EMCS (Energy Management Control System) is a full-stack energy analytics, All-India utility billing, and IoT load automation platform. It enables residential and commercial consumers to monitor appliance-level power consumption, forecast monthly electricity bills using state and private DISCOM tariff slabs, and protect electrical equipment against grid voltage anomalies.
​🌟 Core Features
​1. All-India Tariff & Billing Engine
​Government & Private Utilities: Pre-configured tiered slab rates, Fixed Demand Charges (per kW), FPPCA surcharges, and Electricity Duty for major Indian utilities including Bihar (NBPDCL/SBPDCL), UP (UPPCL), Maharashtra (MSEDCL), Delhi, Karnataka (BESCOM), Rajasthan, West Bengal, Tamil Nadu, Gujarat, Punjab, Haryana, MP, and private discoms (Tata Power, BSES, Adani Electricity, CESC, Torrent Power).
​Multi-Category Support: Dynamically switches calculations between Domestic (Residential) and Commercial connections across Urban and Rural areas.
​Custom User-Defined Tariff: Allows users to configure and persist custom unit slabs, fixed charges, and duty percentages.
​2. Smart Load & Appliance Analytics
​Appliance Profiler & Presets: Add custom appliances or select from standard household presets to compute daily and monthly kWh consumption.
​Interactive Flowgraph & 2D Charts: Real-time data visualization powered by Chart.js with instant toggle between Curve Flowgraphs, Colorful 2D Bar Charts, and Load Share Doughnut Charts.
​Sanctioned Load (MDI) Overload Guard: Alerts the user when active running wattage exceeds their sanctioned meter capacity and provides one-click heavy load cutoff.
​3. Grid Safety & Backup Tools
​Real-Time Voltage & Surge Guard: Simulates and monitors grid brownouts (<180V) and high-voltage spikes (>260V), automatically triggering heavy compressor/heating relays to cut off and prevent PCB damage.
​Manual Inverter & Battery Backup Calculator: Calculates exact backup runtime (Hours & Minutes) from user-entered Battery Capacity (Ah), System Voltage (12V/24V/48V), and Running Load (Watts), with one-click active load sync.
​Standby (Vampire) Power Audit: Tracks and reclaims hidden phantom power drain from idle wall sockets and adapters.
​4. AI, OCR & Smart Meter Tools
​Electricity Bill OCR Scanner: Uses Tesseract.js to scan paper electricity bill images and extract consumed units (kWh) directly into the simulator.
​Smart Meter CSV Analyzer: Parses hourly interval .csv logs exported from smart meters to highlight peak demand hours and daily averages.
​Time-of-Day (ToD) & Solar Rooftop ROI: Guides users on shifting heavy loads to solar off-peak hours (10 AM - 3 PM) and estimates PM Surya Ghar rooftop solar sizing, subsidies, and payback periods.
​Centered AI Energy Assistant (with Female Voice TTS): Interactive natural-language assistant capable of answering electrical safety queries and executing load-shedding commands.
​5. Dual-Mode Hardware & IoT Control
​Wired Web Serial API: Direct USB-TTL serial communication (115200 baud) with Arduino/ESP32 microcontrollers.
​HMAC-Secured Local Wi-Fi Webhook: Dispatches local LAN relay triggers signed with a dynamic SHA-256 HMAC + UNIX Timestamp signature to prevent packet sniffing and replay attacks.
​6. Multi-Language Interface
​Instant live translation across English (EN), Hindi (हिंदी), and Hinglish.
​🔒 Enterprise Security & Privacy Architecture
​Anti-Bot Honeypot & 24-Hour IP Registration Cap: Blocks automated registration scripts using hidden honeypot traps and restricts account creation to a maximum of 3 accounts per IP address every 24 hours (with stricter penalties for suspicious proxy/VPN headers).
​Atomic Brute-Force Defense (TOCTOU Fix): Uses MongoDB atomic $inc and $set operators on failed login attempts to eliminate race conditions and enforce a 15-minute lockout after 5 failed attempts.
​Server-Side Input Clamping (Inspect Element Immunity): Strictly validates and clamps wattage (1W - 50,000W), hours (0.1h - 24h), and tariff bounds on the backend so DOM tampering cannot corrupt database records.
​Native Biometric App Lock (WebAuthn): Optional device Fingerprint / Face ID / Windows Hello lock in the user profile.
​48-Hour Device Session Manager: Tracks active logged-in devices and enforces a 48-hour security window before secondary sessions can be remotely revoked.
​Mandatory Legal Consent & 2-Year Soft Delete TTL: Requires explicit Privacy Policy & Terms acceptance during sign-up. Account deletion immediately deactivates login access and schedules permanent erasure after 2 years (63,072,000 seconds) via a native MongoDB TTL index.
​Automated Error Telemetry (Admin Error List): Captures frontend runtime exceptions (window.onerror, unhandledrejection) and backend Express/MongoDB errors in real time, displaying them inside the Admin Panel's Error List tab.

​🛠️ Technology Stack
LayerTechnologies Used
FrontendHTML5, CSS3 (Custom Light/Dark Variables), Vanilla JavaScript (ES6+), Chart.js, Tesseract.js, html2pdf.js
BackendNode.js, Express.js
DatabaseMongoDB, Mongoose ODM (Atomic Operators & TTL Indexes)
Security & AuthJWT (HttpOnly Cookies), bcryptjs, Web Crypto API (HMAC-SHA256), WebAuthn Biometrics, Custom CSRF & SSRF Guards

📂 Project Structure
EMCS-Project/
├── index.html       # Complete UI layout, responsive styling, and centered modals
├── script.js        # Frontend engine, multi-language dictionary, charts & error telemetry
├── server.js        # Express server, security middlewares, rate limiters & MongoDB routes
├── package.json     # Node.js dependencies and start scripts
└── README.md        # Project documentation

⚙️ Local Setup & Installation
​1. Clone the Repository
git clone https://github.com/believerabhishek-raj/EMCS-By-Abhishek
cd emcs-energy-system

2. Install Node Dependencies
npm install

3. Configure Environment Variables
​Set the following environment variables in your terminal or .env configuration:
PORT=5000
NODE_ENV=development
MONGO_URI=mongodb://127.0.0.1:27017/emcs_project_db
MASTER_OWNER_KEY=Admin123

4. Run the Server
npm start

Open http://localhost:5000 in your browser.
​☁️ Deploying on Render
​Push index.html, script.js, server.js, package.json, and README.md to your GitHub repository.
​Create a new Web Service on Render and connect your repository.
​Use the following build settings:
​Runtime: Node
​Build Command: npm install
​Start Command: node server.js
​Add your Environment Variables in the Render dashboard:
​NODE_ENV = production
​MONGO_URI = your_mongodb_atlas_connection_string
​MASTER_OWNER_KEY = your_secret_admin_password
​Click Create Web Service.
​🛡️ Admin Control Panel Access
​Click Login / Connect on the sidebar.
​Switch to the Admin tab.
​Leave the Staff Username blank (for Master Owner) and enter your MASTER_OWNER_KEY (default:Admin123).
​From the Admin Hub, you can:
​Reply to consumer inquiries in the Support Chat Desk.
​Inspect registered consumers and sanctioned loads.
​Update live website announcements, legal policies, and FAQs.
​Monitor real-time client and server exceptions in the Error List tab.
​Export a full JSON backup of the database.

Powered By KamAbhi Tech Solutions
