# ⚡ EMCS (Energy Management Control System)

![Node.js](https://img.shields.io/badge/Node.js-Express-green?style=flat-square&logo=node.js)
![MongoDB](https://img.shields.io/badge/Database-MongoDB-brightgreen?style=flat-square&logo=mongodb)
![Security](https://img.shields.io/badge/Security-Production%20Hardened-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)

**EMCS** is an enterprise-grade full-stack energy monitoring, tariff calculation, and hardware automation platform. It tracks power consumption, optimizes electricity bills using regional tariff slabs, and safeguards smart appliances against grid anomalies.

---

## 🚀 Key Features

* **All-India Tariff & Billing Engine:** Supports state electricity boards and private utilities across Urban/Rural and Domestic/Commercial categories with custom manual slab configuration.
* **Live Appliance Flowgraph:** Dynamic 2D flow distribution diagrams, gradient flow curves, and load share breakdowns with zero dummy data.
* **Real-Time Voltage & Surge Guard:** Automated safety cutoffs during grid brownouts (<180V) and high surges (>260V).
* **Inverter Backup Estimator:** Computes exact backup runtime based on battery capacity (Ah), system voltage, and active running load.
* **Smart Bill OCR Scanner:** Extracts consumer IDs and consumed units directly from paper bill images using Tesseract.js OCR.
* **Smart Meter CSV Analyzer:** Parses granular hourly interval telemetry data for deep energy audits.
* **Hardware Relay Control:** Dual-mode IoT control protected by time-stamped **SHA-256 HMAC signatures**.

---

## 🛡️ Production Security & Hardening
Audited and fortified against top-tier OWASP vulnerabilities:
1. **Multi-Tier Rate Limiting:** Global API limits, strict Auth brute-force lockouts, and payload limits to prevent DDoS and memory exhaustion.
2. **Strict Input Validation:** Server-side schema sanitization and allowed-value enums to block NoSQL/SQL injections and XSS.
3. **RBAC & Data Isolation:** Granular Role-Based Access Control (RBAC) for Admin/Staff and strict IDOR/BOLA prevention via Consumer ID mapping.
4. **Secrets Management:** Zero hardcoded credentials. All JWT keys and hardware secrets are injected dynamically via environment variables.
5. **File Upload Security:** Magic-bytes (File Signature) validation, strict MIME-type checks, and 2MB/4MB file size caps.
6. **Zero Information Leakage:** Generic client-facing error handling with an encrypted server-side system telemetry ledger for admin debugging.

---

## 🛠️ Tech Stack

* **Frontend:** HTML5, CSS3, Vanilla JS (ES6+), Chart.js, Tesseract.js, html2pdf.js
* **Backend:** Node.js, Express.js, Mongoose ODM
* **Database:** MongoDB (with TTL indexes & atomic operations)
* **Security:** bcryptjs, JSON Web Tokens (JWT), Web Crypto API (HMAC-SHA256)

---

## ⚙️ Installation & Deployment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/believerabhishek-raj/EMCS-By-Abhishek

**2.Install dependencies:**
npm install

**3.Configure Environment Variables:**
Create a .env file in the root directory:
PORT=5000
MONGO_URI=mongodb+srv://<your-db-url>
MASTER_OWNER_KEY=YourStrongAdminPassword
NODE_ENV=production

**4.Start the server:**
npm start

**Powered By KamAbhi Tech Solutions**