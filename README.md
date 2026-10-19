# 🛡️ SENTINEL IDS — Rule-Based Intrusion Detection System

A complete, beginner-friendly **Intrusion Detection System (IDS)** web application developed using **HTML5, CSS3, JavaScript, Python Flask, and SQLite**.

> **College Mini-Project Note**: This project intentionally uses **100% deterministic rule-based signature detection (Zero AI or Machine Learning)**. Every security alert is fully explainable, verifiable, and conforms to industry-standard signature inspection models used by tools like Snort and Suricata.

---

## 🌟 Key Features

1. **Modern Cybersecurity SOC Dashboard**:
   - Sleek dark-mode aesthetic with neon cyan (`#00f0ff`), matrix emerald (`#00ff88`), caution amber (`#ffb703`), and threat crimson (`#ff2a5f`).
   - Real-time UTC Security Operations Center (SOC) clock.
   - Dynamic metric counters: *Total Inspected*, *High Risk Alerts*, *Suspicious Events*, *Safe Traffic*, and *Threat Ratio (%)*.
   - Interactive **Chart.js** Donut Chart visualizing threat distribution.

2. **Analyst Authentication Portal (Login Page)**:
   - Secure session-based authentication backed by SQLite.
   - Password hashing with PBKDF2/SHA-256 via Werkzeug.
   - **1-Click Auto-Fill Demo Credentials** (`admin` / `admin123`) for smooth viva presentations.

3. **Deterministic Rule-Based Detection Engine (No AI/ML)**:
   - **Strict Rule Categorization**:
     - 🔴 **SQL Injection (`SELECT`, `UNION`, `' OR '1'='1'`)**: Marked as **High Risk**. Detects query manipulation, authentication bypass, and table exfiltration syntax.
     - 🔴 **Cross-Site Scripting (`<script>`)**: Marked as **High Risk**. Detects client-side script execution and session cookie hijack payloads.
     - 🟡/🔴 **Brute-Force Keywords (`failed`, `unauthorized`)**: Marked as **Suspicious** (or **High Risk** if request volume exceeds 30 req/min). Detects repeated authentication errors and unauthorized endpoint probes.
     - 🔴 **Network Backdoors & Intel**: Dangerous ports (4444 Metasploit), directory traversal (`../`), and threat intelligence blacklisted IPs.
     - 🟢 **Safe Baseline**: Any input that does not contain malicious injection tokens or intrusion indicators is classified as **Safe**.
   - **Explainable Evidence on UI**: Every single scan explicitly presents the exact matched tokens and a human-readable reason why the rule was triggered.

4. **Interactive Network Event Analysis Console**:
   - Form fields: *Source IP Address*, *Destination Port*, *Protocol (TCP/UDP/HTTP/HTTPS/ICMP)*, *Request Rate (req/min)*, *User-Agent*, and *Packet Payload / Query String*.
   - **One-Click Scenario Presets** for immediate examiner testing:
     - 🟢 *Normal Traffic (Safe)*: Clean authorized request.
     - 🔴 *SQLi (High Risk)*: `admin' OR '1'='1' -- UNION SELECT username, password FROM users`.
     - 🔴 *XSS (High Risk)*: `<script>alert('XSS Exploit Injected: ' + document.cookie)</script>`.
     - 🟡 *Brute-Force (Suspicious)*: `status=failed&error=unauthorized access attempt for user admin`.
     - 🔴 *Metasploit Shell (High Risk)*: Port 4444 reverse shell.
     - 🔴 *Blacklisted Botnet IP (High Risk)*: `198.51.100.23`.

5. **Instant Classification & SOC Recommendations**:
   - Classifies every event into:
     - 🟢 **SAFE**: Threat Score 0–19 (Clean traffic — no SQLi, XSS, or brute-force indicators)
     - 🟡 **SUSPICIOUS**: Threat Score 20–49 (Anomalies, 'failed'/'unauthorized' keywords, or administrative ports)
     - 🔴 **HIGH RISK**: Threat Score 50–100 (Critical exploits, SQLi, XSS, backdoor ports, or blacklisted hosts)
   - Dynamic Threat Score progress meter (0–100).
   - Dedicated **Detection Reason & Evidence Box** displayed on the UI.
   - Actionable SOC mitigation recommendation (e.g. *Immediate Firewall Drop*, *Rate Limit & Review*).

6. **Persistent SQLite Database Ledger**:
   - All inspected events are automatically recorded into `ids_database.db`.
   - Records include timestamp, source IP, port, protocol, payload, threat score, severity, triggered rules, and analyst username.
   - Pre-seeded with 5 realistic sample logs on initial launch.

7. **Detection History & Audit Center**:
   - Full search bar (by IP, payload keyword, or action taken).
   - Filter pills: *All Events*, *High Risk Only*, *Suspicious Only*, *Safe Only*.
   - **Export to CSV** feature for compliance reporting and examiner demonstration.
   - Purge/Clear history button with confirmation.

8. **Signature Rule Catalog Page**:
   - Comprehensive documentation page explaining each rule, its category, threat score weight, description, and test triggers.

---

## 📁 Project Directory Structure

```text
cyber_ids_project/
├── app.py                     # Flask application & Rule-Based Detection Engine
├── requirements.txt           # Project Python dependencies
├── ids_database.db            # SQLite database (auto-generated on first run)
├── README.md                  # Complete documentation and viva guide
├── templates/                 # Jinja2 HTML Templates
│   ├── base.html              # Cyber SOC navigation, live clock, status pill, footer
│   ├── login.html             # Analyst login card with auto-fill demo button
│   ├── dashboard.html         # SOC Command Center (Form, Presets, Chart, Stat Cards)
│   ├── history.html           # Full SQLite detection logs table with search & filters
│   └── rules.html             # Detailed signature catalog and threat IP blocklist
└── static/
    ├── css/
    │   └── style.css          # Dark cybersecurity stylesheet with glowing neon accents
    └── js/
        └── main.js            # AJAX inspection, presets, Chart.js donut chart, SOC clock
```

---

## 🚀 Simple Windows Instructions to Run the Project

### Prerequisites
- Python 3.8+ installed on Windows ([Download Python](https://www.python.org/downloads/)).
- When installing Python, ensure **"Add python.exe to PATH"** is checked.

### Step 1: Open PowerShell or Command Prompt
Press `Win + R`, type `powershell` (or `cmd`), and hit **Enter**.

### Step 2: Navigate to the Project Directory
```powershell
cd C:\Users\Administrator\Desktop\cyber_ids_project
```
*(Or the location where your project folder is stored).*

### Step 3: Install Required Dependencies
Run:
```powershell
pip install -r requirements.txt
```
*(Only Flask and Werkzeug are required — no complex ML frameworks!)*

### Step 4: Start the Flask Application
Run:
```powershell
python app.py
```

You will see terminal output similar to:
```text
============================================================
 [✓] Intrusion Detection System (IDS) Engine Started
 [✓] Rule-based detection active (Zero AI/ML)
 [✓] SQLite Database: ids_database.db initialized
 [✓] Demo Credentials: admin / admin123
 [✓] Access at: http://127.0.0.1:5000/
============================================================
```

### Step 5: Open Your Web Browser
Open Chrome, Edge, or Firefox and go to:
👉 **`http://127.0.0.1:5000/`**

### Step 6: Log In
- **Username**: `admin`
- **Password**: `admin123`
- *(Tip: You can also click the **"Auto-Fill"** button on the login card!)*

---

## 🎯 How to Demonstrate in a College Viva / Presentation

1. **Show the Dashboard**:
   - Point out the real-time SOC clock, active status indicator, and dynamic metric cards.
   - Explain the Donut Chart visualizing Safe vs. Suspicious vs. High Risk traffic.

2. **Demonstrate 1-Click Presets**:
   - Click **"SQL Injection"** &rarr; hit **"INSPECT EVENT & DETECT"**.
     - Result: 🔴 **HIGH RISK** (Score 95/100).
     - Trigger: `RULE-02` (SQL Injection Attack).
   - Click **"Normal Traffic"** &rarr; hit **"INSPECT EVENT & DETECT"**.
     - Result: 🟢 **SAFE** (Score 0/100).
     - Trigger: Zero malicious signatures matched.
   - Click **"Metasploit (Port 4444)"** &rarr; hit **"INSPECT EVENT & DETECT"**.
     - Result: 🔴 **HIGH RISK** (Score 100/100).
     - Trigger: `RULE-05` (Dangerous Port) and `RULE-10` (Reverse Shell).
   - Click **"High Request Flood"** &rarr; hit **"INSPECT EVENT & DETECT"**.
     - Result: 🔴 **HIGH RISK** (Score 45/100).
     - Trigger: `RULE-08` (High Request Rate).

3. **Show Detection History**:
   - Navigate to the **"Detection Logs"** page in the top menu.
   - Demonstrate the **Risk Filters** (e.g. click "High Risk Only").
   - Search for an IP like `198.51.100.23`.
   - Click **"Export to CSV"** to demonstrate log downloading.

4. **Show the Rule Catalog**:
   - Click **"Rule Catalog"** in the navigation bar to walk through the 11 signature rules and show the examiner how each rule operates.

---

## 🎓 College Viva Questions & Answers (Frequently Asked)

**Q1: What is an Intrusion Detection System (IDS)?**  
*Answer:* An IDS is a software application or device that monitors network traffic or system events for malicious activities, policy violations, or unauthorized intrusions. When suspicious activity is detected, it logs the event and generates alerts for security analysts.

**Q2: Why did you choose Rule-Based detection instead of Machine Learning (AI)?**  
*Answer:* 
1. **Explainability & Auditability**: Every alert pinpoints the exact signature or rule triggered. Black-box ML models cannot explain why a packet was classified as malicious.
2. **Deterministic Speed**: Rule checks execute in sub-millisecond time using regex and hash sets, making them suitable for high-throughput packet inspection without GPU overhead.
3. **Industry Alignment**: Primary production IDS systems such as **Snort** and **Suricata** fundamentally operate on rule-based signature engines.
4. **Zero Model Drift**: Rules remain consistently accurate without requiring continuous retraining or suffering from adversarial evasion attacks.

**Q3: What is the difference between an IDS and an IPS?**  
*Answer:* An **IDS (Intrusion Detection System)** is passive: it monitors traffic, analyzes packets, and raises alerts without altering packet flow. An **IPS (Intrusion Prevention System)** sits inline with network traffic and actively drops, blocks, or rejects malicious packets in real time.

**Q4: How does the system calculate the Threat Score?**  
*Answer:* The engine maintains a weighted scoring system:
- Critical rules (SQLi, Metasploit port, Blacklisted IP) contribute +45 to +55 points.
- Moderate rules (Suspicious admin ports, scanner user agents, moderate frequency) contribute +20 to +30 points.
- The total score is capped at 100.
- If total score $\ge 50$ or any High-severity rule matches $\rightarrow$ **High Risk**.
- If total score $\ge 20$ $\rightarrow$ **Suspicious**.
- Otherwise $\rightarrow$ **Safe**.

**Q5: What database is used and why?**  
*Answer:* **SQLite3**. It is serverless, zero-configuration, lightweight, and stores all records in a single self-contained file (`ids_database.db`), making the project completely portable and easy to run on any computer.

---

## 🛡️ License & Academic Usage
Designed and developed for academic demonstrations, college mini-projects, viva examinations, and introductory cybersecurity lab sessions.
