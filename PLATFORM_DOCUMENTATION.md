# ABSEGA Detection Engineering & Validation Platform

## Complete Documentation

---

## Table of Contents

1. [What Is This Project?](#1-what-is-this-project)
2. [Background Concepts (What You Need to Know First)](#2-background-concepts)
   - [What Is a SIEM?](#what-is-a-siem)
   - [What Is Wazuh?](#what-is-wazuh)
   - [What Are Logs?](#what-are-logs)
   - [What Are Alerts and Detection Rules?](#what-are-alerts-and-detection-rules)
   - [What Is MITRE ATT&CK?](#what-is-mitre-attck)
   - [What Is Sigma?](#what-is-sigma)
   - [What Is DVWA?](#what-is-dvwa)
3. [How the Platform Works (Big Picture)](#3-how-the-platform-works)
4. [Architecture and Technology Stack](#4-architecture-and-technology-stack)
5. [Project File Structure](#5-project-file-structure)
6. [Environment Setup](#6-environment-setup)
   - [The .env File](#the-env-file)
   - [WSL2 Networking](#wsl2-networking)
   - [Wazuh Custom Rules](#wazuh-custom-rules)
7. [Web Attack Simulation (DVWA)](#7-web-attack-simulation-dvwa)
   - [How It Works](#how-web-attacks-work)
   - [The 10 Web Attacks](#the-10-web-attacks)
   - [Tagging Rules (100100, 100200, 100201)](#web-tagging-rules)
   - [Validation Logic](#web-validation-logic)
   - [Results Explained](#web-results-explained)
8. [Linux Attack Simulation (SSH)](#8-linux-attack-simulation-ssh)
   - [How It Works](#how-linux-attacks-work)
   - [The 15 Linux Attacks](#the-15-linux-attacks)
   - [Tagging Rules (100300–100315)](#linux-tagging-rules)
   - [Validation Logic](#linux-validation-logic)
   - [Results Explained](#linux-results-explained)
9. [The Three Detection Statuses](#9-the-three-detection-statuses)
10. [Backend Code Walkthrough](#10-backend-code-walkthrough)
    - [app/main.py — The Server Entry Point](#appmainpy)
    - [app/wazuh_client.py — Talking to Wazuh](#appwazuh_clientpy)
    - [app/routes/wazuh.py — The Brain of the Platform](#approuteswazuhpy)
    - [attack_dvwa.py — Web Attack Script](#attack_dvwapy)
    - [attack_linux.py — Linux Attack Script](#attack_linuxpy)
11. [Frontend Walkthrough](#11-frontend-walkthrough)
12. [Wazuh Gap Analysis Report](#12-wazuh-gap-analysis-report)
13. [How to Run the Platform](#13-how-to-run-the-platform)
14. [Troubleshooting Common Issues](#14-troubleshooting-common-issues)
15. [Results Summary](#15-results-summary)

---

## 1. What Is This Project?

The ABSEGA Detection Engineering & Validation Platform is a tool that answers one simple question:

**"If an attacker attacks our systems, will our security tools actually catch it?"**

Most companies have security tools (like Wazuh, Splunk, etc.) that are supposed to detect attacks. But nobody actually tests whether those tools work. This platform does exactly that:

1. It **simulates real attacks** against a target machine (web attacks and Linux attacks)
2. It **checks whether Wazuh** (our SIEM — the security tool watching for threats) **actually detected those attacks**
3. It **shows you a clear report** — which attacks were caught, which were missed, and where the gaps are

Think of it like a fire drill for your security system. You set a small controlled fire (the simulated attack), then check if the fire alarm went off (Wazuh detection).

---

## 2. Background Concepts

### What Is a SIEM?

SIEM stands for **Security Information and Event Management**. It is a tool that:

- **Collects logs** from all your computers, servers, and applications
- **Analyzes those logs** looking for signs of attacks
- **Sends alerts** when it finds something suspicious

Think of it as a security camera system, but instead of watching video, it watches text logs from every computer on your network.

### What Is Wazuh?

Wazuh is a free, open-source SIEM. It has three main parts:

| Component | What It Does | Port |
|-----------|-------------|------|
| **Wazuh Manager** | The brain — receives logs, runs detection rules against them, decides what is an alert | 55000 (API) |
| **Wazuh Indexer** | The database — stores all the alerts so you can search them later (uses OpenSearch, which is like Elasticsearch) | 9200 |
| **Wazuh Agent** | A small program that runs on each computer you want to monitor — it collects logs and sends them to the Manager | N/A |

In our setup, the Wazuh Manager, Indexer, and Agent all run on the same Ubuntu VM at `192.168.36.128`. The Agent has ID `000` (which means it is the manager monitoring itself).

### What Are Logs?

Logs are text messages that computers write when things happen. Every program writes logs. For example:

**When someone logs in via SSH:**
```
Jul 12 17:10:55 wazuh-server sshd[18016]: Accepted password for ubuntu from 192.168.36.2 port 54321 ssh2
```

**When someone fails to log in:**
```
Jul 12 17:10:55 wazuh-server sshd[18016]: Failed password for invalid user hacker from 192.168.36.2 port 54321 ssh2
```

**When a web server gets a request:**
```
192.168.36.2 - - [12/Jul/2026:20:04:00] "GET /dvwa/vulnerabilities/sqli/?id=1' OR 1=1-- HTTP/1.1" 200 4523
```

These logs are stored in files like `/var/log/auth.log` (login attempts) and `/var/log/apache2/access.log` (web requests). Wazuh reads these log files, analyzes them, and decides if something bad is happening.

### What Are Alerts and Detection Rules?

A **detection rule** is a pattern that Wazuh looks for in logs. For example:

- Rule 5503: "If a log says 'Failed password' → send an alert: PAM: User login failed"
- Rule 2832: "If a log says the crontab changed → send an alert: Crontab entry changed"
- Rule 31106: "If a web request matches a known attack pattern → send an alert: A web attack returned code 200"

An **alert** is the message Wazuh creates when a rule matches. Each alert has:

- **Rule ID** — a number like `5503`
- **Rule Level** — how serious it is (0 = nothing, 15 = very critical)
- **Description** — what happened in plain English
- **Full Log** — the original log line that triggered the alert
- **Groups** — categories like `authentication_failed`, `syslog`, `web`

### What Is MITRE ATT&CK?

MITRE ATT&CK is a big public list of every known attack technique that hackers use. Each technique has an ID like:

- **T1059.001** — PowerShell execution
- **T1110** — Brute force attacks
- **T1053** — Scheduled task/job (like cron)

Security tools tag their rules with these IDs so you can see which techniques you can detect and which ones you cannot. Our platform uses MITRE ATT&CK IDs to compare Wazuh rules against Sigma rules and find gaps.

### What Is Sigma?

Sigma is a standard way to write detection rules that work across different SIEMs. Instead of writing one rule for Wazuh and a different one for Splunk, you write one Sigma rule and convert it to any format. Our platform stores a library of Sigma rules in its database and compares them against what Wazuh has.

### What Is DVWA?

DVWA stands for **Damn Vulnerable Web Application**. It is a website that is **intentionally full of security holes**. Security people use it to practice attacks in a safe environment. It has pages for:

- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- File Upload
- And more...

In our platform, we attack DVWA to test whether Wazuh catches web attacks.

---

## 3. How the Platform Works

Here is the complete flow, step by step:

### Web Attack Flow

```
1. You click "Run Web Attacks" in the browser
         ↓
2. The platform (FastAPI server) runs attack_dvwa.py
         ↓
3. attack_dvwa.py sends 10 different attacks to DVWA
   Each request has a "Run ID" tag like WAZUH_DVWA_TEST_20260712_170351
         ↓
4. DVWA is running on the Ubuntu VM where Wazuh is watching
         ↓
5. Wazuh sees the web traffic in Apache logs and creates alerts
   - Some alerts come from our CUSTOM tagging rules (100100, 100200, 100201)
     These just say "we saw the test traffic"
   - Some alerts come from REAL Wazuh detection rules (like 31106, 941100)
     These mean Wazuh actually detected the attack
         ↓
6. You click "Validate Detection Rules"
         ↓
7. The platform queries the Wazuh Indexer (OpenSearch at port 9200)
   It searches for all alerts that contain the Run ID
         ↓
8. For each of the 10 attacks, it checks:
   - Did a REAL Wazuh rule fire? → DETECTED
   - Did only our tagging rule fire? → LOGGED ONLY (gap!)
   - Did nothing fire at all? → NOT DETECTED
         ↓
9. Results are shown in a table
```

### Linux Attack Flow

```
1. You click "Run Linux Attacks" in the browser
         ↓
2. The platform runs attack_linux.py
         ↓
3. attack_linux.py connects to the target VM via SSH (using paramiko)
   and runs 15 different attack commands
         ↓
4. For each attack, it also runs:
   logger -t ABSEGA_ATTACK 'WAZUH_LINUX_TEST_20260712_172857 attack=SSH_Brute_Force'
   This writes a tagged syslog entry that our custom rules (100300-100315) will catch
         ↓
5. Wazuh sees two types of activity:
   - The logger entries → caught by our tagging rules (just markers)
   - The actual attack activity (failed logins, cron changes, etc.) → caught by
     real Wazuh detection rules IF Wazuh has rules for them
         ↓
6. You click "Validate Detection Rules" with "Linux Attacks" selected
         ↓
7. The platform queries the Wazuh Indexer with TWO searches:
   a) Search for Run ID → finds our tagging alerts
   b) Search by time range → finds ALL alerts since the attacks started
   Then it merges and deduplicates them
         ↓
8. For each of the 15 attacks, it matches alerts using:
   - tag_match: looks for the attack name in logger output (tagging)
   - detect_groups: looks for specific rule groups like "authentication_failed"
   - detect_desc: looks for keywords in the rule description
   - detect_log: looks for keywords in the full log text
         ↓
9. Same three statuses: DETECTED, LOGGED ONLY, NOT DETECTED
```

---

## 4. Architecture and Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | Single HTML page with vanilla JavaScript | The web interface you see in the browser |
| **Backend** | Python + FastAPI | The API server that handles all requests |
| **Database** | SQLite (`detection_platform.db`) | Stores Sigma rules, detections, and validation data |
| **SIEM** | Wazuh (Manager + Indexer + Agent) | The security tool being tested |
| **Target** | Ubuntu VM with DVWA + SSH | The machine being attacked |
| **Attack Scripts** | `attack_dvwa.py` and `attack_linux.py` | Automated attack simulators |
| **Environment** | WSL2 (Kali Linux) | Where the platform runs |

### Network Layout

```
┌─────────────────────┐         ┌──────────────────────────────┐
│  WSL2 (Kali Linux)  │         │  Ubuntu VM (192.168.36.128)  │
│                     │         │                              │
│  ABSEGA Platform    │ ──SSH──→│  Wazuh Agent (ID 000)        │
│  (FastAPI :8001)    │         │  Wazuh Manager (:55000)      │
│                     │ ──HTTP─→│  Wazuh Indexer (:9200)       │
│  attack_dvwa.py     │ ──HTTP─→│  Apache + DVWA (:80)         │
│  attack_linux.py    │         │                              │
└─────────────────────┘         └──────────────────────────────┘
```

---

## 5. Project File Structure

```
Soc-project-main/
├── app/
│   ├── main.py              # FastAPI server setup, routes, static files
│   ├── database.py          # SQLite database connection
│   ├── wazuh_client.py      # Functions to talk to Wazuh API and Indexer
│   ├── sigma_eval.py        # Sigma rule evaluation engine
│   └── routes/
│       ├── wazuh.py         # Attack Lab endpoints (run attacks, validate)
│       ├── detections.py    # Detection rule management
│       ├── telemetry.py     # Telemetry data
│       ├── mitre.py         # MITRE ATT&CK coverage
│       ├── validation.py    # Validation management
│       ├── auth.py          # Login/authentication
│       ├── atomic.py        # Atomic Red Team integration
│       └── ai.py            # AI features
├── attack_dvwa.py           # Web attack automation script (10 attacks)
├── attack_linux.py          # Linux attack automation script (15 attacks)
├── frontend.html            # Main dashboard (Attack Lab, alerts, validation)
├── login.html               # Login page
├── homepage.html            # Landing page
├── .env                     # Passwords and connection settings
├── detection_platform.db    # SQLite database
├── requirements.txt         # Python dependencies
├── connection-fix.txt       # WSL2 network fix instructions
└── .venv/                   # Python virtual environment
```

---

## 6. Environment Setup

### The .env File

The `.env` file stores all connection credentials. The platform reads these when it starts.

```env
# Wazuh Manager API (for fetching rules and agents)
WAZUH_URL=https://192.168.36.128:55000
WAZUH_USER=wazuh-wui
WAZUH_PASSWORD=0Wxu582IT8iSPMDuyfgB6xePk29*O?32
WAZUH_VERIFY_SSL=false

# Wazuh Indexer / OpenSearch (for fetching alerts)
INDEXER_URL=https://192.168.36.128:9200
INDEXER_USER=admin
INDEXER_PASSWORD=P7AuG.276.flhijnOs7+2uuPbE44cI.e
INDEXER_VERIFY_SSL=false

# SSH target for Linux attacks
TARGET_HOST=192.168.36.128
TARGET_USER=ubuntu
TARGET_PASSWORD=ubuntu
```

**Important:** `WAZUH_VERIFY_SSL=false` because Wazuh uses self-signed SSL certificates (certificates the server created itself, not from a trusted authority). This is normal in lab environments.

### WSL2 Networking

Our platform runs on WSL2 (Windows Subsystem for Linux — Kali). The Ubuntu VM runs in VirtualBox. They talk to each other through a network adapter called `eth1`.

**Known issue:** Every time WSL restarts, `eth1` goes DOWN (stops working). You must run this command to fix it:

```bash
sudo ip link set eth1 up
```

You can verify the connection with:

```bash
ping 192.168.36.128
```

### Wazuh Custom Rules

We installed custom tagging rules on the Wazuh Manager at `/var/ossec/etc/rules/local_rules.xml`. These rules do NOT detect attacks — they just mark (tag) our test traffic so we can find it later.

**Web tagging rules:**

| Rule ID | Purpose |
|---------|---------|
| 100100 | Matches tagged web requests in Apache access logs (contains `WAZUH_DVWA_TEST`) |
| 100200 | Base rule for ModSecurity JSON audit logs |
| 100201 | Matches tagged ModSecurity alerts (contains `WAZUH_DVWA_TEST`) |

**Linux tagging rules:**

| Rule ID | Purpose |
|---------|---------|
| 100300 | Parent rule — matches any log from program `ABSEGA_ATTACK` |
| 100301 | Child rule — matches `attack=SSH_Brute_Force` |
| 100302 | Child rule — matches `attack=Failed_Auth_Flood` |
| 100303 | Child rule — matches `attack=Cron_Job_Persistence` |
| ... | One rule per attack type... |
| 100315 | Child rule — matches `attack=Data_Exfiltration` |

**How child rules work:** Rule 100300 fires first (it matches the program name `ABSEGA_ATTACK`). Then rules 100301-100315 check for the specific attack name. The `<if_sid>100300</if_sid>` tag means "only check this rule if rule 100300 already fired."

Example rule:
```xml
<rule id="100301" level="3">
    <if_sid>100300</if_sid>
    <match>attack=SSH_Brute_Force</match>
    <description>ABSEGA: SSH Brute Force attack simulation</description>
</rule>
```

This means: "If the parent rule 100300 already matched, AND the log also contains the text `attack=SSH_Brute_Force`, then fire this rule with level 3 and the given description."

---

## 7. Web Attack Simulation (DVWA)

### How Web Attacks Work

The `attack_dvwa.py` script:

1. Logs into DVWA with username `admin` and password `password`
2. Sets the security level to `low` (so attacks work)
3. Sends 10 different attack types, one for each DVWA module
4. Tags every HTTP request with the Run ID in the User-Agent header: `Mozilla/5.0 (WAZUH_DVWA_TEST_20260712_170351)`
5. Saves a JSON report file

The Run ID format is: `WAZUH_DVWA_TEST_YYYYMMDD_HHMMSS`

### The 10 Web Attacks

| # | Attack | What It Does | Severity |
|---|--------|-------------|----------|
| 1 | **SQL Injection** | Sends `' OR 1=1--` to the database query page to dump all users | High |
| 2 | **SQL Injection (Blind)** | Sends `AND 1=1` / `AND 1=2` to guess data character by character | High |
| 3 | **XSS (DOM-based)** | Puts `<script>alert('XSS')</script>` in the URL that the page executes | High |
| 4 | **XSS (Reflected)** | Sends a `<script>` tag that bounces back in the response | High |
| 5 | **XSS (Stored)** | Stores an `onerror=alert()` payload that runs for every visitor | High |
| 6 | **Command Injection** | Sends `; id` after a ping command to run system commands | Critical |
| 7 | **File Inclusion (LFI)** | Sends `../../etc/passwd` to read files outside the web folder | High |
| 8 | **Malicious File Upload** | Uploads a PHP file (`<?php system($_GET['cmd']); ?>`) that acts as a backdoor | Critical |
| 9 | **Brute Force Login** | Tries many username/password combinations on the login page | Medium |
| 10 | **CSRF (Password Change)** | Changes a user's password through a forged cross-site request | Medium |

### Web Tagging Rules

Every HTTP request from our attack script contains the Run ID. This means:

- Apache writes the Run ID in its access log
- ModSecurity (the web firewall) also sees the Run ID
- Our custom Wazuh rules (100100, 100200, 100201) match on the Run ID text

These tagging rules fire for ALL our test requests, regardless of whether Wazuh's real detection rules caught the attack. This is how we know an attack was at least "logged" even if not "detected."

### Web Validation Logic

The `/api/wazuh/validate-live` endpoint works like this:

1. **Fetch alerts** — Queries the Wazuh Indexer for all alerts containing the Run ID
2. **For each of the 10 attacks**, check the fetched alerts:
   - Extract the request URL from the log (e.g., `/dvwa/vulnerabilities/sqli/`)
   - Check if the URL matches the attack's `url_patterns` (e.g., `["vulnerabilities/sqli"]`)
   - Check if the log body matches the attack's `patterns` (e.g., `["union select", "or 1=1"]`)
3. **Classify the matching alerts:**
   - Alerts from rules 100100/100200/100201 → tagging alerts (our custom rules)
   - Alerts from any other rule → detection alerts (real Wazuh rules)
4. **Determine status:**
   - Has detection alerts → `detected`
   - Has only tagging alerts → `logged` (gap!)
   - Has nothing → `not_detected`

### Web Results Explained

Our actual results were:

| Attack | Status | Why |
|--------|--------|-----|
| SQL Injection | DETECTED | ModSecurity rule 941100 caught the SQL patterns |
| XSS (DOM) | DETECTED | ModSecurity rule 941100 caught the `<script>` tag |
| XSS (Reflected) | DETECTED | Same as above |
| File Inclusion | DETECTED | Wazuh rule 31106 caught the path traversal `../` |
| SQL Injection (Blind) | LOGGED ONLY | The `AND 1=1` pattern is too subtle for default rules |
| XSS (Stored) | LOGGED ONLY | POST body is not visible in access logs |
| Command Injection | LOGGED ONLY | POST body (`; id`) is not in Apache access logs |
| File Upload | LOGGED ONLY | File content is not logged by Apache |
| Brute Force | LOGGED ONLY | DVWA returns HTTP 200 for both success and failure |
| CSRF | LOGGED ONLY | The request looks like a normal password change |

**Why "LOGGED ONLY" is not a bug:** These are real gaps in Wazuh's default rules. POST request bodies are not written to Apache access logs, so Wazuh never sees the attack payload for Command Injection, File Upload, and Stored XSS. This is exactly what the platform is designed to find.

---

## 8. Linux Attack Simulation (SSH)

### How Linux Attacks Work

The `attack_linux.py` script:

1. Connects to the target VM via SSH (using the `paramiko` library)
2. Creates a safe working directory at `/opt/attack_test/`
3. Runs 15 different attack types
4. For EACH attack, it also calls `logger -t ABSEGA_ATTACK '{RUN_ID} attack={Attack_Name}'`
5. Waits 15 seconds for Wazuh to process the logs
6. Queries the Wazuh Indexer for alerts
7. Saves a JSON report

The `logger` command writes a line to the system's syslog. The `-t ABSEGA_ATTACK` flag sets the program name to `ABSEGA_ATTACK`. Wazuh reads syslog and our custom rule 100300 matches on this program name.

The Run ID format is: `WAZUH_LINUX_TEST_YYYYMMDD_HHMMSS`

### The 15 Linux Attacks

| # | Attack | What It Does | Severity |
|---|--------|-------------|----------|
| 1 | **SSH Brute Force** | Tries wrong passwords with `su root` 5 times | Medium |
| 2 | **Failed Auth Flood** | Runs `sudo -u nobody` 5 times to generate auth failures | Medium |
| 3 | **Cron Job Persistence** | Adds a malicious entry to the crontab (scheduled tasks) | High |
| 4 | **SUID Binary Abuse** | Copies `/usr/bin/find` and sets the SUID bit (runs as root) | High |
| 5 | **Unauthorized User Creation** | Creates a new user with `useradd`, adds to sudo group, then deletes | Critical |
| 6 | **SSH Key Injection** | Adds an attacker's SSH key to `~/.ssh/authorized_keys` | High |
| 7 | **Systemd Backdoor** | Creates a fake systemd service that opens a reverse shell | High |
| 8 | **Bashrc Persistence** | Adds a malicious alias to `~/.bashrc` that steals sudo passwords | High |
| 9 | **Log Tampering** | Edits fake log files and clears bash history | Medium |
| 10 | **Credential Dumping** | Reads `/etc/shadow` to get password hashes | Critical |
| 11 | **Sudoers Modification** | Adds a file to `/etc/sudoers.d/` that gives attacker root access | Critical |
| 12 | **Hosts File Modification** | Adds fake DNS entries to `/etc/hosts` (DNS spoofing) | Medium |
| 13 | **Firewall Tampering** | Adds an iptables rule to open port 4444 (backdoor port) | High |
| 14 | **System Reconnaissance** | Runs `whoami`, `id`, `uname -a`, `netstat`, etc. to gather info | Low |
| 15 | **Data Exfiltration** | Reads sensitive files, encodes them with base64, stages for extraction | Critical |

**Safety:** Most attacks use the safe directory `/opt/attack_test/` (not real system paths) and clean up after themselves (delete test users, remove injected SSH keys, etc.).

### Linux Tagging Rules

Each attack calls `logger -t ABSEGA_ATTACK` before running. This creates a syslog entry like:

```
Jul 12 17:10:42 wazuh-server ABSEGA_ATTACK[18177]: WAZUH_LINUX_TEST_20260712_171013 attack=SSH_Brute_Force
```

Wazuh reads this and:
1. Rule 100300 fires (it matches `program_name = ABSEGA_ATTACK`)
2. Rule 100301 fires (it matches `attack=SSH_Brute_Force` and requires 100300 to have fired first)

This creates an alert that says "ABSEGA: SSH Brute Force attack simulation." This is our tagging alert — it proves the attack ran but does NOT mean Wazuh detected the actual attack.

### Linux Validation Logic

The `/api/wazuh/validate-linux` endpoint is more complex than web validation because Linux attacks do not put the Run ID in the actual attack logs (unlike web attacks where the Run ID is in every HTTP request).

Here is why: When we do an SSH brute force attack, the failed login log looks like:

```
Jul 12 17:10:50 wazuh-server sshd: Failed password for root from 192.168.36.2
```

There is no Run ID in that log. The Run ID is only in the separate `logger` entry. So the platform uses a **two-query approach**:

1. **Query 1 — Search by Run ID:** Find all alerts that contain the Run ID text. These are the tagging alerts (100300-100315).
2. **Query 2 — Search by time range:** Find ALL alerts that happened after the attacks started. These include real detection alerts that do not have the Run ID.
3. **Merge and deduplicate** the two result sets.

Then for each of the 15 attacks, it classifies alerts:

- **Tagging alert:** Rule ID is 100300-100315 AND the full log contains the attack's `tag_match` (e.g., `ssh_brute_force`)
- **Detection alert:** Rule ID is NOT 100300-100315 AND one of these matches:
  - The alert's rule groups match `detect_groups` (e.g., `["authentication_failed", "pam"]`)
  - The alert's description matches `detect_desc` (e.g., `["authentication failure", "incorrect password"]`)
  - The full log text matches `detect_log` (e.g., `["crontab"]`)

### Linux Results Explained

Our actual results were:

| Attack | Status | Why |
|--------|--------|-----|
| SSH Brute Force | DETECTED | Wazuh rule 5503 (PAM: User login failed) fired on the failed `su` attempts |
| Failed Auth Flood | DETECTED | Wazuh rule 5503/5301 fired on the failed `sudo -u nobody` attempts |
| Cron Job Persistence | DETECTED | Wazuh rule 2832 (Crontab entry changed) fired when crontab was modified |
| SUID Binary Abuse | LOGGED ONLY | No built-in SUID detection rule. FIM (File Integrity Monitoring) would need to cover `/opt/` |
| User Creation | LOGGED ONLY | Wazuh has rules 5901/5902 but the quick create-and-delete may be missed by agent 000 |
| SSH Key Injection | LOGGED ONLY | `/home/` is not in the default FIM scan scope |
| Systemd Backdoor | LOGGED ONLY | Attack writes to `/opt/attack_test/fake_systemd/`, not real `/etc/systemd/` |
| Bashrc Persistence | LOGGED ONLY | `/home/` is not in the default FIM scan scope |
| Log Tampering | LOGGED ONLY | Attack tampers with fake logs in `/opt/attack_test/`, not real `/var/log/` |
| Credential Dumping | LOGGED ONLY | FIM monitors file changes, not file reads. `cat /etc/shadow` does not modify anything |
| Sudoers Modification | LOGGED ONLY | FIM covers `/etc/` but only scans every 12 hours — attack finishes in seconds |
| Hosts File Modification | LOGGED ONLY | Same 12-hour FIM scan delay |
| Firewall Tampering | LOGGED ONLY | `iptables` commands produce no syslog entry |
| System Reconnaissance | LOGGED ONLY | Linux has no default command execution logging (unlike Windows) |
| Data Exfiltration | LOGGED ONLY | No built-in rule for `base64`, `gzip`, or data staging |

**Why "LOGGED ONLY" is correct:** These are genuine gaps in Wazuh's default configuration. Fixing them would require:
- Enabling FIM (File Integrity Monitoring) with `realtime="yes"` and expanding the scan scope
- Installing and configuring `auditd` (Linux Audit Daemon) to monitor file reads and command execution
- Writing custom Wazuh rules for specific attack patterns

---

## 9. The Three Detection Statuses

| Status | Color | Meaning |
|--------|-------|---------|
| **DETECTED** | Green | A real Wazuh detection rule fired. The security team would be alerted about this attack. |
| **LOGGED ONLY** | Yellow | The attack appears in the logs (our tagging rule caught it), but NO real Wazuh detection rule fired. This is a **detection gap** — the attack happened and left traces, but no alarm went off. |
| **NOT DETECTED** | Red | Nothing at all. No tagging alert, no detection alert. The attack is completely invisible. |

The key difference between "detected" and "logged only" is:

- **Detected** = a real Wazuh rule (like rule 5503 "PAM: User login failed") fired. A security analyst would see this alert in the Wazuh dashboard.
- **Logged only** = ONLY our custom tagging rules (100100/100200/100201 for web, 100300-100315 for Linux) fired. These rules exist only because WE installed them for testing. In a real production environment without our tagging rules, there would be zero alerts.

---

## 10. Backend Code Walkthrough

### app/main.py

This is the starting point of the server. It:

1. Loads environment variables from `.env` using `load_dotenv()`
2. Creates the FastAPI application
3. Adds CORS middleware (allows the browser to talk to the API)
4. Registers all API route files under their URL prefixes:
   - `/api/wazuh/*` → `app/routes/wazuh.py` (Attack Lab, alerts, validation)
   - `/api/detections/*` → detection management
   - `/api/mitre/*` → MITRE coverage
   - etc.
5. Serves the HTML files (homepage, login, frontend)

### app/wazuh_client.py

This file contains functions that talk to Wazuh. There are two connections:

**1. Wazuh Manager API (port 55000)** — Used for:
- `fetch_all_rules()` — Gets every detection rule loaded in Wazuh
- `fetch_agents()` — Gets the list of connected Wazuh agents

The Manager API uses token authentication:
```python
# Step 1: Send username/password to get a token
r = requests.post(f"{url}/security/user/authenticate", auth=(user, password))
token = r.json()["data"]["token"]

# Step 2: Use the token in all future requests
headers = {"Authorization": f"Bearer {token}"}
r = requests.get(f"{url}/rules", headers=headers)
```

**2. Wazuh Indexer / OpenSearch (port 9200)** — Used for:
- `fetch_alerts()` — Searches for alerts using OpenSearch queries

The Indexer uses basic authentication (username:password with every request) and returns alerts in JSON format. The function supports:
- `search` parameter — text search across all alert fields
- `time_from` parameter — only return alerts after a certain time
- `level` parameter — minimum alert level
- `agent_id` parameter — filter by agent

The function also has **retry logic** — if the connection fails, it waits 2 seconds and tries again (up to 3 times). This handles the flaky WSL2 network.

**Deduplication:** The function tracks `full_log` values in a `seen_logs` set. If the same log text appears in multiple alerts (which happens when archives are enabled), it skips the duplicates.

### app/routes/wazuh.py

This is the main file for the Attack Lab. It contains:

**Data definitions:**

- `_CUSTOM_TAG_RULES = {"100100", "100200", "100201"}` — Web tagging rule IDs
- `_LINUX_TAG_RULES = {str(i) for i in range(100300, 100316)}` — Linux tagging rule IDs (100300 through 100315)
- `_DVWA_ATTACKS` — List of 10 web attack definitions with `patterns` and `url_patterns`
- `_LINUX_ATTACKS` — List of 15 Linux attack definitions with `tag_match`, `detect_groups`, `detect_desc`, `detect_log`

**API Endpoints:**

| Endpoint | Method | What It Does |
|----------|--------|-------------|
| `/api/wazuh/alerts` | GET | Fetch live alerts from the Indexer |
| `/api/wazuh/agents` | GET | Fetch connected Wazuh agents |
| `/api/wazuh/run-attacks` | POST | Run the DVWA web attack script |
| `/api/wazuh/run-linux-attacks` | POST | Run the Linux attack script |
| `/api/wazuh/validate-live` | POST | Validate web attack detection coverage |
| `/api/wazuh/validate-linux` | POST | Validate Linux attack detection coverage |
| `/api/wazuh/import-compare` | POST | Compare Sigma rules vs Wazuh rules |
| `/api/wazuh/import-compare/report` | GET | Generate HTML gap analysis report |

**How `/run-linux-attacks` works:**

```python
@router.post("/run-linux-attacks")
async def run_linux_attacks(req: _RunLinuxReq):
    # 1. Find the attack script
    script = os.path.join(_PROJECT_ROOT, "attack_linux.py")

    # 2. Use the virtual environment's Python (so paramiko/httpx are available)
    venv_python = os.path.join(_PROJECT_ROOT, ".venv", "bin", "python3")
    python = venv_python if os.path.exists(venv_python) else "python3"

    # 3. Run the script as a subprocess with a 3-minute timeout
    cmd = [python, script, "--target", req.target]
    proc = await asyncio.create_subprocess_exec(*cmd, ...)
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)

    # 4. Extract the Run ID from the script's output
    m = re.search(r"WAZUH_LINUX_TEST_\d{8}_\d{6}", output)
    run_id = m.group()

    # 5. Load the JSON report if the script saved one
    report_path = f"linux_report_{run_id}.json"
    return {"run_id": run_id, "report": report}
```

### attack_dvwa.py

This script automates 10 DVWA attacks. Key features:

- Uses the `requests` library to send HTTP requests
- Logs into DVWA and gets a session cookie
- Sets security to "low" so attacks succeed
- Tags every request with the Run ID in the User-Agent header
- Handles CSRF tokens (DVWA uses tokens to prevent double-submission)
- Saves results to `dvwa_report_{RUN_ID}.json`

Example attack (SQL Injection):
```python
# The attack sends this URL to DVWA:
# /dvwa/vulnerabilities/sqli/?id=1' OR 1=1 UNION SELECT user,password FROM users--&Submit=Submit
```

### attack_linux.py

This script automates 15 Linux attacks via SSH. Key features:

- Uses `paramiko` library for SSH connections
- Uses `httpx` library to query the Wazuh Indexer directly
- Creates a safe working directory `/opt/attack_test/`
- Each attack function:
  1. Calls `log_attack(client, "Attack_Name")` to write a tagged syslog entry
  2. Runs the actual attack commands via SSH
  3. Returns an `AttackResult` object with success/failure and details
- Cleans up after dangerous attacks (deletes test users, removes SSH keys, etc.)

Example of how `log_attack` works:
```python
def log_attack(client, attack_name):
    ssh_run(client, f"logger -t ABSEGA_ATTACK '{RUN_ID} attack={attack_name}'")
```

This runs on the target VM:
```bash
logger -t ABSEGA_ATTACK 'WAZUH_LINUX_TEST_20260712_172857 attack=SSH_Brute_Force'
```

Which creates this syslog entry:
```
Jul 12 17:28:58 wazuh-server ABSEGA_ATTACK[12345]: WAZUH_LINUX_TEST_20260712_172857 attack=SSH_Brute_Force
```

Wazuh reads this and our custom rule 100301 fires.

---

## 11. Frontend Walkthrough

The frontend is a single HTML file (`frontend.html`) with embedded CSS and JavaScript. No frameworks — just plain HTML/CSS/JS.

### Attack Lab Section

The Attack Lab has two modes, selected by a dropdown:

**Web Attacks (DVWA) mode:**
- Target URL input (default: `http://127.0.0.1/dvwa`)
- "Run Web Attacks" button
- Shows progress and results

**Linux Attacks (SSH) mode:**
- Target host input (default: `192.168.36.128`)
- "Run Linux Attacks" button
- Shows progress and results

When you switch modes, the `laToggleAttackMode()` function:
1. Shows/hides the correct input fields
2. Syncs the validation category dropdown

### Wazuh Alerts Section

Shows the last 100 alerts from the Wazuh Indexer. You can:
- Filter by alert level
- Filter by agent
- Search by text or Run ID
- Auto-refreshes every 15 seconds

### Detection Rule Validation Section

Has a dropdown to choose "Web Attacks" or "Linux Attacks" and a "Validate Detection Rules" button. Calls the appropriate endpoint based on the selection:

```javascript
var category = document.getElementById('la-attack-category').value;
var endpoint = category === 'linux' ? '/api/wazuh/validate-linux' : '/api/wazuh/validate-live';
```

The `laRenderValidation()` function:
1. Shows summary tiles (alerts analyzed, attacks detected, logged only, not detected)
2. Shows a color legend explaining the three statuses
3. Renders a table with one row per attack, showing:
   - Attack name and severity
   - Status (DETECTED / LOGGED ONLY / NOT DETECTED)
   - Number of alerts
   - Which Wazuh rules fired (tagging rules shown in gray, detection rules in blue)
4. Uses `wr.is_tagging` from the backend response to mark tagging rules (not hardcoded)
5. Dynamically sets the table header to "DVWA Attack Coverage" or "Linux Attack Coverage"

---

## 12. Wazuh Gap Analysis Report

Besides the Attack Lab, the platform also generates a **Wazuh vs Sigma Gap Analysis Report**. This compares:

- Your Sigma detection rule library (stored in the SQLite database) against
- The rules loaded in your live Wazuh instance

It matches them by MITRE ATT&CK technique IDs and shows:

1. **Gaps in Wazuh** — Techniques your Sigma library covers but Wazuh has no rule for
2. **Gaps in your library** — Techniques Wazuh detects but your Sigma library has no rule for
3. **Covered by both** — Techniques where both systems have rules (your strongest areas)

Access it at: `/api/wazuh/import-compare/report`

---

## 13. How to Run the Platform

### Starting the server:

```bash
cd /home/kali/internship/Soc-project-main
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```

Then open `http://localhost:8001` in your browser.

### Before running attacks:

1. Make sure the VM is reachable:
   ```bash
   sudo ip link set eth1 up
   ping 192.168.36.128
   ```

2. For web attacks: DVWA must be running on the VM at `http://192.168.36.128/dvwa`

3. For Linux attacks: SSH must be running on the VM:
   ```bash
   # On the VM:
   sudo systemctl start ssh
   ```

### Running web attacks:

1. Go to Attack Lab
2. Select "Web Attacks (DVWA)"
3. Click "Run Web Attacks"
4. Wait ~30 seconds
5. Select "Web Attacks" in the validation dropdown
6. Click "Validate Detection Rules"

### Running Linux attacks:

1. Go to Attack Lab
2. Select "Linux Attacks (SSH)"
3. Click "Run Linux Attacks"
4. Wait ~45 seconds
5. Select "Linux Attacks" in the validation dropdown
6. Click "Validate Detection Rules"

---

## 14. Troubleshooting Common Issues

### "Network is unreachable" error

The WSL2 `eth1` network adapter went down. Fix:
```bash
sudo ip link set eth1 up
```

### "Address already in use" when starting the server

Another process is using the port. Either:
```bash
# Kill it
fuser -k 8001/tcp
# Or use a different port
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8002 --reload
```

### "ModuleNotFoundError: No module named 'httpx'" (or paramiko)

Install the missing package in the virtual environment:
```bash
.venv/bin/pip install httpx paramiko
```

### "Connection refused" on SSH

SSH server is not running on the VM:
```bash
# On the VM:
sudo apt install openssh-server -y
sudo systemctl start ssh
```

### Wazuh Manager fails to start after rule changes

Usually a syntax error in `/var/ossec/etc/rules/local_rules.xml`. Check:
```bash
# On the VM:
sudo journalctl -u wazuh-manager --no-pager | tail -20
```

Common issues:
- Duplicate rule IDs
- Nested `<group>` tags (each `<group>` must be properly closed)
- Missing closing `</group>` tag

### Alerts show as "0 alerts" right after running attacks

The Wazuh Indexer needs a few seconds to process and index the alerts. Wait 5-10 seconds and click the Refresh button.

---

## 15. Results Summary

### Web Attack Coverage (DVWA)

| Metric | Value |
|--------|-------|
| Attacks tested | 10 |
| Detected | 4 (40%) |
| Logged only (gaps) | 6 (60%) |
| Not detected | 0 (0%) |

**Detected attacks:** SQL Injection, XSS (DOM), XSS (Reflected), File Inclusion
**Gaps:** XSS (Stored), SQL Injection (Blind), Command Injection, File Upload, Brute Force, CSRF

### Linux Attack Coverage (SSH)

| Metric | Value |
|--------|-------|
| Attacks tested | 15 |
| Detected | 3 (20%) |
| Logged only (gaps) | 12 (80%) |
| Not detected | 0 (0%) |

**Detected attacks:** SSH Brute Force, Failed Auth Flood, Cron Job Persistence
**Gaps:** SUID Binary, User Creation, SSH Key Injection, Systemd Backdoor, Bashrc Persistence, Log Tampering, Credential Dumping, Sudoers Modification, Hosts Modification, Firewall Tampering, Reconnaissance, Data Exfiltration

### What This Means

Wazuh's default configuration is good at detecting:
- Attacks that generate syslog entries (failed logins, auth attempts, cron changes)
- Web attacks with clear signatures visible in GET request URLs

Wazuh's default configuration misses:
- POST-based web attacks (the body is not logged by Apache)
- File system changes unless FIM realtime monitoring is enabled
- File reads (like `cat /etc/shadow`) — FIM only monitors writes
- Command execution — Linux has no default process audit logging
- Network tool abuse (`iptables`, `base64`, `curl`) — no syslog output

These are not bugs — they are genuine detection gaps that can be fixed by enabling additional Wazuh features (FIM realtime scanning, auditd integration, custom decoders) or writing custom detection rules.

---

*This documentation was written for the ABSEGA Detection Engineering & Validation Platform internship project.*
