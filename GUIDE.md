# ABSEGA DVWA Attack Lab

A step-by-step guide to what this project does, how the button works, and how to set it up from scratch.

---

## Part 1: What We Built

We built a system that **attacks a practice website on purpose**, watches the logs that the attacks create, then **checks if our detection rules can spot each attack**. Everything runs with one button click.

There are four pieces working together:

### DVWA
A website that is built to be hacked. It has pages for SQL injection, XSS, file upload, command injection, and more. We attack this website on purpose to create logs.

### Wazuh
A security tool (SIEM) that watches log files on the server. When something happens, Wazuh creates an alert and saves it in a database called OpenSearch.

### ModSecurity
A firewall that sits in front of the web server. It logs the full content of every request, including what users type into forms (POST body). Apache logs alone don't capture this.

### ABSEGA Platform
Our web app (FastAPI + JavaScript). It has the button that runs the attacks, shows the alerts, and checks if our detection rules work.

### Why do we need ModSecurity?

Some attacks use GET requests — the attack payload is in the URL, so Apache's normal log captures it. But some attacks use POST requests — the payload is hidden in the request body (like a form submission). Apache does not log POST bodies. ModSecurity does. Without it, we can't detect Command Injection, File Upload, or Stored XSS.

### What is a "Run ID"?

Every time we run the attacks, the script creates a unique tag like `WAZUH_DVWA_TEST_20260706_203151`. This tag is put into every single request (in the User-Agent header and in the attack payloads). Later, we search for this tag to find only the alerts from this specific test run — not old alerts or other noise.

---

## Part 2: What Happens When You Press the Button

Here is every step, from the moment you click **"Run DVWA Attacks"** to the final results.

### Step 1 — You click "Run DVWA Attacks"

The browser sends a request to our backend: `POST /api/wazuh/run-attacks` with the DVWA target URL (for example `http://192.168.36.128/dvwa`).

### Step 2 — The backend runs the attack script

Our FastAPI server runs `attack_dvwa.py` as a separate process. The script creates a unique Run ID and starts working.

### Step 3 — The script logs into DVWA and runs 10 attacks

It logs in as admin, sets security to LOW, then runs each attack one by one:

| Attack | Method | What it does |
|--------|--------|-------------|
| Brute Force | GET | Tries 8 wrong passwords, then the right one |
| Command Injection | POST | Sends `127.0.0.1; echo TEST; id` to the ping form |
| CSRF | GET | Changes the password through the URL (no form needed) |
| File Inclusion (LFI) | GET | Tries to read `/etc/passwd` through path traversal |
| File Upload | POST | Uploads a PHP shell file, then accesses it |
| SQL Injection | GET | Uses `UNION SELECT` to dump the users table |
| SQL Injection (Blind) | GET | Uses `AND 1=1` vs `AND 1=2` to test true/false |
| XSS (DOM) | GET | Puts a `<script>` tag in the URL parameter |
| XSS (Reflected) | GET | Puts a `<script>` tag in the name field |
| XSS (Stored) | POST | Posts an `<img onerror=alert()>` to the guestbook |

Every request has the Run ID in the User-Agent header and in the payloads.

### Step 4 — The attacks create two types of logs on the server

**Apache access log** — records every request with the URL, method, and User-Agent. Good for GET attacks where the payload is in the URL. Does NOT capture POST body content.

**ModSecurity audit log** — records the full request including POST body data. This is how we catch Command Injection, File Upload, and Stored XSS payloads.

### Step 5 — Wazuh reads the logs and creates alerts

Wazuh is always watching these log files. When it sees a new line, it checks it against its rules:

- **Rule 100100** (level 3) — catches any Apache log line containing our Run ID tag. Creates one alert per web request.
- **Rule 100200** (level 0, silent) — matches any ModSecurity JSON log entry.
- **Rule 100201** (level 6) — child of 100200. Only fires when the ModSecurity log also contains our Run ID tag.
- **Built-in rules** (31101, 31106, etc.) — Wazuh's own web attack rules that catch things like 400 errors and successful attacks.

Each alert is saved to OpenSearch (the database) with a `full_log` field that contains the raw log line.

### Step 6 — The platform waits 10 seconds, then loads the alerts

After the attack script finishes, the frontend waits 10 seconds. This gives Wazuh time to read the logs, create alerts, and save them to OpenSearch. Then it searches OpenSearch for all alerts containing our Run ID.

### Step 7 — You click "Validate Detection Rules"

The browser sends `POST /api/wazuh/validate-live` with the Run ID. The backend fetches all alerts for that Run ID from OpenSearch.

### Step 8 — The backend tests 7 Sigma rules against every alert

For each alert, the backend:

1. Takes the `full_log` field (the raw log content)
2. URL-decodes it (turns `%3B` back into `;`, `%3C` back into `<`, etc.)
3. Tests each Sigma rule against it to see if the patterns match

The 7 Sigma rules look for specific strings in the log:

| Rule | Severity | What it looks for in the log |
|------|----------|------------------------------|
| SQL Injection | HIGH | `UNION SELECT`, `OR 1=1`, `AND 1=1` |
| XSS | HIGH | `<script>`, `onerror=`, `alert(` |
| Path Traversal / LFI | HIGH | `../`, `/etc/passwd` |
| Command Injection | CRITICAL | `; echo`, `; id`, `| cat` in POST body |
| File Upload | CRITICAL | `<?php` in body, or `.php` in `/uploads/` |
| Brute Force | MEDIUM | `/vulnerabilities/brute` + `Login=Login` |
| CSRF | MEDIUM | `password_new=` + `password_conf=` |

### Step 9 — You see the results

The frontend shows a summary: how many alerts were found, how many rules matched (7/7), and which specific alerts each rule matched. Any alerts that no rule caught are shown separately as "unmatched".

---

## Part 3: How to Set This Up From Scratch

Your friend needs two machines: an **Ubuntu VM** (runs DVWA + Wazuh + ModSecurity) and a **Kali machine** (runs the ABSEGA platform). They can be on the same network.

### A. Ubuntu VM — Install the software

- Install **Wazuh all-in-one** (Manager + Indexer + Dashboard) on the Ubuntu VM
- Install **DVWA** on Apache with PHP and MySQL
- Install **ModSecurity** with OWASP CRS (Core Rule Set)

### B. Ubuntu VM — Configure ModSecurity audit logging

ModSecurity needs to write its logs in JSON format. Edit the ModSecurity config:

```bash
sudo nano /etc/modsecurity/modsecurity.conf
```

Make sure these lines are set:

```
SecAuditEngine RelevantOnly
SecAuditLogFormat JSON
SecAuditLog /var/log/apache2/modsecurity_audit.json
```

Restart Apache:

```bash
sudo systemctl restart apache2
```

### C. Ubuntu VM — Tell Wazuh to read the ModSecurity log

Edit the Wazuh config:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add this inside the `<ossec_config>` block:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/apache2/modsecurity_audit.json</location>
</localfile>
```

### D. Ubuntu VM — Add custom Wazuh rules

We need 3 custom rules so Wazuh creates alerts for our tagged requests. Run this command:

```bash
echo '<group name="local,web,dvwa_test,">
  <rule id="100100" level="3">
    <if_sid>31100</if_sid>
    <match>WAZUH_DVWA_TEST</match>
    <description>DVWA test: tagged web request</description>
    <group>web,dvwa_test,</group>
  </rule>
</group>

<group name="local,modsecurity,web,">
  <rule id="100200" level="0">
    <decoded_as>json</decoded_as>
    <match>modsecurity</match>
    <description>ModSecurity JSON audit base</description>
  </rule>
  <rule id="100201" level="6">
    <if_sid>100200</if_sid>
    <match>WAZUH_DVWA_TEST</match>
    <description>ModSecurity: DVWA attack test detected</description>
    <group>modsecurity,web,dvwa_test,</group>
  </rule>
</group>' | sudo tee -a /var/ossec/etc/rules/local_rules.xml
```

**What do these rules do?**

- **Rule 100100** — catches every Apache access log line that has our test tag. This makes sure every request we send shows up as an alert.
- **Rule 100200** — a silent base rule (level 0 means no alert). It just identifies "this log came from ModSecurity" by matching the word "modsecurity" in the JSON.
- **Rule 100201** — child of 100200. When a ModSecurity log also contains our test tag, it creates an alert at level 6. This is how we get the POST body data into our alerts.

### E. Ubuntu VM — Make OpenSearch reachable from the network

By default, OpenSearch only listens on localhost. Your Kali machine needs to reach it:

```bash
sudo sed -i 's/^network.host:.*/network.host: 0.0.0.0/' /etc/wazuh-indexer/opensearch.yml
sudo systemctl restart wazuh-indexer
```

### F. Ubuntu VM — Restart Wazuh and get the passwords

```bash
sudo systemctl restart wazuh-manager
```

Your friend needs two sets of credentials. Here is exactly how to get each one.

---

### How to Get the .env Values

The `.env` file tells our platform how to talk to Wazuh and OpenSearch. You need to fill in 6 values. Here is exactly what each one is and how to find it.

> **Important:** All commands in this section should be run on the **Ubuntu VM** (the machine running Wazuh), unless it says otherwise.

---

#### 1. `WAZUH_URL` — Where is the Wazuh API?

This is your Ubuntu VM's IP address with port `55000` added to it.

**How to find your VM's IP address:**

Run this on the Ubuntu VM:

```bash
hostname -I
```

This prints your IP address. It will look something like `192.168.36.128`.

Now put `https://` in front and `:55000` at the end:

```
WAZUH_URL=https://192.168.36.128:55000
```

Replace `192.168.36.128` with whatever IP your VM has.

---

#### 2. `WAZUH_USER` — What username to log in with?

This is always the same. Wazuh creates this user when you install it:

```
WAZUH_USER=wazuh-wui
```

You don't need to change this.

---

#### 3. `WAZUH_PASSWORD` — What is the password for that user?

This password was shown on screen when you first installed Wazuh. If you saved that output, look for a line with `wazuh-wui` and the password next to it.

**If you don't have it saved, here is how to find it:**

Run this on the Ubuntu VM:

```bash
sudo cat /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
```

Look at the output. You will see something like:

```
hosts:
  - default:
      url: https://localhost
      port: 55000
      username: wazuh-wui
      password: THE_PASSWORD_IS_HERE
```

Copy the password value.

**If that file doesn't show a password, reset all passwords:**

```bash
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -a
```

This will print a big list. It looks like this:

```
The password for user admin is: AbCdEfGh123...
The password for user kibanaserver is: XyZaBcDe456...
The password for user wazuh-wui is: MnOpQrSt789...
```

**Write down ALL of these passwords.** You need:
- The `wazuh-wui` password → goes in `WAZUH_PASSWORD`
- The `admin` password → goes in `INDEXER_PASSWORD` (see below)
- The `kibanaserver` password → you need this to fix the Wazuh Dashboard (see below)

**After resetting passwords, fix the Wazuh Dashboard:**

The Dashboard needs the new `kibanaserver` password to work. Open this file:

```bash
sudo nano /etc/wazuh-dashboard/opensearch_dashboards.yml
```

Find the line that says `opensearch.password:` and replace the old password with the new `kibanaserver` password you wrote down. Save the file, then restart:

```bash
sudo systemctl restart wazuh-dashboard
```

---

#### 4. `INDEXER_URL` — Where is OpenSearch?

OpenSearch is the database that stores all the alerts. It runs on the same Ubuntu VM, but on port `9200`.

Use the same IP address as `WAZUH_URL`, just change the port:

```
INDEXER_URL=https://192.168.36.128:9200
```

---

#### 5. `INDEXER_USER` — What username for OpenSearch?

This is always the same:

```
INDEXER_USER=admin
```

You don't need to change this.

---

#### 6. `INDEXER_PASSWORD` — What is the password for OpenSearch?

This is the password for the `admin` user.

**Where to find it:**

- If you saved the output from when you installed Wazuh, look for the `admin` user's password
- If you ran the password reset tool (step 3 above), you already wrote it down — it's the `admin` password from that list

**How to check if you have the right password:**

Run this from your **Kali machine** (replace the IP and password):

```bash
curl -k -u admin:YOUR_PASSWORD_HERE https://192.168.36.128:9200
```

If the password is correct, you will see a JSON response with `"cluster_name" : "wazuh-cluster"`.

If you see `"Connection refused"`, go back to **Step E** and make sure OpenSearch is listening on `0.0.0.0`.

If you see `"Unauthorized"`, the password is wrong. Go back and check.

---

#### 7. `WAZUH_VERIFY_SSL` and `INDEXER_VERIFY_SSL` — Always `false`

Wazuh uses self-signed SSL certificates (not real ones from a company like Let's Encrypt). Python will refuse to connect unless we tell it to skip the certificate check. These two lines do that:

```
WAZUH_VERIFY_SSL=false
INDEXER_VERIFY_SSL=false
```

You don't need to change these.

---

### The complete .env file

Create a file called `.env` in the project folder (on the **Kali machine**). Put all the values together:

```
WAZUH_URL=https://YOUR_VM_IP:55000
WAZUH_USER=wazuh-wui
WAZUH_PASSWORD=YOUR_WAZUH_WUI_PASSWORD
WAZUH_VERIFY_SSL=false

INDEXER_URL=https://YOUR_VM_IP:9200
INDEXER_USER=admin
INDEXER_PASSWORD=YOUR_ADMIN_PASSWORD
INDEXER_VERIFY_SSL=false
```

Replace:
- `YOUR_VM_IP` → the IP address from step 1 (run `hostname -I` on the Ubuntu VM)
- `YOUR_WAZUH_WUI_PASSWORD` → the password from step 3
- `YOUR_ADMIN_PASSWORD` → the password from step 6

---

### G. Kali machine — Clone the project and install packages

```bash
cd ~/internship/Soc-project-main
pip install fastapi uvicorn requests pyyaml pySigma
```

### H. Kali machine — Start the server and test

```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open the browser, go to `http://<KALI_IP>:8000`, navigate to **Live Alerts**.

1. Set the DVWA target URL to `http://<UBUNTU_VM_IP>/dvwa`
2. Click **"Run DVWA Attacks"**
3. Wait for it to finish — it runs all 10 attacks, then waits 10 seconds for alerts to appear
4. The Run ID will be filled in automatically and alerts will load
5. Click **"Validate Detection Rules"** under Web Attacks
6. You should see **7/7 rules detected**

---

## Summary: The Big Picture

This project is a **detection engineering workflow**. We are not just attacking — we are testing whether our security tools can actually catch the attacks. The flow is:

**Attack → Create Logs → Wazuh Makes Alerts → Sigma Rules Check Alerts → See What We Caught**

If a detection rule misses something, we know there's a gap. We can then write better rules or add more log sources (like we did with ModSecurity to catch POST-based attacks).
