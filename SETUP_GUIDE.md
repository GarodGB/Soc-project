# ABSEGA Platform — Setup Guide

Follow these steps in order. Copy-paste every command.

---

## Step 1: Update the .env file with YOUR Wazuh credentials

Open the `.env` file in the project root and change these values to match YOUR setup:

```
WAZUH_URL=https://YOUR_WAZUH_IP:55000
WAZUH_USER=YOUR_WAZUH_API_USER
WAZUH_PASSWORD=YOUR_WAZUH_API_PASSWORD
WAZUH_VERIFY_SSL=false

INDEXER_URL=https://YOUR_WAZUH_IP:9200
INDEXER_USER=admin
INDEXER_PASSWORD=YOUR_INDEXER_PASSWORD
INDEXER_VERIFY_SSL=false

TARGET_HOST=YOUR_WAZUH_IP
TARGET_USER=YOUR_SSH_USERNAME
TARGET_PASSWORD=YOUR_SSH_PASSWORD
```

Replace `YOUR_WAZUH_IP` with the IP address of your Wazuh VM (e.g., `192.168.56.102`).

To find your Wazuh API credentials, check the Wazuh dashboard or look in `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml` on the Wazuh VM.

To find your Indexer password, check `/etc/wazuh-indexer/opensearch-security/internal_users.yml` or use the default `admin` user.

---

## Step 2: Install Python dependencies

```bash
cd Soc-project-main
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Step 3: Enable SSH on the Wazuh VM

On the Wazuh VM (open a terminal or console on the VM itself):

```bash
sudo apt update
sudo apt install openssh-server -y
sudo systemctl enable ssh
sudo systemctl start ssh
sudo systemctl status ssh
```

Verify SSH works from your machine:

```bash
ssh YOUR_SSH_USERNAME@YOUR_WAZUH_IP
```

---

## Step 4: Install DVWA on the Wazuh VM (needed for web attacks)

If DVWA is not already installed, run these on the Wazuh VM:

```bash
sudo apt update
sudo apt install apache2 php php-mysqli php-gd libapache2-mod-php mariadb-server -y
```

```bash
cd /var/www/html
sudo git clone https://github.com/digininja/DVWA.git dvwa
sudo chown -R www-data:www-data dvwa
sudo cp dvwa/config/config.inc.php.dist dvwa/config/config.inc.php
```

Edit the DVWA config:

```bash
sudo nano /var/www/html/dvwa/config/config.inc.php
```

Change these lines:
```
$_DVWA[ 'db_user' ]     = 'dvwa';
$_DVWA[ 'db_password' ] = 'dvwa';
$_DVWA[ 'db_database' ] = 'dvwa';
```

Set up the database:

```bash
sudo mysql -e "CREATE DATABASE IF NOT EXISTS dvwa;"
sudo mysql -e "CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'dvwa';"
sudo mysql -e "GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"
```

Enable Apache and restart:

```bash
sudo systemctl enable apache2
sudo systemctl restart apache2
```

Then open `http://YOUR_WAZUH_IP/dvwa/setup.php` in a browser and click "Create / Reset Database."

Login with `admin` / `password`.

---

## Step 5: Install ModSecurity on the Wazuh VM (needed for web attack detection)

```bash
sudo apt install libapache2-mod-security2 -y
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
```

Edit ModSecurity config:

```bash
sudo nano /etc/modsecurity/modsecurity.conf
```

Find the line `SecRuleEngine DetectionOnly` and make sure it says:
```
SecRuleEngine DetectionOnly
```

(DetectionOnly means it logs attacks but does not block them — DVWA needs the attacks to go through.)

Enable the OWASP Core Rule Set:

```bash
sudo apt install modsecurity-crs -y
sudo a2enmod security2
sudo systemctl restart apache2
```

Set up ModSecurity JSON audit logging so Wazuh can read it:

```bash
sudo nano /etc/modsecurity/modsecurity.conf
```

Find and set these lines:
```
SecAuditLog /var/log/apache2/modsec_audit.json
SecAuditLogFormat JSON
SecAuditLogType Serial
```

Restart Apache:

```bash
sudo systemctl restart apache2
```

Add the ModSecurity log to Wazuh agent config:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add this block inside the `<ossec_config>` section:

```xml
<localfile>
    <log_format>json</log_format>
    <location>/var/log/apache2/modsec_audit.json</location>
</localfile>
```

Restart Wazuh agent:

```bash
sudo systemctl restart wazuh-manager
```

---

## Step 6: Install the custom Wazuh tagging rules

On the Wazuh VM, edit the local rules file:

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Add ALL of the following rules. If the file already has content, add these BELOW the existing rules, but make sure each `<group>` block is properly opened and closed (not nested inside another group).

```xml
<group name="local,web,dvwa_test,">
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
</group>

<group name="absega_linux,">
  <rule id="100300" level="3">
    <program_name>ABSEGA_ATTACK</program_name>
    <description>ABSEGA Linux attack simulation detected</description>
  </rule>
  <rule id="100301" level="3">
    <if_sid>100300</if_sid>
    <match>attack=SSH_Brute_Force</match>
    <description>ABSEGA: SSH Brute Force attack simulation</description>
  </rule>
  <rule id="100302" level="3">
    <if_sid>100300</if_sid>
    <match>attack=Failed_Auth_Flood</match>
    <description>ABSEGA: Failed Auth Flood attack simulation</description>
  </rule>
  <rule id="100303" level="3">
    <if_sid>100300</if_sid>
    <match>attack=Cron_Job_Persistence</match>
    <description>ABSEGA: Cron Job Persistence attack simulation</description>
  </rule>
  <rule id="100304" level="3">
    <if_sid>100300</if_sid>
    <match>attack=SUID_Binary_Abuse</match>
    <description>ABSEGA: SUID Binary Abuse attack simulation</description>
  </rule>
  <rule id="100305" level="3">
    <if_sid>100300</if_sid>
    <match>attack=Unauthorized_User_Creation</match>
    <description>ABSEGA: Unauthorized User Creation attack simulation</description>
  </rule>
  <rule id="100306" level="3">
    <if_sid>100300</if_sid>
    <match>attack=SSH_Key_Injection</match>
    <description>ABSEGA: SSH Key Injection attack simulation</description>
  </rule>
  <rule id="100307" level="3">
    <if_sid>100300</if_sid>
    <match>attack=Systemd_Backdoor</match>
    <description>ABSEGA: Systemd Backdoor attack simulation</description>
  </rule>
  <rule id="100308" level="3">
    <if_sid>100300</if_sid>
    <match>attack=Bashrc_Persistence</match>
    <description>ABSEGA: Bashrc Persistence attack simulation</description>
  </rule>
  <rule id="100309" level="3">
    <if_sid>100300</if_sid>
    <match>attack=Log_Tampering</match>
    <description>ABSEGA: Log Tampering attack simulation</description>
  </rule>
  <rule id="100310" level="3">
    <if_sid>100300</if_sid>
    <match>attack=Credential_Dumping</match>
    <description>ABSEGA: Credential Dumping attack simulation</description>
  </rule>
  <rule id="100311" level="3">
    <if_sid>100300</if_sid>
    <match>attack=Sudoers_Modification</match>
    <description>ABSEGA: Sudoers Modification attack simulation</description>
  </rule>
  <rule id="100312" level="3">
    <if_sid>100300</if_sid>
    <match>attack=Hosts_File_Modification</match>
    <description>ABSEGA: Hosts File Modification attack simulation</description>
  </rule>
  <rule id="100313" level="3">
    <if_sid>100300</if_sid>
    <match>attack=Firewall_Tampering</match>
    <description>ABSEGA: Firewall Tampering attack simulation</description>
  </rule>
  <rule id="100314" level="3">
    <if_sid>100300</if_sid>
    <match>attack=System_Reconnaissance</match>
    <description>ABSEGA: System Reconnaissance attack simulation</description>
  </rule>
  <rule id="100315" level="3">
    <if_sid>100300</if_sid>
    <match>attack=Data_Exfiltration</match>
    <description>ABSEGA: Data Exfiltration attack simulation</description>
  </rule>
</group>
```

Save and restart Wazuh:

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

If it fails, check the error:
```bash
sudo journalctl -u wazuh-manager --no-pager | tail -20
```

The most common error is duplicate rule IDs or nested `<group>` tags.

---

## Step 7: Start the platform

Back on your machine (not the VM):

```bash
cd Soc-project-main
source .venv/bin/activate
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open in browser: `http://localhost:8000`

---

## Step 8: Test web attacks

1. Go to the **Attack Lab** tab
2. Select **"Web Attacks (DVWA)"**
3. Set the target to `http://YOUR_WAZUH_IP/dvwa`
4. Click **"Run Web Attacks"**
5. Wait ~30 seconds
6. Select **"Web Attacks"** in the validation dropdown
7. Click **"Validate Detection Rules"**

Expected results: 4/10 detected, 6/10 logged only.

---

## Step 9: Test Linux attacks

1. In the **Attack Lab**, select **"Linux Attacks (SSH)"**
2. Set the target to `YOUR_WAZUH_IP`
3. Click **"Run Linux Attacks"**
4. Wait ~45 seconds
5. Select **"Linux Attacks"** in the validation dropdown
6. Click **"Validate Detection Rules"**

Expected results: 3/15 detected, 12/15 logged only.

---

## Checklist

Before running, make sure:

- [ ] `.env` file has the correct IP, Wazuh API credentials, Indexer credentials, and SSH credentials
- [ ] Python venv is created and `requirements.txt` is installed
- [ ] Wazuh VM is running and reachable (`ping YOUR_WAZUH_IP`)
- [ ] SSH is enabled on the Wazuh VM
- [ ] DVWA is installed and accessible at `http://YOUR_WAZUH_IP/dvwa`
- [ ] ModSecurity is installed with JSON audit logging
- [ ] Wazuh is reading the ModSecurity log (`/var/log/apache2/modsec_audit.json`)
- [ ] Custom rules (100100-100201 and 100300-100315) are in `local_rules.xml`
- [ ] Wazuh Manager restarted successfully after adding rules
- [ ] The SSH user on the VM has `sudo` access (needed for Linux attacks)
