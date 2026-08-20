import re
import html
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from app.database import get_connection
from app.services.ad_catalog import mask_sensitive
from app.services.audit_service import log_audit
from app.services.auth_service import ROLE_ADMIN, current_actor, require_read_access, require_write_access
from app.wazuh_client import (
    fetch_all_rules, fetch_alerts, fetch_agents, indexer_pipeline_health, WazuhError,
)

import asyncio
import json as _json
import logging as _logging
import os
from urllib.parse import unquote_plus
from pydantic import BaseModel
from app.sigma_eval import (
    SigmaAggregationUnsupported,
    SigmaEvaluationError,
    evaluate_sigma_rule,
    evaluate_sigma_rule_over_events,
    has_aggregation_condition,
)
import yaml as _yaml

router = APIRouter(dependencies=[Depends(require_read_access)])

_TECH_RE = re.compile(r"[Tt](\d{4}(?:\.\d{3})?)")
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _script_python() -> str:
    """Interpreter used to launch the attack scripts. Prefer the project venv
    (which has paramiko/httpx/requests): Windows .venv\\Scripts\\python.exe,
    POSIX .venv/bin/python3; then the interpreter running this server; finally
    a bare 'python' on PATH."""
    import sys
    for p in (os.path.join(_PROJECT_ROOT, ".venv", "Scripts", "python.exe"),
              os.path.join(_PROJECT_ROOT, ".venv", "bin", "python3")):
        if os.path.exists(p):
            return p
    return sys.executable or "python"


class _RunAttacksReq(BaseModel):
    target: str = "http://127.0.0.1/dvwa"


class _ValidateReq(BaseModel):
    run_id: str
    agent_id: str = ""
    target: str = ""


WEB_ATTACK_RULES = []


def _normalize_ids(values) -> set:
    out = set()
    if values is None:
        return out
    if isinstance(values, str):
        values = [values]
    for v in values:
        if not v:
            continue
        for m in _TECH_RE.finditer(str(v)):
            out.add("T" + m.group(1))
    return out


def _wazuh_mitre_ids(rule: dict) -> set:
    mitre = rule.get("mitre") or {}
    ids = set()
    if isinstance(mitre, dict):
        ids |= _normalize_ids(mitre.get("id"))
        ids |= _normalize_ids(mitre.get("technique"))
    elif isinstance(mitre, list):
        ids |= _normalize_ids(mitre)
    return ids


def _attack_url(tid: str) -> str:
    if "." in tid:
        base, sub = tid.split(".", 1)
        return f"https://attack.mitre.org/techniques/{base}/{sub}/"
    return f"https://attack.mitre.org/techniques/{tid}/"


def _compare():
    """Full bidirectional comparison: Sigma ↔ Wazuh."""
    try:
        wazuh_rules = fetch_all_rules()
    except WazuhError as e:
        raise HTTPException(status_code=502, detail=f"Wazuh: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Wazuh connection error: {e}")

    # ── Wazuh side ──
    wazuh_ids = set()
    wazuh_by_technique = defaultdict(list)
    wazuh_with_mitre = 0
    for r in wazuh_rules:
        rule_ids = _wazuh_mitre_ids(r)
        if rule_ids:
            wazuh_with_mitre += 1
        wazuh_ids |= rule_ids
        for tid in rule_ids:
            wazuh_by_technique[tid].append({
                "rule_id": str(r.get("id", "")),
                "description": r.get("description", ""),
                "level": r.get("level", 0),
                "filename": r.get("filename", ""),
            })

    # ── Sigma/DB side ──
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT detection_id, title, tags, severity, status, platform FROM detections"
        ).fetchall()
        # Load MITRE technique names
        mitre_rows = conn.execute(
            "SELECT technique_id, name, tactic FROM mitre_techniques"
        ).fetchall()
    finally:
        conn.close()

    mitre_db = {}
    for mr in mitre_rows:
        mitre_db[mr["technique_id"]] = {"name": mr["name"], "tactic": mr["tactic"]}

    db_ids = set()
    db_by_technique = defaultdict(list)
    platform_counts = defaultdict(int)
    for row in rows:
        platform_counts[row["platform"] or "unknown"] += 1
        ids = _normalize_ids(row["tags"])
        if not ids:
            continue
        db_ids |= ids
        for tid in ids:
            db_by_technique[tid].append({
                "id":       str(row["detection_id"]),
                "title":    row["title"] or "",
                "severity": (row["severity"] or "").lower(),
                "status":   (row["status"] or "").lower(),
                "platform": (row["platform"] or "").lower(),
            })

    # ── Compute overlaps ──
    both = db_ids & wazuh_ids
    sigma_only = db_ids - wazuh_ids
    wazuh_only = wazuh_ids - db_ids
    all_techniques = db_ids | wazuh_ids

    # ── Build missing dicts ──
    missing_in_wazuh = {}
    for tid in sorted(sigma_only):
        missing_in_wazuh[tid] = sorted(db_by_technique[tid], key=lambda d: d["title"].lower())

    missing_in_sigma = {}
    for tid in sorted(wazuh_only):
        missing_in_sigma[tid] = sorted(wazuh_by_technique[tid], key=lambda d: d["description"].lower())

    summary = {
        "wazuh_rules_total":       len(wazuh_rules),
        "wazuh_with_mitre":        wazuh_with_mitre,
        "wazuh_mitre_ids":         len(wazuh_ids),
        "db_detections_total":     len(rows),
        "db_mitre_ids":            len(db_ids),
        "platform_counts":         dict(platform_counts),
        "both_count":              len(both),
        "sigma_only_count":        len(sigma_only),
        "wazuh_only_count":        len(wazuh_only),
        "total_unique_techniques": len(all_techniques),
        "missing_in_wazuh_rules":  sum(len(v) for v in missing_in_wazuh.values()),
        "missing_in_sigma_rules":  sum(len(v) for v in missing_in_sigma.values()),
    }
    return summary, missing_in_wazuh, missing_in_sigma, mitre_db, wazuh_by_technique, db_by_technique, both


@router.get("/alerts")
def get_alerts(
    request: Request,
    limit:    int = 50,
    offset:   int = 0,
    level:    int = None,
    agent_id: str = None,
    search:   str = None,
    archives: bool = False,
    time_from: str = None,
):
    """Fetch live alerts from Wazuh Manager, excluding our custom tagging rules.

    The exclusion is applied inside the Indexer query (not after the fact) so
    that ``limit`` reflects the number of real alerts returned, not the size
    of the raw fetch before tagging noise is stripped out.
    """
    try:
        data = fetch_alerts(limit=limit, offset=offset, level=level, agent_id=agent_id, search=search, include_archives=archives, time_from=time_from, exclude_rule_ids=_ALL_TAG_RULES)
        if current_actor(request).role != ROLE_ADMIN:
            data["alerts"] = [mask_sensitive(a) for a in data["alerts"]]
        data["total"] = len(data["alerts"])
        return data
    except WazuhError as e:
        raise HTTPException(status_code=502, detail=f"Wazuh: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Wazuh connection error: {e}")


@router.get("/pipeline-health")
def get_pipeline_health():
    """Is the Wazuh indexer actually able to write new alerts right now?

    Lets the UI tell a real detection gap apart from a stalled/disk-blocked
    indexer (the lab's flood-stage-watermark failure) before trusting a
    'nothing detected' result."""
    return indexer_pipeline_health()


@router.get("/agents")
def get_agents():
    """Fetch connected Wazuh agents."""
    try:
        return {"agents": fetch_agents()}
    except WazuhError as e:
        raise HTTPException(status_code=502, detail=f"Wazuh: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Wazuh connection error: {e}")


@router.post("/run-attacks", dependencies=[Depends(require_write_access)])
async def run_dvwa_attacks(req: _RunAttacksReq):
    """Run the DVWA attack script and return the report."""
    if not req.target.startswith(("http://", "https://")):
        raise HTTPException(400, "Target must be an HTTP URL")

    script = os.path.join(_PROJECT_ROOT, "attack_dvwa.py")
    if not os.path.exists(script):
        raise HTTPException(404, "attack_dvwa.py not found in project root")

    proc = await asyncio.create_subprocess_exec(
        _script_python(), script, "--target", req.target,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=_PROJECT_ROOT,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
    except asyncio.TimeoutError:
        proc.kill()
        raise HTTPException(504, "Attack script timed out")

    output = stdout.decode("utf-8", errors="replace")
    error_output = stderr.decode("utf-8", errors="replace")

    if proc.returncode != 0:
        detail = (error_output or output)[-1500:]
        raise HTTPException(502, f"Attack script failed: {detail}")

    m = re.search(r"WAZUH_DVWA_TEST_\d{8}_\d{6}", output)
    if not m:
        raise HTTPException(500, f"Script error: {error_output[:500]}")

    run_id = m.group()
    report = {}
    report_path = os.path.join(_PROJECT_ROOT, f"dvwa_report_{run_id}.json")
    if os.path.exists(report_path):
        with open(report_path) as f:
            report = _json.load(f)

    return {"run_id": run_id, "report": report}


_CUSTOM_TAG_RULES = {"100100", "100200", "100201"}

_LINUX_TAG_RULES = {str(i) for i in range(100300, 100316)}

_ALL_TAG_RULES = _CUSTOM_TAG_RULES | _LINUX_TAG_RULES

# Any ABSEGA custom rule ID (100000-100999) is one of our own tagging/tracking
# rules — a wide net so a tag rule with an unexpected ID can never be mistaken
# for a real detection.
_ABSEGA_RULE_RANGE = range(100000, 101000)

# Text that only ever appears in our own tagging rules, never in a genuine
# Wazuh detection rule.
_TRACKING_DESC_MARKERS = ("absega", "attack simulation")


def _is_tracking_alert(alert: dict) -> bool:
    """True when an alert fired only because Wazuh *saw* our attack-runner's
    tracking marker (the RUN_ID logged via `logger -t ABSEGA_ATTACK` or the
    RUN_ID User-Agent tag) rather than because it *detected* the attack.

    These prove traffic reached Wazuh, not that a detection rule caught the
    behaviour, so they must never count toward detection coverage.
    """
    rid = str(alert.get("rule_id", ""))
    if rid in _ALL_TAG_RULES:
        return True
    if rid.isdigit() and int(rid) in _ABSEGA_RULE_RANGE:
        return True
    desc = (alert.get("rule_description") or "").lower()
    return any(marker in desc for marker in _TRACKING_DESC_MARKERS)

_LINUX_ATTACKS = [
    # Detection criteria describe what a REAL Wazuh rule (not our tag rule) emits
    # when it catches the behaviour. An attack counts as detected only if one of:
    #   detect_groups  — alert's rule.groups intersect these (specific groups only)
    #   detect_desc    — substring appears in the rule description
    #   detect_cmd     — substring appears in full_log (sudo COMMAND=, auth line, …)
    #   detect_fim     — substring appears in syscheck.path (File Integrity Monitoring
    #                    of the EXACT changed file — never a bare "syscheck" group,
    #                    so a change to one file is not credited to every attack)
    # Attacks whose artefacts live under /opt/attack_test or a user's home and are
    # not FIM-monitored legitimately have no real detection — a genuine gap, not a
    # bug — and correctly report not_detected.
    {
        "id": "ssh-brute",
        "title": "SSH Brute Force",
        "severity": "medium",
        "tag_rule": "100301",
        "tag_match": "SSH_Brute_Force",
        "detect_groups": ["authentication_failed", "authentication_failures"],
        "detect_desc": ["authentication failed", "failed password",
                        "user login failed", "multiple failed"],
    },
    {
        "id": "cron-persist",
        "title": "Cron Job Persistence",
        "severity": "high",
        "tag_rule": "100303",
        "tag_match": "Cron_Job_Persistence",
        "detect_desc": ["crontab entry changed", "crontab"],
        "detect_cmd": ["(ubuntu) replace", "(root) replace", "crontab["],
    },
    {
        "id": "suid-binary",
        "title": "SUID Binary Abuse",
        "severity": "high",
        "tag_rule": "100304",
        "tag_match": "SUID_Binary_Abuse",
        "detect_cmd": ["chmod u+s", "chmod 4755", "chmod +s"],
        "detect_fim": ["suid_find"],
    },
    {
        "id": "user-creation",
        "title": "Unauthorized User Creation",
        "severity": "critical",
        "tag_rule": "100305",
        "tag_match": "Unauthorized_User_Creation",
        "detect_groups": ["adduser", "account_changed"],
        "detect_desc": ["new user added", "new group added"],
        "detect_cmd": ["/usr/sbin/useradd", "useradd -m"],
    },
    {
        "id": "ssh-key-inject",
        "title": "SSH Key Injection",
        "severity": "high",
        "tag_rule": "100306",
        "tag_match": "SSH_Key_Injection",
        "detect_fim": ["authorized_keys"],
    },
    {
        "id": "systemd-backdoor",
        "title": "Systemd Backdoor",
        "severity": "high",
        "tag_rule": "100307",
        "tag_match": "Systemd_Backdoor",
        "detect_fim": ["/etc/systemd/system", "backdoor.service", "system-health"],
        "detect_cmd": ["daemon-reload", "/etc/systemd/system"],
    },
    {
        "id": "bashrc-persist",
        "title": "Bashrc Persistence",
        "severity": "high",
        "tag_rule": "100308",
        "tag_match": "Bashrc_Persistence",
        "detect_fim": ["/.bashrc"],
    },
    {
        "id": "log-tamper",
        "title": "Log Tampering",
        "severity": "medium",
        "tag_rule": "100309",
        "tag_match": "Log_Tampering",
        "detect_desc": ["log file cleared", "syslog cleared"],
        "detect_cmd": ["truncate -s 0", "truncate -s0"],
        # FIM now watches the work dir + the user's shell history, so clearing
        # ~/.bash_history and staging a tampered auth.log both surface as real
        # syscheck changes.
        "detect_fim": ["/var/log/auth.log", "auth.log", "bash_history"],
    },
    {
        "id": "cred-dump",
        "title": "Credential Dumping",
        "severity": "critical",
        "tag_rule": "100310",
        "tag_match": "Credential_Dumping",
        "detect_cmd": ["cat /etc/shadow", "/bin/cat /etc/shadow",
                       "/usr/bin/cat /etc/shadow"],
    },
    {
        "id": "sudoers-mod",
        "title": "Sudoers Modification",
        "severity": "critical",
        "tag_rule": "100311",
        "tag_match": "Sudoers_Modification",
        "detect_fim": ["/etc/sudoers"],
        "detect_cmd": ["/etc/sudoers.d", "sudoers.d/"],
    },
    {
        "id": "hosts-mod",
        "title": "Hosts File Modification",
        "severity": "medium",
        "tag_rule": "100312",
        "tag_match": "Hosts_File_Modification",
        "detect_fim": ["/etc/hosts"],
        "detect_cmd": [">> /etc/hosts", "/etc/hosts"],
    },
    {
        "id": "firewall-tamper",
        "title": "Firewall Tampering",
        "severity": "high",
        "tag_rule": "100313",
        "tag_match": "Firewall_Tampering",
        "detect_desc": ["iptables", "firewall"],
        "detect_cmd": ["iptables -a", "iptables -i", "--dport 4444"],
    },
    {
        "id": "recon",
        "title": "System Reconnaissance",
        "severity": "low",
        "tag_rule": "100314",
        "tag_match": "System_Reconnaissance",
        "detect_desc": ["enumeration", "reconnaissance"],
        "detect_cmd": ["sudo -l", "sudo -s -l"],
    },
    {
        "id": "data-exfil",
        "title": "Data Exfiltration",
        "severity": "critical",
        "tag_rule": "100315",
        "tag_match": "Data_Exfiltration",
        "detect_cmd": ["exfil_", "gzip | base64", "| base64"],
    },
]

_DVWA_ATTACKS = [
    {
        "id": "sqli",
        "title": "SQL Injection",
        "severity": "high",
        "patterns": ["union select", "or 1=1", "from users--"],
        # trailing slash so this does not also match /vulnerabilities/sqli_blind/
        "url_patterns": ["vulnerabilities/sqli/"],
    },
    {
        "id": "sqli-blind",
        "title": "SQL Injection (Blind)",
        "severity": "high",
        "patterns": ["and 1=1", "and 1=2"],
        "url_patterns": ["sqli_blind"],
    },
    {
        "id": "xss-dom",
        "title": "XSS (DOM-based)",
        "severity": "high",
        "patterns": ["<script>"],
        "url_patterns": ["xss_d"],
    },
    {
        "id": "xss-reflected",
        "title": "XSS (Reflected)",
        "severity": "high",
        "patterns": ["<script>"],
        "url_patterns": ["xss_r"],
    },
    {
        "id": "xss-stored",
        "title": "XSS (Stored)",
        "severity": "high",
        "patterns": ["onerror=", "alert("],
        "url_patterns": ["xss_s"],
    },
    {
        "id": "cmdi",
        "title": "Command Injection",
        "severity": "critical",
        "patterns": ["; echo", "; id"],
        "url_patterns": ["vulnerabilities/exec"],
    },
    {
        "id": "lfi",
        "title": "File Inclusion / Path Traversal",
        "severity": "high",
        "patterns": ["../", "/etc/passwd"],
        "url_patterns": ["vulnerabilities/fi"],
    },
    {
        "id": "file-upload",
        "title": "Malicious File Upload",
        "severity": "critical",
        "patterns": ["<?php", "hackable/uploads"],
        "url_patterns": ["vulnerabilities/upload", "hackable/uploads"],
    },
    {
        "id": "brute-force",
        "title": "Brute Force Login",
        "severity": "medium",
        "patterns": ["login=login"],
        "url_patterns": ["vulnerabilities/brute"],
    },
    {
        "id": "csrf",
        "title": "CSRF (Password Change)",
        "severity": "medium",
        "patterns": ["password_new=", "password_conf="],
        "url_patterns": ["vulnerabilities/csrf"],
    },
]


# OWASP CRS rule IDs that fire on almost every request and do NOT indicate a real
# attack: protocol/host enforcement (920xxx) and the anomaly-score summaries
# (949110 / 980130 / 980140). A ModSecurity alert whose ONLY messages are these
# means CRS logged the request but did not catch an attack.
_CRS_NON_ATTACK_IDS = {"920350", "949110", "980130", "980140"}
_CRS_ID_RE = re.compile(r'\[id "(\d+)"\]')
_CRS_MSG_RE = re.compile(r'\[msg "([^"]+)"\]')


def _modsec_attack_hits(full_log: str):
    """Parse a ModSecurity audit-log alert (rule 100201). Returns
    ``(request_line, decoded_body, crs_text)`` only when OWASP CRS actually
    flagged an attack (an attack-category rule fired, not just the protocol
    warning / score summary). Returns None otherwise — including for benign
    requests that merely tripped the numeric-Host-header warning.

    This is what lets POST attacks (Command Injection, Stored XSS, File Upload)
    be validated: their payload lives in the request BODY, which standard Apache
    access logs drop but the ModSecurity audit log captures in full.
    """
    if not full_log.startswith("{"):
        return None
    try:
        j = _json.loads(full_log)
    except Exception:
        return None
    audit = j.get("audit_data") or {}
    messages = audit.get("messages") or []
    if isinstance(messages, str):
        messages = [messages]

    attack_msgs = []
    for m in messages:
        rid_match = _CRS_ID_RE.search(m)
        rid = rid_match.group(1) if rid_match else ""
        if rid and rid not in _CRS_NON_ATTACK_IDS:
            msg_match = _CRS_MSG_RE.search(m)
            attack_msgs.append((rid + " " + (msg_match.group(1) if msg_match else "")).lower())
    if not attack_msgs:
        return None  # CRS saw the request but did not detect an attack

    req = j.get("request") or {}
    request_line = req.get("request_line", "") or ""
    body = req.get("body", "")
    if isinstance(body, list):
        body = " ".join(str(b) for b in body)
    return request_line, unquote_plus(str(body)).lower(), " ".join(attack_msgs)


_WEB_SIGMA_MAP = {}
_WEB_SIGMA_BY_ID = {r["id"]: r for r in WEB_ATTACK_RULES}


def _saved_sigma_rule_for(conn, surface: str, attack_id: str) -> dict | None:
    """The most recently saved AI-generated Sigma rule for this attack, if any.

    ``/rule-suggestions/{id}/save-to-platform`` inserts an AI-drafted rule into
    ``detections`` tagged ``absega.surface.<surface>`` / ``absega.attack.<attack_id>``.
    Attack replay has to re-evaluate against that rule too — not just the
    hand-authored WEB_ATTACK_RULES catalog — or a rule a Detection Engineer just
    approved can never be confirmed to actually detect the attack it was
    written for, and the verdict never moves off WAZUH_ONLY/NO_DETECTION_IN_EITHER.
    """
    row = conn.execute(
        "SELECT detection_id, raw_yaml FROM detections "
        "WHERE tags LIKE %s AND tags LIKE %s AND status != 'rejected' "
        "AND raw_yaml IS NOT NULL AND raw_yaml != '' "
        "ORDER BY updated_at DESC, detection_id DESC LIMIT 1",
        (f"%absega.surface.{surface}%", f"%absega.attack.{attack_id}%"),
    ).fetchone()
    if not row:
        return None
    return {"id": f"detection-{row[0]}", "sigma": row[1]}

# Best-effort MITRE technique labels for the Recent Runs list — not used for
# any detection logic, purely informational.
_WEB_MITRE_MAP = {
    "sqli": "T1190", "sqli-blind": "T1190", "xss-dom": "T1190", "xss-reflected": "T1190",
    "xss-stored": "T1190", "cmdi": "T1190", "lfi": "T1190", "file-upload": "T1190",
    "brute-force": "T1110", "csrf": "T1190",
}
_LINUX_MITRE_MAP = {
    "ssh-brute": "T1110", "cron-persist": "T1053.003", "suid-binary": "T1548.001",
    "user-creation": "T1136", "ssh-key-inject": "T1098.004", "systemd-backdoor": "T1543.002",
    "bashrc-persist": "T1546.004", "log-tamper": "T1070.002", "cred-dump": "T1003",
    "sudoers-mod": "T1548.003", "hosts-mod": "T1565.001", "firewall-tamper": "T1562.004",
    "recon": "T1082", "data-exfil": "T1041",
}


def _persist_validation_result(surface: str, run_id: str, target: str, agent_id: str, results: list) -> None:
    """Persist one validate-live/validate-linux call into
    web_linux_validation_runs/web_linux_evidence, and annotate each item in
    ``results`` in place with verdict/sigma_supported/sigma_matched/evidence_count.

    Never invented: sigma_matched is only ever set from a real pySigma
    evaluation of a mapped rule. "Mapped" means either the hand-authored
    WEB_ATTACK_RULES catalog (web only) or a rule a Detection Engineer saved
    via save-to-platform for this surface/attack (see
    ``_saved_sigma_rule_for`` — this is how a freshly AI-generated rule gets
    re-evaluated on the next attack replay, and it's Linux's only path to any
    Sigma coverage at all). When no rule is mapped either way, that is a
    missing-content gap, not an evaluator limitation — Wazuh's own detection
    result is still a known fact, so the verdict falls back to WAZUH_ONLY /
    NO_DETECTION_IN_EITHER like any other real coverage gap. EVALUATOR_UNSUPPORTED
    is reserved for when a Sigma rule *is* mapped but the local evaluator could
    not run it against the captured event.

    This is best-effort — any failure here must never break the live JSON
    response the frontend already depends on.
    """
    mitre_map = _WEB_MITRE_MAP if surface == "web" else _LINUX_MITRE_MAP
    now = datetime.now(timezone.utc).isoformat()
    try:
        conn = get_connection()
        for r in results:
            attack_id = r["id"]
            wazuh_detected = r["status"] == "detected"
            wazuh_rule_ids = sorted({wr["rule_id"] for wr in r.get("wazuh_rules", [])})

            sigma_supported = False
            sigma_matched = None
            sigma_rule_ids: list = []

            sigma_id = None
            sigma_rule = None
            if surface == "web":
                sigma_id = _WEB_SIGMA_MAP.get(attack_id)
                sigma_rule = _WEB_SIGMA_BY_ID.get(sigma_id) if sigma_id else None

            # A Detection Engineer's saved rule always takes precedence over the
            # hand-authored catalog — it is the more current, human-approved
            # content, and it's the only path Linux has to any Sigma coverage.
            saved_rule = _saved_sigma_rule_for(conn, surface, attack_id)
            if saved_rule:
                sigma_id = saved_rule["id"]
                sigma_rule = saved_rule

            if sigma_rule:
                sigma_supported = True
                sigma_rule_ids = [sigma_id]
                sample_alerts = r.get("sample_alerts") or []
                if sample_alerts and has_aggregation_condition(sigma_rule["sigma"]):
                    # A `| count() by ... > N in Tm` rule (brute-force/threshold
                    # style) can never be satisfied by a single event — it needs
                    # the whole captured batch, grouped and counted.
                    events = [
                        _json.dumps({
                            "full_log": unquote_plus(alert.get("full_log", "")),
                            "timestamp": alert.get("timestamp"),
                        })
                        for alert in sample_alerts if alert.get("full_log")
                    ]
                    try:
                        outcome = evaluate_sigma_rule_over_events(sigma_rule["sigma"], events)
                        sigma_matched = bool(outcome.get("matched"))
                    except (SigmaEvaluationError, SigmaAggregationUnsupported):
                        sigma_matched = None
                elif sample_alerts:
                    # An attack run captures several events (recon, the actual
                    # modification, verification, ...) and sample_alerts[0] is
                    # only ever the first one chronologically — not necessarily
                    # the one that represents the attack. A Sigma rule watching
                    # this event stream would fire if ANY captured event
                    # matches, so evaluate against all of them, not just the
                    # first.
                    sigma_matched = False
                    evaluated = False
                    for alert in sample_alerts:
                        raw_log = alert.get("full_log", "")
                        if not raw_log:
                            continue
                        sample_event = _json.dumps({"full_log": unquote_plus(raw_log)})
                        try:
                            outcome = evaluate_sigma_rule(sigma_rule["sigma"], sample_event)
                        except SigmaEvaluationError:
                            continue
                        evaluated = True
                        if outcome.get("matched"):
                            sigma_matched = True
                            break
                    if not evaluated:
                        sigma_matched = None
                else:
                    sigma_matched = False

            if not sigma_supported:
                verdict = "WAZUH_ONLY" if wazuh_detected else "NO_DETECTION_IN_EITHER"
            elif sigma_matched is None:
                verdict = "EVALUATOR_UNSUPPORTED"
            elif wazuh_detected and sigma_matched:
                verdict = "VERIFIED_OVERLAP"
            elif wazuh_detected and not sigma_matched:
                verdict = "WAZUH_ONLY"
            elif not wazuh_detected and sigma_matched:
                verdict = "SIGMA_ONLY"
            else:
                verdict = "NO_DETECTION_IN_EITHER"

            evidence_rows = r.get("sample_alerts") or []

            r["verdict"] = verdict
            r["sigma_supported"] = sigma_supported
            r["sigma_matched"] = sigma_matched
            r["sigma_rule_ids"] = sigma_rule_ids
            r["evidence_count"] = len(evidence_rows)

            conn.execute(
                """INSERT INTO web_linux_validation_runs
                   (run_id, surface, attack_id, attack_name, mitre_technique, target,
                    source_ip, started_at, ended_at, execution_status, wazuh_detected,
                    wazuh_rule_ids_json, sigma_supported, sigma_matched, sigma_rule_ids_json,
                    verdict, evidence_count, created_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT(run_id, attack_id) DO UPDATE SET
                     wazuh_detected=excluded.wazuh_detected,
                     wazuh_rule_ids_json=excluded.wazuh_rule_ids_json,
                     sigma_supported=excluded.sigma_supported,
                     sigma_matched=excluded.sigma_matched,
                     sigma_rule_ids_json=excluded.sigma_rule_ids_json,
                     verdict=excluded.verdict,
                     evidence_count=excluded.evidence_count,
                     ended_at=excluded.ended_at
                """,
                (run_id, surface, attack_id, r.get("title"), mitre_map.get(attack_id), target or None,
                 agent_id or None, now, now, "EXECUTED", int(wazuh_detected),
                 _json.dumps(wazuh_rule_ids), int(sigma_supported),
                 (None if sigma_matched is None else int(sigma_matched)),
                 _json.dumps(sigma_rule_ids), verdict, len(evidence_rows), now),
            )
            conn.execute("DELETE FROM web_linux_evidence WHERE run_id=%s AND attack_id=%s", (run_id, attack_id))
            for a in evidence_rows:
                conn.execute(
                    """INSERT INTO web_linux_evidence
                       (run_id, attack_id, wazuh_rule_id, rule_description, rule_level,
                        full_log, agent_id, agent_name, event_timestamp, imported_at)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (run_id, attack_id, a.get("rule_id"), a.get("description"), a.get("rule_level"),
                     a.get("full_log"), a.get("agent_id"), a.get("agent_name"), a.get("timestamp"), now),
                )
        conn.commit()
        conn.close()
    except Exception:
        _logging.getLogger(__name__).exception(
            "web/linux validation persistence failed (surface=%s run_id=%s)", surface, run_id)


@router.post("/validate-live", dependencies=[Depends(require_write_access)])
def validate_live_alerts(req: _ValidateReq):
    """Validate detection coverage per DVWA attack type.

    Fetches all Wazuh alerts since the attack run, filters OUT our custom
    tagging rules (100100/100200/100201), and checks which attack types
    have real Wazuh detection alerts.

    Two statuses:
      detected     — a real Wazuh rule fired an alert for this attack
      not_detected — no alert exists for this attack (detection gap)
    """
    if not req.run_id:
        raise HTTPException(400, "run_id is required")

    m = re.search(r"(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})", req.run_id)
    if not m:
        raise HTTPException(400, "Cannot parse timestamp from run_id")
    time_from = f"{m.group(1)}-{m.group(2)}-{m.group(3)}T{m.group(4)}:{m.group(5)}:{m.group(6)}Z"

    try:
        data = fetch_alerts(limit=500, time_from=time_from, level=5,
                            agent_id=req.agent_id or None)
    except WazuhError as e:
        raise HTTPException(502, f"Wazuh: {e}")

    all_alerts = data.get("alerts", [])

    _REQ_LINE_RE = re.compile(
        r'(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/',
        re.IGNORECASE,
    )

    run_id_lc = req.run_id.lower()

    real_alerts = []
    table_alerts = []
    for alert in all_alerts:
        full_log = alert.get("full_log") or ""
        rule_id = str(alert.get("rule_id", ""))

        modsec = _modsec_attack_hits(full_log)
        if modsec:
            request_line, body_decoded, crs_text = modsec
            m_url = _REQ_LINE_RE.search(request_line)
            req_url = unquote_plus(m_url.group(1)).lower() if m_url else request_line.lower()
            request_content = f"{req_url} {body_decoded} {crs_text}"
            display = f"{request_line}  |  OWASP CRS: {crs_text}"
            is_modsec = True
        else:
            if _is_tracking_alert(alert):
                continue
            m_url = _REQ_LINE_RE.search(full_log)
            req_url = unquote_plus(m_url.group(1)).lower() if m_url else ""
            if full_log.startswith("{"):
                try:
                    log_json = _json.loads(full_log)
                    req_part = log_json.get("request", {})
                    body = req_part.get("body", "")
                    if isinstance(body, list):
                        body = " ".join(str(b) for b in body)
                    request_content = req_url + " " + unquote_plus(body).lower()
                except Exception:
                    request_content = req_url
            else:
                request_content = unquote_plus(full_log).lower()
            display = full_log
            is_modsec = False

        request_content = request_content.replace(run_id_lc, "")
        req_url = req_url.replace(run_id_lc, "")

        real_alerts.append({
            "rule_id": rule_id,
            "rule_description": alert.get("rule_description", ""),
            "rule_level": alert.get("rule_level", 0),
            "full_log": full_log,
            "display": display,
            "decoded": request_content,
            "request_url": req_url,
            "is_modsec": is_modsec,
            "agent_id": alert.get("agent_id"),
            "agent_name": alert.get("agent_name"),
            "timestamp": alert.get("timestamp"),
        })
        table_alerts.append(alert)

    claimed = set()
    results = []
    for attack in _DVWA_ATTACKS:
        candidates = []
        url_pats = attack.get("url_patterns")
        patterns = attack.get("patterns")

        for idx, a in enumerate(real_alerts):
            if idx in claimed:
                continue
            url_ok = (not url_pats) or any(p in a["request_url"] for p in url_pats)
            if a["is_modsec"]:
                if url_ok:
                    candidates.append((idx, a))
                continue
            pat_ok = (not patterns) or any(p in a["decoded"] for p in patterns)
            if url_ok and pat_ok:
                candidates.append((idx, a))

        seen_urls = set()
        matched = []
        for idx, a in candidates:
            url = a["request_url"]
            if url and url in seen_urls:
                continue
            if url:
                seen_urls.add(url)
            matched.append(a)
            claimed.add(idx)

        seen_rules = {}
        for a in matched:
            rid = a["rule_id"]
            if rid not in seen_rules:
                seen_rules[rid] = a["rule_description"]

        results.append({
            "id": attack["id"],
            "title": attack["title"],
            "severity": attack["severity"],
            "status": "detected" if matched else "not_detected",
            "total_alerts": len(matched),
            "wazuh_rules": [{"rule_id": rid, "description": desc}
                            for rid, desc in seen_rules.items()],
            "sample_alerts": [
                {"rule_id": a["rule_id"],
                 "rule_level": a.get("rule_level", 0),
                 "description": a["rule_description"],
                 "full_log": a.get("display") or a["full_log"],
                 "agent_id": a.get("agent_id"),
                 "agent_name": a.get("agent_name"),
                 "timestamp": a.get("timestamp")}
                for a in matched
            ],
        })

    detected = sum(1 for r in results if r["status"] == "detected")
    not_detected = sum(1 for r in results if r["status"] == "not_detected")

    matched_table_alerts = [table_alerts[i] for i in sorted(claimed)]

    _persist_validation_result("web", req.run_id, req.target, req.agent_id, results)

    # When nothing was detected, distinguish a genuine gap from a stalled/blocked
    # indexer so the UI never reports a misleading all-clear zero.
    pipeline_health = None
    if detected == 0:
        pipeline_health = indexer_pipeline_health(window_from=time_from)

    return {
        "run_id": req.run_id,
        "total_alerts": len(all_alerts),
        "real_alerts": len(matched_table_alerts),
        "attacks_tested": len(results),
        "attacks_detected": detected,
        "attacks_not_detected": not_detected,
        "results": results,
        "table_alerts": matched_table_alerts,
        "pipeline_health": pipeline_health,
    }


class _RunLinuxReq(BaseModel):
    target: str = ""


@router.post("/run-linux-attacks", dependencies=[Depends(require_write_access)])
async def run_linux_attacks(req: _RunLinuxReq):
    """Run the Linux attack script via SSH against the target."""
    script = os.path.join(_PROJECT_ROOT, "attack_linux.py")
    if not os.path.exists(script):
        raise HTTPException(404, "attack_linux.py not found in project root")

    cmd = [_script_python(), script]
    if req.target:
        cmd += ["--target", req.target]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=_PROJECT_ROOT,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
    except asyncio.TimeoutError:
        proc.kill()
        raise HTTPException(504, "Linux attack script timed out")

    output = stdout.decode()
    m = re.search(r"WAZUH_LINUX_TEST_\d{8}_\d{6}", output)
    if not m:
        raise HTTPException(500, f"Script error: {stderr.decode()[:500]}")

    run_id = m.group()
    report = {}
    report_path = os.path.join(_PROJECT_ROOT, f"linux_report_{run_id}.json")
    if os.path.exists(report_path):
        with open(report_path) as f:
            report = _json.load(f)

    return {"run_id": run_id, "report": report}


@router.post("/validate-linux", dependencies=[Depends(require_write_access)])
def validate_linux_alerts(req: _ValidateReq):
    """Validate detection coverage per Linux attack type.

    Fetches all Wazuh alerts since the attack run, filters OUT our custom
    tagging rules (100300-100315), and checks which attack types have
    real Wazuh detection alerts.

    Two statuses:
      detected     — a real Wazuh rule fired an alert for this attack
      not_detected — no alert exists for this attack (detection gap)
    """
    if not req.run_id:
        raise HTTPException(400, "run_id is required")

    m = re.search(r"(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})", req.run_id)
    if not m:
        raise HTTPException(400, "Cannot parse timestamp from run_id")
    time_from = f"{m.group(1)}-{m.group(2)}-{m.group(3)}T{m.group(4)}:{m.group(5)}:{m.group(6)}Z"

    try:
        # Level floor of 3 (Wazuh's default minimum stored level) so genuine but
        # low-level detections are NOT dropped — e.g. rule 5402 "Successful sudo
        # to ROOT executed" (level 3) is the primary evidence for most privileged
        # Linux attacks. The old level=5 floor silently discarded them, which is
        # why every Linux attack reported not-detected.
        data = fetch_alerts(limit=500, time_from=time_from, level=3,
                            agent_id=req.agent_id or None)
    except WazuhError as e:
        raise HTTPException(502, f"Wazuh: {e}")

    all_alerts = data.get("alerts", [])

    run_id_lc = req.run_id.lower()

    real_alerts = []
    table_alerts = []
    for alert in all_alerts:
        if _is_tracking_alert(alert):
            continue
        full_log_raw = alert.get("full_log") or ""
        full_log_lc = full_log_raw.lower().replace(run_id_lc, "")
        real_alerts.append({
            "rule_id": str(alert.get("rule_id", "")),
            "rule_description": alert.get("rule_description", ""),
            "rule_level": alert.get("rule_level", 0),
            "full_log": full_log_lc,
            "full_log_raw": full_log_raw,
            "rule_groups": [g.lower() for g in (alert.get("rule_groups") or [])],
            "rule_desc_lower": (alert.get("rule_description") or "").lower(),
            "syscheck_path": (alert.get("syscheck_path") or "").lower(),
            "agent_id": alert.get("agent_id"),
            "agent_name": alert.get("agent_name"),
            "timestamp": alert.get("timestamp"),
        })
        table_alerts.append(alert)

    claimed = set()
    results = []
    for attack in _LINUX_ATTACKS:
        matched = []
        detect_groups = {g.lower() for g in attack.get("detect_groups", [])}
        detect_desc = [d.lower() for d in attack.get("detect_desc", [])]
        detect_cmd = [c.lower() for c in attack.get("detect_cmd", [])]
        detect_fim = [f.lower() for f in attack.get("detect_fim", [])]

        for idx, a in enumerate(real_alerts):
            if idx in claimed:
                continue
            hit = False
            if detect_groups and any(g in detect_groups for g in a["rule_groups"]):
                hit = True
            elif detect_desc and any(d in a["rule_desc_lower"] for d in detect_desc):
                hit = True
            elif detect_cmd and a["full_log"] and any(c in a["full_log"] for c in detect_cmd):
                hit = True
            elif detect_fim and a["syscheck_path"] and any(f in a["syscheck_path"] for f in detect_fim):
                hit = True
            if hit:
                matched.append(a)
                claimed.add(idx)

        seen_rules = {}
        for a in matched:
            rid = a["rule_id"]
            if rid not in seen_rules:
                seen_rules[rid] = a["rule_description"]

        results.append({
            "id": attack["id"],
            "title": attack["title"],
            "severity": attack["severity"],
            "status": "detected" if matched else "not_detected",
            "total_alerts": len(matched),
            "wazuh_rules": [{"rule_id": rid, "description": desc}
                            for rid, desc in seen_rules.items()],
            "sample_alerts": [
                {"rule_id": a["rule_id"],
                 "rule_level": a.get("rule_level", 0),
                 "description": a["rule_description"],
                 # FIM alerts have no full_log — surface the changed file instead.
                 "full_log": (a.get("full_log_raw")
                              or (f"File Integrity Monitoring: {a['syscheck_path']}"
                                  if a["syscheck_path"] else "")
                              or a["full_log"]),
                 "agent_id": a.get("agent_id"),
                 "agent_name": a.get("agent_name"),
                 "timestamp": a.get("timestamp")}
                for a in matched
            ],
        })

    detected = sum(1 for r in results if r["status"] == "detected")
    not_detected = sum(1 for r in results if r["status"] == "not_detected")

    matched_table_alerts = [table_alerts[i] for i in sorted(claimed)]

    _persist_validation_result("linux", req.run_id, req.target, req.agent_id, results)

    pipeline_health = None
    if detected == 0:
        pipeline_health = indexer_pipeline_health(window_from=time_from)

    return {
        "run_id": req.run_id,
        "total_alerts": len(all_alerts),
        "real_alerts": len(matched_table_alerts),
        "attacks_tested": len(results),
        "attacks_detected": detected,
        "attacks_not_detected": not_detected,
        "results": results,
        "table_alerts": matched_table_alerts,
        "pipeline_health": pipeline_health,
    }


@router.post("/import-compare", dependencies=[Depends(require_write_access)])
def import_and_compare():
    summary, missing_in_wazuh, missing_in_sigma, mitre_db, _, _, _ = _compare()
    return {
        "summary": summary,
        "missing_in_wazuh": missing_in_wazuh,
        "missing_in_sigma": {tid: rules for tid, rules in missing_in_sigma.items()},
    }


@router.get("/import-compare/report", response_class=HTMLResponse)
def import_and_compare_report():
    summary, missing_in_wazuh, missing_in_sigma, mitre_db, wazuh_by_technique, db_by_technique, both = _compare()
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    return HTMLResponse(content=_render_report(
        summary, missing_in_wazuh, missing_in_sigma, mitre_db,
        wazuh_by_technique, db_by_technique, both, generated_at
    ))


# ── Wazuh Rule Import ────────────────────────────────────────────────────────

def _wazuh_level_to_severity(level: int) -> str:
    if level >= 13:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    if level >= 4:
        return "low"
    return "informational"


def _wazuh_groups_to_platform(groups: list) -> str:
    g = " ".join(g.lower() for g in (groups or []))
    if any(k in g for k in ("windows", "sysmon", "powershell", "win_")):
        return "windows"
    if any(k in g for k in ("linux", "syslog", "sshd", "pam", "unix")):
        return "linux"
    if any(k in g for k in ("web", "apache", "nginx", "ids", "modsecurity")):
        return "network"
    return "windows"


def _delete_imported_wazuh(conn):
    """Remove all previously imported Wazuh rules from the database."""
    ids = [
        row[0] for row in conn.execute(
            "SELECT detection_id FROM detections WHERE author = 'Wazuh (imported)'"
        ).fetchall()
    ]
    if not ids:
        return 0
    placeholders = ",".join(["%s"] * len(ids))
    conn.execute(
        f"DELETE FROM detection_technique_mapping WHERE detection_id IN ({placeholders})", ids
    )
    conn.execute(
        f"DELETE FROM detection_telemetry WHERE detection_id IN ({placeholders})", ids
    )
    conn.execute(
        f"DELETE FROM validation_cases WHERE detection_id IN ({placeholders})", ids
    )
    conn.execute(
        f"DELETE FROM detections WHERE detection_id IN ({placeholders})", ids
    )
    return len(ids)


@router.delete("/import-rules")
def delete_wazuh_rules(actor=Depends(require_write_access)):
    """Delete all previously imported Wazuh rules."""
    conn = get_connection()
    try:
        deleted = _delete_imported_wazuh(conn)
        conn.commit()
        log_audit(actor, "delete", "imported_wazuh_rules", detail=f"{deleted} detections deleted")
        return {"deleted": deleted}
    finally:
        conn.close()


@router.post("/import-rules")
def import_wazuh_rules(actor=Depends(require_write_access)):
    """Delete any previously imported Wazuh rules, then import a fresh set."""
    try:
        wazuh_rules = fetch_all_rules()
    except WazuhError as e:
        raise HTTPException(status_code=502, detail=f"Wazuh: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Wazuh connection error: {e}")

    conn = get_connection()
    try:
        deleted = _delete_imported_wazuh(conn)
        conn.commit()

        known_techniques = set()
        for row in conn.execute(
            "SELECT technique_id FROM mitre_techniques"
        ).fetchall():
            known_techniques.add(row["technique_id"])

        imported = 0
        mitre_mapped = 0

        for r in wazuh_rules:
            rule_id = str(r.get("id", ""))
            description = r.get("description", "") or ""
            level = r.get("level", 0) or 0
            groups = r.get("groups", []) or []
            filename = r.get("filename", "") or ""
            status_raw = r.get("status", "") or ""

            title = description

            mitre_ids = _wazuh_mitre_ids(r)
            if not mitre_ids:
                continue
            tags = ", ".join(f"attack.{tid.lower()}" for tid in sorted(mitre_ids))

            mitre_block = r.get("mitre") or {}
            tactics = []
            if isinstance(mitre_block, dict):
                tactics = mitre_block.get("tactic", []) or []

            severity = _wazuh_level_to_severity(level)
            platform = _wazuh_groups_to_platform(groups)
            det_status = "stable" if status_raw == "enabled" else "test"

            details = r.get("details") or {}
            details_lines = []
            for dk, dv in details.items():
                if isinstance(dv, dict):
                    pat = dv.get("pattern", "")
                    dtype = dv.get("type", "")
                    details_lines.append(f"  {dk}: {pat}" + (f" ({dtype})" if dtype else ""))
                elif dv == "":
                    details_lines.append(f"  {dk}")
                else:
                    details_lines.append(f"  {dk}: {dv}")

            rule_logic = (
                f"Wazuh Rule ID: {rule_id}\n"
                f"Level: {level}\n"
                f"Groups: {', '.join(groups)}\n"
                f"File: {filename}\n"
                f"\nDetection Logic:\n" + "\n".join(details_lines)
            )
            if tactics:
                rule_logic += f"\n\nMITRE Tactics: {', '.join(tactics)}"

            pci = r.get("pci_dss") or []
            nist = r.get("nist_800_53") or []
            gdpr_list = r.get("gdpr") or []
            if pci:
                rule_logic += f"\nPCI DSS: {', '.join(pci)}"
            if nist:
                rule_logic += f"\nNIST 800-53: {', '.join(nist)}"
            if gdpr_list:
                rule_logic += f"\nGDPR: {', '.join(gdpr_list)}"

            raw_json = _json.dumps(r, default=str)

            cur = conn.execute("""
                INSERT INTO detections
                  (title, description, severity, status, platform,
                   author, falsepositives, raw_yaml, tags, rule_logic,
                   updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now()::text)
                RETURNING detection_id
            """, (
                title,
                description,
                severity,
                det_status,
                platform,
                "Wazuh (imported)",
                "",
                raw_json,
                tags,
                rule_logic,
            ))
            det_id = cur.fetchone()[0]

            for tid in mitre_ids:
                if tid in known_techniques:
                    conn.execute("""
                        INSERT INTO detection_technique_mapping
                          (detection_id, technique_id)
                        VALUES (%s, %s)
                    """, (det_id, tid))
                    mitre_mapped += 1

            imported += 1

        conn.commit()

        skipped = len(wazuh_rules) - imported

        log_audit(actor, "import", "imported_wazuh_rules",
                  detail=f"{imported} imported, {deleted} old deleted, {skipped} skipped (no MITRE mapping)")

        return {
            "imported": imported,
            "deleted_old": deleted,
            "total_wazuh_rules": len(wazuh_rules),
            "skipped_no_mitre": skipped,
            "mitre_mappings_created": mitre_mapped,
        }
    finally:
        conn.close()


# ── Coverage Comparison ──────────────────────────────────────────────────────

@router.get("/compare-coverage")
def compare_coverage():
    """Full bidirectional Sigma ↔ Wazuh comparison with rule-content analysis."""

    try:
        wazuh_api_rules = fetch_all_rules()
    except WazuhError as e:
        raise HTTPException(status_code=502, detail=f"Wazuh: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Wazuh connection error: {e}")

    conn = get_connection()
    try:
        sigma_rows = conn.execute(
            "SELECT detection_id, title, tags, severity, status, platform, raw_yaml "
            "FROM detections "
            "WHERE author != 'Wazuh (imported)' OR author IS NULL"
        ).fetchall()

        mitre_rows = conn.execute(
            "SELECT technique_id, name, tactic, description, url FROM mitre_techniques"
        ).fetchall()
    finally:
        conn.close()

    mitre_db = {}
    for r in mitre_rows:
        mitre_db[r["technique_id"]] = {
            "name": r["name"],
            "tactic": r["tactic"],
            "description": r["description"] or "",
            "url": r["url"] or "",
        }

    # ── Wazuh side: extract rules + patterns ──
    wazuh_with_mitre_count = 0
    wazuh_no_mitre_count = 0
    wazuh_by_tech = defaultdict(list)
    wazuh_techs = set()
    for r in wazuh_api_rules:
        mitre_ids = _wazuh_mitre_ids(r)
        if mitre_ids:
            wazuh_with_mitre_count += 1
            wazuh_techs |= mitre_ids
            info = _extract_wazuh_rule_info(r)
            for tid in mitre_ids:
                wazuh_by_tech[tid].append(info)
        else:
            wazuh_no_mitre_count += 1

    # ── Sigma side: extract rules + patterns ──
    sigma_by_tech = defaultdict(list)
    sigma_no_mitre = 0
    for r in sigma_rows:
        ids = _normalize_ids(r["tags"])
        if not ids:
            sigma_no_mitre += 1
            continue
        sigma_info = _extract_sigma_rule_info(r["raw_yaml"] or "")
        for tid in ids:
            sigma_by_tech[tid].append({
                "id": str(r["detection_id"]),
                "title": r["title"] or "",
                "severity": r["severity"] or "medium",
                "platform": r["platform"] or "windows",
                "patterns": sigma_info.get("patterns", set()),
            })
    sigma_techs = set(sigma_by_tech.keys())

    # ── Set operations ──
    both_techs_set = sigma_techs & wazuh_techs
    sigma_only_set = sigma_techs - wazuh_techs
    wazuh_only_set = wazuh_techs - sigma_techs
    all_techs = sigma_techs | wazuh_techs

    def _make_entry(tid, verdict, pattern_cmp=None, note=""):
        info = mitre_db.get(tid, {"name": tid, "tactic": "Unknown",
                                   "description": "", "url": ""})
        s_rules = sigma_by_tech.get(tid, [])
        w_rules = wazuh_by_tech.get(tid, [])
        sev_counts = {}
        for rule in s_rules:
            s = rule["severity"]
            sev_counts[s] = sev_counts.get(s, 0) + 1

        entry = {
            "technique_id": tid,
            "name": info["name"],
            "tactic": info["tactic"],
            "description": info["description"],
            "url": info["url"],
            "verdict": verdict,
            "note": note,
            "sigma_count": len(s_rules),
            "wazuh_count": len(w_rules),
            "severity_breakdown": sev_counts,
            "sigma_rules": [
                {"id": r["id"], "title": r["title"], "severity": r["severity"],
                 "platform": r["platform"],
                 "searches_for": sorted(r.get("patterns", set()))[:10]}
                for r in s_rules[:10]
            ],
            "wazuh_rules": [
                {"rule_id": r["rule_id"], "description": r["description"],
                 "level": r["level"],
                 "searches_for": sorted(r.get("patterns", set()))[:10]}
                for r in w_rules[:10]
            ],
        }
        if pattern_cmp:
            entry["pattern_comparison"] = pattern_cmp
        return entry

    # ── Analyse techniques where both have rules ──
    covered_list = []
    partial_list = []
    content_gap_list = []
    for tid in sorted(both_techs_set):
        all_sigma_pats = set()
        for sr in sigma_by_tech[tid]:
            all_sigma_pats |= sr.get("patterns", set())
        all_wazuh_pats = set()
        for wr in wazuh_by_tech[tid]:
            all_wazuh_pats |= wr.get("patterns", set())

        pattern_cmp = _find_shared_patterns(all_sigma_pats, all_wazuh_pats)
        verdict = _decide_verdict(pattern_cmp)
        note = _build_note(verdict, pattern_cmp)
        entry = _make_entry(tid, verdict, pattern_cmp, note)

        if verdict == "COVERED":
            covered_list.append(entry)
        elif verdict == "PARTIAL":
            partial_list.append(entry)
        else:
            content_gap_list.append(entry)

    # ── Techniques only one side has ──
    sigma_only_list = []
    for tid in sorted(sigma_only_set):
        sigma_only_list.append(_make_entry(
            tid, "NO WAZUH RULES",
            note="Wazuh has NO rules for this technique."))

    wazuh_only_list = []
    for tid in sorted(wazuh_only_set):
        wazuh_only_list.append(_make_entry(
            tid, "NO SIGMA RULES",
            note="We have no Sigma rules for this technique."))

    return {
        "summary": {
            "wazuh_total_rules": len(wazuh_api_rules),
            "wazuh_with_mitre": wazuh_with_mitre_count,
            "wazuh_no_mitre": wazuh_no_mitre_count,
            "wazuh_techniques": len(wazuh_techs),
            "sigma_total_rules": len(sigma_rows),
            "sigma_with_mitre": len(sigma_rows) - sigma_no_mitre,
            "sigma_no_mitre": sigma_no_mitre,
            "sigma_techniques": len(sigma_techs),
            "both_techniques": len(both_techs_set),
            "sigma_only_techniques": len(sigma_only_set),
            "wazuh_only_techniques": len(wazuh_only_set),
            "all_techniques": len(all_techs),
            "covered_count": len(covered_list),
            "partial_count": len(partial_list),
            "content_gap_count": len(content_gap_list),
        },
        "covered": covered_list,
        "partial": partial_list,
        "content_gap": content_gap_list,
        "sigma_only": sigma_only_list,
        "wazuh_only": wazuh_only_list,
    }


# ── HTML Report ───────────────────────────────────────────────────────────────

_SEV_COLORS = {
    "critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04",
    "low": "#16a34a", "informational": "#0891b2",
}

_LEVEL_LABELS = {
    range(0, 4): "Info", range(4, 7): "Low", range(7, 10): "Medium",
    range(10, 13): "High", range(13, 16): "Critical",
}


def _sev_badge(sev: str) -> str:
    color = _SEV_COLORS.get(sev, "#6b7280")
    label = html.escape(sev.upper() if sev else "—")
    return (f'<span style="display:inline-block;padding:2px 8px;border-radius:10px;'
            f'background:{color};color:#fff;font-size:11px;font-weight:600;'
            f'letter-spacing:.3px">{label}</span>')


def _level_badge(level) -> str:
    level = int(level) if level else 0
    label = "Info"
    color = "#0891b2"
    if level >= 13:
        label, color = "Critical", "#dc2626"
    elif level >= 10:
        label, color = "High", "#ea580c"
    elif level >= 7:
        label, color = "Medium", "#ca8a04"
    elif level >= 4:
        label, color = "Low", "#16a34a"
    return (f'<span style="display:inline-block;padding:2px 8px;border-radius:10px;'
            f'background:{color};color:#fff;font-size:11px;font-weight:600">'
            f'Lv{level} {label}</span>')


def _platform_badge(platform: str) -> str:
    colors = {"windows": "#0078d4", "linux": "#e95420", "identity": "#8b5cf6"}
    color = colors.get(platform, "#6b7280")
    label = html.escape(platform.upper() if platform else "—")
    return (f'<span style="display:inline-block;padding:2px 8px;border-radius:10px;'
            f'background:{color};color:#fff;font-size:11px;font-weight:600">{label}</span>')


def _status_badge(status: str) -> str:
    label = html.escape((status or "—").upper())
    return (f'<span style="display:inline-block;padding:2px 8px;border-radius:10px;'
            f'background:#1f2937;color:#cbd5e1;font-size:11px;font-weight:500;'
            f'border:1px solid #334155">{label}</span>')


def _render_report(summary, missing_in_wazuh, missing_in_sigma, mitre_db,
                   wazuh_by_technique, db_by_technique, both, generated_at):
    s = summary
    pc = s.get("platform_counts", {})

    # Coverage percentages
    if s["total_unique_techniques"] > 0:
        both_pct = round(100 * s["both_count"] / s["total_unique_techniques"])
        sigma_only_pct = round(100 * s["sigma_only_count"] / s["total_unique_techniques"])
        wazuh_only_pct = round(100 * s["wazuh_only_count"] / s["total_unique_techniques"])
    else:
        both_pct = sigma_only_pct = wazuh_only_pct = 0

    # ── Tiles ──
    tiles_html = f'''
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:24px">
      <div class="tile" style="border-left-color:#0ea5e9">
        <div class="tile-label">Wazuh Rules Loaded</div>
        <div class="tile-value" style="color:#0ea5e9">{s["wazuh_rules_total"]:,}</div>
        <div class="tile-sub">{s["wazuh_with_mitre"]:,} have MITRE tags</div>
      </div>
      <div class="tile" style="border-left-color:#8b5cf6">
        <div class="tile-label">Sigma Platform Rules</div>
        <div class="tile-value" style="color:#8b5cf6">{s["db_detections_total"]:,}</div>
        <div class="tile-sub">Win {pc.get("windows",0)} · Linux {pc.get("linux",0)} · Identity {pc.get("identity",0)}</div>
      </div>
      <div class="tile" style="border-left-color:#16a34a">
        <div class="tile-label">Techniques in Both</div>
        <div class="tile-value" style="color:#16a34a">{s["both_count"]}</div>
        <div class="tile-sub">{both_pct}% of {s["total_unique_techniques"]} total techniques</div>
      </div>
      <div class="tile" style="border-left-color:#f59e0b">
        <div class="tile-label">Wazuh Unique Techniques</div>
        <div class="tile-value" style="color:#f59e0b">{s["wazuh_mitre_ids"]}</div>
        <div class="tile-sub">{s["wazuh_only_count"]} not in your platform</div>
      </div>
      <div class="tile" style="border-left-color:#a855f7">
        <div class="tile-label">Sigma Unique Techniques</div>
        <div class="tile-value" style="color:#a855f7">{s["db_mitre_ids"]}</div>
        <div class="tile-sub">{s["sigma_only_count"]} not in Wazuh</div>
      </div>
      <div class="tile" style="border-left-color:#ef4444">
        <div class="tile-label">Total Gaps (Both Sides)</div>
        <div class="tile-value" style="color:#ef4444">{s["sigma_only_count"] + s["wazuh_only_count"]}</div>
        <div class="tile-sub">{s["sigma_only_count"]} Wazuh gaps + {s["wazuh_only_count"]} Sigma gaps</div>
      </div>
    </div>'''

    # ── Coverage bar ──
    bar_html = f'''
    <div class="section" style="margin-bottom:24px">
      <div style="font-size:15px;font-weight:700;color:#f1f5f9;margin-bottom:16px">
        MITRE ATT&CK Technique Coverage — {s["total_unique_techniques"]} Total Unique Techniques
      </div>
      <div style="display:flex;height:36px;border-radius:8px;overflow:hidden;margin-bottom:12px">
        <div style="width:{both_pct}%;background:#16a34a;display:flex;align-items:center;justify-content:center;
                    color:#fff;font-size:12px;font-weight:700">{s["both_count"]} Both</div>
        <div style="width:{sigma_only_pct}%;background:#3b82f6;display:flex;align-items:center;justify-content:center;
                    color:#fff;font-size:12px;font-weight:700">{s["sigma_only_count"]} Sigma Only</div>
        <div style="width:{wazuh_only_pct}%;background:#f59e0b;display:flex;align-items:center;justify-content:center;
                    color:#fff;font-size:12px;font-weight:700">{s["wazuh_only_count"]} Wazuh Only</div>
      </div>
      <div style="display:flex;gap:24px;font-size:12px;color:#94a3b8">
        <span><span style="display:inline-block;width:12px;height:12px;background:#16a34a;border-radius:3px;
               margin-right:6px;vertical-align:middle"></span>Covered by Both — no action needed</span>
        <span><span style="display:inline-block;width:12px;height:12px;background:#3b82f6;border-radius:3px;
               margin-right:6px;vertical-align:middle"></span>Sigma Only — Wazuh is missing these (deploy to SIEM)</span>
        <span><span style="display:inline-block;width:12px;height:12px;background:#f59e0b;border-radius:3px;
               margin-right:6px;vertical-align:middle"></span>Wazuh Only — Platform is missing these (add Sigma rules)</span>
      </div>
    </div>'''

    # ── How to read ──
    howto_html = '''
    <div class="section" style="margin-bottom:24px;line-height:1.7;font-size:13px;color:#cbd5e1">
      <b style="color:#f1f5f9;font-size:14px">How to Read This Report</b><br><br>
      This report compares your <b style="color:#8b5cf6">ABSEGA Detection Platform</b> (Sigma rules)
      against your live <b style="color:#0ea5e9">Wazuh SIEM</b> by matching MITRE ATT&CK technique IDs.<br><br>
      <b style="color:#3b82f6">Section 1 — Gaps in Wazuh (Sigma Only)</b><br>
      MITRE techniques your platform has Sigma rules for, but Wazuh has <b>no matching rule</b>.
      These are attacks your platform can describe but your SIEM would miss in production.
      <b>Action:</b> Consider deploying these as custom Wazuh rules or decoders.<br><br>
      <b style="color:#f59e0b">Section 2 — Gaps in Platform (Wazuh Only)</b><br>
      MITRE techniques Wazuh actively detects, but your Sigma platform has <b>no rule for</b>.
      Your SIEM catches these attacks, but they are not documented in your detection library.
      <b>Action:</b> Consider writing Sigma rules for these to complete your library.<br><br>
      <b style="color:#16a34a">Section 3 — Covered by Both</b><br>
      Techniques where both systems have rules. These are your strongest areas.
    </div>'''

    # ── SECTION 1: Gaps in Wazuh (Sigma has, Wazuh doesn't) ──
    section1_html = ""
    if missing_in_wazuh:
        toc1 = "".join(
            f'<a href="#wazuh-{html.escape(tid)}" class="toc-link">'
            f'{html.escape(tid)} <span style="color:#94a3b8">·{len(dets)}</span></a>'
            for tid, dets in missing_in_wazuh.items()
        )
        cards1 = ""
        for tid, dets in missing_in_wazuh.items():
            tech_info = mitre_db.get(tid, {"name": "Unknown", "tactic": "Unknown"})
            rows_html = "".join(
                f'''<tr style="border-bottom:1px solid #1f2937">
                  <td style="padding:10px 12px;color:#94a3b8;font-family:monospace;font-size:12px">#{html.escape(d["id"])}</td>
                  <td style="padding:10px 12px;color:#e2e8f0;font-size:13px">{html.escape(d["title"])}</td>
                  <td style="padding:10px 12px">{_platform_badge(d["platform"])}</td>
                  <td style="padding:10px 12px">{_sev_badge(d["severity"])}</td>
                  <td style="padding:10px 12px">{_status_badge(d["status"])}</td>
                </tr>''' for d in dets
            )
            cards1 += f'''
            <section id="wazuh-{html.escape(tid)}" class="card">
              <header class="card-header">
                <div style="display:flex;align-items:baseline;gap:14px;flex-wrap:wrap">
                  <a href="{_attack_url(tid)}" target="_blank" rel="noreferrer" class="tech-id">{html.escape(tid)}</a>
                  <span style="color:#e2e8f0;font-size:14px;font-weight:600">{html.escape(tech_info["name"])}</span>
                  <span style="color:#64748b;font-size:12px">Tactic: {html.escape(tech_info["tactic"])}</span>
                </div>
                <div style="display:flex;align-items:center;gap:10px">
                  <span style="color:#94a3b8;font-size:12px">{len(dets)} rule{"s" if len(dets)!=1 else ""}</span>
                  <span class="badge-missing">WAZUH MISSING</span>
                </div>
              </header>
              <table style="width:100%;border-collapse:collapse">
                <thead><tr style="background:#0b1220">
                  <th class="th">Rule ID</th><th class="th">Title</th><th class="th">Platform</th>
                  <th class="th">Severity</th><th class="th">Status</th>
                </tr></thead>
                <tbody>{rows_html}</tbody>
              </table>
            </section>'''

        section1_html = f'''
        <div class="section-header" style="border-left-color:#3b82f6">
          <div style="font-size:20px;font-weight:700;color:#f1f5f9">
            Gaps in Wazuh — Your SIEM is Missing These
          </div>
          <div style="color:#94a3b8;font-size:13px;margin-top:4px">
            {len(missing_in_wazuh)} MITRE techniques ({s["missing_in_wazuh_rules"]} Sigma rules)
            your platform covers but Wazuh has no detection for.
            Your SIEM would not alert on these attacks.
          </div>
        </div>
        <div class="toc">{toc1}</div>
        {cards1}'''
    else:
        section1_html = '''
        <div class="section-header" style="border-left-color:#3b82f6">
          <div style="font-size:20px;font-weight:700;color:#f1f5f9">Gaps in Wazuh</div>
        </div>
        <div class="success-box">✓ No gaps — Wazuh covers every MITRE technique in your platform.</div>'''

    # ── SECTION 2: Gaps in Sigma (Wazuh has, Sigma doesn't) ──
    section2_html = ""
    if missing_in_sigma:
        toc2 = "".join(
            f'<a href="#sigma-{html.escape(tid)}" class="toc-link">'
            f'{html.escape(tid)} <span style="color:#94a3b8">·{len(rules)}</span></a>'
            for tid, rules in missing_in_sigma.items()
        )
        cards2 = ""
        for tid, rules in missing_in_sigma.items():
            tech_info = mitre_db.get(tid, {"name": "Unknown", "tactic": "Unknown"})
            rows_html = "".join(
                f'''<tr style="border-bottom:1px solid #1f2937">
                  <td style="padding:10px 12px;color:#94a3b8;font-family:monospace;font-size:12px">#{html.escape(str(r["rule_id"]))}</td>
                  <td style="padding:10px 12px;color:#e2e8f0;font-size:13px">{html.escape(r["description"])}</td>
                  <td style="padding:10px 12px">{_level_badge(r["level"])}</td>
                  <td style="padding:10px 12px;color:#64748b;font-size:12px">{html.escape(r["filename"])}</td>
                </tr>''' for r in rules[:20]  # cap at 20 to keep report manageable
            )
            more_note = ""
            if len(rules) > 20:
                more_note = f'<div style="padding:10px 12px;color:#64748b;font-size:12px;text-align:center">… and {len(rules)-20} more rules</div>'
            cards2 += f'''
            <section id="sigma-{html.escape(tid)}" class="card">
              <header class="card-header" style="border-bottom-color:#1f2937">
                <div style="display:flex;align-items:baseline;gap:14px;flex-wrap:wrap">
                  <a href="{_attack_url(tid)}" target="_blank" rel="noreferrer" class="tech-id" style="color:#fbbf24">{html.escape(tid)}</a>
                  <span style="color:#e2e8f0;font-size:14px;font-weight:600">{html.escape(tech_info["name"])}</span>
                  <span style="color:#64748b;font-size:12px">Tactic: {html.escape(tech_info["tactic"])}</span>
                </div>
                <div style="display:flex;align-items:center;gap:10px">
                  <span style="color:#94a3b8;font-size:12px">{len(rules)} Wazuh rule{"s" if len(rules)!=1 else ""}</span>
                  <span class="badge-sigma-missing">PLATFORM MISSING</span>
                </div>
              </header>
              <table style="width:100%;border-collapse:collapse">
                <thead><tr style="background:#0b1220">
                  <th class="th">Wazuh Rule ID</th><th class="th">Description</th>
                  <th class="th">Level</th><th class="th">Source File</th>
                </tr></thead>
                <tbody>{rows_html}</tbody>
              </table>
              {more_note}
            </section>'''

        section2_html = f'''
        <div class="section-header" style="border-left-color:#f59e0b;margin-top:40px">
          <div style="font-size:20px;font-weight:700;color:#f1f5f9">
            Gaps in Platform — Wazuh Detects These But Your Library Doesn't
          </div>
          <div style="color:#94a3b8;font-size:13px;margin-top:4px">
            {len(missing_in_sigma)} MITRE techniques ({s["missing_in_sigma_rules"]} Wazuh rules)
            your SIEM actively detects but your Sigma library has no rule for.
            Consider adding Sigma rules for full documentation.
          </div>
        </div>
        <div class="toc">{toc2}</div>
        {cards2}'''
    else:
        section2_html = '''
        <div class="section-header" style="border-left-color:#f59e0b;margin-top:40px">
          <div style="font-size:20px;font-weight:700;color:#f1f5f9">Gaps in Platform</div>
        </div>
        <div class="success-box">✓ No gaps — Your platform covers every MITRE technique Wazuh detects.</div>'''

    # ── SECTION 3: Covered by Both ──
    both_rows_html = ""
    for tid in sorted(both):
        tech_info = mitre_db.get(tid, {"name": "Unknown", "tactic": "Unknown"})
        sigma_count = len(db_by_technique.get(tid, []))
        wazuh_count = len(wazuh_by_technique.get(tid, []))
        both_rows_html += f'''<tr style="border-bottom:1px solid #1f2937">
          <td style="padding:8px 12px;font-family:monospace;color:#4ade80;font-weight:700;font-size:13px">
            <a href="{_attack_url(tid)}" target="_blank" rel="noreferrer" style="color:#4ade80;text-decoration:none">{html.escape(tid)}</a>
          </td>
          <td style="padding:8px 12px;color:#e2e8f0;font-size:13px">{html.escape(tech_info["name"])}</td>
          <td style="padding:8px 12px;color:#64748b;font-size:12px">{html.escape(tech_info["tactic"])}</td>
          <td style="padding:8px 12px;text-align:center;color:#60a5fa;font-weight:600">{sigma_count}</td>
          <td style="padding:8px 12px;text-align:center;color:#fbbf24;font-weight:600">{wazuh_count}</td>
        </tr>'''

    section3_html = f'''
    <div class="section-header" style="border-left-color:#16a34a;margin-top:40px">
      <div style="font-size:20px;font-weight:700;color:#f1f5f9">
        Covered by Both — Strongest Detection Areas
      </div>
      <div style="color:#94a3b8;font-size:13px;margin-top:4px">
        {len(both)} MITRE techniques are detected by both your Sigma platform and Wazuh SIEM. No action needed.
      </div>
    </div>
    <div class="card" style="overflow:hidden">
      <table style="width:100%;border-collapse:collapse">
        <thead><tr style="background:#0b1220">
          <th class="th">Technique</th><th class="th">Name</th><th class="th">Tactic</th>
          <th class="th" style="text-align:center">Sigma Rules</th>
          <th class="th" style="text-align:center">Wazuh Rules</th>
        </tr></thead>
        <tbody>{both_rows_html}</tbody>
      </table>
    </div>'''

    # ── Tab navigation ──
    tab_html = f'''
    <div style="display:flex;gap:8px;margin-bottom:24px;flex-wrap:wrap" class="no-print">
      <button onclick="showSection('all')" class="tab-btn active" id="tab-all">
        Show All
      </button>
      <button onclick="showSection('s1')" class="tab-btn" id="tab-s1" style="border-color:#3b82f6">
        Wazuh Gaps ({len(missing_in_wazuh)})
      </button>
      <button onclick="showSection('s2')" class="tab-btn" id="tab-s2" style="border-color:#f59e0b">
        Platform Gaps ({len(missing_in_sigma)})
      </button>
      <button onclick="showSection('s3')" class="tab-btn" id="tab-s3" style="border-color:#16a34a">
        Both Covered ({len(both)})
      </button>
    </div>'''

    return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ABSEGA — Wazuh ↔ Sigma Full Gap Analysis</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    @media print {{
      body {{ background:#fff !important; color:#000 !important; }}
      section, .tile {{ break-inside:avoid; }}
      a {{ color:#1d4ed8 !important; }}
      .no-print {{ display:none !important; }}
    }}
    body {{ margin:0; background:#020617; color:#e2e8f0;
           font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
           line-height:1.5; }}
    .wrap {{ max-width:1200px; margin:0 auto; padding:32px 24px 64px; }}
    h1 {{ font-size:28px; margin:0 0 4px; color:#f1f5f9; font-weight:700; }}
    .tile {{ background:#111827; border:1px solid #1f2937; border-radius:12px;
             padding:18px; border-left:4px solid; }}
    .tile-label {{ font-size:11px; color:#94a3b8; text-transform:uppercase;
                   letter-spacing:.6px; font-weight:600; }}
    .tile-value {{ font-size:32px; font-weight:700; margin-top:6px;
                   font-variant-numeric:tabular-nums; }}
    .tile-sub {{ font-size:12px; color:#64748b; margin-top:6px; }}
    .section {{ background:#0f172a; border:1px solid #1f2937; border-radius:12px;
               padding:16px 20px; }}
    .section-header {{ background:#0f172a; border:1px solid #1f2937; border-radius:12px;
                       padding:20px 24px; margin-bottom:16px; border-left:4px solid; }}
    .card {{ background:#111827; border:1px solid #1f2937; border-radius:12px;
             margin-bottom:16px; overflow:hidden; scroll-margin-top:20px; }}
    .card-header {{ display:flex; align-items:center; justify-content:space-between;
                    padding:16px 20px; background:#0f172a; border-bottom:1px solid #1f2937;
                    flex-wrap:wrap; gap:10px; }}
    .tech-id {{ color:#60a5fa; text-decoration:none; font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
               font-size:18px; font-weight:700; }}
    .tech-id:hover {{ text-decoration:underline; }}
    .th {{ text-align:left; padding:8px 12px; color:#64748b; font-size:11px;
           text-transform:uppercase; letter-spacing:.5px; font-weight:600; }}
    .badge-missing {{ background:#dc2626; color:#fff; padding:4px 12px; border-radius:10px;
                      font-size:12px; font-weight:600; }}
    .badge-sigma-missing {{ background:#f59e0b; color:#000; padding:4px 12px; border-radius:10px;
                            font-size:12px; font-weight:700; }}
    .toc {{ background:#0f172a; border:1px solid #1f2937; border-radius:12px;
            padding:14px 18px; margin-bottom:20px; }}
    .toc-link {{ display:inline-block; margin:4px 6px 4px 0; padding:4px 10px;
                 background:#1f2937; color:#cbd5e1; border-radius:6px; text-decoration:none;
                 font-family:monospace; font-size:12px; }}
    .toc-link:hover {{ background:#334155; }}
    .success-box {{ background:#052e16; border:1px solid #14532d; border-radius:12px;
                    padding:32px; text-align:center; color:#86efac; font-size:18px; font-weight:600;
                    margin-bottom:20px; }}
    .tab-btn {{ padding:10px 20px; border:2px solid #334155; background:#111827; color:#ccc;
               border-radius:8px; cursor:pointer; font-size:14px; font-weight:600; }}
    .tab-btn:hover {{ background:#1f2937; }}
    .tab-btn.active {{ background:#1e293b; color:#fff; border-color:#60a5fa; }}
  </style>
</head>
<body>
<div class="wrap">
  <header style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:24px;gap:16px;flex-wrap:wrap">
    <div>
      <h1>Wazuh ↔ Sigma — Full Gap Analysis</h1>
      <div style="color:#94a3b8;font-size:14px">Bidirectional detection-coverage comparison by MITRE ATT&CK technique</div>
      <div style="color:#64748b;font-size:12px;margin-top:6px">Generated {html.escape(generated_at)} · ABSEGA CYBER</div>
    </div>
    <div class="no-print" style="display:flex;gap:8px">
      <button onclick="window.print()" style="background:#1f2937;color:#e2e8f0;border:1px solid #334155;
              padding:8px 14px;border-radius:8px;font-size:13px;cursor:pointer">🖨 Print / PDF</button>
      <a href="/api/wazuh/import-compare/report" download="wazuh-sigma-gap-report.html"
         style="background:#2563eb;color:#fff;border:1px solid #1d4ed8;padding:8px 14px;
                border-radius:8px;font-size:13px;text-decoration:none">⬇ Download HTML</a>
    </div>
  </header>

  {tiles_html}
  {bar_html}
  {howto_html}
  {tab_html}

  <div id="section-s1">{section1_html}</div>
  <div id="section-s2">{section2_html}</div>
  <div id="section-s3">{section3_html}</div>
</div>

<script>
function showSection(which) {{
  const s1 = document.getElementById('section-s1');
  const s2 = document.getElementById('section-s2');
  const s3 = document.getElementById('section-s3');
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  if (which === 'all') {{
    s1.style.display = ''; s2.style.display = ''; s3.style.display = '';
    document.getElementById('tab-all').classList.add('active');
  }} else if (which === 's1') {{
    s1.style.display = ''; s2.style.display = 'none'; s3.style.display = 'none';
    document.getElementById('tab-s1').classList.add('active');
  }} else if (which === 's2') {{
    s1.style.display = 'none'; s2.style.display = ''; s3.style.display = 'none';
    document.getElementById('tab-s2').classList.add('active');
  }} else if (which === 's3') {{
    s1.style.display = 'none'; s2.style.display = 'none'; s3.style.display = '';
    document.getElementById('tab-s3').classList.add('active');
  }}
}}
</script>
</body>
</html>'''


# ── Deep Comparison ──────────────────────────────────────────────────────────
#
# For each MITRE technique: parse what Sigma and Wazuh actually detect,
# then give a clear COVERED / GAP verdict.
# ─────────────────────────────────────────────────────────────────────────────


def _is_meaningful(value: str) -> bool:
    v = (value or "").strip()
    if not v or len(v) < 4:
        return False
    if v.isdigit() or v.startswith("0x") and len(v) <= 4:
        return False
    if all(c in "#+-_.*?^$|\\()[]{}/" for c in v):
        return False
    return True


def _extract_wazuh_rule_info(rule: dict) -> dict:
    patterns = set()
    details = rule.get("details") or {}
    for value in details.values():
        if isinstance(value, dict):
            pat = value.get("pattern", "")
            if _is_meaningful(pat):
                patterns.add(pat.strip())
        elif isinstance(value, str) and _is_meaningful(value):
            patterns.add(value.strip())
    return {
        "patterns":    patterns,
        "description": (rule.get("description") or "").strip(),
        "groups":      [g.lower() for g in (rule.get("groups") or [])],
        "level":       rule.get("level", 0) or 0,
        "filename":    rule.get("filename", ""),
        "rule_id":     str(rule.get("id", "")),
    }


def _extract_sigma_rule_info(raw_yaml: str) -> dict:
    patterns = set()
    fields = set()
    logsource = {}
    level = "medium"
    try:
        parsed = _yaml.safe_load(raw_yaml)
        if not isinstance(parsed, dict):
            return {"patterns": patterns, "fields": fields,
                    "logsource": logsource, "level": level}
        logsource = parsed.get("logsource", {}) or {}
        level = parsed.get("level", "medium") or "medium"
        detection = parsed.get("detection", {}) or {}
        for key, value in detection.items():
            if key == "condition":
                continue
            _collect_sigma_leaf_values(value, patterns, fields)
    except Exception:
        pass
    return {"patterns": patterns, "fields": fields,
            "logsource": logsource, "level": level}


def _collect_sigma_leaf_values(obj, patterns: set, fields: set):
    if isinstance(obj, str):
        s = obj.strip()
        if _is_meaningful(s):
            patterns.add(s)
    elif isinstance(obj, (int, float, bool)):
        pass
    elif isinstance(obj, list):
        for item in obj:
            _collect_sigma_leaf_values(item, patterns, fields)
    elif isinstance(obj, dict):
        for key, value in obj.items():
            field_name = key.split("|")[0] if "|" in key else key
            if field_name and not field_name.startswith("_"):
                fields.add(field_name)
            _collect_sigma_leaf_values(value, patterns, fields)


def _find_shared_patterns(sigma_patterns: set, wazuh_patterns: set) -> dict:
    sigma_lower = {p.lower() for p in sigma_patterns if p.strip()}
    wazuh_lower = {p.lower() for p in wazuh_patterns if p.strip()}

    shared = sigma_lower & wazuh_lower

    sigma_rest = sigma_lower - shared
    wazuh_rest = wazuh_lower - shared

    partial = []
    sigma_partial_hit = set()
    wazuh_partial_hit = set()
    for sp in sigma_rest:
        for wp in wazuh_rest:
            if len(sp) > 5 and sp in wp:
                partial.append(f"Sigma '{sp}' found inside Wazuh '{wp}'")
                sigma_partial_hit.add(sp)
                wazuh_partial_hit.add(wp)
            elif len(wp) > 5 and wp in sp:
                partial.append(f"Wazuh '{wp}' found inside Sigma '{sp}'")
                sigma_partial_hit.add(sp)
                wazuh_partial_hit.add(wp)

    sigma_only = sorted(sigma_rest - sigma_partial_hit)
    wazuh_only = sorted(wazuh_rest - wazuh_partial_hit)

    return {
        "shared": sorted(shared),
        "partial_matches": partial[:10],
        "sigma_only": sigma_only[:15],
        "wazuh_only": wazuh_only[:15],
    }


def _decide_verdict(pattern_cmp: dict) -> str:
    shared = pattern_cmp.get("shared", [])
    partial = pattern_cmp.get("partial_matches", [])
    sigma_only = pattern_cmp.get("sigma_only", [])

    if shared and not sigma_only:
        return "COVERED"
    if shared or partial:
        return "PARTIAL"
    return "GAP"


def _build_note(verdict: str, pattern_cmp: dict) -> str:
    if verdict == "GAP" and not pattern_cmp:
        return "Wazuh has NO rules for this technique. Your SIEM will not detect this attack."
    if verdict == "WAZUH ONLY":
        return ("Your Sigma library has no rules for this technique, "
                "but Wazuh actively detects it.")

    shared = pattern_cmp.get("shared", [])
    sigma_only = pattern_cmp.get("sigma_only", [])
    wazuh_only = pattern_cmp.get("wazuh_only", [])
    partial = pattern_cmp.get("partial_matches", [])

    if verdict == "COVERED":
        parts = ["Fully covered."]
        if shared:
            parts.append(f"Both detect: {', '.join(shared[:5])}.")
        if wazuh_only:
            parts.append(f"Wazuh also checks for: {', '.join(wazuh_only[:5])}.")
        return " ".join(parts)

    if verdict == "PARTIAL":
        parts = ["Partially covered — Wazuh detects some of what Sigma looks for, but not all."]
        if shared:
            parts.append(f"Both detect: {', '.join(shared[:5])}.")
        if partial:
            parts.append(f"Similar patterns: {'; '.join(partial[:3])}.")
        if sigma_only:
            parts.append(f"Missing in Wazuh: {', '.join(sigma_only[:5])}.")
        if wazuh_only:
            parts.append(f"Extra in Wazuh: {', '.join(wazuh_only[:5])}.")
        return " ".join(parts)

    parts = ["Both have rules for this technique but they search for completely "
             "different things — Wazuh may be detecting a different variant."]
    if sigma_only:
        parts.append(f"Sigma looks for: {', '.join(sigma_only[:5])}.")
    if wazuh_only:
        parts.append(f"Wazuh looks for: {', '.join(wazuh_only[:5])}.")
    return " ".join(parts)


def _deep_compare():
    try:
        wazuh_rules = fetch_all_rules()
    except WazuhError as e:
        raise HTTPException(status_code=502, detail=f"Wazuh: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Wazuh connection error: {e}")

    wazuh_by_tech: dict[str, list] = defaultdict(list)
    for r in wazuh_rules:
        ids = _wazuh_mitre_ids(r)
        info = _extract_wazuh_rule_info(r)
        for tid in ids:
            wazuh_by_tech[tid].append(info)

    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT detection_id, title, description, severity, status,
                   platform, tags, raw_yaml
            FROM detections
            WHERE author != 'Wazuh (imported)' OR author IS NULL
        """).fetchall()

        mitre_rows = conn.execute(
            "SELECT technique_id, name, tactic FROM mitre_techniques"
        ).fetchall()
    finally:
        conn.close()

    mitre_db = {}
    for mr in mitre_rows:
        mitre_db[mr["technique_id"]] = {
            "name": mr["name"], "tactic": mr["tactic"],
        }

    sigma_by_tech: dict[str, list] = defaultdict(list)
    for row in rows:
        ids = _normalize_ids(row["tags"])
        sigma_info = _extract_sigma_rule_info(row["raw_yaml"] or "")
        for tid in ids:
            sigma_by_tech[tid].append({
                "detection_id": str(row["detection_id"]),
                "title":        row["title"] or "",
                "severity":     (row["severity"] or "medium").lower(),
                "status":       (row["status"] or "").lower(),
                "platform":     (row["platform"] or "").lower(),
                **sigma_info,
            })

    wazuh_techs = set(wazuh_by_tech.keys())
    sigma_techs = set(sigma_by_tech.keys())
    both_techs  = sorted(wazuh_techs & sigma_techs)
    sigma_only  = sorted(sigma_techs - wazuh_techs)
    wazuh_only  = sorted(wazuh_techs - sigma_techs)

    # ── Build results per technique ──
    covered = []
    partial = []
    content_gaps = []
    for tid in both_techs:
        s_rules = sigma_by_tech[tid]
        w_rules = wazuh_by_tech[tid]
        tech = mitre_db.get(tid, {"name": "Unknown", "tactic": "Unknown"})

        all_sigma_pats = set()
        for sr in s_rules:
            all_sigma_pats |= sr.get("patterns", set())

        all_wazuh_pats = set()
        for wr in w_rules:
            all_wazuh_pats |= wr.get("patterns", set())

        pattern_cmp = _find_shared_patterns(all_sigma_pats, all_wazuh_pats)
        verdict = _decide_verdict(pattern_cmp)

        entry = {
            "technique_id":   tid,
            "technique_name": tech["name"],
            "tactic":         tech["tactic"],
            "verdict":        verdict,
            "sigma_rules": [
                {"id": r["detection_id"], "title": r["title"],
                 "severity": r["severity"],
                 "searches_for": sorted(r.get("patterns", set()))[:10]}
                for r in s_rules[:10]
            ],
            "wazuh_rules": [
                {"rule_id": r["rule_id"], "description": r["description"],
                 "level": r["level"],
                 "searches_for": sorted(r.get("patterns", set()))[:10],
                 "log_groups": r.get("groups", [])}
                for r in w_rules[:10]
            ],
            "pattern_comparison": pattern_cmp,
            "note": _build_note(verdict, pattern_cmp),
        }

        if verdict == "COVERED":
            covered.append(entry)
        elif verdict == "PARTIAL":
            partial.append(entry)
        else:
            content_gaps.append(entry)

    gaps_in_wazuh = []
    for tid in sigma_only:
        tech = mitre_db.get(tid, {"name": "Unknown", "tactic": "Unknown"})
        rules = sigma_by_tech[tid]
        gaps_in_wazuh.append({
            "technique_id":   tid,
            "technique_name": tech["name"],
            "tactic":         tech["tactic"],
            "verdict":        "GAP",
            "sigma_rules": [
                {"id": r["detection_id"], "title": r["title"],
                 "severity": r["severity"],
                 "searches_for": sorted(r.get("patterns", set()))[:10]}
                for r in rules[:10]
            ],
            "wazuh_rules": [],
            "note": _build_note("gap", {}),
        })

    extra_in_wazuh = []
    for tid in wazuh_only:
        tech = mitre_db.get(tid, {"name": "Unknown", "tactic": "Unknown"})
        rules = wazuh_by_tech[tid]
        extra_in_wazuh.append({
            "technique_id":   tid,
            "technique_name": tech["name"],
            "tactic":         tech["tactic"],
            "verdict":        "WAZUH ONLY",
            "sigma_rules": [],
            "wazuh_rules": [
                {"rule_id": r["rule_id"], "description": r["description"],
                 "level": r["level"],
                 "searches_for": sorted(r.get("patterns", set()))[:10],
                 "log_groups": r.get("groups", [])}
                for r in rules[:10]
            ],
            "note": _build_note("wazuh_only", {}),
        })

    return {
        "summary": {
            "total_sigma_rules":     len(rows),
            "total_wazuh_rules":     len(wazuh_rules),
            "techniques_covered":    len(covered),
            "techniques_partial":    len(partial),
            "techniques_gap":        len(sigma_only) + len(content_gaps),
            "techniques_wazuh_only": len(wazuh_only),
        },
        "covered":        covered,
        "partial":        partial,
        "gaps_in_wazuh":  content_gaps + gaps_in_wazuh,
        "extra_in_wazuh": extra_in_wazuh,
    }


@router.get("/deep-compare")
def deep_compare():
    """Compare platform Sigma rules against live Wazuh rules.
    For each MITRE technique, shows what both sides detect and
    gives a clear COVERED / GAP verdict."""
    return _deep_compare()



# ── Content-level comparison (actual rule logic + log sources, not MITRE IDs) ─
#
# Compares WHAT each rule detects:
#   Wazuh side : description + groups + the `details` block (match/regex/field
#                conditions) returned by GET /rules
#   Sigma side : logsource + rule_logic (the parsed detection section) stored
#                in the detections table
# Both sides are normalized into: log channels, event IDs, and literal tokens
# (e.g. "powershell.exe", "encodedcommand", "mimikatz"). Two rules overlap in
# content when they watch compatible log sources AND share condition literals.

import yaml as _cc_yaml

_CC_STOPWORDS = {
    # generic words that appear everywhere and carry no detection meaning
    "windows", "microsoft", "system32", "syswow64", "program", "files",
    "possible", "possibly", "potential", "potentially", "suspicious",
    "detected", "detection", "detects", "activity", "activities", "attempt",
    "attempts", "attempted", "event", "events", "process", "processes",
    "command", "commands", "file", "files", "user", "users", "using", "used",
    "created", "create", "creation", "deleted", "delete", "execution",
    "executed", "execute", "remote", "local", "access", "accessed", "which",
    "with", "from", "this", "that", "were", "been", "have", "has", "was",
    "the", "and", "for", "not", "new", "may", "could", "should", "would",
    "unusual", "unknown", "multiple", "single", "first", "time", "error",
    "warning", "failed", "failure", "success", "successful", "logon", "logged",
    "group", "groups", "policy", "service", "services", "server", "client",
    "network", "computer", "machine", "host", "domain", "account", "accounts",
    "value", "values", "field", "type", "name", "path", "true", "false",
    "null", "none", "data", "image", "your", "system", "info", "information",
    "rule", "rules", "alert", "alerts", "sigma", "wazuh", "level", "audit",
    "security", "application", "operational", "generic", "default", "select",
    "selection", "condition", "filter", "contains", "endswith", "startswith",
}

# characters kept inside a token: letters, digits, dot, underscore, dash.
# Everything else (\, /, spaces, regex metachars, quotes…) splits tokens, so
# "C:\\Windows\\powershell.exe" and "powershell\.exe" both yield "powershell.exe".
import re as _cc_re
_CC_TOKEN_RE = _cc_re.compile(r"[a-z0-9][a-z0-9._-]{3,}")


def _cc_tokens(text) -> set:
    """Extract lowercase literal fragments worth comparing."""
    out = set()
    if text is None:
        return out
    text = str(text).lower()
    # neutralize regex syntax so pcre2 patterns yield their literal parts:
    #   (?i)\\-e(nc(odedcommand)?)?\\s  ->  -encodedcommand
    #   powershell\\.exe               ->  powershell.exe
    text = _cc_re.sub(r"\(\?[a-z:=!<-]*\)?", " ", text)      # inline flags / lookarounds
    text = text.replace("\\\\.", ".").replace("\\.", ".")
    text = _cc_re.sub(r"\\+[wsdbazWSDBAZ]", " ", text)        # char classes \w \s \d …
    text = text.replace("|", " ")                       # alternation splits tokens
    text = _cc_re.sub(r"[(){}\[\]?*+^$]", "", text)         # drop grouping/quantifiers
    for frag in _CC_TOKEN_RE.findall(text):
        frag = frag.strip("._-")
        if len(frag) < 4 or frag in _CC_STOPWORDS or frag.isdigit():
            continue
        out.add(frag)
    return out


def _cc_walk_strings(value, out: list):
    """Collect every string/number leaf inside nested dict/list structures."""
    if value is None:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            _cc_walk_strings(v, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _cc_walk_strings(v, out)
    else:
        out.append(str(value))


# ── Wazuh side ────────────────────────────────────────────────────────────────

_CC_SYSMON_GROUP_RE = _cc_re.compile(r"sysmon_e(?:vent_?|id_?)(\d+)")
_CC_EVENTID_KV_RE = _cc_re.compile(r"eventid[\"'`:\s^(]*(\d{1,5})", _cc_re.I)

_CC_WAZUH_GROUP_CHANNELS = {
    "sysmon": "sysmon",
    "windows_security": "security",
    "windows_system": "system",
    "windows_application": "application",
    "powershell": "powershell",
    "windows_powershell": "powershell",
    "windefender": "windefend",
    "windows_defender": "windefend",
}


def _cc_wazuh_profile(rule: dict) -> dict:
    groups = rule.get("groups") or []
    if isinstance(groups, str):
        groups = [groups]
    details = rule.get("details") or {}

    channels = set()
    event_ids = set()
    for g in map(str, groups):
        gl = g.lower()
        m = _CC_SYSMON_GROUP_RE.search(gl)
        if m:
            channels.add("sysmon")
            event_ids.add(int(m.group(1)))
        for key, ch in _CC_WAZUH_GROUP_CHANNELS.items():
            if key in gl:
                channels.add(ch)

    leaves: list = []
    _cc_walk_strings(details, leaves)
    detail_text = " ".join(leaves)

    # explicit event IDs referenced in rule conditions
    for m in _CC_EVENTID_KV_RE.finditer(detail_text):
        try:
            event_ids.add(int(m.group(1)))
        except ValueError:
            pass
    if "win.eventdata" in detail_text or "sysmon" in detail_text:
        channels.add("sysmon")

    tokens = _cc_tokens(detail_text) | _cc_tokens(rule.get("description"))
    # group names themselves are meaningful content ("mimikatz", "psexec"…)
    for g in map(str, groups):
        tokens |= _cc_tokens(g)

    return {
        "rule_id": str(rule.get("id", "")),
        "description": rule.get("description", "") or "",
        "level": rule.get("level", 0),
        "filename": rule.get("filename", "") or "",
        "channels": channels,
        "event_ids": event_ids,
        "tokens": tokens,
        "has_details": bool(leaves),
    }


# ── Sigma side ────────────────────────────────────────────────────────────────

_CC_CATEGORY_MAP = {
    # sigma logsource category -> (channels, event IDs)
    "process_creation":     ({"sysmon", "security"}, {1, 4688}),
    "network_connection":   ({"sysmon", "security"}, {3, 5156}),
    "dns_query":            ({"sysmon"}, {22}),
    "file_event":           ({"sysmon"}, {11}),
    "file_delete":          ({"sysmon"}, {23, 26}),
    "file_change":          ({"sysmon"}, {2}),
    "file_access":          ({"security"}, {4663}),
    "process_access":       ({"sysmon"}, {10}),
    "image_load":           ({"sysmon"}, {7}),
    "driver_load":          ({"sysmon"}, {6}),
    "registry_add":         ({"sysmon"}, {12}),
    "registry_delete":      ({"sysmon"}, {12}),
    "registry_set":         ({"sysmon"}, {13}),
    "registry_rename":      ({"sysmon"}, {14}),
    "registry_event":       ({"sysmon"}, {12, 13, 14}),
    "create_remote_thread": ({"sysmon"}, {8}),
    "create_stream_hash":   ({"sysmon"}, {15}),
    "pipe_created":         ({"sysmon"}, {17, 18}),
    "raw_access_thread":    ({"sysmon"}, {9}),
    "wmi_event":            ({"sysmon"}, {19, 20, 21}),
    "ps_script":            ({"powershell"}, {4104}),
    "ps_module":            ({"powershell"}, {4103}),
    "ps_classic_start":     ({"powershell"}, {400}),
    "ps_classic_script":    ({"powershell"}, {800}),
}

_CC_SERVICE_MAP = {
    "sysmon": "sysmon", "security": "security", "system": "system",
    "application": "application", "powershell": "powershell",
    "powershell-classic": "powershell", "windefend": "windefend",
}


def _cc_sigma_profile(row) -> dict | None:
    try:
        logsource = _cc_yaml.safe_load(row["logsource"] or "") or {}
    except Exception:
        logsource = {}
    try:
        logic = _cc_yaml.safe_load(row["rule_logic"] or "") or {}
    except Exception:
        logic = {}
    if not isinstance(logsource, dict):
        logsource = {}
    if not isinstance(logic, dict):
        logic = {}

    channels = set()
    event_ids = set()
    category = str(logsource.get("category") or "").lower()
    service = str(logsource.get("service") or "").lower()
    if category in _CC_CATEGORY_MAP:
        ch, eids = _CC_CATEGORY_MAP[category]
        channels |= ch
        event_ids |= set(eids)
    if service in _CC_SERVICE_MAP:
        channels.add(_CC_SERVICE_MAP[service])

    # explicit EventID values inside the detection logic
    def _collect_event_ids(value, key=None):
        if isinstance(value, dict):
            for k, v in value.items():
                _collect_event_ids(v, k)
        elif isinstance(value, (list, tuple)):
            for v in value:
                _collect_event_ids(v, key)
        elif key and "eventid" in str(key).lower():
            try:
                event_ids.add(int(value))
            except (TypeError, ValueError):
                pass

    _collect_event_ids(logic)

    leaves: list = []
    _cc_walk_strings(logic, leaves)
    tokens = _cc_tokens(" ".join(leaves)) | _cc_tokens(row["title"])

    return {
        "detection_id": str(row["detection_id"]),
        "title": row["title"] or "",
        "platform": (row["platform"] or "").lower(),
        "channels": channels,
        "event_ids": event_ids,
        "tokens": tokens,
    }


# ── Matching ─────────────────────────────────────────────────────────────────

def _cc_compatible(a_channels: set, b_channels: set) -> bool:
    """Channels are compatible when unknown on either side or overlapping."""
    if not a_channels or not b_channels:
        return True
    return bool(a_channels & b_channels)


def content_compare(wazuh_rules: list, sigma_rows: list,
                    min_score: float = 6.0, limit: int = 300,
                    only_detection_id=None) -> dict:
    import math

    wazuh_profiles = [_cc_wazuh_profile(r) for r in wazuh_rules]
    sigma_profiles = [p for p in (_cc_sigma_profile(r) for r in sigma_rows) if p]

    # document frequency across BOTH rule sets -> rarity weight per token.
    # A shared rare token ("encodedcommand", "mimikatz") counts far more than
    # a shared generic one ("powershell.exe").
    df: dict = {}
    for prof in wazuh_profiles:
        for t in prof["tokens"]:
            df[t] = df.get(t, 0) + 1
    for prof in sigma_profiles:
        for t in prof["tokens"]:
            df[t] = df.get(t, 0) + 1
    n_docs = len(wazuh_profiles) + len(sigma_profiles)
    idf = {t: math.log(n_docs / d) for t, d in df.items()}

    # inverted index over discriminating wazuh tokens
    index: dict = {}
    for i, wp in enumerate(wazuh_profiles):
        for t in wp["tokens"]:
            if idf.get(t, 0) >= 2.0:          # skip near-universal tokens
                index.setdefault(t, []).append(i)

    # rarity is always computed from the FULL corpora above; when a single
    # detection is requested we only restrict which rules get paired.
    if only_detection_id is not None:
        target = str(only_detection_id)
        pairing_profiles = [p for p in sigma_profiles
                            if p["detection_id"] == target]
    else:
        pairing_profiles = sigma_profiles

    pairs = []
    sigma_matched = set()
    wazuh_matched = set()
    for sp in pairing_profiles:
        candidates = set()
        for t in sp["tokens"]:
            candidates.update(index.get(t, ()))
        for i in candidates:
            wp = wazuh_profiles[i]
            if not _cc_compatible(sp["channels"], wp["channels"]):
                continue
            shared = sp["tokens"] & wp["tokens"]
            if not shared:
                continue
            shared_eids = sp["event_ids"] & wp["event_ids"]
            score = sum(idf.get(t, 0) for t in shared)
            if shared_eids:
                score += 1.5                   # same event source is evidence
            if score < min_score:
                continue
            top_shared = sorted(shared, key=lambda t: -idf.get(t, 0))
            pairs.append({
                "sigma": {"detection_id": sp["detection_id"], "title": sp["title"]},
                "wazuh": {"rule_id": wp["rule_id"], "level": wp["level"],
                          "description": wp["description"], "filename": wp["filename"]},
                "shared_tokens": top_shared[:15],
                "shared_token_count": len(shared),
                "shared_event_ids": sorted(shared_eids),
                "overlap_score": round(score, 2),
            })
            sigma_matched.add(sp["detection_id"])
            wazuh_matched.add(wp["rule_id"])

    pairs.sort(key=lambda p: p["overlap_score"], reverse=True)

    wazuh_with_content = sum(1 for wp in wazuh_profiles if wp["has_details"])
    sigma_no_match = [
        {"detection_id": sp["detection_id"], "title": sp["title"]}
        for sp in sigma_profiles
        if sp["detection_id"] not in sigma_matched and sp["platform"] == "windows"
    ]
    wazuh_no_match = [
        {"rule_id": wp["rule_id"], "description": wp["description"], "level": wp["level"]}
        for wp in wazuh_profiles
        if wp["rule_id"] not in wazuh_matched and ("sysmon" in wp["channels"]
            or "security" in wp["channels"] or "powershell" in wp["channels"])
    ]

    return {
        "summary": {
            "wazuh_rules_total": len(wazuh_profiles),
            "wazuh_rules_with_condition_details": wazuh_with_content,
            "sigma_detections_total": len(sigma_profiles),
            "content_overlap_pairs": len(pairs),
            "sigma_with_content_match": len(sigma_matched),
            "sigma_windows_without_content_match": len(sigma_no_match),
            "wazuh_windows_without_content_match": len(wazuh_no_match),
            "min_score": min_score,
        },
        "overlaps": pairs[:limit],
        "sigma_without_match_sample": sigma_no_match[:50],
        "wazuh_without_match_sample": wazuh_no_match[:50],
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/content-compare", dependencies=[Depends(require_write_access)])
def content_compare_full(min_score: float = 6.0, limit: int = 300):
    """Compare Sigma detections and Wazuh rules by ACTUAL rule content:
    log sources, event IDs and condition literals — not MITRE IDs."""
    min_score = max(0.0, float(min_score))
    limit = max(1, min(int(limit), 2000))
    try:
        wazuh_rules = fetch_all_rules()
    except WazuhError as e:
        raise HTTPException(status_code=502, detail=f"Wazuh: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Wazuh connection error: {e}")

    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT detection_id, title, platform, logsource, rule_logic "
            "FROM detections"
        ).fetchall()
    finally:
        conn.close()
    return content_compare(wazuh_rules, rows, min_score=min_score, limit=limit)


@router.get("/content-compare/detection/{detection_id}")
def content_compare_single(detection_id: int, min_score: float = 3.0,
                           limit: int = 20):
    """Duplicate check for ONE detection: which Wazuh rules already cover
    similar content? Run this before writing any custom Wazuh rule."""
    min_score = max(0.0, float(min_score))
    limit = max(1, min(int(limit), 200))
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT detection_id, title FROM detections WHERE detection_id = %s",
            (detection_id,),
        ).fetchone()
        all_rows = conn.execute(
            "SELECT detection_id, title, platform, logsource, rule_logic "
            "FROM detections"
        ).fetchall()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404,
                            detail=f"Detection {detection_id} not found")
    try:
        wazuh_rules = fetch_all_rules()
    except WazuhError as e:
        raise HTTPException(status_code=502, detail=f"Wazuh: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Wazuh connection error: {e}")

    result = content_compare(wazuh_rules, all_rows, min_score=min_score,
                             limit=limit, only_detection_id=detection_id)
    return {
        "detection": {"detection_id": str(row["detection_id"]),
                      "title": row["title"] or ""},
        "wazuh_content_matches": result["overlaps"],
        "match_count": len(result["overlaps"]),
        "note": ("Matches listed here indicate Wazuh rules whose content "
                 "overlaps this detection. Review before creating a custom "
                 "Wazuh rule to avoid duplicates."),
    }