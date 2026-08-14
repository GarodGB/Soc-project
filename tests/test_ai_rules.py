"""ABSEGA — AI Detection Rule Recommendation test suite.

Every Gemini call is mocked. No test in this file ever touches the real Gemini
API, the real Wazuh Manager, or the live database:

  * the API tests run against detection_platform_test, a dedicated Postgres
    database reset to a clone of the real one (see tests/conftest.py);
  * ``gemini_service.set_transport`` installs a fake transport;
  * ``app.wazuh_client`` functions are monkeypatched per test.

Run from the project root:
    python -m pytest tests/test_ai_rules.py -v
"""
from __future__ import annotations

import json
import os

import pytest

from tests.conftest import reset_test_database

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

WEB_RUN = "WAZUH_DVWA_TEST_20260101_000000"
LINUX_RUN = "WAZUH_LINUX_TEST_20260101_000000"
AD_RUN = "AD-RUN-ASREP-TEST"
WIN_RUN = "AD-RUN-WINPS-TEST"

APACHE_LFI_LOG = (
    '10.10.10.77 - - [01/Jan/2026:10:00:00 +0000] '
    '"GET /dvwa/vulnerabilities/fi/?page=../../../../etc/passwd HTTP/1.1" '
    '200 4523 "-" "Mozilla/5.0 (X11; Linux x86_64)"'
)
APACHE_SQLI_LOG = (
    '10.10.10.77 - - [01/Jan/2026:10:01:00 +0000] '
    '"GET /dvwa/vulnerabilities/sqli/?id=1%27+UNION+SELECT+1,2--+ HTTP/1.1" '
    '200 3200 "-" "sqlmap/1.7"'
)
SSH_BRUTE_LOG = (
    "Jan  1 10:02:00 ubuntu sshd[4242]: Failed password for invalid user admin "
    "from 10.10.10.77 port 55123 ssh2"
)

ASREP_EVENT = {
    "timestamp": "2026-01-01T10:03:00.000Z",
    "agent": {"id": "001", "name": "DC01", "ip": "192.168.56.20"},
    "rule": {"id": 60103, "level": 3, "description": "Windows logon attempt"},
    "data": {"win": {
        "system": {"eventID": "4768", "channel": "Security",
                   "providerName": "Microsoft-Windows-Security-Auditing",
                   "computer": "DC01.absega.local",
                   "eventRecordID": "998877",
                   "systemTime": "2026-01-01T10:03:00.000Z"},
        "eventdata": {"targetUserName": "svc_sql", "ipAddress": "10.10.10.77",
                      "ticketEncryptionType": "0x17", "preAuthType": "0"},
    }},
}

ASREP_SIGMA = """title: AS-REP Roasting Attempt
id: 11111111-2222-3333-4444-555555555555
status: test
description: Kerberos TGT request for an account with pre-authentication disabled.
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: '4768'
        Channel: 'Security'
    condition: selection
falsepositives:
    - Legacy accounts with pre-authentication disabled
level: high
tags:
    - attack.t1558.004
    - attack.credential_access
"""

GOOD_WAZUH_XML = """<group name="absega_ai,web,attack,">
  <rule id="__ABSEGA_AI_RULE_ID__" level="10">
    <decoded_as>web-accesslog</decoded_as>
    <regex>\\.\\./|/etc/passwd</regex>
    <description>Path traversal / local file inclusion attempt in web request URI</description>
    <group>web_scan,attack,absega_ai,</group>
    <mitre><id>T1190</id></mitre>
  </rule>
</group>"""

GOOD_SIGMA_YAML = """title: Web Path Traversal Attempt
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
status: test
description: Detects directory traversal sequences in web request URIs.
author: ABSEGA AI
date: 2026/01/01
logsource:
    category: webserver
detection:
    selection:
        uri|contains:
            - '../'
            - '/etc/passwd'
    condition: selection
falsepositives:
    - Backup tools that legitimately reference parent paths
level: high
tags:
    - attack.t1190
"""


# ── model-response builders ──────────────────────────────────────────────────

def make_response(gap_type: str, surface: str, *, wazuh: bool = False,
                  sigma: bool = False, telemetry: bool = False,
                  summary: str = "Draft detection content for the observed gap.",
                  **overrides) -> str:
    payload = {
        "gap_type": gap_type,
        "summary": summary,
        "reasoning_summary": "Derived from the captured event fields.",
        "assumptions": ["The Wazuh web-accesslog decoder parses the request URI."],
        "confidence": 72,
        "target_surface": surface,
        "mitre": {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
                  "tactic": "initial-access"},
        "required_data_sources": ["Apache access log"],
        "wazuh": {
            "required": wazuh,
            "title": "Path traversal attempt" if wazuh else "",
            "description": "Detects ../ and /etc/passwd in the request URI." if wazuh else "",
            "level": 10 if wazuh else 0,
            "groups": ["web_scan", "attack"] if wazuh else [],
            "xml": GOOD_WAZUH_XML if wazuh else "",
            "expected_fields": ["url", "srcip"] if wazuh else [],
            "false_positives": ["Backup jobs referencing parent paths"] if wazuh else [],
            "tuning_notes": ["Exclude approved scanners by source IP."] if wazuh else [],
            "test_event": APACHE_LFI_LOG if wazuh else "",
            "expected_match": "rule fires on the traversal pattern" if wazuh else "",
        },
        "sigma": {
            "required": sigma,
            "title": "Web Path Traversal Attempt" if sigma else "",
            "description": "Directory traversal in web URIs." if sigma else "",
            "yaml": GOOD_SIGMA_YAML if sigma else "",
            "logsource_explanation": "Apache access logs, webserver category." if sigma else "",
            "expected_fields": ["uri"] if sigma else [],
            "false_positives": ["Legitimate parent-path references"] if sigma else [],
            "tuning_notes": [] if not sigma else ["Scope to the DVWA vhost."],
        },
        "telemetry_recommendations": ([{
            "source": "Linux auditd",
            "problem": "auditd execve records are not reaching Wazuh.",
            "configuration": "auditctl -a always,exit -F arch=b64 -S execve -k absega_exec",
            "verification": "tail -f /var/ossec/logs/archives/archives.log | grep execve",
        }] if telemetry else []),
        "deployment_risks": ["May be noisy on hosts running vulnerability scanners."],
    }
    payload.update(overrides)
    return json.dumps(payload)


class FakeTransport:
    """Scripted Gemini transport. Records prompts; never touches the network."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.prompts = []
        self.calls = 0

    def __call__(self, settings, prompt):
        self.calls += 1
        self.prompts.append(prompt)
        item = self.responses.pop(0) if self.responses else self.responses
        if isinstance(item, Exception):
            raise item
        if callable(item):
            return item(settings, prompt)
        return item


class FakeHttpError(Exception):
    def __init__(self, code, message="upstream error"):
        super().__init__(f"{code}: {message}")
        self.code = code


# ── fixtures ─────────────────────────────────────────────────────────────────

def _seed() -> None:
    from app.database import get_connection

    con = get_connection()
    now = "2026-01-01T10:00:00+00:00"

    con.execute("DELETE FROM web_linux_validation_runs WHERE run_id IN (%s,%s)",
                (WEB_RUN, LINUX_RUN))
    con.execute("DELETE FROM web_linux_evidence WHERE run_id IN (%s,%s)",
                (WEB_RUN, LINUX_RUN))

    def wl(surface, attack_id, name, tech, verdict, wazuh_detected,
           sigma_supported, sigma_matched, wazuh_ids, sigma_ids,
           status="EXECUTED", evidence=0):
        run = WEB_RUN if surface == "web" else LINUX_RUN
        con.execute(
            "INSERT INTO web_linux_validation_runs "
            "(run_id, surface, attack_id, attack_name, mitre_technique, target, "
            " source_ip, started_at, ended_at, execution_status, wazuh_detected, "
            " wazuh_rule_ids_json, sigma_supported, sigma_matched, sigma_rule_ids_json, "
            " verdict, evidence_count, created_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (run, surface, attack_id, name, tech, "192.168.56.101", "001", now, now,
             status, wazuh_detected, json.dumps(wazuh_ids), sigma_supported,
             sigma_matched, json.dumps(sigma_ids), verdict, evidence, now))

    def ev(surface, attack_id, rule_id, description, level, log):
        run = WEB_RUN if surface == "web" else LINUX_RUN
        con.execute(
            "INSERT INTO web_linux_evidence "
            "(run_id, attack_id, wazuh_rule_id, rule_description, rule_level, "
            " full_log, agent_id, agent_name, event_timestamp, imported_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (run, attack_id, rule_id, description, level, log, "001", "ubuntu", now, now))

    # WEB ────────────────────────────────────────────────────────────────────
    wl("web", "lfi", "File Inclusion / Path Traversal", "T1190",
       "SIGMA_ONLY", 0, 1, 1, [], ["WEB-LFI-001"], evidence=1)
    ev("web", "lfi", None, "captured request (no Wazuh rule fired)", None, APACHE_LFI_LOG)

    wl("web", "sqli", "SQL Injection", "T1190",
       "VERIFIED_OVERLAP", 1, 1, 1, ["31103"], ["WEB-SQLI-001"], evidence=1)
    ev("web", "sqli", "31103", "SQL injection attempt", 6, APACHE_SQLI_LOG)

    wl("web", "cmdi", "Command Injection", "T1190",
       "WAZUH_ONLY", 1, 1, 0, ["31104"], ["WEB-CMDI-001"], evidence=1)
    ev("web", "cmdi", "31104", "Command injection attempt", 10, APACHE_SQLI_LOG)

    wl("web", "xss-dom", "DOM XSS", "T1190",
       "EVALUATOR_UNSUPPORTED", 0, 0, None, [], [], evidence=1)
    ev("web", "xss-dom", None, "captured request", None, APACHE_SQLI_LOG)

    wl("web", "csrf", "CSRF", "T1190", "NOT_EXECUTED", None, 0, None, [], [],
       status="NOT_EXECUTED")

    # LINUX ──────────────────────────────────────────────────────────────────
    wl("linux", "ssh-brute", "SSH Brute Force", "T1110",
       "NO_DETECTION_IN_EITHER", 0, 0, None, [], [], evidence=1)
    ev("linux", "ssh-brute", None, "captured auth.log line", None, SSH_BRUTE_LOG)

    wl("linux", "cred-dump", "Credential Dumping", "T1003",
       "NO_DETECTION_IN_EITHER", 0, 0, None, [], [], evidence=0)

    # AD / WINDOWS ───────────────────────────────────────────────────────────
    con.execute("DELETE FROM ad_rule_comparisons WHERE run_id IN (%s,%s)", (AD_RUN, WIN_RUN))
    con.execute("DELETE FROM ad_evidence WHERE run_id IN (%s,%s)", (AD_RUN, WIN_RUN))
    con.execute("DELETE FROM ad_validation_runs WHERE run_id IN (%s,%s)", (AD_RUN, WIN_RUN))
    con.execute("DELETE FROM ad_attack_tests WHERE test_id IN (%s,%s)",
                ("TEST-ASREP", "TEST-WINPS"))

    cur = con.execute(
        "INSERT INTO detections (title, description, severity, status, platform, "
        " author, falsepositives, tags, raw_yaml, logsource, created_at, updated_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now()::text,now()::text) "
        "RETURNING detection_id",
        ("AS-REP Roasting Attempt (test fixture)", "AS-REP roasting", "high", "test",
         "windows", "fixture", "Legacy accounts", "attack.t1558.004",
         ASREP_SIGMA, "product=windows, service=security"))
    asrep_detection_id = cur.fetchone()[0]

    for test_id, behavior, tech, channels in (
        ("TEST-ASREP", "AS-REP Roasting", "T1558.004", ["Security"]),
        ("TEST-WINPS", "Encoded PowerShell Execution", "T1059.001",
         ["Microsoft-Windows-Sysmon/Operational"]),
    ):
        con.execute(
            "INSERT INTO ad_attack_tests (test_id, behavior_name, technique_id, "
            " expected_channels_json, expected_event_ids_json, expected_fields_json, "
            " risk_tier, enabled, description, mitre_tactic, attack_category) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (test_id, behavior, tech, json.dumps(channels), json.dumps(["4768"]),
             "{}", "low", 1, f"{behavior} validation fixture", "credential-access",
             "credential-access"))

    for run_id, test_id in ((AD_RUN, "TEST-ASREP"), (WIN_RUN, "TEST-WINPS")):
        con.execute(
            "INSERT INTO ad_validation_runs (run_id, test_id, started_at, ended_at, "
            " source_host, target_host, source_ip, status, created_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (run_id, test_id, now, now, "KALI01", "DC01", "10.10.10.77", "complete", now))
        con.execute(
            "INSERT INTO ad_evidence (run_id, evidence_type, event_fingerprint, "
            " agent_name, channel, event_id, event_timestamp, payload_json, imported_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (run_id, "wazuh_alert", f"fp-{run_id}", "DC01", "Security", "4768", now,
             json.dumps(ASREP_EVENT), now))

    # AD: Sigma matched, Wazuh did not fire  → SIGMA_ONLY
    con.execute(
        "INSERT INTO ad_rule_comparisons (run_id, wazuh_rule_id, detection_id, "
        " total_score, static_verdict, wazuh_fired, sigma_matched, behavioral_verdict, "
        " compared_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (AD_RUN, None, asrep_detection_id, 8.0, "PARTIAL", 0, 1, "SIGMA_ONLY", now))

    # Windows: Wazuh fired, no Sigma candidate → WAZUH_ONLY
    con.execute(
        "INSERT INTO ad_rule_comparisons (run_id, wazuh_rule_id, detection_id, "
        " total_score, static_verdict, wazuh_fired, sigma_matched, behavioral_verdict, "
        " compared_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (WIN_RUN, 60103, None, 4.0, "PARTIAL", 1, None, "WAZUH_ONLY", now))

    con.commit()
    con.close()


@pytest.fixture(scope="module")
def env():
    """TestClient + dedicated test DB + Gemini env, with no network access anywhere."""
    from fastapi.testclient import TestClient

    reset_test_database()

    os.environ["GEMINI_API_KEY"] = "test-key-not-a-real-secret"
    os.environ["GEMINI_MODEL"] = "gemini-test-model"
    os.environ["GEMINI_ENABLED"] = "true"
    os.environ["GEMINI_RATE_LIMIT_PER_MINUTE"] = "60"
    os.environ["GEMINI_MAX_RETRIES"] = "2"

    _seed()

    import app.main as main
    client = TestClient(main.app)

    login = client.post("/api/auth/login",
                        json={"email": "engineer@absega.local", "password": "eng123"})
    engineer_token = login.json()["access_token"]
    analyst = client.post("/api/auth/login",
                          json={"email": "analyst@absega.local", "password": "analyst123"})
    analyst_token = analyst.json()["access_token"]

    yield {
        "client": client,
        "engineer": {"Authorization": f"Bearer {engineer_token}"},
        "analyst": {"Authorization": f"Bearer {analyst_token}"},
    }


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    """No real Gemini, no real Wazuh, no leftover rate-limit state."""
    from app.services import gemini_service
    import app.wazuh_client as wazuh_client

    gemini_service.reset_limits()
    gemini_service.set_transport(lambda settings, prompt: (_ for _ in ()).throw(
        AssertionError("A test called Gemini without installing a mock transport")))

    monkeypatch.setattr(wazuh_client, "indexer_pipeline_health",
                        lambda window_from=None: {"healthy": True, "reason": "",
                                                  "blocked_indices": [], "disk_percent": 20},
                        raising=False)
    monkeypatch.setattr(wazuh_client, "fetch_local_rule_ids", lambda: set(), raising=False)

    def _no_manager(*args, **kwargs):
        raise wazuh_client.WazuhError("Wazuh Manager API is not reachable in tests")

    monkeypatch.setattr(wazuh_client, "logtest", _no_manager, raising=False)
    yield
    gemini_service.set_transport(None)
    gemini_service.reset_limits()


def script(responses):
    from app.services import gemini_service
    transport = FakeTransport(responses)
    gemini_service.set_transport(transport)
    return transport


def generate(env, surface, attack_id, run_id=None, headers=None, **extra):
    body = {"surface": surface, "attack_id": attack_id, "validation_run_id": run_id}
    body.update(extra)
    return env["client"].post("/api/ai/rule-suggestions/generate", json=body,
                              headers=headers if headers is not None else env["engineer"])


def by_attack(env, surface, attack_id, run_id=None, headers=None):
    url = f"/api/ai/rule-suggestions/by-attack/{surface}/{attack_id}"
    if run_id:
        url += f"?validation_run_id={run_id}"
    return env["client"].get(url, headers=headers if headers is not None else env["engineer"])


# ═══════════════════════════════════════════════════════════════════════════
#  1-6  Gap decision engine — one verdict, one permitted action
# ═══════════════════════════════════════════════════════════════════════════

def test_01_sigma_only_generates_wazuh_xml(env):
    transport = script([make_response("wazuh_rule", "web", wazuh=True)])
    res = generate(env, "web", "lfi", WEB_RUN)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["decision"]["verdict"] == "SIGMA_ONLY"
    assert data["decision"]["gap_type"] == "wazuh_rule"
    version = data["current_version"]
    assert version["wazuh_xml"] and "<rule" in version["wazuh_xml"]
    assert not version["sigma_yaml"]
    assert transport.calls == 1
    # The rule ID placeholder must have been replaced with a real allocated ID.
    assert "__ABSEGA_AI_RULE_ID__" not in version["wazuh_xml"]
    assert 'id="11' in version["wazuh_xml"]


def test_02_wazuh_only_generates_sigma_yaml(env):
    script([make_response("sigma_rule", "web", sigma=True)])
    res = generate(env, "web", "cmdi", WEB_RUN)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["decision"]["verdict"] == "WAZUH_ONLY"
    assert data["decision"]["gap_type"] == "sigma_rule"
    version = data["current_version"]
    assert version["sigma_yaml"] and "detection:" in version["sigma_yaml"]
    assert not version["wazuh_xml"]


def test_03_neither_detects_generates_both_when_telemetry_exists(env):
    script([make_response("both_rules", "linux", wazuh=True, sigma=True)])
    res = generate(env, "linux", "ssh-brute", LINUX_RUN)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["decision"]["verdict"] == "NEITHER_DETECTS"
    assert data["decision"]["gap_type"] == "both_rules"
    assert data["current_version"]["wazuh_xml"]
    assert data["current_version"]["sigma_yaml"]


def test_04_telemetry_gap_returns_guidance_only(env, monkeypatch):
    """A tracked telemetry source recorded as missing must yield telemetry-only."""
    from app.database import get_connection

    con = get_connection()
    con.execute("UPDATE telemetry_sources SET status='missing' WHERE name='Linux auditd'")
    con.commit()
    con.close()
    try:
        script([make_response("telemetry", "linux", telemetry=True)])
        res = generate(env, "linux", "cred-dump", LINUX_RUN)
        assert res.status_code == 200, res.text
        data = res.json()
        assert data["decision"]["verdict"] == "TELEMETRY_GAP"
        assert data["decision"]["gap_type"] == "telemetry"
        assert data["decision"]["approval_allowed"] is False
        assert data["decision"]["deployment_allowed"] is False
        version = data["current_version"]
        assert not version["wazuh_xml"] and not version["sigma_yaml"]
        assert version["telemetry_recommendations"]
    finally:
        con = get_connection()
        con.execute("UPDATE telemetry_sources SET status='active' WHERE name='Linux auditd'")
        con.commit()
        con.close()


def test_05_verified_overlap_disables_generation(env):
    state = by_attack(env, "web", "sqli", WEB_RUN).json()
    assert state["decision"]["gap_type"] == "none"
    assert state["decision"]["generation_allowed"] is False
    assert state["decision"]["message"] == \
        "No AI rule required — detection coverage is verified."
    assert state["permissions"]["can_generate"] is False

    res = generate(env, "web", "sqli", WEB_RUN)
    assert res.status_code == 409
    assert "detection coverage is verified" in res.json()["detail"]


def test_06_evaluator_unsupported_is_not_a_detection_failure(env):
    state = by_attack(env, "web", "xss-dom", WEB_RUN).json()
    decision = state["decision"]
    assert decision["verdict"] == "EVALUATOR_UNSUPPORTED"
    assert decision["gap_type"] == "evaluator"
    # Explicitly NOT treated as a Wazuh or Sigma failure.
    assert decision["allow_wazuh_rule"] is False
    assert decision["allow_sigma_rule"] is False
    assert decision["approval_allowed"] is False
    assert decision["deployment_allowed"] is False
    assert "not a Wazuh or Sigma detection failure" in decision["message"]

    script([make_response("evaluator", "web", telemetry=True)])
    res = generate(env, "web", "xss-dom", WEB_RUN)
    assert res.status_code == 200, res.text
    assert res.json()["current_version"]["gap_type"] == "evaluator"


# ═══════════════════════════════════════════════════════════════════════════
#  7-13  Availability, transport and output handling
# ═══════════════════════════════════════════════════════════════════════════

def test_07_wazuh_outage_prevents_generation(env, monkeypatch):
    import app.wazuh_client as wazuh_client
    monkeypatch.setattr(wazuh_client, "indexer_pipeline_health",
                        lambda window_from=None: {
                            "healthy": False,
                            "reason": "alert indices are read-only (disk watermark)",
                            "blocked_indices": ["wazuh-alerts-4.x-2026.01.01"],
                            "disk_percent": 97})
    state = by_attack(env, "web", "lfi", WEB_RUN).json()
    assert state["decision"]["gap_type"] == "incomplete"
    assert state["decision"]["message"].startswith("Validation is incomplete.")

    res = generate(env, "web", "lfi", WEB_RUN)
    assert res.status_code == 409
    assert "Restore Wazuh connectivity" in res.json()["detail"]


def test_08_missing_api_key_returns_clear_error(env, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    status = env["client"].get("/api/ai/status").json()
    assert status["configured"] is False
    assert "GEMINI_API_KEY" in status["missing"]

    res = generate(env, "linux", "ssh-brute", LINUX_RUN, force_regenerate=True)
    assert res.status_code == 503
    assert "GEMINI_API_KEY" in res.json()["detail"]


def test_09_disabled_provider_returns_clear_status(env, monkeypatch):
    monkeypatch.setenv("GEMINI_ENABLED", "false")
    status = env["client"].get("/api/ai/status").json()
    assert status["enabled"] is False
    assert "disabled" in status["reason"]

    res = generate(env, "linux", "ssh-brute", LINUX_RUN, force_regenerate=True)
    assert res.status_code == 503
    assert "disabled" in res.json()["detail"]


def test_10_http_429_is_handled_safely(env):
    script([FakeHttpError(429, "Resource has been exhausted (quota)"),
            FakeHttpError(429, "Resource has been exhausted (quota)"),
            FakeHttpError(429, "Resource has been exhausted (quota)")])
    res = generate(env, "web", "lfi", WEB_RUN, force_regenerate=True)
    assert res.status_code == 429
    assert "quota" in res.json()["detail"].lower()


def test_11_transient_5xx_is_retried(env):
    transport = script([FakeHttpError(503, "backend unavailable"),
                        make_response("wazuh_rule", "web", wazuh=True)])
    res = generate(env, "web", "lfi", WEB_RUN, force_regenerate=True)
    assert res.status_code == 200, res.text
    assert transport.calls == 2


def test_12_invalid_json_is_repaired_then_rejected(env):
    # Repaired on the second attempt.
    transport = script(["this is not JSON at all",
                        make_response("wazuh_rule", "web", wazuh=True)])
    res = generate(env, "web", "lfi", WEB_RUN, force_regenerate=True)
    assert res.status_code == 200, res.text
    assert transport.calls == 2
    assert "rejected by the platform's validator" in transport.prompts[1]

    # Still invalid after the single repair attempt → rejected, nothing stored.
    script(["not json", "still not json"])
    res = generate(env, "web", "lfi", WEB_RUN, force_regenerate=True)
    assert res.status_code == 502
    assert "repair attempt also failed" in res.json()["detail"]


def test_13_markdown_fences_are_stripped(env):
    body = make_response("wazuh_rule", "web", wazuh=True)
    script(["```json\n" + body + "\n```"])
    res = generate(env, "web", "lfi", WEB_RUN, force_regenerate=True)
    assert res.status_code == 200, res.text
    assert res.json()["current_version"]["wazuh_xml"]


def test_14_contradictory_output_is_rejected(env):
    # Claims a Sigma rule is needed when the verdict calls for a Wazuh rule.
    bad = make_response("sigma_rule", "web", sigma=True)
    script([bad, bad])
    res = generate(env, "web", "lfi", WEB_RUN, force_regenerate=True)
    assert res.status_code == 502
    assert "contradicts the deterministic" in res.json()["detail"]


def test_14b_fabricated_success_claim_is_rejected(env):
    lie = make_response(
        "wazuh_rule", "web", wazuh=True,
        summary="Rule drafted. The validation test passed and the rule was "
                "successfully deployed to the Wazuh manager.")
    script([lie, lie])
    res = generate(env, "web", "lfi", WEB_RUN, force_regenerate=True)
    assert res.status_code == 502
    assert "never ran" in res.json()["detail"] or "contradicts" in res.json()["detail"]


# ═══════════════════════════════════════════════════════════════════════════
#  15-17  Versioning and engineer feedback
# ═══════════════════════════════════════════════════════════════════════════

def test_15_regeneration_creates_version_2_and_keeps_version_1(env):
    script([make_response("wazuh_rule", "web", wazuh=True, summary="Version one draft.")])
    first = generate(env, "web", "lfi", WEB_RUN, force_regenerate=True).json()
    suggestion_id = first["suggestion"]["suggestion_id"]
    v1_number = first["current_version"]["version_number"]
    v1_summary = first["current_version"]["summary"]

    feedback = ("This matches our approved scanner. Exclude 10.10.10.50 and "
                "require five events in 60 seconds.")
    transport = script([make_response("wazuh_rule", "web", wazuh=True,
                                      summary="Version two draft with scanner exclusion.")])
    res = env["client"].post(
        f"/api/ai/rule-suggestions/{suggestion_id}/regenerate",
        json={"feedback": feedback}, headers=env["engineer"])
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["current_version"]["version_number"] == v1_number + 1
    assert data["current_version"]["engineer_feedback"] == feedback
    # The previous draft and the feedback were both sent to the model.
    assert "PREVIOUS DRAFT" in transport.prompts[0]
    assert feedback in transport.prompts[0]

    # Version 1 is still stored, unchanged.
    history = env["client"].get(
        f"/api/ai/rule-suggestions/{suggestion_id}/history",
        headers=env["engineer"]).json()
    stored = {v["version_number"]: v for v in history["versions"]}
    assert v1_number in stored
    assert stored[v1_number]["summary"] == v1_summary
    assert len(history["versions"]) >= 2


def test_17_rejection_requires_a_reason(env):
    script([make_response("wazuh_rule", "web", wazuh=True)])
    data = generate(env, "web", "lfi", WEB_RUN, force_regenerate=True).json()
    suggestion_id = data["suggestion"]["suggestion_id"]

    empty = env["client"].post(f"/api/ai/rule-suggestions/{suggestion_id}/reject",
                               json={"reason": "   "}, headers=env["engineer"])
    assert empty.status_code == 422

    ok = env["client"].post(
        f"/api/ai/rule-suggestions/{suggestion_id}/reject",
        json={"reason": "Too broad — matches normal administrative activity."},
        headers=env["engineer"])
    assert ok.status_code == 200
    assert ok.json()["suggestion"]["status"] == "rejected"

    # Regeneration also requires non-empty feedback.
    bad = env["client"].post(f"/api/ai/rule-suggestions/{suggestion_id}/regenerate",
                             json={"feedback": ""}, headers=env["engineer"])
    assert bad.status_code == 422


# ═══════════════════════════════════════════════════════════════════════════
#  18-22  Rule content validation
# ═══════════════════════════════════════════════════════════════════════════

def test_18_invalid_xml_cannot_be_deployed(env):
    from app.services import gap_decision_service as gap
    from app.services.rule_validation_service import validate_draft

    decision = gap.decide(surface="web", attack_id="lfi", raw_verdict="SIGMA_ONLY")
    result = validate_draft(
        surface="web", wazuh_xml="<group><rule id=", sigma_yaml=None,
        evidence={"telemetry_health": {"available": True}, "raw_logs": []},
        decision=decision, run_manager_tests=False)
    assert result["wazuh"]["syntax_valid"] is False
    assert result["ready_for_deployment"] is False
    assert result["ready_for_review"] is False


def test_19_doctype_and_external_entities_are_rejected(env):
    from app.services.rule_validation_service import parse_wazuh_xml

    xxe = ('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
           '<group><rule id="110001" level="5"><description>&xxe;</description></rule></group>')
    group, problems = parse_wazuh_xml(xxe)
    assert group is None
    assert any("DOCTYPE" in p for p in problems)
    assert any("ENTITY" in p for p in problems)

    group, problems = parse_wazuh_xml(
        '<group><rule id="110001" level="5"><description>&evil;</description></rule></group>')
    assert group is None
    assert any("entity" in p.lower() for p in problems)


def test_20_duplicate_wazuh_ids_are_rejected_and_reassignment_works(env):
    from app.services import gap_decision_service as gap
    from app.services.rule_validation_service import (
        allocate_rule_ids, apply_rule_ids, validate_draft, RULE_ID_PLACEHOLDER)

    # 100201 is one of the reserved ABSEGA tagging IDs → must be rejected.
    taken = ('<group><rule id="100201" level="10">'
             '<decoded_as>web-accesslog</decoded_as><regex>\\.\\./</regex>'
             '<description>dup</description></rule></group>')
    decision = gap.decide(surface="web", attack_id="lfi", raw_verdict="SIGMA_ONLY")
    result = validate_draft(surface="web", wazuh_xml=taken, sigma_yaml=None,
                            evidence={"telemetry_health": {"available": True}, "raw_logs": []},
                            decision=decision, run_manager_tests=False)
    assert result["wazuh"]["rule_id_available"] is False
    assert result["ready_for_deployment"] is False

    # Reassignment from the configured AI range produces a free, non-reserved ID.
    allocated = allocate_rule_ids(1, include_manager=False)
    assert 110000 <= allocated[0] <= 119999
    fixed, used = apply_rule_ids(
        taken.replace('id="100201"', f'id="{RULE_ID_PLACEHOLDER}"'), allocated)
    assert f'id="{allocated[0]}"' in fixed
    assert used == [allocated[0]]

    # A draft that declares the same ID twice is also rejected.
    twice = ('<group>'
             '<rule id="110500" level="10"><decoded_as>web-accesslog</decoded_as>'
             '<regex>a</regex><description>one</description></rule>'
             '<rule id="110500" level="10"><decoded_as>web-accesslog</decoded_as>'
             '<regex>b</regex><description>two</description></rule></group>')
    dup = validate_draft(surface="web", wazuh_xml=twice, sigma_yaml=None,
                         evidence={"telemetry_health": {"available": True}, "raw_logs": []},
                         decision=decision, run_manager_tests=False)
    assert any("more than once" in e for e in dup["wazuh"]["errors"])


def test_20b_multi_rule_drafts_get_every_id_and_keep_correlation_intact(env):
    """A base rule + <frequency> correlation rule must both get real IDs, and
    the correlation must still point at its own base rule."""
    from app.services.rule_validation_service import (
        apply_rule_ids, placeholder_indices, unresolved_placeholders)

    draft = ('<group name="absega_ai,web,">'
             '<rule id="__ABSEGA_AI_RULE_ID_1__" level="5">'
             '<decoded_as>web-accesslog</decoded_as><url>/vulnerabilities/brute</url>'
             '<description>DVWA login attempt</description></rule>'
             '<rule id="__ABSEGA_AI_RULE_ID_2__" level="10">'
             '<if_matched_sid>__ABSEGA_AI_RULE_ID_1__</if_matched_sid>'
             '<same_source_ip /><frequency>5</frequency><timeframe>60</timeframe>'
             '<description>Brute force from same source</description></rule></group>')

    assert placeholder_indices(draft) == [1, 2]
    fixed, used = apply_rule_ids(draft, [110100, 110101, 110102])
    assert used == [110100, 110101]
    assert unresolved_placeholders(fixed) == []
    assert 'id="110100"' in fixed and 'id="110101"' in fixed
    # The correlation still references its own base rule, not a stale token.
    assert "<if_matched_sid>110100</if_matched_sid>" in fixed


def test_20c_unresolved_placeholder_blocks_deployment(env):
    """Under-allocation must fail validation, never reach the Deploy button."""
    from app.services import gap_decision_service as gap
    from app.services.rule_validation_service import apply_rule_ids, validate_draft

    draft = ('<group><rule id="__ABSEGA_AI_RULE_ID_1__" level="5">'
             '<decoded_as>web-accesslog</decoded_as><url>/x</url>'
             '<description>base</description></rule>'
             '<rule id="__ABSEGA_AI_RULE_ID_2__" level="10">'
             '<if_matched_sid>__ABSEGA_AI_RULE_ID_1__</if_matched_sid>'
             '<frequency>5</frequency><timeframe>60</timeframe>'
             '<description>corr</description></rule></group>')
    partial, used = apply_rule_ids(draft, [110200])   # only one ID available
    assert used == [110200]

    decision = gap.decide(surface="web", attack_id="brute-force",
                          raw_verdict="SIGMA_ONLY")
    result = validate_draft(
        surface="web", wazuh_xml=partial, sigma_yaml=None,
        evidence={"telemetry_health": {"available": True}, "raw_logs": []},
        decision=decision, run_manager_tests=False, allocated_rule_ids=used)

    assert result["wazuh"]["rule_id_available"] is False
    assert any("placeholder" in e for e in result["wazuh"]["errors"])
    assert result["ready_for_deployment"] is False
    assert result["ready_for_review"] is False


def test_21_invalid_sigma_yaml_is_rejected(env):
    from app.services.rule_validation_service import inspect_sigma_rule, parse_sigma_yaml

    document, problems = parse_sigma_yaml("title: broken\n  bad indent: [")
    assert document is None and problems

    document, problems = parse_sigma_yaml("!!python/object:os.system 'echo pwned'")
    assert document is None
    assert any("unsafe" in p.lower() for p in problems)

    document, _ = parse_sigma_yaml(
        "title: t\nstatus: test\nlevel: high\n"
        "logsource:\n  category: webserver\n"
        "detection:\n  selection:\n    uri: x\n  condition: undefined_selection\n")
    errors, _ = inspect_sigma_rule(document)
    assert any("undefined_selection" in e for e in errors)


def test_22_evaluator_unsupported_is_represented_correctly(env, monkeypatch):
    from app.services import rule_validation_service as rvs

    class Unsupported(Exception):
        pass

    import app.sigma_eval as sigma_eval
    monkeypatch.setattr(sigma_eval, "evaluate_sigma_rule",
                        lambda y, s: (_ for _ in ()).throw(
                            sigma_eval.SigmaEvaluationError("aggregation is unsupported")))

    result = rvs.evaluate_sigma_against_evidence(
        GOOD_SIGMA_YAML,
        {"raw_logs": [{"full_log": APACHE_LFI_LOG}]})
    assert result["status"] == "EVALUATOR_UNSUPPORTED"
    assert result["executed"] is False
    # Never reported as a match or a miss.
    assert result["matched"] is None
    assert "not a failed rule" in result["reason"]


# ═══════════════════════════════════════════════════════════════════════════
#  23-24  Save to platform + authorisation
# ═══════════════════════════════════════════════════════════════════════════

def test_23_save_to_platform_is_idempotent(env):
    script([make_response("sigma_rule", "web", sigma=True)])
    data = generate(env, "web", "cmdi", WEB_RUN, force_regenerate=True).json()
    suggestion_id = data["suggestion"]["suggestion_id"]

    first = env["client"].post(
        f"/api/ai/rule-suggestions/{suggestion_id}/save-to-platform",
        json={}, headers=env["engineer"])
    assert first.status_code == 200, first.text
    detection_id = first.json()["detection_id"]
    assert first.json()["already_saved"] is False

    second = env["client"].post(
        f"/api/ai/rule-suggestions/{suggestion_id}/save-to-platform",
        json={}, headers=env["engineer"])
    assert second.status_code == 200
    assert second.json()["already_saved"] is True
    assert second.json()["detection_id"] == detection_id

    from app.database import get_connection

    con = get_connection()
    row = dict(con.execute("SELECT * FROM detections WHERE detection_id=%s",
                           (detection_id,)).fetchone())
    count = con.execute(
        "SELECT COUNT(*) FROM ai_rule_platform_saves WHERE suggestion_id=%s",
        (suggestion_id,)).fetchone()[0]
    con.close()
    assert count == 1
    # Saved as draft/testing — never production.
    assert row["status"] == "test"
    assert "absega.ai_generated" in row["tags"]
    assert f"absega.attack.cmdi" in row["tags"]


def test_24_unauthorized_deployment_is_blocked(env):
    script([make_response("wazuh_rule", "web", wazuh=True)])
    data = generate(env, "web", "lfi", WEB_RUN, force_regenerate=True).json()
    suggestion_id = data["suggestion"]["suggestion_id"]

    # No session at all.
    anon = env["client"].post(
        f"/api/ai/rule-suggestions/{suggestion_id}/deploy-to-wazuh",
        json={"confirm": True})
    assert anon.status_code == 401

    # Authenticated, but the Analyst role may not deploy.
    analyst = env["client"].post(
        f"/api/ai/rule-suggestions/{suggestion_id}/deploy-to-wazuh",
        json={"confirm": True}, headers=env["analyst"])
    assert analyst.status_code == 403
    assert "Detection Engineer or Administrator" in analyst.json()["detail"]

    # Authorised role, but no explicit confirmation.
    unconfirmed = env["client"].post(
        f"/api/ai/rule-suggestions/{suggestion_id}/deploy-to-wazuh",
        json={"confirm": False}, headers=env["engineer"])
    assert unconfirmed.status_code == 400
    assert "explicit confirmation" in unconfirmed.json()["detail"]

    # Analyst may not approve or edit either.
    assert env["client"].post(f"/api/ai/rule-suggestions/{suggestion_id}/approve",
                              json={}, headers=env["analyst"]).status_code == 403
    assert env["client"].patch(f"/api/ai/rule-suggestions/{suggestion_id}/draft",
                               json={"summary": "x"},
                               headers=env["analyst"]).status_code == 403


def test_24b_approval_requires_passing_validation_and_never_deploys(env, monkeypatch):
    import app.wazuh_client as wazuh_client
    deployed = []
    monkeypatch.setattr(wazuh_client, "write_rule_file",
                        lambda *a, **k: deployed.append(a), raising=False)

    script([make_response("sigma_rule", "web", sigma=True)])
    data = generate(env, "web", "cmdi", WEB_RUN, force_regenerate=True).json()
    suggestion_id = data["suggestion"]["suggestion_id"]

    res = env["client"].post(f"/api/ai/rule-suggestions/{suggestion_id}/approve",
                             json={}, headers=env["engineer"])
    assert res.status_code == 200, res.text
    assert res.json()["suggestion"]["status"] == "approved"
    assert "does NOT" in res.json()["message"] or "nothing has been written" in \
        res.json()["message"].lower()
    # Approval must never touch the manager.
    assert deployed == []


# ═══════════════════════════════════════════════════════════════════════════
#  25-26  Deployment failure → backup restore and health-check rollback
# ═══════════════════════════════════════════════════════════════════════════

def _fake_manager(monkeypatch, *, validation_valid=True, healthy=True,
                  existing="<group name=\"absega_ai,\"><rule id=\"110999\" level=\"3\">"
                           "<description>previous</description></rule></group>"):
    import app.wazuh_client as wazuh_client
    state = {"file": existing, "writes": [], "restarts": 0, "deleted": False}

    monkeypatch.setattr(wazuh_client, "manager_info",
                        lambda: {"url": "https://wazuh.test:55000", "api_version": "4.9"},
                        raising=False)
    monkeypatch.setattr(wazuh_client, "read_rule_file",
                        lambda name: state["file"], raising=False)

    def write(name, content):
        state["writes"].append(content)
        state["file"] = content
        return {"error": 0}

    monkeypatch.setattr(wazuh_client, "write_rule_file", write, raising=False)
    monkeypatch.setattr(wazuh_client, "delete_rule_file",
                        lambda name: state.update(deleted=True), raising=False)
    monkeypatch.setattr(wazuh_client, "validate_configuration",
                        lambda: {"valid": validation_valid,
                                 "errors": [] if validation_valid else
                                 ["absega_ai_rules.xml: invalid regex in rule 110001"],
                                 "raw": {}}, raising=False)

    def restart():
        state["restarts"] += 1
        return {"error": 0}

    monkeypatch.setattr(wazuh_client, "restart_manager", restart, raising=False)
    monkeypatch.setattr(wazuh_client, "manager_status",
                        lambda: {"healthy": healthy, "daemons": {},
                                 "unhealthy": [] if healthy else ["wazuh-analysisd"]},
                        raising=False)
    monkeypatch.setattr(wazuh_client, "logtest",
                        lambda log, log_format="syslog", location="": {
                            "ran": True, "rule_id": "110001", "level": 10,
                            "description": "AI rule", "groups": [], "raw": {}},
                        raising=False)
    return state


DEPLOYABLE_XML = ('<group name="absega_ai,web,">'
                  '<rule id="110001" level="10">'
                  '<decoded_as>web-accesslog</decoded_as>'
                  '<regex>\\.\\./</regex>'
                  '<description>Path traversal attempt</description>'
                  '<mitre><id>T1190</id></mitre>'
                  '</rule></group>')


def test_25_failed_deployment_restores_the_backup(env, monkeypatch):
    from app.services.rule_deployment_service import deploy_rule

    state = _fake_manager(monkeypatch, validation_valid=False)
    original = state["file"]

    result = deploy_rule(rule_xml=DEPLOYABLE_XML, positive_event=APACHE_LFI_LOG,
                         surface="web", actor="engineer@absega.local")

    assert result.success is False
    assert result.stage == "validate"
    assert result.rolled_back is True
    assert result.backup_taken is True
    # The previous file content is back on the manager, and no restart happened.
    assert state["file"] == original
    assert state["restarts"] == 0
    assert "invalid regex" in result.message


def test_26_failed_health_check_triggers_rollback(env, monkeypatch):
    from app.services.rule_deployment_service import deploy_rule

    state = _fake_manager(monkeypatch, validation_valid=True, healthy=False)
    original = state["file"]

    result = deploy_rule(rule_xml=DEPLOYABLE_XML, positive_event=APACHE_LFI_LOG,
                         surface="web", actor="engineer@absega.local")

    assert result.success is False
    assert result.stage == "health"
    assert result.rolled_back is True
    assert state["file"] == original
    # Restarted once for the deploy, once more to restore the previous config.
    assert state["restarts"] == 2
    assert "unhealthy" in result.message.lower()


def test_26b_successful_deployment_merges_and_reports_honestly(env, monkeypatch):
    from app.services.rule_deployment_service import deploy_rule

    state = _fake_manager(monkeypatch)
    result = deploy_rule(rule_xml=DEPLOYABLE_XML, positive_event=APACHE_LFI_LOG,
                         surface="web", actor="engineer@absega.local")

    assert result.success is True
    assert result.rule_ids == [110001]
    assert result.rolled_back is False
    # The pre-existing AI rule was preserved, not overwritten.
    assert "110999" in state["file"] and "110001" in state["file"]
    assert result.logtest["executed"] is True
    assert "Re-run the original attack" in result.message


def test_26c_deployment_never_writes_default_wazuh_files(env):
    from app.config import deployment_settings
    settings = deployment_settings()
    assert settings.manager_path == "/var/ossec/etc/rules/absega_ai_rules.xml"
    assert settings.rules_filename.endswith(".xml")
    assert "/" not in settings.rules_filename and "\\" not in settings.rules_filename


# ═══════════════════════════════════════════════════════════════════════════
#  27  Secrets, sanitisation and XSS
# ═══════════════════════════════════════════════════════════════════════════

def test_27_gemini_output_is_escaped_against_xss(env):
    """The panel escapes every model-supplied string before rendering."""
    panel = os.path.join(ROOT, "ai_panel.js")
    with open(panel, "r", encoding="utf-8") as handle:
        source = handle.read()
    # Escaping helper exists and covers the dangerous characters.
    for token in ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;"):
        assert token in source
    # Model-supplied values are only ever interpolated through esc(...).
    for field in ("cur.summary", "cur.reasoning_summary", "cur.wazuh_xml",
                  "cur.sigma_yaml", "decision.message", "decision.reason",
                  "t.source", "t.configuration", "v.summary", "a.comment"):
        assert f"esc({field}" in source, f"{field} is rendered without escaping"
    # No raw interpolation of model content into innerHTML.
    for unsafe in ("+ cur.summary +", "+ cur.wazuh_xml +", "+ cur.sigma_yaml +",
                   "+ decision.message +"):
        assert unsafe not in source, f"unescaped interpolation found: {unsafe}"


def test_27b_evidence_sanitization_redacts_secrets_and_keeps_behaviour(env):
    from app.services.evidence_sanitization_service import sanitize_evidence

    dirty = {
        "attack_id": "lfi",
        "relevant_fields": {
            "http_method": "GET",
            "uri": "/dvwa/vulnerabilities/fi/",
            "query_parameters": ["page"],
            "status_code": "200",
            "password": "SuperSecret123",
            "username": "gordonb",
        },
        "raw_logs": [{"full_log":
            'POST /dvwa/login.php?password=letmein HTTP/1.1\n'
            'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdef\n'
            'Cookie: PHPSESSID=8a7f6e5d4c3b2a1908f7e6d5c4b3a219\n'
            'api_key=AIzaSyFAKEKEYFAKEKEYFAKEKEYFAKEKEY123\n'
            'hash=aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\n'
            'contact: soc@absega.local\n'
            'GET /vulnerabilities/fi/?page=../../../../etc/passwd HTTP/1.1'}],
    }
    clean = json.dumps(sanitize_evidence(dirty))

    for secret in ("SuperSecret123", "letmein", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdef",
                   "8a7f6e5d4c3b2a1908f7e6d5c4b3a219", "AIzaSyFAKEKEYFAKEKEYFAKEKEYFAKEKEY123",
                   "31d6cfe0d16ae931b73c59d7e0c089c0", "soc@absega.local", "gordonb"):
        assert secret not in clean, f"{secret} survived sanitisation"

    for placeholder in ("[REDACTED_PASSWORD]", "[REDACTED_TOKEN]", "[REDACTED_API_KEY]",
                        "[REDACTED_HASH]", "[REDACTED_EMAIL]", "[REDACTED_USERNAME]"):
        assert placeholder in clean

    # Detection-relevant content is preserved.
    for keep in ("GET", "/etc/passwd", "../../../..", "status_code", "200", "page"):
        assert keep in clean, f"{keep} was lost during sanitisation"


def test_27c_api_never_returns_the_gemini_key(env, monkeypatch):
    secret = "AIzaSyTESTKEYTESTKEYTESTKEYTESTKEY0000"
    monkeypatch.setenv("GEMINI_API_KEY", secret)

    for url in ("/api/ai/status", "/api/ai/health",
                f"/api/ai/rule-suggestions/by-attack/web/lfi?validation_run_id={WEB_RUN}"):
        res = env["client"].get(url, headers=env["engineer"])
        body = res.text
        assert secret not in body
        # No substring of the key either.
        assert secret[:12] not in body
        assert secret[-8:] not in body


def test_27d_secrets_are_scrubbed_from_error_messages(env, monkeypatch):
    secret = "AIzaSyTESTKEYTESTKEYTESTKEYTESTKEY0000"
    monkeypatch.setenv("GEMINI_API_KEY", secret)
    script([FakeHttpError(400, f"invalid request for key {secret}"),
            FakeHttpError(400, f"invalid request for key {secret}")])
    res = generate(env, "web", "lfi", WEB_RUN, force_regenerate=True)
    assert res.status_code >= 400
    assert secret not in res.text
    assert "[REDACTED_GEMINI_API_KEY]" in res.json()["detail"]


# ═══════════════════════════════════════════════════════════════════════════
#  28-32  All four surfaces render, and state survives a refresh
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("surface,attack_id,run_id,expected", [
    ("ad", "TEST-ASREP", AD_RUN, "SIGMA_ONLY"),
    ("windows", "TEST-WINPS", WIN_RUN, "WAZUH_ONLY"),
    ("linux", "ssh-brute", LINUX_RUN, "NEITHER_DETECTS"),
    ("web", "lfi", WEB_RUN, "SIGMA_ONLY"),
])
def test_28_31_every_surface_returns_a_panel_payload(env, surface, attack_id,
                                                     run_id, expected):
    res = by_attack(env, surface, attack_id, run_id)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["surface"] == surface
    assert data["attack_id"] == attack_id
    assert data["decision"]["verdict"] == expected
    # Everything the panel header renders is present.
    for key in ("provider", "permissions", "telemetry", "wazuh_health", "decision"):
        assert key in data
    assert data["provider"]["provider"] == "gemini"
    assert data["provider"]["notice"].startswith("Gemini is a cloud API")


def test_28b_ad_surface_generates_wazuh_xml_from_real_event_fields(env):
    """Scenario B — AS-REP roasting: Sigma matched, Wazuh did not."""
    transport = script([make_response(
        "wazuh_rule", "ad", wazuh=True,
        mitre={"technique_id": "T1558.004", "technique_name": "AS-REP Roasting",
               "tactic": "credential-access"})])
    res = generate(env, "ad", "TEST-ASREP", AD_RUN)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["decision"]["gap_type"] == "wazuh_rule"
    assert data["current_version"]["wazuh_xml"]
    # The prompt carried the real captured Event ID 4768 evidence.
    prompt = transport.prompts[0]
    assert "4768" in prompt
    assert "T1558.004" in prompt
    # Nothing is claimed to be validated until it is tested.
    validation = data["current_version"]["validation_result"]
    assert validation["wazuh"]["positive_test_executed"] is False
    assert validation["wazuh"]["positive_test_matched"] is None


def test_32_page_refresh_restores_the_current_suggestion(env):
    script([make_response("wazuh_rule", "web", wazuh=True,
                          summary="Persisted across a refresh.")])
    generated = generate(env, "web", "lfi", WEB_RUN, force_regenerate=True).json()
    suggestion_id = generated["suggestion"]["suggestion_id"]

    # A fresh GET (what the panel does on mount after a reload).
    reloaded = by_attack(env, "web", "lfi", WEB_RUN).json()
    assert reloaded["suggestion"]["suggestion_id"] == suggestion_id
    assert reloaded["current_version"]["summary"] == "Persisted across a refresh."
    assert reloaded["current_version"]["wazuh_xml"]
    assert reloaded["versions"]


def test_32b_equivalent_draft_is_reused_instead_of_calling_gemini_again(env):
    transport = script([make_response("wazuh_rule", "web", wazuh=True)])
    first = generate(env, "web", "lfi", WEB_RUN, force_regenerate=True).json()
    assert transport.calls == 1

    # No force flag and unchanged evidence → reuse, no second Gemini call.
    second = generate(env, "web", "lfi", WEB_RUN).json()
    assert second["reused"] is True
    assert transport.calls == 1
    assert second["current_version"]["version_number"] == \
        first["current_version"]["version_number"]


# ═══════════════════════════════════════════════════════════════════════════
#  33  Existing validation APIs still work
# ═══════════════════════════════════════════════════════════════════════════

def test_33_existing_validation_apis_still_work(env):
    client = env["client"]

    assert client.get("/health").json() == {"status": "ok"}

    detections = client.get("/api/detections/?limit=5")
    assert detections.status_code == 200 and isinstance(detections.json(), list)

    runs = client.get(f"/api/validation-runs?surface=web&limit=50")
    assert runs.status_code == 200
    ids = {i["attack_id"] for i in runs.json()["items"]}
    assert "lfi" in ids

    detail = client.get(f"/api/validation-runs/{WEB_RUN}")
    assert detail.status_code == 200
    assert detail.json()["surface"] == "web"

    summary = client.get("/api/validation-runs/summary?surface=linux")
    assert summary.status_code == 200 and "total_behaviors" in summary.json()

    ad_run = client.get(f"/api/ad-validation/runs/{AD_RUN}")
    assert ad_run.status_code == 200
    assert ad_run.json()["detail"]["result_state"] == "SIGMA_ONLY"

    assert client.get("/api/telemetry/").status_code == 200
    assert client.get("/api/ai/health").status_code == 200
    assert client.get("/api/detections/stats").status_code == 200


def test_33b_full_engineer_workflow_end_to_end(env, monkeypatch):
    """Scenario E — generate → reject with feedback → v2 → validate → approve →
    save to platform → deploy (mocked manager) → history."""
    _fake_manager(monkeypatch)
    client = env["client"]

    script([make_response("wazuh_rule", "web", wazuh=True, summary="Initial LFI draft.")])
    data = generate(env, "web", "lfi", WEB_RUN, force_regenerate=True).json()
    suggestion_id = data["suggestion"]["suggestion_id"]

    feedback = "Exclude 10.10.10.50 and require five events in 60 seconds."
    script([make_response("wazuh_rule", "web", wazuh=True,
                          summary="Revised LFI draft with scanner exclusion.")])
    v2 = client.post(f"/api/ai/rule-suggestions/{suggestion_id}/regenerate",
                     json={"feedback": feedback}, headers=env["engineer"]).json()
    assert v2["current_version"]["version_number"] >= 2

    validated = client.post(f"/api/ai/rule-suggestions/{suggestion_id}/validate",
                            json={}, headers=env["engineer"])
    assert validated.status_code == 200
    assert validated.json()["validation"]["ready_for_review"] is True

    approved = client.post(f"/api/ai/rule-suggestions/{suggestion_id}/approve",
                           json={}, headers=env["engineer"])
    assert approved.status_code == 200, approved.text

    saved = client.post(f"/api/ai/rule-suggestions/{suggestion_id}/save-to-platform",
                        json={}, headers=env["engineer"])
    assert saved.status_code == 200, saved.text

    preview = client.get(f"/api/ai/rule-suggestions/{suggestion_id}/deployment-preview",
                         headers=env["engineer"]).json()
    assert preview["target_file"] == "/var/ossec/etc/rules/absega_ai_rules.xml"
    assert preview["rules"]

    deployed = client.post(f"/api/ai/rule-suggestions/{suggestion_id}/deploy-to-wazuh",
                           json={"confirm": True}, headers=env["engineer"])
    assert deployed.status_code == 200, deployed.text
    assert deployed.json()["suggestion"]["status"] == "deployed"
    assert "Re-run the original attack" in deployed.json()["next_step"]

    history = client.get(f"/api/ai/rule-suggestions/{suggestion_id}/history",
                         headers=env["engineer"]).json()
    actions = {a["action"] for a in history["actions"]}
    assert {"generated", "regenerated", "validated", "approved",
            "saved_to_platform", "deployment_requested", "deployed"} <= actions
    assert len(history["versions"]) >= 2
    assert history["deployments"]


def test_34_gap_decision_engine_is_shared_by_every_surface(env):
    """One mapping, four surfaces — no per-surface branch of the gap logic."""
    from app.services import gap_decision_service as gap

    for surface in ("ad", "windows", "linux", "web"):
        assert gap.decide(surface=surface, attack_id="x",
                          raw_verdict="VERIFIED_OVERLAP").gap_type == "none"
        assert gap.decide(surface=surface, attack_id="x",
                          raw_verdict="SIGMA_ONLY").gap_type == "wazuh_rule"
        assert gap.decide(surface=surface, attack_id="x",
                          raw_verdict="WAZUH_ONLY").gap_type == "sigma_rule"
        assert gap.decide(surface=surface, attack_id="x",
                          raw_verdict="NO_DETECTION_IN_EITHER").gap_type == "both_rules"
        assert gap.decide(surface=surface, attack_id="x",
                          raw_verdict="NO_DETECTION_IN_EITHER",
                          telemetry_available=False).gap_type == "telemetry"
        assert gap.decide(surface=surface, attack_id="x",
                          raw_verdict="EVALUATOR_UNSUPPORTED").gap_type == "evaluator"
        assert gap.decide(surface=surface, attack_id="x",
                          raw_verdict="NOT_EXECUTED").gap_type == "incomplete"
        assert gap.decide(surface=surface, attack_id="x", raw_verdict="SIGMA_ONLY",
                          wazuh_available=False).gap_type == "incomplete"

    # WAZUH_ONLY is a Sigma gap, so it is never deployable to the Wazuh manager.
    assert gap.decide(surface="web", attack_id="x",
                      raw_verdict="WAZUH_ONLY").deployment_allowed is False
    # Telemetry and evaluator states can never be approved or deployed.
    for verdict in ("TELEMETRY_GAP", "EVALUATOR_UNSUPPORTED"):
        decision = gap.decide(surface="linux", attack_id="x", raw_verdict=verdict)
        assert decision.approval_allowed is False
        assert decision.deployment_allowed is False
