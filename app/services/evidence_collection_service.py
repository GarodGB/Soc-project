"""Normalized evidence collection for every validation surface.

One evidence model serves Active Directory, Windows, Linux and Web. The
verdict, the telemetry state and the captured events are all read back out of
the platform's own tables here — nothing in this module trusts a value supplied
by the frontend, and nothing in it calls Gemini.

Two data paths feed the same normalized shape:

* **AD / Windows** — ``ad_validation_runs`` + ``ad_evidence`` +
  ``ad_rule_comparisons``, run through the existing deterministic detail
  builder in ``app.routes.ad_validation`` so the AI workflow sees exactly the
  verdict the Validation drawer shows.
* **Linux / Web** — ``web_linux_validation_runs`` + ``web_linux_evidence``,
  written by the live ``validate-linux`` / ``validate-live`` endpoints.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from app.database import get_connection
from app.services import gap_decision_service as gap

logger = logging.getLogger(__name__)

AD_SURFACES = ("ad", "windows")
WL_SURFACES = ("linux", "web")
ALL_SURFACES = AD_SURFACES + WL_SURFACES


class EvidenceNotFound(Exception):
    """No validation run exists for the requested attack."""


# ── Expected telemetry per surface / attack ──────────────────────────────────
# Names on the right match telemetry_sources.name where the platform tracks the
# source's health. Sources with no row are reported as "not tracked" and never
# used to block generation on their own.

_LINUX_TELEMETRY = {
    "ssh-brute":        ["Linux auth.log"],
    "cron-persist":     ["Linux syslog"],
    "suid-binary":      ["Linux auditd", "Linux syslog"],
    "user-creation":    ["Linux auth.log", "Linux syslog"],
    "ssh-key-inject":   ["Linux auditd"],
    "systemd-backdoor": ["Linux syslog"],
    "bashrc-persist":   ["Linux auditd"],
    "log-tamper":       ["Linux syslog", "Linux auditd"],
    "cred-dump":        ["Linux auditd"],
    "sudoers-mod":      ["Linux auth.log", "Linux auditd"],
    "hosts-mod":        ["Linux auditd"],
    "firewall-tamper":  ["Linux syslog", "Linux auditd"],
    "recon":            ["Linux auditd", "Linux bash history"],
    "data-exfil":       ["Linux auditd"],
}
_LINUX_DEFAULT_TELEMETRY = ["Linux auth.log", "Linux syslog"]

_WEB_TELEMETRY = ["Apache access log", "ModSecurity audit log"]

#: Windows event channel (from ad_attack_tests.expected_channels_json) →
#: telemetry_sources.name, so AD/Windows telemetry health uses tracked rows too.
_CHANNEL_TO_SOURCE = {
    "security": "Windows Security Event Log",
    "system": "Windows System Event Log",
    "application": "Windows Application Event Log",
    "microsoft-windows-sysmon/operational": "Sysmon",
    "sysmon": "Sysmon",
    "microsoft-windows-powershell/operational": "PowerShell Operational Log",
    "windows powershell": "PowerShell Operational Log",
    "microsoft-windows-windows defender/operational": "Windows Defender Log",
}

#: Surface-specific reminders included in the prompt context so the model works
#: from the log sources this lab actually collects.
SURFACE_CONTEXT = {
    "ad": (
        "Active Directory / domain controller telemetry. Relevant Windows Security "
        "events include 4625 (logon failure), 4768 (Kerberos TGT request, incl. "
        "pre-auth-disabled AS-REP), 4769 (Kerberos service ticket, incl. RC4 "
        "0x17 for Kerberoasting), 4776 (NTLM credential validation), 5136/4662 "
        "(directory changes / DCSync-style replication access) and 7045 (service "
        "install, e.g. PsExec). Prefer behaviour (ticket encryption type, request "
        "volume, service account targeting) over offensive tool names."
    ),
    "windows": (
        "Windows endpoint telemetry: Sysmon Event ID 1 (process creation), 3 "
        "(network connect), 10 (process access), 11 (file create), 22 (DNS "
        "query); Security log 4688 process creation with command line; "
        "PowerShell Script Block Logging 4104; service creation 7045; scheduled "
        "tasks; Run-key and service registry persistence; LSASS credential "
        "access. Prefer command-line and parent/child behaviour over binary names."
    ),
    "linux": (
        "Linux endpoint telemetry collected by the Wazuh agent: /var/log/auth.log "
        "(sshd, sudo, su, useradd), /var/log/syslog (cron, systemd), and "
        "/var/log/audit/audit.log (auditd execve/syscall records). Wazuh decodes "
        "these with its sshd/sudo/pam/auditd decoders. Brute-force style "
        "behaviour must use frequency/timeframe over repeated failures, not a "
        "single log line containing the word 'failed'."
    ),
    "web": (
        "Web application telemetry from the DVWA lab: Apache/Nginx access logs "
        "(HTTP method, URI, query string, status code, user agent, source IP) and "
        "ModSecurity/OWASP CRS audit alerts. Wazuh's web-accesslog and "
        "modsecurity decoders parse these. Detection must key on the request "
        "pattern (URI, parameter name, payload shape) rather than only on the "
        "ModSecurity message text."
    ),
}


# ── Result shape ─────────────────────────────────────────────────────────────

@dataclass
class EvidenceBundle:
    surface: str
    attack_id: str
    validation_run_id: str | None
    decision: gap.GapDecision
    evidence: dict[str, Any]
    telemetry: dict[str, Any]
    wazuh_health: dict[str, Any]
    attack_name: str = ""
    mitre: dict[str, Any] = field(default_factory=dict)
    evidence_present: bool = False


# ── Small helpers ────────────────────────────────────────────────────────────

def _json_load(value: Any, default: Any) -> Any:
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _techniques_from_tags(tags: Any) -> list[str]:
    if not tags:
        return []
    text = tags if isinstance(tags, str) else " ".join(str(t) for t in tags)
    seen: list[str] = []
    for match in re.findall(r"[tT](\d{4}(?:\.\d{3})?)", text):
        tid = "T" + match
        if tid not in seen:
            seen.append(tid)
    return seen


def _mitre_lookup(conn, technique_id: str) -> dict[str, Any]:
    out = {"technique_id": technique_id or "", "technique_name": "", "tactic": ""}
    if not technique_id:
        return out
    try:
        row = conn.execute(
            "SELECT technique_id, name, tactic FROM mitre_techniques WHERE technique_id = %s",
            (technique_id,),
        ).fetchone()
        if row is None:
            base = technique_id.split(".")[0]
            row = conn.execute(
                "SELECT technique_id, name, tactic FROM mitre_techniques WHERE technique_id = %s",
                (base,),
            ).fetchone()
        if row is not None:
            row = dict(row)
            out["technique_name"] = row.get("name") or ""
            out["tactic"] = row.get("tactic") or ""
    except Exception:  # table shape differs across installs — informational only
        logger.debug("MITRE lookup failed for %s", technique_id, exc_info=True)
    return out


# ── Telemetry health ─────────────────────────────────────────────────────────

def _expected_sources(surface: str, attack_id: str, ad_channels: list[str]) -> list[str]:
    if surface == "linux":
        return _LINUX_TELEMETRY.get(attack_id, _LINUX_DEFAULT_TELEMETRY)
    if surface == "web":
        return list(_WEB_TELEMETRY)
    names: list[str] = []
    for channel in ad_channels or []:
        mapped = _CHANNEL_TO_SOURCE.get(str(channel).strip().lower())
        if mapped and mapped not in names:
            names.append(mapped)
    if not names:
        names = ["Windows Security Event Log"]
    return names


_HEALTHY_STATUSES = {"active", "healthy", "enabled", "ok"}


def assess_telemetry(conn, surface: str, attack_id: str, *,
                     evidence_present: bool,
                     ad_channels: list[str] | None = None,
                     pipeline_healthy: bool | None = None) -> dict[str, Any]:
    """Measure whether the telemetry a detection would need is actually present.

    ``available`` is False only when a *tracked* telemetry source the attack
    depends on is recorded as degraded/missing in ``telemetry_sources``. A
    source the platform does not track is reported honestly as "not tracked"
    and never used on its own to claim a telemetry gap.
    """
    expected = _expected_sources(surface, attack_id, ad_channels or [])
    rows: dict[str, dict[str, Any]] = {}
    try:
        for row in conn.execute(
            "SELECT source_id, name, category, status FROM telemetry_sources"
        ).fetchall():
            row = dict(row)
            rows[str(row.get("name", "")).strip().lower()] = row
    except Exception:
        logger.debug("telemetry_sources unavailable", exc_info=True)

    sources: list[dict[str, Any]] = []
    unhealthy: list[str] = []
    for name in expected:
        row = rows.get(name.strip().lower())
        if row is None:
            sources.append({"name": name, "tracked": False, "status": "not_tracked"})
            continue
        status = str(row.get("status") or "").strip().lower()
        healthy = status in _HEALTHY_STATUSES
        sources.append({
            "name": name,
            "tracked": True,
            "status": row.get("status"),
            "category": row.get("category"),
            "healthy": healthy,
        })
        if not healthy:
            unhealthy.append(f"{name} (status={row.get('status')})")

    available = not unhealthy
    if available and not evidence_present and pipeline_healthy is False:
        available = False

    if unhealthy:
        reason = ("Required telemetry is not healthy: " + "; ".join(unhealthy) +
                  ". A detection rule cannot be derived from events that are not "
                  "being collected.")
    elif evidence_present:
        reason = "Required telemetry is present — real events were captured for this run."
    elif pipeline_healthy is False:
        reason = ("No events were captured and the Wazuh indexing pipeline is "
                  "unhealthy, so telemetry availability cannot be confirmed.")
    else:
        reason = ("Every tracked telemetry source this behaviour depends on is "
                  "recorded as active.")

    return {
        "available": available,
        "reason": reason,
        "expected_sources": expected,
        "sources": sources,
        "unhealthy": unhealthy,
        "evidence_present": evidence_present,
        "pipeline_healthy": pipeline_healthy,
    }


def wazuh_pipeline_health(window_from: str | None = None) -> dict[str, Any]:
    """Best-effort Wazuh indexer health, used to detect incomplete validation.

    ``window_from`` is deliberately *not* forwarded. The underlying check also
    reports "pipeline stalled" when no alert has been written since a given
    timestamp — correct right after a run, but wrong here: a historical run on a
    quiet lab would then look like a Wazuh outage and block generation on
    perfectly good evidence. What matters for "can this verdict be trusted" is
    whether the indexer is reachable and accepting writes right now.
    """
    try:
        from app.wazuh_client import indexer_pipeline_health
        return indexer_pipeline_health(None)
    except Exception as exc:  # never break evidence collection
        logger.debug("indexer health check failed", exc_info=True)
        return {"healthy": None, "reason": f"health check unavailable: {exc}"}


# ── Related existing content ─────────────────────────────────────────────────

def _existing_wazuh_content(conn, technique_id: str, limit: int = 5) -> list[dict[str, Any]]:
    """Wazuh rules already mapped to this technique — context, not a template."""
    if not technique_id:
        return []
    out: list[dict[str, Any]] = []
    try:
        rows = conn.execute(
            "SELECT wazuh_rule_id, level, description, filename, groups_json, mitre_json "
            "FROM wazuh_rule_catalog WHERE mitre_json ILIKE %s LIMIT %s",
            (f"%{technique_id}%", limit),
        ).fetchall()
        for row in rows:
            row = dict(row)
            out.append({
                "rule_id": row.get("wazuh_rule_id"),
                "level": row.get("level"),
                "description": row.get("description"),
                "file": row.get("filename"),
                "groups": _json_load(row.get("groups_json"), []),
            })
    except Exception:
        logger.debug("wazuh_rule_catalog lookup failed", exc_info=True)
    return out


def _existing_sigma_content(conn, technique_id: str, limit: int = 5) -> list[dict[str, Any]]:
    if not technique_id:
        return []
    out: list[dict[str, Any]] = []
    try:
        rows = conn.execute(
            "SELECT detection_id, title, sigma_id, logsource, tags FROM detections "
            "WHERE tags ILIKE %s LIMIT %s",
            (f"%{technique_id.lower()}%", limit),
        ).fetchall()
        for row in rows:
            row = dict(row)
            out.append({
                "detection_id": row.get("detection_id"),
                "title": row.get("title"),
                "sigma_id": row.get("sigma_id"),
                "logsource": row.get("logsource"),
                "techniques": _techniques_from_tags(row.get("tags")),
            })
    except Exception:
        logger.debug("detections lookup failed", exc_info=True)
    return out


# ── Run resolution ───────────────────────────────────────────────────────────

def latest_run_id(conn, surface: str, attack_id: str) -> str | None:
    """Newest validation run for an attack on a surface, or None."""
    if surface in AD_SURFACES:
        row = conn.execute(
            "SELECT run_id FROM ad_validation_runs WHERE test_id = %s "
            "ORDER BY COALESCE(started_at, created_at) DESC, rowid DESC LIMIT 1",
            (attack_id,),
        ).fetchone()
        return row["run_id"] if row else None
    row = conn.execute(
        "SELECT run_id FROM web_linux_validation_runs "
        "WHERE surface = %s AND attack_id = %s ORDER BY created_at DESC, id DESC LIMIT 1",
        (surface, attack_id),
    ).fetchone()
    return row["run_id"] if row else None


# ── AD / Windows collection ──────────────────────────────────────────────────

def _collect_ad(conn, surface: str, attack_id: str, run_id: str) -> EvidenceBundle:
    from app.routes.ad_validation import _build_run_detail  # local: avoids import cycle

    run_row = conn.execute(
        """
        SELECT r.run_id, r.test_id, r.started_at, r.ended_at, r.source_host,
               r.target_host, r.source_ip, r.status, r.notes, r.created_at,
               t.behavior_name, t.technique_id, t.description, t.mitre_tactic,
               t.attack_category, t.risk_tier, t.expected_channels_json, t.expected_event_ids_json,
               t.expected_fields_json, t.simulation_command, t.false_positive_notes,
               t.required_wazuh_telemetry_json, t.telemetry_components_json
        FROM ad_validation_runs AS r
        LEFT JOIN ad_attack_tests AS t ON t.test_id = r.test_id
        WHERE r.run_id = %s
        """,
        (run_id,),
    ).fetchone()
    if run_row is None:
        raise EvidenceNotFound(f"No AD/Windows validation run '{run_id}'")

    run = dict(run_row)
    expected_channels = _json_load(run.pop("expected_channels_json", None), [])
    expected_event_ids = _json_load(run.pop("expected_event_ids_json", None), [])
    expected_fields = _json_load(run.pop("expected_fields_json", None), {})
    required_telemetry = _json_load(run.pop("required_wazuh_telemetry_json", None), [])
    telemetry_components = _json_load(run.pop("telemetry_components_json", None), [])

    # _build_run_detail expects the same keys get_validation_run passes.
    run["expected_channels"] = expected_channels
    run["expected_event_ids"] = expected_event_ids
    run["expected_fields"] = expected_fields

    evidence_rows = [dict(r) for r in conn.execute(
        "SELECT evidence_id, run_id, evidence_type, event_fingerprint, agent_name, "
        "channel, event_id, event_timestamp, wazuh_rule_id, imported_at, payload_json "
        "FROM ad_evidence WHERE run_id = %s ORDER BY evidence_id DESC",
        (run_id,),
    ).fetchall()]

    comparisons: list[dict[str, Any]] = []
    for row in conn.execute(
        "SELECT comparison_id, run_id, wazuh_rule_id, detection_id, total_score, "
        "static_verdict, wazuh_fired, sigma_matched, behavioral_verdict, "
        "matched_fields_json, missing_fields_json, tuning_notes, compared_at "
        "FROM ad_rule_comparisons WHERE run_id = %s ORDER BY comparison_id DESC",
        (run_id,),
    ).fetchall():
        comparison = dict(row)
        comparison["matched_fields"] = _json_load(comparison.pop("matched_fields_json", None), [])
        comparison["missing_fields"] = _json_load(comparison.pop("missing_fields_json", None), [])
        comparisons.append(comparison)

    detail = _build_run_detail(conn, run, evidence_rows, comparisons)

    raw_verdict = detail.get("result_state") or "UNKNOWN"
    technique_id = run.get("technique_id") or ""
    mitre = _mitre_lookup(conn, technique_id)
    if not mitre["tactic"]:
        mitre["tactic"] = run.get("mitre_tactic") or ""

    evidence_present = (detail.get("evidence") or {}).get("state") == "STORED"

    health = wazuh_pipeline_health(run.get("started_at"))
    telemetry = assess_telemetry(
        conn, surface, attack_id,
        evidence_present=evidence_present,
        ad_channels=expected_channels,
        pipeline_healthy=health.get("healthy"),
    )
    telemetry["expected_channels"] = expected_channels
    telemetry["expected_event_ids"] = expected_event_ids
    telemetry["required_wazuh_telemetry"] = required_telemetry
    telemetry["telemetry_components"] = telemetry_components

    wz = detail.get("wazuh") or {}
    sg = detail.get("sigma") or {}
    ev = detail.get("evidence") or {}

    raw_logs: list[dict[str, Any]] = []
    for row in evidence_rows[:3]:
        payload = _json_load(row.get("payload_json"), None)
        raw_logs.append({
            "channel": row.get("channel"),
            "event_id": row.get("event_id"),
            "agent_name": row.get("agent_name"),
            "event_timestamp": row.get("event_timestamp"),
            "wazuh_rule_id": row.get("wazuh_rule_id"),
            "payload": payload,
        })

    evidence = {
        "attack_id": attack_id,
        "attack_name": run.get("behavior_name") or attack_id,
        "surface": surface,
        "severity": run.get("risk_tier") or "",
        "mitre": mitre,
        "verdict": gap.normalize_verdict(raw_verdict),
        "raw_verdict": raw_verdict,
        "attack_description": run.get("description") or "",
        "attack_category": run.get("attack_category") or "",
        "expected_behavior": detail.get("recommendation_reason") or "",
        "expected_telemetry": {
            "channels": expected_channels,
            "event_ids": expected_event_ids,
            "fields": expected_fields,
            "components": telemetry_components,
        },
        "telemetry_health": {
            "available": telemetry["available"],
            "reason": telemetry["reason"],
            "sources": telemetry["sources"],
        },
        "wazuh_result": {
            "fired": detail.get("wazuh_fired"),
            "rule_state": wz.get("state"),
            "reason": wz.get("reason"),
        },
        "sigma_result": {
            "matched": detail.get("sigma_matched"),
            "state": sg.get("state"),
            "reason": sg.get("reason"),
            "condition_evaluation": detail.get("condition_evaluation"),
            "candidate_classification": detail.get("candidate_classification"),
        },
        "wazuh_rules": ([{
            "rule_id": wz.get("rule_id"),
            "raw_rule": wz.get("raw_rule"),
            "effective_logic": wz.get("effective_logic"),
        }] if wz.get("rule_id") is not None else []),
        "sigma_rules": ([{
            "detection_id": sg.get("detection_id"),
            "title": sg.get("title"),
            "techniques": sg.get("techniques"),
            "raw_yaml": sg.get("raw_yaml"),
        }] if sg.get("detection_id") is not None else []),
        "relevant_fields": ev.get("normalized_event"),
        "decoder": {
            "channel": ev.get("channel"),
            "event_id": ev.get("event_id"),
            "source": "Wazuh windows_eventchannel decoder",
        },
        "attack_execution": {
            "source_host": (detail.get("host") or {}).get("source"),
            "target_host": (detail.get("host") or {}).get("target"),
            "source_ip": (detail.get("host") or {}).get("source_ip"),
            "simulation_command": run.get("simulation_command"),
            "started_at": run.get("started_at"),
        },
        "known_false_positives": run.get("false_positive_notes") or detail.get("false_positive_notes"),
        "raw_logs": raw_logs,
        "existing_wazuh_content": _existing_wazuh_content(conn, technique_id),
        "existing_sigma_content": _existing_sigma_content(conn, technique_id),
        "surface_context": SURFACE_CONTEXT.get(surface, ""),
    }

    decision = gap.decide(
        surface=surface,
        attack_id=attack_id,
        raw_verdict=raw_verdict,
        telemetry_available=telemetry["available"],
        telemetry_reason=telemetry["reason"],
        wazuh_available=health.get("healthy"),
        wazuh_reason=health.get("reason", ""),
        validation_complete=evidence_present or raw_verdict != "INCOMPLETE_NO_EVIDENCE",
        validation_reason=(ev.get("reason") or ""),
    )

    return EvidenceBundle(
        surface=surface,
        attack_id=attack_id,
        validation_run_id=run_id,
        decision=decision,
        evidence=evidence,
        telemetry=telemetry,
        wazuh_health=health,
        attack_name=evidence["attack_name"],
        mitre=mitre,
        evidence_present=evidence_present,
    )


# ── Linux / Web collection ───────────────────────────────────────────────────

def _collect_web_linux(conn, surface: str, attack_id: str, run_id: str) -> EvidenceBundle:
    row = conn.execute(
        "SELECT * FROM web_linux_validation_runs WHERE run_id = %s AND surface = %s AND attack_id = %s",
        (run_id, surface, attack_id),
    ).fetchone()
    if row is None:
        raise EvidenceNotFound(
            f"No {surface} validation result for attack '{attack_id}' in run '{run_id}'"
        )
    run = dict(row)

    evidence_rows = [dict(r) for r in conn.execute(
        "SELECT wazuh_rule_id, rule_description, rule_level, full_log, agent_id, "
        "agent_name, event_timestamp FROM web_linux_evidence "
        "WHERE run_id = %s AND attack_id = %s ORDER BY evidence_id",
        (run_id, attack_id),
    ).fetchall()]

    execution_status = run.get("execution_status") or "EXECUTED"
    raw_verdict = run.get("verdict") or ("NOT_EXECUTED" if execution_status == "NOT_EXECUTED" else "UNKNOWN")
    technique_id = run.get("mitre_technique") or ""
    mitre = _mitre_lookup(conn, technique_id)
    evidence_present = bool(evidence_rows)

    health = wazuh_pipeline_health(run.get("started_at"))
    telemetry = assess_telemetry(
        conn, surface, attack_id,
        evidence_present=evidence_present,
        pipeline_healthy=health.get("healthy"),
    )

    sigma_rules: list[dict[str, Any]] = []
    for sigma_id in _json_load(run.get("sigma_rule_ids_json"), []):
        entry: dict[str, Any] = {"sigma_rule_id": sigma_id}
        if surface == "web":
            try:
                from app.routes.wazuh import _WEB_SIGMA_BY_ID
                mapped = _WEB_SIGMA_BY_ID.get(sigma_id)
                if mapped:
                    entry["title"] = mapped.get("title")
                    entry["raw_yaml"] = mapped.get("sigma")
                    entry["severity"] = mapped.get("severity")
            except Exception:
                logger.debug("web sigma catalog lookup failed", exc_info=True)
        sigma_rules.append(entry)

    wazuh_rules = [
        {
            "rule_id": e.get("wazuh_rule_id"),
            "description": e.get("rule_description"),
            "level": e.get("rule_level"),
        }
        for e in evidence_rows
        if e.get("wazuh_rule_id")
    ]
    # de-duplicate by rule id, preserving order
    seen_rules: set[str] = set()
    unique_wazuh_rules = []
    for entry in wazuh_rules:
        key = str(entry["rule_id"])
        if key not in seen_rules:
            seen_rules.add(key)
            unique_wazuh_rules.append(entry)

    relevant_fields = _extract_request_fields(surface, evidence_rows)

    evidence = {
        "attack_id": attack_id,
        "attack_name": run.get("attack_name") or attack_id,
        "surface": surface,
        "severity": "",
        "mitre": mitre,
        "verdict": gap.normalize_verdict(raw_verdict),
        "raw_verdict": raw_verdict,
        "attack_description": "",
        "expected_behavior": "",
        "expected_telemetry": {"sources": telemetry["expected_sources"]},
        "telemetry_health": {
            "available": telemetry["available"],
            "reason": telemetry["reason"],
            "sources": telemetry["sources"],
        },
        "wazuh_result": {
            "fired": (bool(run["wazuh_detected"]) if run.get("wazuh_detected") is not None else None),
            "rule_ids": _json_load(run.get("wazuh_rule_ids_json"), []),
        },
        "sigma_result": {
            "supported": bool(run.get("sigma_supported")),
            "matched": (bool(run["sigma_matched"]) if run.get("sigma_matched") is not None else None),
            "rule_ids": _json_load(run.get("sigma_rule_ids_json"), []),
        },
        "wazuh_rules": unique_wazuh_rules,
        "sigma_rules": sigma_rules,
        "relevant_fields": relevant_fields,
        "decoder": {
            "source": ("Wazuh web-accesslog / modsecurity decoders" if surface == "web"
                       else "Wazuh sshd / sudo / pam / auditd decoders"),
        },
        "attack_execution": {
            "target": run.get("target"),
            "agent_id": run.get("source_ip"),
            "started_at": run.get("started_at"),
            "execution_status": execution_status,
            "error_code": run.get("error_code"),
            "error_reason": run.get("error_reason"),
        },
        "raw_logs": [
            {
                "wazuh_rule_id": e.get("wazuh_rule_id"),
                "rule_description": e.get("rule_description"),
                "rule_level": e.get("rule_level"),
                "event_timestamp": e.get("event_timestamp"),
                "full_log": e.get("full_log"),
            }
            for e in evidence_rows[:3]
        ],
        "existing_wazuh_content": _existing_wazuh_content(conn, technique_id),
        "existing_sigma_content": _existing_sigma_content(conn, technique_id),
        "surface_context": SURFACE_CONTEXT.get(surface, ""),
    }

    decision = gap.decide(
        surface=surface,
        attack_id=attack_id,
        raw_verdict=raw_verdict,
        telemetry_available=telemetry["available"],
        telemetry_reason=telemetry["reason"],
        wazuh_available=health.get("healthy"),
        wazuh_reason=health.get("reason", ""),
        validation_complete=execution_status != "NOT_EXECUTED",
        validation_reason=(run.get("error_reason") or
                           "The attack never executed, so nothing was validated."),
    )

    return EvidenceBundle(
        surface=surface,
        attack_id=attack_id,
        validation_run_id=run_id,
        decision=decision,
        evidence=evidence,
        telemetry=telemetry,
        wazuh_health=health,
        attack_name=evidence["attack_name"],
        mitre=mitre,
        evidence_present=evidence_present,
    )


_REQUEST_LINE_RE = re.compile(
    r"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/([\d.]+)", re.IGNORECASE)
_STATUS_RE = re.compile(r'"\s+(\d{3})\s+')
_UA_RE = re.compile(r'"[^"]*"\s+\d{3}\s+\S+\s+"[^"]*"\s+"([^"]*)"')
_SRCIP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
# Standard syslog "program[pid]: message" framing (crontab, sudo, systemd, ...).
_SYSLOG_PROC_RE = re.compile(r"(?P<program>[A-Za-z0-9_.\-]+)\[(?P<pid>\d+)\]:\s*(?P<message>.*)$")
# Same, for daemons that log without a pid (some sshd/sudo configurations).
_SYSLOG_PROC_NOPID_RE = re.compile(
    r"\b(?P<program>sshd|sudo|su|useradd|userdel|crontab|systemd|kernel|auditd|passwd|login)"
    r"\s*:\s*(?P<message>.*)$", re.IGNORECASE)


def _extract_request_fields(surface: str, evidence_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Pull the detection-relevant parsed fields out of the captured raw logs.

    These are the fields a rule must key on — HTTP method/URI/query/status for
    web, process/user/auth-result hints for Linux — so the model works from what
    was actually logged rather than from the attack's display name.
    """
    fields: dict[str, Any] = {}
    for row in evidence_rows:
        log = row.get("full_log") or ""
        if not log:
            continue
        if surface == "web":
            match = _REQUEST_LINE_RE.search(log)
            if match and "http_method" not in fields:
                uri = match.group(2)
                fields["http_method"] = match.group(1).upper()
                fields["uri"] = uri.split("?", 1)[0]
                if "?" in uri:
                    query = uri.split("?", 1)[1]
                    fields["query_string"] = query
                    fields["query_parameters"] = sorted({
                        p.split("=", 1)[0] for p in query.split("&") if p
                    })
            status = _STATUS_RE.search(log)
            if status and "status_code" not in fields:
                fields["status_code"] = status.group(1)
            agent = _UA_RE.search(log)
            if agent and "user_agent" not in fields:
                fields["user_agent"] = agent.group(1)
        else:
            proc_match = _SYSLOG_PROC_RE.search(log) or _SYSLOG_PROC_NOPID_RE.search(log)
            if proc_match and "program" not in fields:
                gd = proc_match.groupdict()
                fields["program"] = gd["program"]
                if gd.get("pid"):
                    fields["pid"] = gd["pid"]
                fields["message"] = gd["message"].strip()
            elif "message" not in fields:
                # No syslog "program[pid]: ..." framing -- e.g. a Wazuh FIM/
                # syscheck alert body, which is its own multi-line text, not a
                # syslog line. Fall back to the raw log itself as the message,
                # since that's what a model-drafted `message|contains` means.
                fields["message"] = log
            for token in ("sshd", "sudo", "su", "useradd", "crontab", "systemd", "audit"):
                if token in log.lower():
                    fields.setdefault("processes", [])
                    if token not in fields["processes"]:
                        fields["processes"].append(token)
            if "type=" in log and "audit" in log.lower():
                fields.setdefault("audit_record", True)
            lowered = log.lower()
            if "failed password" in lowered or "authentication failure" in lowered:
                fields["auth_result"] = "failure"
            elif "accepted password" in lowered or "session opened" in lowered:
                fields["auth_result"] = "success"
        ip = _SRCIP_RE.search(log)
        if ip and "source_ip" not in fields:
            addr = ip.group(1)
            fields["source_ip"] = addr
            fields["source_ip_class"] = (
                "private/lab" if addr.startswith(("10.", "192.168.", "172.16.", "127."))
                else "external"
            )
        if row.get("rule_description") and "wazuh_rule_description" not in fields:
            fields["wazuh_rule_description"] = row["rule_description"]
    return fields


# ── Public entry point ───────────────────────────────────────────────────────

def collect(surface: str, attack_id: str,
            validation_run_id: str | None = None) -> EvidenceBundle:
    """Collect normalized evidence + the deterministic decision for one attack.

    Raises :class:`EvidenceNotFound` when the attack has never been validated.
    """
    surface = (surface or "").strip().lower()
    if surface not in ALL_SURFACES:
        raise ValueError(f"surface must be one of {ALL_SURFACES}")
    attack_id = (attack_id or "").strip()
    if not attack_id:
        raise ValueError("attack_id is required")

    conn = get_connection()
    try:
        run_id = validation_run_id or latest_run_id(conn, surface, attack_id)
        if not run_id:
            raise EvidenceNotFound(
                f"No validation run has been recorded for {surface} attack '{attack_id}'. "
                "Run the attack and validate it before requesting an AI recommendation."
            )
        if surface in AD_SURFACES:
            return _collect_ad(conn, surface, attack_id, run_id)
        return _collect_web_linux(conn, surface, attack_id, run_id)
    finally:
        conn.close()
