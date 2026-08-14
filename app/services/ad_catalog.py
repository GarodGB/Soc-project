"""
ABSEGA - AD catalog service helpers (additive, no existing logic touched).

Responsibilities:
  * validate_targets()      - enforce the lab allowlist / reject public + external
  * mask_sensitive()        - redact passwords / hashes / krbtgt / keys before
                              storing or returning evidence
  * observed_components()   - which telemetry components are PROVEN to reach the
                              pipeline, derived from REAL ad_evidence rows
  * attack_readiness()      - ready / partially_ready / missing / unknown, from
                              observed evidence (never "ready" just because a
                              definition lists an Event ID)
  * serialize_attack()      - assemble the full catalog/detail object
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Iterable, Mapping

# ---------------------------------------------------------------- allowlist ---
ALLOWED_HOSTS = {"dc01", "win11"}          # short names (case-insensitive)
ALLOWED_DOMAIN = "absega.local"
ALLOWED_IPS = {"10.10.10.10", "10.10.10.11"}
# lab infra we still consider internal (Wazuh mgr) - allowed as source, not a
# valid attack *target*, but we don't reject it outright for run bookkeeping.
LAB_INFRA_IPS = {"10.10.10.20", "192.168.56.101"}


def _host_allowed(value: str) -> bool:
    v = value.strip().lower()
    if not v:
        return True
    if v == ALLOWED_DOMAIN or v.endswith("." + ALLOWED_DOMAIN):
        return True
    short = v.split(".")[0]
    return short in ALLOWED_HOSTS


def _ip_allowed(value: str) -> tuple[bool, str | None]:
    v = value.strip()
    if not v:
        return True, None
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        # not an IP literal -> treat as hostname elsewhere
        return _host_allowed(v), None
    if ip.is_global:
        return False, f"{v} is a public IP address (rejected)"
    if v in ALLOWED_IPS or v in LAB_INFRA_IPS:
        return True, None
    # private but not on the lab allowlist
    return False, f"{v} is not on the lab allowlist ({sorted(ALLOWED_IPS)})"


def validate_targets(
    source_host: str | None,
    target_host: str | None,
    source_ip: str | None,
    target_ip: str | None = None,
) -> tuple[bool, list[str]]:
    """Return (ok, violations). ok=False means the run must be rejected."""
    violations: list[str] = []

    for label, host in (("source_host", source_host), ("target_host", target_host)):
        if host and not _host_allowed(str(host)):
            violations.append(f"{label} '{host}' is not a lab host (DC01/WIN11/absega.local)")

    for label, ip in (("source_ip", source_ip), ("target_ip", target_ip)):
        if ip:
            ok, reason = _ip_allowed(str(ip))
            if not ok:
                violations.append(f"{label} {reason}")

    return (len(violations) == 0), violations


# --------------------------------------------------------------- masking -----
_SENSITIVE_KEY = re.compile(
    r"(password|passwd|pwd|cpassword|nthash|lmhash|ntlm|krbtgt|secret|"
    r"privatekey|private_key|keycredential|key_credential|aes256|aes128|"
    r"kirbi|ticket_blob|plaintext|credential_blob)",
    re.IGNORECASE,
)
# Long hex blobs that look like hashes / keys (>=32 hex chars). File hashes
# (MD5/SHA1/SHA256/SHA512/IMPHASH — exactly how Sysmon labels its `Hashes`
# field) are public fingerprints, not credentials: an engineer needs them for
# detection tuning and threat-intel lookups, so a blob immediately preceded
# by one of those labels is left alone. Anything else that looks like a
# hash/key blob (an NTLM/LM hash, or credential material with no recognizable
# file-hash label) is still redacted — masking is the safe default.
_FILE_HASH_LABELS = r"MD5|SHA1|SHA256|SHA512|IMPHASH"
_HEX_BLOB = re.compile(
    rf"(?:\b(?:{_FILE_HASH_LABELS})=)?\b[0-9a-fA-F]{{32,}}\b",
    re.IGNORECASE,
)
_FILE_HASH_PREFIX = re.compile(rf"^(?:{_FILE_HASH_LABELS})=", re.IGNORECASE)
REDACTED = "***REDACTED***"


def _redact_hex_blob(match: "re.Match[str]") -> str:
    return match.group(0) if _FILE_HASH_PREFIX.match(match.group(0)) else REDACTED


def mask_sensitive(obj: Any) -> Any:
    """Recursively redact sensitive values. Returns a masked *copy*."""
    if isinstance(obj, Mapping):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if isinstance(k, str) and _SENSITIVE_KEY.search(k):
                out[k] = REDACTED
            else:
                out[k] = mask_sensitive(v)
        return out
    if isinstance(obj, list):
        return [mask_sensitive(v) for v in obj]
    if isinstance(obj, str):
        return _HEX_BLOB.sub(_redact_hex_blob, obj)
    return obj


# --------------------------------------------------- telemetry readiness -----
# Map real evidence (channel substrings / event-id ranges) -> component keys.
# A component is "observed" only if actual ad_evidence shows it reached the pipe.
_CHANNEL_COMPONENT = [
    ("security", "security_log"),
    ("system", "system_log"),
    ("directory service", "directory_service_log"),
    ("powershell/operational", "powershell_operational"),
    ("windows powershell", "windows_powershell"),
    ("sysmon", "sysmon_operational"),
    ("certificateservices", "cert_services_log"),
    ("winrm", "system_log"),
]
_EVENTID_COMPONENT = {
    "4662": "ds_access_audit",
    "4663": "object_access_audit",
    "5136": "ds_changes_audit", "5137": "ds_changes_audit",
    "5139": "ds_changes_audit", "5141": "ds_changes_audit",
    "4688": "process_creation_cmdline",
    "4768": "kerberos_audit", "4769": "kerberos_audit", "4771": "kerberos_audit",
    "4776": "credential_validation",
    "4720": "account_management", "4722": "account_management",
    "4724": "account_management", "4738": "account_management",
    "4728": "group_management", "4732": "group_management", "4756": "group_management",
    "1644": "ldap_diagnostics",
    "4886": "cert_services_log", "4887": "cert_services_log",
}


def observed_components(connection) -> set[str]:
    """Components proven present, derived from REAL ad_evidence rows + archives."""
    observed: set[str] = set()
    rows = connection.execute(
        "SELECT DISTINCT channel, event_id FROM ad_evidence"
    ).fetchall()
    for r in rows:
        ch = (r["channel"] or "").lower() if _has_key(r, "channel") else ""
        eid = str(r["event_id"] or "") if _has_key(r, "event_id") else ""
        for needle, comp in _CHANNEL_COMPONENT:
            if needle in ch:
                observed.add(comp)
        if eid in _EVENTID_COMPONENT:
            observed.add(_EVENTID_COMPONENT[eid])
    # any stored evidence at all proves the Wazuh archive path works
    if rows:
        observed.add("wazuh_archives")
    return observed


def _has_key(row, key) -> bool:
    try:
        return key in row.keys()
    except Exception:
        return True


def attack_readiness(required: Iterable[str], observed: set[str]) -> tuple[str, list[str], list[str]]:
    req = [c for c in required if c]
    if not req:
        return "unknown", [], []
    present = [c for c in req if c in observed]
    missing = [c for c in req if c not in observed]
    if not present:
        return "missing", present, missing
    if missing:
        return "partially_ready", present, missing
    return "ready", present, missing


# ------------------------------------------------- serialization -------------
def _loads(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return default


def serialize_attack(
    row: Mapping[str, Any],
    observed: set[str],
    latest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the catalog/detail object for one attack row."""
    tcs = _loads(row["telemetry_components_json"] if _has_key(row, "telemetry_components_json") else None, [])
    readiness, present, missing = attack_readiness(tcs, observed)

    data = {
        "attack_key": row["attack_key"] if _has_key(row, "attack_key") else row["test_id"],
        "test_id": row["test_id"],
        "display_name": _get(row, "display_name") or _get(row, "behavior_name"),
        "description": _get(row, "description"),
        "technique_id": _get(row, "technique_id"),
        "mitre_tactic": _get(row, "mitre_tactic"),
        "attack_category": _get(row, "attack_category"),
        "attack_stage": _get(row, "attack_stage"),
        "execution_host": _get(row, "execution_host"),
        "target_host": _get(row, "target_host"),
        "required_privileges": _get(row, "required_privileges"),
        "risk_tier": _get(row, "risk_tier"),
        "support_mode": _get(row, "support_mode"),
        "prerequisite_status": _get(row, "prerequisite_status"),
        "implementation_status": _get(row, "implementation_status"),
        "prerequisites": _loads(_get(row, "prerequisites_json"), []),
        "required_tools": _loads(_get(row, "required_tools_json"), []),
        "expected_channels": _loads(_get(row, "expected_channels_json"), []),
        "expected_event_ids": _loads(_get(row, "expected_event_ids_json"), []),
        "expected_sysmon_ids": _loads(_get(row, "expected_sysmon_ids_json"), []),
        "expected_protocols": _loads(_get(row, "expected_protocols_json"), []),
        "required_wazuh_telemetry": _loads(_get(row, "required_wazuh_telemetry_json"), []),
        "false_positive_notes": _get(row, "false_positive_notes"),
        "simulation_command": _get(row, "simulation_command"),
        "cleanup_command": _get(row, "cleanup_command"),
        "rollback_requirements": _get(row, "rollback_requirements"),
        "telemetry_components": tcs,
        "telemetry_readiness": readiness,
        "telemetry_present": present,
        "telemetry_missing": missing,
        # run / verdict summary (None until a run exists)
        "last_run_id": None,
        "last_run_at": None,
        "latest_verdict": None,
        "wazuh_result": None,
        "sigma_result": None,
    }

    if latest:
        data["last_run_id"] = latest.get("run_id")
        data["last_run_at"] = latest.get("started_at")
        wfired = latest.get("wazuh_fired")
        smatch = latest.get("sigma_matched")
        data["latest_verdict"] = latest.get("behavioral_verdict") or latest.get("static_verdict")
        data["wazuh_result"] = (
            "alert" if wfired == 1 else "no_alert" if wfired == 0 else "not_evaluated"
        )
        data["sigma_result"] = (
            "match" if smatch == 1 else "no_match" if smatch == 0 else "not_evaluated"
        )

    # honesty overrides: never imply a result that wasn't produced
    if data["prerequisite_status"] == "blocked_by_prerequisite" and not data["latest_verdict"]:
        data["latest_verdict"] = "BLOCKED_BY_PREREQUISITE"
    if not data["latest_verdict"]:
        data["latest_verdict"] = "NOT_EXECUTED"

    return data


def _get(row: Mapping[str, Any], key: str) -> Any:
    return row[key] if _has_key(row, key) else None
