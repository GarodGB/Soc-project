from __future__ import annotations

import json
import re
from typing import Any, Iterable, Mapping


FIELD_ALIASES = {
    "win.system.eventid": "event_id",
    "win.system.eventID": "event_id",
    "eventid": "event_id",
    "event_id": "event_id",
    "win.eventdata.image": "image",
    "image": "image",
    "win.eventdata.commandline": "command_line",
    "commandline": "command_line",
    "command_line": "command_line",
    "win.eventdata.parentimage": "parent_image",
    "parentimage": "parent_image",
    "win.eventdata.targetusername": "target_user",
    "targetusername": "target_user",
    "win.eventdata.subjectusername": "subject_user",
    "subjectusername": "subject_user",
    "win.eventdata.ipaddress": "source_ip",
    "sourceip": "source_ip",
    "win.eventdata.pipename": "pipe_name",
    "pipename": "pipe_name",
    "win.eventdata.targetfilename": "file_name",
    "targetfilename": "file_name",
}


def _canonical_field(value: str) -> str:
    compact = value.strip().replace(" ", "").casefold()
    return FIELD_ALIASES.get(compact, compact)


def _tokenize(value: Any) -> set[str]:
    text = str(value or "").casefold()
    return {
        token.strip(".\\/-_")
        for token in re.findall(r"[a-z0-9_.\\/-]{3,}", text)
        if token.strip(".\\/-_") and not token.isdigit()
    }


def _jaccard(left: set[str], right: set[str], *, unknown_score: float = 0.5) -> float:
    if not left and not right:
        return unknown_score
    if not left or not right:
        return unknown_score
    union = left | right
    return len(left & right) / len(union) if union else unknown_score


# Detection-engineering weights: MITRE technique dominates, raw token/value overlap
# is the weakest signal. Weights are renormalized over the dimensions that actually
# have evidence (see _dim_score), so a missing dimension never grants free credit.
WEIGHTS = {
    "mitre": 0.40,
    "event_id": 0.25,
    "logsource": 0.15,
    "field": 0.12,
    "value": 0.05,
    "dependency": 0.03,
}


def _dim_score(left: set[str], right: set[str]):
    """Jaccard overlap, or None when either side has no evidence for this dimension.

    Returning None (instead of a 0.5 default) means the dimension is EXCLUDED from the
    weighted total rather than inflating an unrelated match."""
    if not left or not right:
        return None
    union = left | right
    return (len(left & right) / len(union)) if union else 0.0


def _base_technique(value: str) -> str:
    v = str(value or "").upper()
    return v.split(".")[0] if v.startswith("T") else v


def _source_terms_wazuh(effective: Mapping[str, Any]) -> set[str]:
    conditions = effective.get("conditions") or {}
    terms: set[str] = set()
    for key in ("decoded_as", "category", "program_name", "groups", "match", "regex"):
        for value in conditions.get(key, []) or []:
            terms |= _tokenize(value)
    for field in conditions.get("fields", []) or []:
        terms |= _tokenize(field.get("field"))
        terms |= _tokenize(field.get("value"))
    normalized: set[str] = set()
    joined = " ".join(terms)
    if "sysmon" in joined:
        normalized.add("sysmon")
    if "powershell" in joined:
        normalized.add("powershell")
    if "security" in joined or "windows" in joined:
        normalized.add("windows")
    if "auditd" in joined or "linux" in joined:
        normalized.add("linux")
    return normalized or terms


def _source_terms_sigma(sigma: Mapping[str, Any]) -> set[str]:
    logsource = sigma.get("logsource") or {}
    terms = {
        str(value).casefold()
        for value in (logsource.get("product"), logsource.get("category"), logsource.get("service"))
        if value
    }
    normalized: set[str] = set()
    joined = " ".join(terms)
    if "sysmon" in joined or "process_creation" in joined:
        normalized.add("sysmon")
    if "powershell" in joined:
        normalized.add("powershell")
    if "windows" in joined:
        normalized.add("windows")
    if "linux" in joined:
        normalized.add("linux")
    return normalized or terms


def _wazuh_features(effective: Mapping[str, Any]) -> dict[str, set[str]]:
    conditions = effective.get("conditions") or {}
    fields: set[str] = set()
    values: set[str] = set()
    event_ids: set[str] = set()

    for item in conditions.get("fields", []) or []:
        field = _canonical_field(str(item.get("field") or ""))
        if field:
            fields.add(field)
        value = item.get("value")
        values |= _tokenize(value)
        if field == "event_id" and value not in (None, ""):
            event_ids.add(str(value))

    for key in ("match", "regex"):
        for value in conditions.get(key, []) or []:
            values |= _tokenize(value)
            text = str(value)
            for pattern in (
                r"event(?:id|_id)?\D{0,8}(\d{1,5})",
                r"win\.system\.eventid\D{0,8}(\d{1,5})",
            ):
                event_ids.update(re.findall(pattern, text, flags=re.IGNORECASE))

    return {"fields": fields, "values": values, "event_ids": event_ids}


def compare_rule_content(wazuh_rule: Mapping[str, Any], sigma_rule: Mapping[str, Any]) -> dict[str, Any]:
    effective = wazuh_rule.get("effective_logic") or wazuh_rule
    wazuh = _wazuh_features(effective)

    sigma_fields = {_canonical_field(str(value)) for value in sigma_rule.get("fields", []) or []}
    sigma_values = {str(value).casefold() for value in sigma_rule.get("values", []) or []}
    sigma_event_ids = {str(value) for value in sigma_rule.get("event_ids", []) or []}

    wazuh_sources = _source_terms_wazuh(effective)
    sigma_sources = _source_terms_sigma(sigma_rule)

    status = str(effective.get("resolution_status") or "unknown")
    dependency_raw = 1.0 if status == "resolved" else 0.5 if status == "partially_resolved" else None

    wazuh_mitre = {
        str(value).upper()
        for value in ((effective.get("conditions") or {}).get("mitre") or {}).get("id", [])
    }
    sigma_mitre = {str(value).upper() for value in sigma_rule.get("mitre", []) or []}

    # Per-dimension similarity. None => no evidence on one/both sides for that dimension.
    dim = {
        "mitre": _dim_score(wazuh_mitre, sigma_mitre),
        "event_id": _dim_score(wazuh["event_ids"], sigma_event_ids),
        "logsource": _dim_score(wazuh_sources, sigma_sources),
        "field": _dim_score(wazuh["fields"], sigma_fields),
        "value": _dim_score(wazuh["values"], sigma_values),
        "dependency": dependency_raw,
    }

    # Weighted score renormalized over dimensions that actually carry evidence.
    present = {k: v for k, v in dim.items() if v is not None}
    weight_sum = sum(WEIGHTS[k] for k in present) or 1.0
    total = round(sum(WEIGHTS[k] * v for k, v in present.items()) / weight_sum, 10) if present else 0.0
    total_percent = round(total * 100.0, 2)

    # ---- MITRE technique compatibility gate ----
    # If BOTH sides declare ATT&CK techniques and their base techniques are disjoint,
    # the comparison is not valid detection coverage (e.g. T1047 vs a firewall rule).
    w_base = {_base_technique(t) for t in wazuh_mitre}
    s_base = {_base_technique(t) for t in sigma_mitre}
    if wazuh_mitre and sigma_mitre:
        mitre_relation = "match" if (w_base & s_base) else "conflict"
    else:
        mitre_relation = "unknown"
    compatible = mitre_relation != "conflict"

    mapping_only = (
        (dim["mitre"] or 0.0) > 0.0
        and not dim["event_id"]
        and not dim["field"]
        and not dim["value"]
    )

    if mitre_relation == "conflict":
        verdict = "NO_COMPATIBLE_DETECTION"
    elif not present:
        verdict = "INSUFFICIENT_DATA"
    elif mapping_only:
        verdict = "MAPPING_ONLY"
    elif total_percent >= 80.0:
        verdict = "STRONG_STATIC_OVERLAP"
    elif total_percent >= 60.0:
        verdict = "LIKELY_STATIC_OVERLAP"
    elif total_percent >= 40.0:
        verdict = "PARTIAL_OVERLAP"
    else:
        verdict = "NO_CONTENT_OVERLAP"

    def _num(x):
        return round(x, 4) if isinstance(x, (int, float)) else 0.0

    matched_fields = sorted(wazuh["fields"] & sigma_fields)
    missing_fields = sorted(sigma_fields - wazuh["fields"])
    matched_values = sorted(wazuh["values"] & sigma_values)

    return {
        "wazuh_rule_id": wazuh_rule.get("rule_id") or wazuh_rule.get("wazuh_rule_id") or effective.get("root_rule_id"),
        "detection_id": sigma_rule.get("detection_id"),
        "compatible": compatible,
        "mitre_relation": mitre_relation,
        "scores": {
            "logsource": _num(dim["logsource"]),
            "event_id": _num(dim["event_id"]),
            "field": _num(dim["field"]),
            "value": _num(dim["value"]),
            "dependency": _num(dim["dependency"]),
            "mitre": _num(dim["mitre"]),
            "total": round(total, 4),
            "total_percent": round(total_percent, 2),
        },
        "applicable": {
            k: (dim[k] is not None)
            for k in ("logsource", "event_id", "field", "value", "dependency", "mitre")
        },
        "verdict": verdict,
        "matched_fields": matched_fields,
        "missing_fields": missing_fields,
        "matched_values": matched_values,
        "evidence": {
            "wazuh_sources": sorted(wazuh_sources),
            "sigma_sources": sorted(sigma_sources),
            "wazuh_event_ids": sorted(wazuh["event_ids"]),
            "sigma_event_ids": sorted(sigma_event_ids),
            "wazuh_mitre": sorted(wazuh_mitre),
            "sigma_mitre": sorted(sigma_mitre),
            "mitre_relation": mitre_relation,
            "wazuh_parent_rule_ids": effective.get("parent_rule_ids", []),
            "resolution_status": status,
        },
    }
