"""Redaction of validation evidence before it is sent to the Gemini cloud API.

The rule of thumb applied throughout: **strip credentials, keep behaviour**.
A detection engineer cannot write a rule for Kerberoasting without the Event ID,
the ticket encryption type and the service name — but nobody needs the NTLM
hash, the session cookie or the DVWA password to do it.

Everything in :func:`sanitize` is applied to the evidence payload *before* it is
serialised into a prompt, and :func:`truncate_evidence` then enforces
``GEMINI_MAX_EVIDENCE_CHARS`` while preserving the detection-relevant keys.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any

from app.config import scrub_secrets

# ── Placeholders ─────────────────────────────────────────────────────────────

REDACTED_API_KEY = "[REDACTED_API_KEY]"
REDACTED_PASSWORD = "[REDACTED_PASSWORD]"
REDACTED_TOKEN = "[REDACTED_TOKEN]"
REDACTED_USERNAME = "[REDACTED_USERNAME]"
REDACTED_HOSTNAME = "[REDACTED_HOSTNAME]"
REDACTED_HASH = "[REDACTED_HASH]"
REDACTED_EMAIL = "[REDACTED_EMAIL]"
REDACTED_KEY = "[REDACTED_PRIVATE_KEY]"

#: Field names whose *values* are always credentials, whatever they contain.
_SECRET_FIELD_NAMES = {
    "password", "passwd", "pwd", "pass", "secret", "api_key", "apikey",
    "access_token", "refresh_token", "id_token", "token", "authorization",
    "auth", "cookie", "cookies", "set-cookie", "session", "sessionid",
    "session_id", "phpsessid", "private_key", "privatekey", "client_secret",
    "credential", "credentials", "ntlm", "nthash", "lmhash", "wazuh_password",
    "indexer_password", "target_password", "gemini_api_key", "anthropic_api_key",
}

#: Field names that carry a person/host identity we do not need for detection
#: logic. The *shape* of the value is preserved via the placeholder.
_IDENTITY_FIELD_NAMES = {
    "user", "username", "user_name", "targetusername", "subjectusername",
    "samaccountname", "dstuser", "srcuser", "account", "account_name",
    "loginuser", "email", "mail", "userprincipalname",
}

_HOSTNAME_FIELD_NAMES = {
    "hostname", "computername", "workstation", "workstationname",
    "agent_name", "agent.name", "host", "dns_hostname",
}

# ── Value-level patterns ─────────────────────────────────────────────────────

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # PEM private keys (whole block).
    (re.compile(r"-----BEGIN[^-]{0,40}PRIVATE KEY-----.*?-----END[^-]{0,40}PRIVATE KEY-----",
                re.DOTALL | re.IGNORECASE), REDACTED_KEY),
    # HTTP auth headers / bearer tokens.
    (re.compile(r"(?i)\bauthorization\s*:\s*(?:bearer|basic|negotiate|ntlm)\s+\S+"),
     f"Authorization: {REDACTED_TOKEN}"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{12,}=*"), f"Bearer {REDACTED_TOKEN}"),
    # Cookie / session headers.
    (re.compile(r"(?i)\b(set-)?cookie\s*:\s*[^\r\n]+"), f"Cookie: {REDACTED_TOKEN}"),
    (re.compile(r"(?i)\bPHPSESSID=[^;&\s\"']+"), f"PHPSESSID={REDACTED_TOKEN}"),
    (re.compile(r"(?i)\b(?:jsessionid|sessionid|session_id|sid)=[^;&\s\"']+"),
     f"sessionid={REDACTED_TOKEN}"),
    # Passwords in query strings, form bodies and command lines.
    (re.compile(r"(?i)\b(password|passwd|pwd|pass)=([^&;\s\"']+)"),
     lambda m: f"{m.group(1)}={REDACTED_PASSWORD}"),
    (re.compile(r"(?i)(-p|--password|/pass:|-Password)\s+(?!\s)\S+"),
     lambda m: f"{m.group(1)} {REDACTED_PASSWORD}"),
    (re.compile(r"(?i)\b(api[_-]?key|apikey|access[_-]?key|client[_-]?secret)"
                r"\s*[=:]\s*[\"']?[A-Za-z0-9\-_]{8,}[\"']?"),
     lambda m: f"{m.group(1)}={REDACTED_API_KEY}"),
    (re.compile(r"(?i)\b(token)\s*[=:]\s*[\"']?[A-Za-z0-9\-._~+/]{12,}=*[\"']?"),
     lambda m: f"{m.group(1)}={REDACTED_TOKEN}"),
    # Known cloud key shapes.
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}"), REDACTED_API_KEY),
    (re.compile(r"\bsk-[A-Za-z0-9\-_]{16,}"), REDACTED_API_KEY),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED_API_KEY),
    # basic-auth inside a URL: scheme://user:pass@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^\s/:@]+:[^\s/@]+@"),
     lambda m: f"{m.group(1)}{REDACTED_USERNAME}:{REDACTED_PASSWORD}@"),
    # Credential hashes: NTLM/LM pairs, and long hex digests presented as hashes.
    (re.compile(r"\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b"), REDACTED_HASH),
    (re.compile(r"(?i)\$krb5(?:tgs|asrep)\$[^\s\"']+"), REDACTED_HASH),
    (re.compile(r"(?i)\b(hash|ntlm|nthash|lmhash|md4|ntlmv2)\s*[=:]\s*[a-fA-F0-9]{16,}"),
     lambda m: f"{m.group(1)}={REDACTED_HASH}"),
    (re.compile(r"\$(?:2[aby]|6|5|1)\$[^\s:\"']+"), REDACTED_HASH),
    # Email addresses.
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), REDACTED_EMAIL),
    # DVWA's well-known demo credentials.
    (re.compile(r"(?i)\b(admin|gordonb|1337|pablo|smithy)\s*[:/]\s*"
                r"(password|abc123|charley|letmein|bushell)\b"),
     lambda m: f"{m.group(1)}:{REDACTED_PASSWORD}"),
    (re.compile(r"(?i)\bssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/=]{40,}"),
     f"ssh-rsa {REDACTED_KEY}"),
]

#: Maximum characters kept from any single raw log / request body.
MAX_SINGLE_LOG_CHARS = 4000

#: Keys that must survive truncation — they carry the detection logic.
PRIORITY_KEYS = (
    "attack_id", "attack_name", "surface", "severity", "verdict", "raw_verdict",
    "mitre", "expected_behavior", "expected_telemetry", "telemetry_health",
    "wazuh_result", "sigma_result", "wazuh_rules", "sigma_rules",
    "relevant_fields", "decoder", "existing_wazuh_content", "existing_sigma_content",
    "previous_draft", "engineer_feedback",
)


def redact_text(value: str) -> str:
    """Apply every value-level redaction to a single string."""
    if not value:
        return value
    out = scrub_secrets(str(value))
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def _placeholder_for_key(key: str) -> str | None:
    lowered = key.strip().lower().replace("-", "_")
    bare = lowered.rsplit(".", 1)[-1]
    if lowered in _SECRET_FIELD_NAMES or bare in _SECRET_FIELD_NAMES:
        if "key" in bare and "private" not in bare:
            return REDACTED_API_KEY
        if "private_key" in bare or bare == "privatekey":
            return REDACTED_KEY
        if "token" in bare or "cookie" in bare or "session" in bare or bare in {"auth", "authorization"}:
            return REDACTED_TOKEN
        if "hash" in bare or bare in {"ntlm", "nthash", "lmhash"}:
            return REDACTED_HASH
        return REDACTED_PASSWORD
    if lowered in _IDENTITY_FIELD_NAMES or bare in _IDENTITY_FIELD_NAMES:
        return REDACTED_EMAIL if bare in {"email", "mail", "userprincipalname"} else REDACTED_USERNAME
    if lowered in _HOSTNAME_FIELD_NAMES or bare in _HOSTNAME_FIELD_NAMES:
        return REDACTED_HOSTNAME
    return None


def sanitize(value: Any, _key: str = "") -> Any:
    """Recursively redact a JSON-serialisable evidence structure.

    Dict keys are matched against known credential/identity field names; every
    string value additionally goes through the pattern redactions. Long raw logs
    are clipped to :data:`MAX_SINGLE_LOG_CHARS` with an explicit marker so the
    model can see that truncation happened.
    """
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, child in value.items():
            placeholder = _placeholder_for_key(str(key))
            if placeholder is not None and not isinstance(child, (dict, list)):
                out[key] = placeholder if child not in (None, "") else child
                continue
            out[key] = sanitize(child, str(key))
        return out
    if isinstance(value, list):
        return [sanitize(item, _key) for item in value]
    if isinstance(value, str):
        cleaned = redact_text(value)
        if len(cleaned) > MAX_SINGLE_LOG_CHARS:
            cleaned = cleaned[:MAX_SINGLE_LOG_CHARS] + "\n…[TRUNCATED_LOG]"
        return cleaned
    return value


def sanitize_evidence(evidence: dict) -> dict:
    """Sanitise a full evidence payload without mutating the caller's copy."""
    return sanitize(copy.deepcopy(evidence))


def evidence_fingerprint(evidence: dict) -> str:
    """Stable hash of the sanitised evidence, used for dedup and draft reuse.

    Volatile keys (timestamps, run identifiers, the engineer's feedback) are
    excluded so re-validating the same attack with the same outcome reuses the
    existing draft instead of spending another Gemini call.
    """
    volatile = {"generated_at", "collected_at", "engineer_feedback", "previous_draft",
                "validation_run_id", "started_at", "ended_at", "event_timestamp"}
    trimmed = {k: v for k, v in evidence.items() if k not in volatile}
    blob = json.dumps(trimmed, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def truncate_evidence(evidence: dict, max_chars: int) -> tuple[str, bool]:
    """Serialise *evidence* to JSON no longer than *max_chars*.

    Priority keys (event IDs, parsed fields, rule IDs, MITRE mappings, attack
    behaviour, URI/command details) are kept intact; bulky raw-log arrays are
    shed first, then progressively clipped.
    """
    def dump(payload: dict) -> str:
        return json.dumps(payload, indent=2, default=str, ensure_ascii=False)

    text = dump(evidence)
    if len(text) <= max_chars:
        return text, False

    trimmed = copy.deepcopy(evidence)

    # 1) Keep only the first raw log entry.
    logs = trimmed.get("raw_logs")
    if isinstance(logs, list) and len(logs) > 1:
        trimmed["raw_logs"] = logs[:1]
        trimmed["raw_logs_omitted"] = len(logs) - 1
        text = dump(trimmed)
        if len(text) <= max_chars:
            return text, True

    # 2) Clip each remaining raw log.
    logs = trimmed.get("raw_logs")
    if isinstance(logs, list):
        budget = max(400, max_chars // 4)
        clipped = []
        for entry in logs:
            if isinstance(entry, dict):
                entry = dict(entry)
                for field_name in ("full_log", "payload", "raw"):
                    val = entry.get(field_name)
                    if isinstance(val, str) and len(val) > budget:
                        entry[field_name] = val[:budget] + "\n…[TRUNCATED_LOG]"
                clipped.append(entry)
            elif isinstance(entry, str) and len(entry) > budget:
                clipped.append(entry[:budget] + "\n…[TRUNCATED_LOG]")
            else:
                clipped.append(entry)
        trimmed["raw_logs"] = clipped
        text = dump(trimmed)
        if len(text) <= max_chars:
            return text, True

    # 3) Drop non-priority sections entirely.
    minimal = {k: v for k, v in trimmed.items() if k in PRIORITY_KEYS}
    minimal["evidence_truncated"] = (
        "Non-essential sections were dropped to fit the evidence budget."
    )
    text = dump(minimal)
    if len(text) <= max_chars:
        return text, True

    # 4) Last resort — hard clip.
    return text[:max_chars] + "\n…[TRUNCATED_EVIDENCE]", True


#: Shown verbatim in the AI panel before anything is sent.
CLOUD_NOTICE = (
    "Gemini is a cloud API. Selected and sanitized validation evidence will be "
    "sent to Gemini to generate this draft."
)
