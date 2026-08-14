"""Server-side Gemini integration for detection-rule recommendation.

Gemini is reachable only from this module, only from the FastAPI backend, and
only with sanitized evidence. The API key is read from ``GEMINI_API_KEY`` and
handed straight to the Google Gen AI SDK — it is never returned, logged or
persisted.

What this module guarantees to its callers:

* one request timeout, exponential backoff, retries on HTTP 429 and transient
  5xx, and no retry at all on a permanent 4xx;
* strict JSON output validated against ``GeminiRuleSuggestion``, with exactly
  one structured repair attempt before giving up;
* per-actor rate limiting and in-flight request de-duplication;
* every error string passed through ``scrub_secrets``.

It never decides a verdict, never approves anything, and has no access to the
deployment service.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Callable

from app.config import PROVIDER, GeminiSettings, gemini_settings, scrub_secrets
from app.models.ai_rule_models import (
    GeminiRuleSuggestion,
    contradictions,
    parse_model_json,
)

logger = logging.getLogger(__name__)


# ── Errors ───────────────────────────────────────────────────────────────────

class GeminiError(Exception):
    """Base class — the message is always safe to return to a client."""

    status_code = 502

    def __init__(self, message: str):
        super().__init__(scrub_secrets(message))


class GeminiNotConfigured(GeminiError):
    status_code = 503


class GeminiDisabled(GeminiError):
    status_code = 503


class GeminiRateLimited(GeminiError):
    status_code = 429


class GeminiQuotaExhausted(GeminiError):
    status_code = 429


class GeminiTimeout(GeminiError):
    status_code = 504


class GeminiInvalidOutput(GeminiError):
    status_code = 502


class GeminiContradiction(GeminiInvalidOutput):
    """The model's output disagrees with the deterministic verdict."""


# ── System instruction ───────────────────────────────────────────────────────

SYSTEM_INSTRUCTION = """\
You are assisting a Detection Engineer in a controlled defensive security \
validation lab.

The application has already determined the validation verdict. Do not change, \
reinterpret, or override that verdict.

Generate defensive detection content only. Use only the supplied evidence.

Do not invent:
- Event fields
- Data sources
- Existing rules
- Wazuh decoder names
- Rule IDs already in use
- Successful validation results
- Successful deployment results
- Telemetry availability
- Wazuh behavior not supported by evidence
- Sigma backend support not demonstrated by the application

If evidence is insufficient, return telemetry or parser recommendations instead \
of pretending that a rule will work.

Prefer behavior-based detection over matching only a known offensive tool name.

Clearly document:
- Assumptions
- Required telemetry
- Expected fields
- False positives
- Tuning recommendations
- Validation requirements
- Deployment risks

WAZUH XML CONSTRAINTS
- Emit a single <group>...</group> block containing one or more <rule> elements.
- Every rule needs id, level and a <description>. Leave the id attribute exactly \
as the placeholder the request supplies; the platform allocates the real ID.
- Never emit a DOCTYPE, an XML declaration, entity definitions, or external \
entity references.
- Use only field matchers supported by Wazuh: <decoded_as>, <program_name>, \
<match>, <regex>, <field name="...">, <srcip>, <dstuser>, <url>, <id>, \
<if_sid>, <if_group>, <if_matched_sid>, <same_source_ip>, <frequency>, \
<timeframe>, <group>, <mitre><id>...</id></mitre>, <options>.
- <frequency> requires <timeframe> and a parent correlation (<if_matched_sid> \
or <same_source_ip>). Use it for brute-force style behaviour instead of \
matching one line.
- <if_sid> is a hard dependency: the new rule is only ever evaluated after the \
parent rule ID has ALREADY matched. Only reference a parent rule ID that is \
listed under evidence.wazuh_result.rule_ids (a rule confirmed to have fired on \
THIS captured event) or that is a generic, level-0 decoder/grouping rule (a \
rule whose own job is only to classify the log source, not to match a \
specific attack signature). Rules listed under evidence.existing_wazuh_content \
are reference/style examples only — most of them are narrow, level > 0 \
attack-signature rules with their own unrelated match conditions, and chaining \
onto one with <if_sid> makes your new rule unreachable unless that exact \
signature also happens to be present.
- Prefer <if_sid> over a standalone <decoded_as>. A rule keyed only on \
<decoded_as> (with no <if_sid> to a base rule) has been confirmed via \
wazuh-logtest to silently never fire on this manager, even though it parses \
and deploys without error — the decoder assigns the field, but nothing \
evaluates the rule. Chain onto the generic level-0 grouping rule for that log \
source instead (e.g. rule 31100, "Access log messages grouped", for Apache \
access logs) and match with <url>/<match>/<field> underneath it. Only fall \
back to bare <decoded_as> if no such grouping rule ID is available in the \
evidence.
- Escape &, < and > inside <match>/<regex> values.
- <match>, <regex>, <url>, <program_name> and <hostname> may each appear AT \
MOST ONCE per <rule>. Wazuh does not AND repeated occurrences of these — it \
concatenates their text into one pattern, which then matches nothing. To \
require two substrings in the same rule, use one <regex> with a lookahead \
(e.g. <regex type="pcre2">(?=.*foo)(?=.*bar)</regex>), or split the \
conditions across a parent/child rule pair with <if_sid>. <field name="..."> \
is the one exception — you may repeat it with a different `name` each time.

SIGMA YAML CONSTRAINTS
- Emit one valid Sigma rule document with title, id, status, description, \
author, date, logsource, detection (with at least one named selection and a \
condition referencing only defined selections), falsepositives, level and tags.
- Tags use the attack.tXXXX / attack.<tactic> convention.
- Use the field names that actually appear in the supplied evidence.
- Do not use aggregation or correlation syntax the platform's evaluator cannot \
assess unless the gap genuinely requires it; if you do, say so in tuning_notes.

Return only JSON matching the supplied schema. Do not return Markdown fences. \
Do not provide hidden reasoning or chain-of-thought. Return only a concise \
reasoning summary intended for the Detection Engineer.
"""

_SCHEMA_HINT = """\
Return JSON with exactly this shape (no extra top-level keys):

{
  "gap_type": "wazuh_rule|sigma_rule|both_rules|telemetry|evaluator",
  "summary": "string",
  "reasoning_summary": "string",
  "assumptions": ["string"],
  "confidence": 0,
  "target_surface": "ad|windows|linux|web",
  "mitre": {"technique_id": "string", "technique_name": "string", "tactic": "string"},
  "required_data_sources": ["string"],
  "wazuh": {
    "required": true, "title": "string", "description": "string", "level": 0,
    "groups": ["string"], "xml": "string", "expected_fields": ["string"],
    "false_positives": ["string"], "tuning_notes": ["string"],
    "test_event": "string", "expected_match": "string"
  },
  "sigma": {
    "required": true, "title": "string", "description": "string", "yaml": "string",
    "logsource_explanation": "string", "expected_fields": ["string"],
    "false_positives": ["string"], "tuning_notes": ["string"]
  },
  "telemetry_recommendations": [
    {"source": "string", "problem": "string", "configuration": "string", "verification": "string"}
  ],
  "deployment_risks": ["string"]
}

confidence is an integer from 0 to 100.
Set "required": false and leave the content empty for any rule type this gap
does not call for.
"""


# ── Prompt construction ──────────────────────────────────────────────────────

_GAP_INSTRUCTIONS = {
    "wazuh_rule": (
        "The deterministic verdict is SIGMA_ONLY: a Sigma rule matched the "
        "captured event but no Wazuh rule fired. Produce a Wazuh XML draft only. "
        "Set wazuh.required=true and sigma.required=false. Use the matching "
        "Sigma rule as context for the behaviour, and key the Wazuh rule on the "
        "fields that appear in the captured event."
    ),
    "sigma_rule": (
        "The deterministic verdict is WAZUH_ONLY: Wazuh detected the attack but "
        "no Sigma rule matched. Produce a Sigma YAML draft only. Set "
        "sigma.required=true and wazuh.required=false. Use the Wazuh alert and "
        "rule metadata as context for the behaviour."
    ),
    "both_rules": (
        "The deterministic verdict is NEITHER_DETECTS and the required telemetry "
        "is available. Produce both a Wazuh XML draft and a Sigma YAML draft. "
        "Set wazuh.required=true and sigma.required=true. Base both on the "
        "telemetry fields that are actually collected."
    ),
    "telemetry": (
        "The required telemetry is missing or insufficient. Do NOT invent a "
        "Wazuh or Sigma rule. Set wazuh.required=false and sigma.required=false, "
        "leave both rule bodies empty, and return concrete "
        "telemetry_recommendations: which source is missing, the exact logging "
        "or collection change needed, and how to verify the events now reach "
        "Wazuh."
    ),
    "evaluator": (
        "The platform's local Sigma evaluator could not assess this rule or "
        "event format. This is NOT a Wazuh or Sigma detection failure and you "
        "must not describe it as one. Set wazuh.required=false and "
        "sigma.required=false. Explain the evaluator limitation and recommend "
        "parser, field-mapping, normalisation or evaluator support work in "
        "telemetry_recommendations."
    ),
}


def build_prompt(*, decision, evidence_json: str, evidence_truncated: bool,
                 rule_id_placeholder: str | None = None,
                 previous_version: dict[str, Any] | None = None,
                 engineer_feedback: str | None = None) -> str:
    """Assemble the user-turn prompt from the deterministic decision + evidence."""
    parts: list[str] = []
    parts.append(
        "DETERMINISTIC VALIDATION RESULT (decided by the platform — treat as fact):\n"
        f"  surface        : {decision.surface}\n"
        f"  attack_id      : {decision.attack_id}\n"
        f"  verdict        : {decision.verdict} (engine reported: {decision.raw_verdict})\n"
        f"  permitted gap  : {decision.gap_type}\n"
        f"  reason         : {decision.reason}"
    )
    parts.append("TASK:\n" + _GAP_INSTRUCTIONS.get(
        decision.gap_type,
        "Explain the gap. Do not produce a rule that the verdict does not call for.",
    ))
    parts.append(f"You must return gap_type=\"{decision.gap_type}\" and "
                 f"target_surface=\"{decision.surface}\".")

    if rule_id_placeholder:
        parts.append(
            "WAZUH RULE IDs — read carefully:\n"
            "  Never write a literal rule ID. Use these placeholders instead, and\n"
            "  the platform substitutes IDs it has verified are free:\n"
            "    first rule   -> id=\"__ABSEGA_AI_RULE_ID_1__\"\n"
            "    second rule  -> id=\"__ABSEGA_AI_RULE_ID_2__\"\n"
            "    third rule   -> id=\"__ABSEGA_AI_RULE_ID_3__\"\n"
            "  Emit at most 3 rules. When a <frequency> correlation rule needs to\n"
            "  reference its own base rule, put the SAME placeholder token in\n"
            "  <if_matched_sid>, e.g. <if_matched_sid>__ABSEGA_AI_RULE_ID_1__"
            "</if_matched_sid>.\n"
            "  <if_sid> may reference a real, existing Wazuh rule ID only when "
            "that ID appears in evidence.wazuh_result.rule_ids (it actually "
            "fired on this captured event) or is a generic level-0 "
            "decoder/grouping rule. Do NOT chain onto a rule from "
            "evidence.existing_wazuh_content merely because it shares this "
            "technique — those are unrelated attack-signature rules whose own "
            "conditions your new rule cannot assume are true. When unsure, "
            "omit <if_sid>."
        )

    if previous_version:
        parts.append(
            "PREVIOUS DRAFT (version "
            f"{previous_version.get('version_number')}) — revise it, do not start over:\n"
            + json.dumps({
                "summary": previous_version.get("summary"),
                "wazuh_xml": previous_version.get("wazuh_xml"),
                "sigma_yaml": previous_version.get("sigma_yaml"),
                "assumptions": previous_version.get("assumptions"),
                "tuning_notes": previous_version.get("tuning_notes"),
            }, indent=2, default=str)
        )
    if engineer_feedback:
        parts.append(
            "DETECTION ENGINEER FEEDBACK — this is the change they asked for. "
            "Address it explicitly and mention how you addressed it in "
            "reasoning_summary:\n" + engineer_feedback
        )

    if evidence_truncated:
        parts.append(
            "NOTE: the evidence below was truncated to fit a size budget. "
            "Detection-relevant fields were preserved; do not infer anything "
            "from what is absent."
        )
    parts.append("SANITIZED VALIDATION EVIDENCE (secrets already redacted with "
                 "[REDACTED_*] placeholders — treat those as unknown values, "
                 "never as literals to match on):\n" + evidence_json)
    parts.append(_SCHEMA_HINT)
    return "\n\n".join(parts)


def _repair_prompt(previous_raw: str, problems: list[str]) -> str:
    return (
        "Your previous response was rejected by the platform's validator.\n\n"
        "Problems:\n" + "\n".join(f"  - {p}" for p in problems) +
        "\n\nReturn a corrected response. Rules:\n"
        "  - Output only a single JSON object matching the schema.\n"
        "  - No Markdown fences, no commentary before or after the JSON.\n"
        "  - Do not change the deterministic verdict or claim any test, "
        "validation or deployment succeeded.\n\n"
        "Your previous (rejected) response was:\n"
        + previous_raw[:4000]
    )


# ── Rate limiting + de-duplication ───────────────────────────────────────────

class _RateLimiter:
    """Sliding-window limiter keyed by actor (falls back to a shared bucket)."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, actor: str, limit_per_minute: int) -> None:
        now = time.monotonic()
        with self._lock:
            window = self._hits[actor or "anonymous"]
            while window and now - window[0] > 60.0:
                window.popleft()
            if len(window) >= limit_per_minute:
                wait = int(60 - (now - window[0])) + 1
                raise GeminiRateLimited(
                    f"Gemini rate limit reached ({limit_per_minute} requests per "
                    f"minute). Try again in about {wait}s."
                )
            window.append(now)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


_rate_limiter = _RateLimiter()


class _InFlight:
    """Blocks a second identical generation while the first is still running."""

    def __init__(self) -> None:
        self._keys: set[str] = set()
        self._lock = threading.Lock()

    def acquire(self, key: str) -> bool:
        with self._lock:
            if key in self._keys:
                return False
            self._keys.add(key)
            return True

    def release(self, key: str) -> None:
        with self._lock:
            self._keys.discard(key)


_in_flight = _InFlight()


def reset_limits() -> None:
    """Test helper — clears rate-limit and in-flight state."""
    _rate_limiter.reset()
    _in_flight._keys.clear()  # noqa: SLF001 - deliberate test hook


# ── Transport ────────────────────────────────────────────────────────────────

@dataclass
class GeminiCallResult:
    suggestion: GeminiRuleSuggestion
    model: str
    attempts: int
    repaired: bool
    raw_text: str


def _status_of(exc: Exception) -> int | None:
    """Best-effort HTTP status extraction from a Gen AI SDK exception."""
    for attr in ("code", "status_code", "http_status"):
        value = getattr(exc, attr, None)
        if isinstance(value, int):
            return value
    response = getattr(exc, "response", None)
    value = getattr(response, "status_code", None)
    if isinstance(value, int):
        return value
    text = str(exc)
    for status in (429, 500, 502, 503, 504, 400, 401, 403, 404):
        if str(status) in text:
            return status
    return None


def _is_timeout(exc: Exception) -> bool:
    name = type(exc).__name__.lower()
    return "timeout" in name or "timeout" in str(exc).lower()


def _default_transport(settings: GeminiSettings, prompt: str) -> str:
    """Send one prompt to Gemini and return the raw response text.

    Imported lazily so the platform still boots (and the test-suite still runs)
    when google-genai is not installed.
    """
    try:
        from google import genai
        from google.genai import types
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise GeminiNotConfigured(
            "The google-genai package is not installed. Run: "
            "pip install -r requirements.txt"
        ) from exc

    client = genai.Client(
        api_key=settings.api_key,
        http_options=types.HttpOptions(timeout=settings.timeout_seconds * 1000),
    )
    response = client.models.generate_content(
        model=settings.model,
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_INSTRUCTION,
            response_mime_type="application/json",
            temperature=0.2,
            candidate_count=1,
        ),
    )
    text = getattr(response, "text", None)
    if not text:
        raise GeminiInvalidOutput(
            "Gemini returned no text content (the response may have been blocked "
            "or truncated)."
        )
    return text


#: Swapped out by the tests. Signature: (settings, prompt) -> raw response text.
TransportFn = Callable[[GeminiSettings, str], str]
_transport: TransportFn = _default_transport


def set_transport(fn: TransportFn | None) -> None:
    """Install a transport (tests inject a mock; None restores the real SDK)."""
    global _transport
    _transport = fn or _default_transport


def _call_with_retries(settings: GeminiSettings, prompt: str) -> tuple[str, int]:
    """Send *prompt*, retrying 429 and transient 5xx with exponential backoff."""
    attempts = 0
    last_error: Exception | None = None
    total = settings.max_retries + 1

    for attempt in range(total):
        attempts += 1
        try:
            return _transport(settings, prompt), attempts
        except GeminiError:
            raise
        except Exception as exc:  # SDK-specific exception types stay out of here
            last_error = exc
            status = _status_of(exc)
            retryable = status == 429 or (status is not None and 500 <= status < 600)
            if _is_timeout(exc) and not retryable:
                retryable = True
            message = scrub_secrets(str(exc))

            if not retryable:
                if status in (401, 403):
                    raise GeminiNotConfigured(
                        "Gemini rejected the configured credentials "
                        f"(HTTP {status}). Check GEMINI_API_KEY in the backend "
                        "environment."
                    ) from exc
                if status == 404:
                    raise GeminiNotConfigured(
                        f"Gemini model '{settings.model}' was not found for this "
                        "API key. Set GEMINI_MODEL to a model your key can use."
                    ) from exc
                raise GeminiError(f"Gemini request failed: {message}") from exc

            if attempt == total - 1:
                break
            backoff = min(2.0 ** attempt, 16.0)
            logger.warning(
                "gemini call failed (status=%s, attempt %d/%d) — retrying in %.1fs",
                status, attempts, total, backoff,
            )
            time.sleep(backoff)

    status = _status_of(last_error) if last_error else None
    message = scrub_secrets(str(last_error)) if last_error else "unknown error"
    if status == 429:
        if "quota" in message.lower() or "exhausted" in message.lower():
            raise GeminiQuotaExhausted(
                "Gemini quota is exhausted for this API key. Wait for the quota "
                "window to reset or raise the limit, then try again."
            )
        raise GeminiRateLimited(
            "Gemini is rate limiting this API key (HTTP 429). Try again shortly."
        )
    if last_error is not None and _is_timeout(last_error):
        raise GeminiTimeout(
            f"Gemini did not respond within {settings.timeout_seconds}s after "
            f"{attempts} attempt(s)."
        )
    raise GeminiError(f"Gemini request failed after {attempts} attempt(s): {message}")


# ── Public API ───────────────────────────────────────────────────────────────

def status() -> dict[str, Any]:
    """Public provider status. Never contains the key or any substring of it."""
    settings = gemini_settings()
    return {
        "enabled": settings.enabled,
        "configured": settings.configured,
        "provider": PROVIDER,
        "model": settings.model or None,
        "missing": settings.missing(),
        "reason": settings.unavailable_reason(),
        "timeout_seconds": settings.timeout_seconds,
        "max_retries": settings.max_retries,
        "max_evidence_chars": settings.max_evidence_chars,
        "rate_limit_per_minute": settings.rate_limit_per_minute,
    }


def require_available(settings: GeminiSettings | None = None) -> GeminiSettings:
    """Return usable settings or raise a precise, safe error."""
    settings = settings or gemini_settings()
    if not settings.enabled:
        raise GeminiDisabled(
            "The Gemini provider is disabled on this server (GEMINI_ENABLED=false). "
            "Enable it in the backend environment to generate rule drafts."
        )
    missing = settings.missing()
    if missing:
        raise GeminiNotConfigured(
            f"Gemini is not configured — {', '.join(missing)} "
            f"{'is' if len(missing) == 1 else 'are'} not set in the backend "
            "environment. Set it in .env and restart the server."
        )
    return settings


def generate_suggestion(*, decision, prompt: str, dedup_key: str,
                        actor: str = "") -> GeminiCallResult:
    """Call Gemini, validate strictly, repair once, and return a stored-safe result.

    Raises a :class:`GeminiError` subclass on every failure path; the caller maps
    ``.status_code`` onto the HTTP response.
    """
    settings = require_available()
    _rate_limiter.check(actor or "anonymous", settings.rate_limit_per_minute)

    if not _in_flight.acquire(dedup_key):
        raise GeminiRateLimited(
            "An identical recommendation is already being generated for this "
            "attack. Wait for it to finish."
        )
    try:
        raw, attempts = _call_with_retries(settings, prompt)
        problems = _validate(raw, decision)
        if not problems:
            return GeminiCallResult(
                suggestion=_parse(raw), model=settings.model,
                attempts=attempts, repaired=False, raw_text=raw,
            )

        logger.warning("gemini output rejected (%d problem(s)); requesting repair",
                       len(problems))
        repaired_raw, repair_attempts = _call_with_retries(
            settings, _repair_prompt(raw, problems))
        repair_problems = _validate(repaired_raw, decision)
        if repair_problems:
            joined = "; ".join(repair_problems[:5])
            if any("contradict" in p or "claims a validation" in p
                   for p in repair_problems):
                raise GeminiContradiction(
                    "Gemini returned output that contradicts the deterministic "
                    f"validation result and could not be repaired: {joined}"
                )
            raise GeminiInvalidOutput(
                "Gemini returned output that does not satisfy the required "
                f"schema, and the repair attempt also failed: {joined}"
            )
        return GeminiCallResult(
            suggestion=_parse(repaired_raw), model=settings.model,
            attempts=attempts + repair_attempts, repaired=True,
            raw_text=repaired_raw,
        )
    finally:
        _in_flight.release(dedup_key)


def _parse(raw: str) -> GeminiRuleSuggestion:
    return GeminiRuleSuggestion.model_validate(parse_model_json(raw))


def _validate(raw: str, decision) -> list[str]:
    """Return the problems with a raw response (empty means acceptable)."""
    try:
        payload = parse_model_json(raw)
    except ValueError as exc:
        return [scrub_secrets(str(exc))]
    try:
        suggestion = GeminiRuleSuggestion.model_validate(payload)
    except Exception as exc:
        problems = []
        errors = getattr(exc, "errors", None)
        if callable(errors):
            for err in errors()[:8]:
                location = ".".join(str(p) for p in err.get("loc", ()))
                problems.append(f"{location or 'body'}: {err.get('msg')}")
        return problems or [scrub_secrets(str(exc))]
    return contradictions(suggestion, decision)
