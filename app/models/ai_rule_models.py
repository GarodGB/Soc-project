"""Pydantic models for the AI Detection Rule Recommendation workflow.

Two families live here:

* ``GeminiRuleSuggestion`` and friends — the **strict** schema every Gemini
  response must satisfy. Anything that does not parse is repaired once and then
  rejected; malformed output is never stored.
* The FastAPI request bodies used by ``app/routes/ai_rules.py``.

Cross-checking a parsed suggestion against the deterministic verdict lives in
:func:`contradictions` — Gemini is never allowed to change, reinterpret or
fabricate a validation result.
"""
from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

GapType = Literal["wazuh_rule", "sigma_rule", "both_rules", "telemetry", "evaluator"]
Surface = Literal["ad", "windows", "linux", "web"]


# ── Gemini response schema ───────────────────────────────────────────────────

class MitreMapping(BaseModel):
    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""


class WazuhDraft(BaseModel):
    required: bool = False
    title: str = ""
    description: str = ""
    level: int = 0
    groups: list[str] = Field(default_factory=list)
    xml: str = ""
    expected_fields: list[str] = Field(default_factory=list)
    false_positives: list[str] = Field(default_factory=list)
    tuning_notes: list[str] = Field(default_factory=list)
    test_event: str = ""
    expected_match: str = ""

    # Gemini sometimes emits explicit `null` for a text field it considers
    # "not applicable" (e.g. xml when only a Sigma rule is needed) instead of
    # "" — with no response_schema enforced on the API call, that's a valid
    # choice from the model's side, so treat null the same as an empty string
    # rather than failing the whole draft over it.
    @field_validator("title", "description", "xml", "test_event", "expected_match",
                     mode="before")
    @classmethod
    def _none_to_empty(cls, value: Any) -> Any:
        return "" if value is None else value

    @field_validator("level")
    @classmethod
    def _level_range(cls, value: int) -> int:
        if value < 0 or value > 16:
            raise ValueError("Wazuh rule level must be between 0 and 16")
        return value


class SigmaDraft(BaseModel):
    required: bool = False
    title: str = ""
    description: str = ""
    yaml: str = ""
    logsource_explanation: str = ""
    expected_fields: list[str] = Field(default_factory=list)
    false_positives: list[str] = Field(default_factory=list)
    tuning_notes: list[str] = Field(default_factory=list)

    @field_validator("title", "description", "yaml", "logsource_explanation",
                     mode="before")
    @classmethod
    def _none_to_empty(cls, value: Any) -> Any:
        return "" if value is None else value


class TelemetryRecommendation(BaseModel):
    source: str = ""
    problem: str = ""
    configuration: str = ""
    verification: str = ""


class GeminiRuleSuggestion(BaseModel):
    """The one shape a Gemini response is allowed to take."""

    gap_type: GapType
    summary: str
    reasoning_summary: str = ""
    assumptions: list[str] = Field(default_factory=list)
    confidence: int = 0
    target_surface: Surface
    mitre: MitreMapping = Field(default_factory=MitreMapping)
    required_data_sources: list[str] = Field(default_factory=list)
    wazuh: WazuhDraft = Field(default_factory=WazuhDraft)
    sigma: SigmaDraft = Field(default_factory=SigmaDraft)
    telemetry_recommendations: list[TelemetryRecommendation] = Field(default_factory=list)
    deployment_risks: list[str] = Field(default_factory=list)

    @field_validator("confidence")
    @classmethod
    def _confidence_range(cls, value: int) -> int:
        if value < 0 or value > 100:
            raise ValueError("confidence must be between 0 and 100")
        return value

    @field_validator("summary")
    @classmethod
    def _summary_present(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("summary must not be empty")
        return value


# ── Guard rails against fabricated results ───────────────────────────────────

#: Claims Gemini is structurally not allowed to make. It has not run anything;
#: only the platform executes validation and deployment.
_FABRICATION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\b(?:the\s+)?(?:test|tests|testing|validation|logtest)\s+(?:has\s+|have\s+|was\s+|were\s+)?"
        r"(?:successfully\s+)?(?:passed|succeeded|completed successfully)",
        r"\b(?:successfully|has been|have been|was|were)\s+(?:deployed|validated|verified in production)",
        r"\bdeployment\s+(?:was\s+)?(?:successful|succeeded|complete)\b",
        r"\bi\s+(?:have\s+)?(?:deployed|tested|validated|verified)\b",
        r"\brule\s+(?:is|has been)\s+(?:now\s+)?(?:live|active in production|deployed)\b",
        r"\bconfirmed\s+working\s+(?:in|on)\s+(?:the\s+)?(?:wazuh|manager|production)",
    )
]


def fabrication_claims(text: str) -> list[str]:
    """Return the fabricated-success phrases found in *text* (empty when clean)."""
    if not text:
        return []
    found: list[str] = []
    for pattern in _FABRICATION_PATTERNS:
        match = pattern.search(text)
        if match:
            found.append(match.group(0).strip())
    return found


def _all_prose(suggestion: GeminiRuleSuggestion) -> str:
    parts = [suggestion.summary, suggestion.reasoning_summary]
    parts.extend(suggestion.assumptions)
    parts.extend(suggestion.deployment_risks)
    parts.extend(suggestion.wazuh.tuning_notes)
    parts.extend(suggestion.sigma.tuning_notes)
    parts.append(suggestion.wazuh.description)
    parts.append(suggestion.sigma.description)
    for rec in suggestion.telemetry_recommendations:
        parts.extend([rec.problem, rec.configuration, rec.verification])
    return "\n".join(p for p in parts if p)


def contradictions(suggestion: GeminiRuleSuggestion, decision: Any) -> list[str]:
    """Reasons the model output contradicts the deterministic decision.

    *decision* is a ``GapDecision`` (duck-typed here to keep this module free of
    a service import). An empty list means the output is consistent and may be
    stored.
    """
    problems: list[str] = []

    expected_gap = getattr(decision, "gap_type", None)
    if expected_gap and suggestion.gap_type != expected_gap:
        problems.append(
            f"gap_type '{suggestion.gap_type}' contradicts the deterministic "
            f"verdict, which requires '{expected_gap}'."
        )

    expected_surface = getattr(decision, "surface", None)
    if expected_surface and suggestion.target_surface != expected_surface:
        problems.append(
            f"target_surface '{suggestion.target_surface}' does not match the "
            f"validated surface '{expected_surface}'."
        )

    if getattr(decision, "allow_wazuh_rule", False):
        if not suggestion.wazuh.required:
            problems.append("A Wazuh rule is required for this gap but wazuh.required is false.")
        elif not suggestion.wazuh.xml.strip():
            problems.append("A Wazuh rule is required for this gap but wazuh.xml is empty.")
    elif suggestion.wazuh.required and suggestion.wazuh.xml.strip():
        problems.append(
            "A Wazuh rule was returned but the deterministic verdict does not "
            "call for one."
        )

    if getattr(decision, "allow_sigma_rule", False):
        if not suggestion.sigma.required:
            problems.append("A Sigma rule is required for this gap but sigma.required is false.")
        elif not suggestion.sigma.yaml.strip():
            problems.append("A Sigma rule is required for this gap but sigma.yaml is empty.")
    elif suggestion.sigma.required and suggestion.sigma.yaml.strip():
        problems.append(
            "A Sigma rule was returned but the deterministic verdict does not "
            "call for one."
        )

    if expected_gap == "telemetry" and not suggestion.telemetry_recommendations:
        problems.append(
            "This is a telemetry gap but no telemetry_recommendations were returned."
        )

    claims = fabrication_claims(_all_prose(suggestion))
    if claims:
        problems.append(
            "Output claims a validation or deployment result that never ran: "
            + "; ".join(sorted(set(claims)))
        )

    return problems


# ── JSON extraction ──────────────────────────────────────────────────────────

_FENCE_RE = re.compile(r"^\s*```(?:json|JSON)?\s*|\s*```\s*$")


def strip_markdown_fences(raw: str) -> str:
    """Remove ```json … ``` fences the model was told not to emit."""
    text = (raw or "").strip()
    if "```" not in text:
        return text
    # Prefer the first fenced block that looks like an object.
    blocks = re.findall(r"```(?:json|JSON)?\s*(.*?)```", text, re.DOTALL)
    for block in blocks:
        candidate = block.strip()
        if candidate.startswith("{"):
            return candidate
    return _FENCE_RE.sub("", text).strip()


def parse_model_json(raw: str) -> dict:
    """Parse a model response into a dict, tolerating fences and prose padding.

    Raises ``ValueError`` when no JSON object can be recovered.
    """
    text = strip_markdown_fences(raw)
    if not text:
        raise ValueError("Model returned an empty response")
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise ValueError("Model response contained no JSON object")
        try:
            loaded = json.loads(text[start:end + 1])
        except json.JSONDecodeError as exc:
            raise ValueError(f"Model response was not valid JSON: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError("Model response JSON was not an object")
    return loaded


# ── API request bodies ───────────────────────────────────────────────────────

class GenerateRequest(BaseModel):
    surface: Surface
    attack_id: str
    validation_run_id: str | None = None
    force_regenerate: bool = False


class RegenerateRequest(BaseModel):
    feedback: str

    @field_validator("feedback")
    @classmethod
    def _feedback_required(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("feedback is required and must not be empty")
        return value.strip()


class DraftEditRequest(BaseModel):
    wazuh_xml: str | None = None
    sigma_yaml: str | None = None
    summary: str | None = None
    false_positives: list[str] | None = None
    tuning_notes: list[str] | None = None
    comment: str | None = None


class RejectRequest(BaseModel):
    reason: str

    @field_validator("reason")
    @classmethod
    def _reason_required(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("reason is required and must not be empty")
        return value.strip()


class ApproveRequest(BaseModel):
    comment: str | None = None


class SaveToPlatformRequest(BaseModel):
    comment: str | None = None


class DeployRequest(BaseModel):
    confirm: bool = False
    comment: str | None = None
