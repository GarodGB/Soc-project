"""The single source of truth for "what, if anything, may the AI do here?".

The deterministic validation engine decides the verdict. This module does one
job: translate that verdict (plus telemetry health and Wazuh availability) into
the *one* permitted AI action. Active Directory, Windows, Linux and Web all go
through this function — there is deliberately no per-surface branch of this
logic anywhere else in the codebase.

Nothing here calls Gemini, and Gemini never calls anything here.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ── Canonical verdicts ───────────────────────────────────────────────────────
# The platform stores verdicts under two historical spellings. These constants
# are the canonical names the AI workflow reasons about.

VERIFIED_OVERLAP = "VERIFIED_OVERLAP"
WAZUH_ONLY = "WAZUH_ONLY"
SIGMA_ONLY = "SIGMA_ONLY"
NEITHER_DETECTS = "NEITHER_DETECTS"
TELEMETRY_GAP = "TELEMETRY_GAP"
EVALUATOR_UNSUPPORTED = "EVALUATOR_UNSUPPORTED"
VALIDATION_INCOMPLETE = "VALIDATION_INCOMPLETE"

#: Raw verdict strings the validation surfaces emit → canonical verdict.
_VERDICT_ALIASES = {
    # shared
    "VERIFIED_OVERLAP": VERIFIED_OVERLAP,
    "BOTH_FIRED_ON_SAME_EVENT": VERIFIED_OVERLAP,
    "WAZUH_ONLY": WAZUH_ONLY,
    "SIGMA_ONLY": SIGMA_ONLY,
    "EVALUATOR_UNSUPPORTED": EVALUATOR_UNSUPPORTED,
    # web / linux (web_linux_validation_runs.verdict)
    "NO_DETECTION_IN_EITHER": NEITHER_DETECTS,
    "NEITHER_DETECTS": NEITHER_DETECTS,
    "NOT_EXECUTED": VALIDATION_INCOMPLETE,
    # AD / Windows (_ad_detail_state_machine result_state)
    "INCOMPLETE_NO_EVIDENCE": VALIDATION_INCOMPLETE,
    # Only a MITRE-incompatible Sigma rule matched: a mapping overlap, not
    # behavioural coverage — so for detection-gap purposes nothing detected it.
    "MAPPING_ONLY": NEITHER_DETECTS,
    # explicit telemetry states, if a surface ever reports one directly
    "TELEMETRY_GAP": TELEMETRY_GAP,
    "NO_TELEMETRY": TELEMETRY_GAP,
}

# Gap types match the Gemini output schema.
GAP_NONE = "none"
GAP_WAZUH = "wazuh_rule"
GAP_SIGMA = "sigma_rule"
GAP_BOTH = "both_rules"
GAP_TELEMETRY = "telemetry"
GAP_EVALUATOR = "evaluator"
GAP_INCOMPLETE = "incomplete"

_VERIFIED_MESSAGE = "No AI rule required — detection coverage is verified."
_INCOMPLETE_MESSAGE = (
    "Validation is incomplete. Restore Wazuh connectivity and run validation "
    "again before generating a rule."
)


def normalize_verdict(raw: str | None) -> str:
    """Map any verdict spelling the platform uses onto a canonical verdict."""
    if not raw:
        return VALIDATION_INCOMPLETE
    key = str(raw).strip().upper()
    return _VERDICT_ALIASES.get(key, VALIDATION_INCOMPLETE)


@dataclass(frozen=True)
class GapDecision:
    """The permitted AI action for one validated attack."""

    surface: str
    attack_id: str
    raw_verdict: str
    verdict: str
    gap_type: str
    generation_allowed: bool
    allow_wazuh_rule: bool
    allow_sigma_rule: bool
    approval_allowed: bool
    deployment_allowed: bool
    message: str
    reason: str
    blockers: list[str] = field(default_factory=list)

    @property
    def target_type(self) -> str:
        """Column value stored on ai_rule_suggestions.target_type."""
        return self.gap_type

    def to_dict(self) -> dict:
        return {
            "surface": self.surface,
            "attack_id": self.attack_id,
            "raw_verdict": self.raw_verdict,
            "verdict": self.verdict,
            "gap_type": self.gap_type,
            "generation_allowed": self.generation_allowed,
            "allow_wazuh_rule": self.allow_wazuh_rule,
            "allow_sigma_rule": self.allow_sigma_rule,
            "approval_allowed": self.approval_allowed,
            "deployment_allowed": self.deployment_allowed,
            "message": self.message,
            "reason": self.reason,
            "blockers": list(self.blockers),
        }


def decide(
    *,
    surface: str,
    attack_id: str,
    raw_verdict: str | None,
    telemetry_available: bool = True,
    telemetry_reason: str = "",
    wazuh_available: bool | None = True,
    wazuh_reason: str = "",
    validation_complete: bool = True,
    validation_reason: str = "",
) -> GapDecision:
    """Map a deterministic verdict to the one permitted AI action.

    ``telemetry_available`` / ``wazuh_available`` / ``validation_complete`` are
    facts measured by the platform (evidence rows, indexer pipeline health,
    telemetry_sources status) — never anything the model or the frontend
    supplied.
    """
    verdict = normalize_verdict(raw_verdict)
    raw = str(raw_verdict or "").strip().upper() or "UNKNOWN"

    def build(**kwargs) -> GapDecision:
        base = {
            "surface": surface,
            "attack_id": attack_id,
            "raw_verdict": raw,
            "verdict": verdict,
            "generation_allowed": False,
            "allow_wazuh_rule": False,
            "allow_sigma_rule": False,
            "approval_allowed": False,
            "deployment_allowed": False,
            "blockers": [],
        }
        base.update(kwargs)
        return GapDecision(**base)

    # ── G. Wazuh unavailable or validation incomplete ────────────────────────
    # Checked before the verdict: a verdict computed while the pipeline was
    # down is not evidence of anything.
    if wazuh_available is False or not validation_complete:
        reason = wazuh_reason or validation_reason or (
            "The validation run did not complete against a healthy Wazuh pipeline."
        )
        return build(
            verdict=VALIDATION_INCOMPLETE,
            gap_type=GAP_INCOMPLETE,
            message=_INCOMPLETE_MESSAGE,
            reason=reason,
            blockers=["validation_incomplete"],
        )

    if verdict == VALIDATION_INCOMPLETE:
        return build(
            gap_type=GAP_INCOMPLETE,
            message=_INCOMPLETE_MESSAGE,
            reason=validation_reason or (
                f"The validation engine reported '{raw}', which is not a completed "
                "detection result."
            ),
            blockers=["validation_incomplete"],
        )

    # ── A. VERIFIED_OVERLAP ──────────────────────────────────────────────────
    if verdict == VERIFIED_OVERLAP:
        return build(
            gap_type=GAP_NONE,
            message=_VERIFIED_MESSAGE,
            reason=("Wazuh detected the attack and a Sigma rule matched the same "
                    "event — coverage is verified, so there is no gap to close."),
        )

    # ── F. EVALUATOR_UNSUPPORTED ─────────────────────────────────────────────
    # Not a detection failure. Gemini may explain the evaluator limitation and
    # recommend parser/normalisation work, but nothing here may be deployed.
    if verdict == EVALUATOR_UNSUPPORTED:
        return build(
            gap_type=GAP_EVALUATOR,
            generation_allowed=True,
            approval_allowed=False,
            deployment_allowed=False,
            message=("The local Sigma evaluator cannot assess this rule or event "
                     "format — this is not a Wazuh or Sigma detection failure."),
            reason=("The evaluator returned EVALUATOR_UNSUPPORTED, so detection "
                    "coverage is unknown, not absent. Recommend parser, field "
                    "mapping, normalisation or evaluator support instead."),
            blockers=["evaluator_unsupported"],
        )

    # ── E. TELEMETRY_GAP (explicit) ──────────────────────────────────────────
    if verdict == TELEMETRY_GAP:
        return build(
            gap_type=GAP_TELEMETRY,
            generation_allowed=True,
            approval_allowed=False,
            deployment_allowed=False,
            message="Required telemetry is missing — no rule can be written yet.",
            reason=telemetry_reason or (
                "The validation engine reported a telemetry gap: the events a "
                "detection would need never reached Wazuh."
            ),
            blockers=["telemetry_gap"],
        )

    # ── B. SIGMA_ONLY → Wazuh detection gap ──────────────────────────────────
    if verdict == SIGMA_ONLY:
        return build(
            gap_type=GAP_WAZUH,
            generation_allowed=True,
            allow_wazuh_rule=True,
            approval_allowed=True,
            deployment_allowed=True,
            message="Wazuh detection gap — a Wazuh rule draft can be generated.",
            reason=("A Sigma rule matched the captured event but no Wazuh rule "
                    "fired, so the gap is on the Wazuh side."),
        )

    # ── C. WAZUH_ONLY → Sigma coverage gap ───────────────────────────────────
    if verdict == WAZUH_ONLY:
        return build(
            gap_type=GAP_SIGMA,
            generation_allowed=True,
            allow_sigma_rule=True,
            approval_allowed=True,
            # A Sigma rule is platform content, not Wazuh manager content.
            deployment_allowed=False,
            message="Sigma coverage gap — a Sigma rule draft can be generated.",
            reason=("Wazuh detected the attack but no Sigma rule matched, so the "
                    "gap is on the Sigma side."),
        )

    # ── D. NEITHER_DETECTS ───────────────────────────────────────────────────
    if verdict == NEITHER_DETECTS:
        if not telemetry_available:
            # Telemetry is checked first: without the events, any rule would be
            # invented rather than derived.
            return build(
                verdict=TELEMETRY_GAP,
                gap_type=GAP_TELEMETRY,
                generation_allowed=True,
                approval_allowed=False,
                deployment_allowed=False,
                message=("Required telemetry is missing or insufficient — "
                         "telemetry recommendations only, no rule draft."),
                reason=telemetry_reason or (
                    "Neither Wazuh nor Sigma detected the behaviour and the "
                    "telemetry a detection would need is not available, so a rule "
                    "cannot be derived from evidence."
                ),
                blockers=["telemetry_gap"],
            )
        return build(
            gap_type=GAP_BOTH,
            generation_allowed=True,
            allow_wazuh_rule=True,
            allow_sigma_rule=True,
            approval_allowed=True,
            deployment_allowed=True,
            message="No detection in either engine — Wazuh and Sigma drafts can be generated.",
            reason=("Neither Wazuh nor Sigma detected the behaviour, and the "
                    "required telemetry is present, so both rule types can be "
                    "drafted from the captured evidence."),
        )

    # Unreachable in practice — normalize_verdict maps unknowns to incomplete.
    return build(  # pragma: no cover
        gap_type=GAP_INCOMPLETE,
        message=_INCOMPLETE_MESSAGE,
        reason=f"Unrecognised verdict '{raw}'.",
        blockers=["unknown_verdict"],
    )
