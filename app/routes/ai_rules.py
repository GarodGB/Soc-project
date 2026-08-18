"""AI Detection Rule Recommendation API.

Responsibility split enforced here, end to end:

1. the deterministic validation engine decides the verdict (read back from the
   platform's own tables — never from the request body);
2. :mod:`app.services.gap_decision_service` decides whether that verdict is a
   gap and which AI action is permitted;
3. Gemini receives selected, sanitized evidence and drafts defensive content;
4. :mod:`app.services.rule_validation_service` validates whatever came back;
5. a Detection Engineer reviews, edits, approves, rejects or regenerates it;
6. deployment happens only on an explicit, confirmed, authorised request.

Gemini cannot reach step 5 or 6 — nothing in this module lets a model response
change a verdict, approve itself, or call the deployment service.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from app.config import PROVIDER, deployment_settings, gemini_settings, scrub_secrets
from app.database import get_connection
from app.models.ai_rule_models import (
    ApproveRequest,
    DeployRequest,
    DraftEditRequest,
    GenerateRequest,
    RegenerateRequest,
    RejectRequest,
    SaveToPlatformRequest,
)
from app.services import ai_rule_repository as repo
from app.services import evidence_collection_service as evidence_svc
from app.services import gap_decision_service as gap
from app.services import gemini_service
from app.services.auth_service import (
    current_actor,
    require_actor,
    require_deployer,
    require_read_access,
    require_reviewer,
)
from app.services.evidence_sanitization_service import (
    CLOUD_NOTICE,
    evidence_fingerprint,
    sanitize_evidence,
    truncate_evidence,
)
from app.services.rule_deployment_service import (
    DeploymentError,
    deploy_rule,
    deployment_preview,
    rollback_deployment,
    rule_ids_from_xml,
)
from app.services.rule_validation_service import (
    MAX_RULES_PER_DRAFT,
    RULE_ID_PLACEHOLDER,
    RuleValidationError,
    allocate_rule_ids,
    apply_rule_ids,
    parse_sigma_yaml,
    validate_draft,
)

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(require_read_access)])


# ── Helpers ──────────────────────────────────────────────────────────────────

def _bundle_or_404(surface: str, attack_id: str, run_id: str | None):
    try:
        return evidence_svc.collect(surface, attack_id, run_id)
    except evidence_svc.EvidenceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("evidence collection failed for %s/%s", surface, attack_id)
        raise HTTPException(
            status_code=500,
            detail=f"Could not collect validation evidence: {scrub_secrets(str(exc))}",
        ) from exc


def _suggestion_or_404(suggestion_id: int, conn=None) -> dict:
    suggestion = repo.get_suggestion(suggestion_id, conn)
    if suggestion is None:
        raise HTTPException(status_code=404,
                            detail=f"AI rule suggestion {suggestion_id} was not found")
    return suggestion


def _decision_for(suggestion: dict):
    """Re-derive the deterministic decision for a stored suggestion.

    Always recomputed from the database so a stale suggestion can never keep
    permissions the current validation state no longer justifies.
    """
    bundle = _bundle_or_404(
        suggestion["surface"], suggestion["attack_id"],
        suggestion.get("validation_run_id"),
    )
    return bundle


def _public_suggestion(suggestion: dict, conn=None) -> dict:
    return {
        "suggestion_id": suggestion["id"],
        "attack_id": suggestion["attack_id"],
        "surface": suggestion["surface"],
        "validation_run_id": suggestion.get("validation_run_id"),
        "verdict": suggestion.get("verdict"),
        "raw_verdict": suggestion.get("raw_verdict"),
        "target_type": suggestion.get("target_type"),
        "status": suggestion.get("status"),
        "provider": suggestion.get("provider"),
        "model": suggestion.get("model"),
        "summary": suggestion.get("summary"),
        "reasoning_summary": suggestion.get("reasoning_summary"),
        "confidence": suggestion.get("confidence"),
        "current_version": suggestion.get("current_version"),
        "created_by": suggestion.get("created_by"),
        "created_at": suggestion.get("created_at"),
        "updated_at": suggestion.get("updated_at"),
    }


def _payload(suggestion: dict | None, bundle, actor, conn=None) -> dict:
    """The one response shape every suggestion endpoint returns."""
    settings = gemini_settings()
    decision = bundle.decision
    current = repo.get_current_version(suggestion, conn) if suggestion else None
    versions = repo.list_versions(suggestion["id"], conn) if suggestion else []
    actions = repo.list_actions(suggestion["id"], conn) if suggestion else []
    saves = repo.platform_saves(suggestion["id"], conn) if suggestion else []

    validation = (current or {}).get("validation_result") if current else None
    ready_for_deployment = bool(validation and validation.get("ready_for_deployment"))

    return {
        "surface": bundle.surface,
        "attack_id": bundle.attack_id,
        "attack_name": bundle.attack_name,
        "validation_run_id": bundle.validation_run_id,
        "decision": decision.to_dict(),
        "telemetry": {
            "available": bundle.telemetry.get("available"),
            "reason": bundle.telemetry.get("reason"),
            "sources": bundle.telemetry.get("sources"),
            "expected_sources": bundle.telemetry.get("expected_sources"),
        },
        "wazuh_health": {
            "healthy": bundle.wazuh_health.get("healthy"),
            "reason": bundle.wazuh_health.get("reason"),
        },
        "provider": {
            "provider": PROVIDER,
            "enabled": settings.enabled,
            "configured": settings.configured,
            "model": settings.model or None,
            "reason": settings.unavailable_reason(),
            "notice": CLOUD_NOTICE,
        },
        "permissions": {
            **actor.to_dict(),
            "can_generate": bool(decision.generation_allowed and settings.configured
                                 and settings.enabled and actor.authenticated),
            "can_approve": bool(decision.approval_allowed and actor.may_review()),
            "can_deploy": bool(decision.deployment_allowed and actor.may_deploy()
                               and ready_for_deployment),
        },
        "suggestion": _public_suggestion(suggestion) if suggestion else None,
        "current_version": current,
        "versions": [
            {
                "version_id": v["version_id"],
                "version_number": v["version_number"],
                "origin": v["origin"],
                "summary": v["summary"],
                "confidence": v["confidence"],
                "engineer_feedback": v["engineer_feedback"],
                "generated_at": v["generated_at"],
                "generated_by": v["generated_by"],
                "has_wazuh_xml": bool(v["wazuh_xml"]),
                "has_sigma_yaml": bool(v["sigma_yaml"]),
                "validated": v["validation_result"] is not None,
            }
            for v in versions
        ],
        "actions": actions,
        "last_action": actions[-1] if actions else None,
        "platform_saves": saves,
    }


def _guard_generation(bundle) -> None:
    decision = bundle.decision
    if decision.generation_allowed:
        return
    if decision.gap_type == gap.GAP_NONE:
        raise HTTPException(status_code=409, detail=decision.message)
    raise HTTPException(status_code=409, detail=decision.message or decision.reason)


def _gemini_http(exc: gemini_service.GeminiError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=str(exc))


def _wazuh_meta(suggestion_model, allocated: list[int]) -> dict[str, Any]:
    return {
        "title": suggestion_model.wazuh.title,
        "description": suggestion_model.wazuh.description,
        "level": suggestion_model.wazuh.level,
        "groups": suggestion_model.wazuh.groups,
        "expected_fields": suggestion_model.wazuh.expected_fields,
        "test_event": suggestion_model.wazuh.test_event,
        "expected_match": suggestion_model.wazuh.expected_match,
        "allocated_rule_ids": allocated,
        "required": suggestion_model.wazuh.required,
    }


def _sigma_meta(suggestion_model) -> dict[str, Any]:
    return {
        "title": suggestion_model.sigma.title,
        "description": suggestion_model.sigma.description,
        "logsource_explanation": suggestion_model.sigma.logsource_explanation,
        "expected_fields": suggestion_model.sigma.expected_fields,
        "required": suggestion_model.sigma.required,
    }


def _run_generation(*, bundle, previous_version: dict | None,
                    engineer_feedback: str | None, actor) -> tuple[Any, list[int], str]:
    """Sanitize evidence, call Gemini, and return (model output, rule ids, fingerprint)."""
    decision = bundle.decision
    try:
        settings = gemini_service.require_available()
    except gemini_service.GeminiError as exc:
        raise _gemini_http(exc) from exc

    sanitized = sanitize_evidence(bundle.evidence)
    fingerprint = evidence_fingerprint(sanitized)
    evidence_json, truncated = truncate_evidence(sanitized, settings.max_evidence_chars)

    allocated: list[int] = []
    placeholder = None
    if decision.allow_wazuh_rule:
        placeholder = RULE_ID_PLACEHOLDER
        try:
            # A draft may legitimately need more than one rule (a base rule plus
            # a <frequency> correlation rule), so reserve a small block and keep
            # only the IDs the model actually uses.
            allocated = allocate_rule_ids(MAX_RULES_PER_DRAFT)
        except RuleValidationError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    prompt = gemini_service.build_prompt(
        decision=decision,
        evidence_json=evidence_json,
        evidence_truncated=truncated,
        rule_id_placeholder=placeholder,
        previous_version=previous_version,
        engineer_feedback=engineer_feedback,
    )
    dedup_key = f"{bundle.surface}:{bundle.attack_id}:{fingerprint[:16]}:{bool(engineer_feedback)}"

    try:
        result = gemini_service.generate_suggestion(
            decision=decision, prompt=prompt, dedup_key=dedup_key,
            actor=actor.email or "anonymous",
        )
    except gemini_service.GeminiError as exc:
        raise _gemini_http(exc) from exc

    return result, allocated, fingerprint


def _persist_generation(*, conn, suggestion_id: int, bundle, result, allocated: list[int],
                        fingerprint: str, origin: str, engineer_feedback: str | None,
                        actor) -> tuple[int, int]:
    model_output = result.suggestion
    decision = bundle.decision

    wazuh_xml = None
    used_ids: list[int] = []
    if decision.allow_wazuh_rule and model_output.wazuh.xml.strip():
        wazuh_xml, used_ids = apply_rule_ids(model_output.wazuh.xml, allocated)
    sigma_yaml = model_output.sigma.yaml.strip() or None if decision.allow_sigma_rule else None

    version_id, version_number = repo.create_version(
        suggestion_id=suggestion_id, conn=conn, origin=origin,
        gap_type=model_output.gap_type, summary=model_output.summary,
        reasoning_summary=model_output.reasoning_summary,
        confidence=model_output.confidence,
        wazuh_xml=wazuh_xml, wazuh_meta=_wazuh_meta(model_output, used_ids),
        sigma_yaml=sigma_yaml, sigma_meta=_sigma_meta(model_output),
        telemetry=[t.model_dump() for t in model_output.telemetry_recommendations],
        assumptions=model_output.assumptions,
        required_data_sources=model_output.required_data_sources,
        false_positives=sorted(set(model_output.wazuh.false_positives
                                   + model_output.sigma.false_positives)),
        tuning_notes=sorted(set(model_output.wazuh.tuning_notes
                                + model_output.sigma.tuning_notes)),
        deployment_risks=model_output.deployment_risks,
        mitre=model_output.mitre.model_dump(),
        engineer_feedback=engineer_feedback,
        generated_by=actor.email,
    )
    repo.update_suggestion(
        suggestion_id, conn,
        status="draft", model=result.model, summary=model_output.summary,
        reasoning_summary=model_output.reasoning_summary,
        confidence=model_output.confidence, evidence_fingerprint=fingerprint,
        current_version=version_number, verdict=decision.verdict,
        raw_verdict=decision.raw_verdict, target_type=decision.gap_type,
        validation_run_id=bundle.validation_run_id,
    )
    repo.record_action(
        suggestion_id=suggestion_id, version_id=version_id,
        action="regenerated" if origin == "regenerated" else "generated",
        actor=actor.email, comment=engineer_feedback or "", conn=conn,
        metadata={"model": result.model, "attempts": result.attempts,
                  "repaired": result.repaired, "gap_type": decision.gap_type,
                  "allocated_rule_ids": used_ids},
    )
    return version_id, version_number


def _validate_version(*, conn, suggestion: dict, version: dict, bundle,
                      actor, run_manager_tests: bool = True) -> dict:
    # Detections this suggestion itself created must not count as duplicates of
    # its own draft when the draft is re-validated after "Save to Platform".
    own_detections = [s["detection_id"]
                      for s in repo.platform_saves(suggestion["id"], conn)]
    result = validate_draft(
        surface=bundle.surface,
        wazuh_xml=version.get("wazuh_xml"),
        sigma_yaml=version.get("sigma_yaml"),
        evidence=bundle.evidence,
        decision=bundle.decision,
        run_manager_tests=run_manager_tests,
        allocated_rule_ids=(version.get("wazuh_meta") or {}).get("allocated_rule_ids"),
        exclude_detection_ids=own_detections,
    )
    repo.set_version_validation(version["version_id"], result, conn)
    repo.update_suggestion(
        suggestion["id"], conn,
        status="ready_for_review" if result["ready_for_review"] else "validation_failed",
    )
    repo.record_action(
        suggestion_id=suggestion["id"], version_id=version["version_id"],
        action="validated", actor=actor.email, conn=conn,
        comment=("ready for review" if result["ready_for_review"] else "validation failed"),
        metadata={"errors": result["errors"][:10],
                  "ready_for_deployment": result["ready_for_deployment"]},
    )
    return result


# ── Status ───────────────────────────────────────────────────────────────────

@router.get("/status")
def ai_status() -> dict:
    """Provider status. Never returns the API key or any substring of it."""
    settings = gemini_settings()
    deploy = deployment_settings()
    return {
        "enabled": settings.enabled,
        "configured": settings.configured,
        "provider": PROVIDER,
        "model": settings.model or None,
        "missing": settings.missing(),
        "reason": settings.unavailable_reason(),
        "notice": CLOUD_NOTICE,
        "limits": {
            "timeout_seconds": settings.timeout_seconds,
            "max_retries": settings.max_retries,
            "max_evidence_chars": settings.max_evidence_chars,
            "rate_limit_per_minute": settings.rate_limit_per_minute,
        },
        "deployment": {
            "target_file": deploy.manager_path,
            "rule_id_range": [deploy.rule_id_min, deploy.rule_id_max],
            "restarts_manager": deploy.restart_manager,
        },
    }


# ── Read ─────────────────────────────────────────────────────────────────────

@router.get("/rule-suggestions/by-attack/{surface}/{attack_id}")
def get_by_attack(surface: str, attack_id: str, request: Request,
                  validation_run_id: str | None = None) -> dict:
    """Current suggestion, version, history and permitted actions for an attack."""
    bundle = _bundle_or_404(surface, attack_id, validation_run_id)
    actor = current_actor(request)
    conn = get_connection()
    try:
        suggestion = repo.find_suggestion_for_attack(
            surface, attack_id, bundle.validation_run_id, conn)
        return _payload(suggestion, bundle, actor, conn)
    finally:
        conn.close()


@router.get("/rule-suggestions/{suggestion_id}/history")
def get_history(suggestion_id: int) -> dict:
    """Full audit trail: versions, feedback, validation, actions, deployments."""
    conn = get_connection()
    try:
        suggestion = _suggestion_or_404(suggestion_id, conn)
        versions = repo.list_versions(suggestion_id, conn)
        actions = repo.list_actions(suggestion_id, conn)
        return {
            "suggestion": _public_suggestion(suggestion),
            "versions": versions,
            "actions": actions,
            "deployments": [a for a in actions
                            if a["action"] in ("deployment_requested", "staged",
                                               "deployed", "deployment_failed")],
            "rollbacks": [a for a in actions if a["action"] == "rolled_back"],
            "platform_saves": repo.platform_saves(suggestion_id, conn),
        }
    finally:
        conn.close()


# ── Generate ─────────────────────────────────────────────────────────────────

@router.post("/rule-suggestions/generate")
def generate(body: GenerateRequest, request: Request) -> dict:
    """Generate version 1 of a recommendation for a validated attack.

    The verdict is retrieved from the platform's own tables; anything the client
    claims about detection state is ignored.
    """
    actor = require_actor(request)
    bundle = _bundle_or_404(body.surface, body.attack_id, body.validation_run_id)
    _guard_generation(bundle)

    conn = get_connection()
    try:
        existing = repo.find_suggestion_for_attack(
            body.surface, body.attack_id, bundle.validation_run_id, conn)
    finally:
        conn.close()

    # Draft reuse: an equivalent draft for the same attack/surface/run/verdict
    # and evidence fingerprint is returned instead of spending another call.
    if existing and not body.force_regenerate and existing.get("current_version"):
        sanitized = sanitize_evidence(bundle.evidence)
        if existing.get("evidence_fingerprint") == evidence_fingerprint(sanitized) \
                and existing.get("verdict") == bundle.decision.verdict:
            conn = get_connection()
            try:
                return {**_payload(existing, bundle, actor, conn), "reused": True}
            finally:
                conn.close()

    result, allocated, fingerprint = _run_generation(
        bundle=bundle, previous_version=None, engineer_feedback=None, actor=actor)

    with repo.transaction() as conn:
        suggestion_id = existing["id"] if existing else repo.create_suggestion(
            surface=bundle.surface, attack_id=bundle.attack_id,
            validation_run_id=bundle.validation_run_id,
            verdict=bundle.decision.verdict, raw_verdict=bundle.decision.raw_verdict,
            target_type=bundle.decision.gap_type, created_by=actor.email, conn=conn,
        )
        version_id, _ = _persist_generation(
            conn=conn, suggestion_id=suggestion_id, bundle=bundle, result=result,
            allocated=allocated, fingerprint=fingerprint,
            origin="generated" if not existing else "regenerated",
            engineer_feedback=None, actor=actor,
        )
        suggestion = _suggestion_or_404(suggestion_id, conn)
        version = repo.get_version(version_id, conn)
        _validate_version(conn=conn, suggestion=suggestion, version=version,
                          bundle=bundle, actor=actor)

    conn = get_connection()
    try:
        return {**_payload(_suggestion_or_404(suggestion_id, conn), bundle, actor, conn),
                "reused": False}
    finally:
        conn.close()


@router.post("/rule-suggestions/{suggestion_id}/regenerate")
def regenerate(suggestion_id: int, body: RegenerateRequest, request: Request) -> dict:
    """Create the next version from engineer feedback. Old versions are kept."""
    actor = require_reviewer(request)
    suggestion = _suggestion_or_404(suggestion_id)
    bundle = _decision_for(suggestion)
    _guard_generation(bundle)

    previous = repo.get_current_version(suggestion)

    result, allocated, fingerprint = _run_generation(
        bundle=bundle, previous_version=previous,
        engineer_feedback=body.feedback, actor=actor)

    with repo.transaction() as conn:
        version_id, _ = _persist_generation(
            conn=conn, suggestion_id=suggestion_id, bundle=bundle, result=result,
            allocated=allocated, fingerprint=fingerprint, origin="regenerated",
            engineer_feedback=body.feedback, actor=actor,
        )
        refreshed = _suggestion_or_404(suggestion_id, conn)
        version = repo.get_version(version_id, conn)
        _validate_version(conn=conn, suggestion=refreshed, version=version,
                          bundle=bundle, actor=actor)

    conn = get_connection()
    try:
        return _payload(_suggestion_or_404(suggestion_id, conn), bundle, actor, conn)
    finally:
        conn.close()


# ── Edit ─────────────────────────────────────────────────────────────────────

@router.patch("/rule-suggestions/{suggestion_id}/draft")
def edit_draft(suggestion_id: int, body: DraftEditRequest, request: Request) -> dict:
    """Store engineer edits as a new, auditable version."""
    actor = require_reviewer(request)
    suggestion = _suggestion_or_404(suggestion_id)
    bundle = _decision_for(suggestion)
    current = repo.get_current_version(suggestion)
    if current is None:
        raise HTTPException(status_code=409,
                            detail="There is no draft to edit yet — generate one first.")

    changed = [name for name, value in (
        ("wazuh_xml", body.wazuh_xml), ("sigma_yaml", body.sigma_yaml),
        ("summary", body.summary), ("false_positives", body.false_positives),
        ("tuning_notes", body.tuning_notes),
    ) if value is not None]
    if not changed:
        raise HTTPException(status_code=400, detail="No editable field was supplied.")

    with repo.transaction() as conn:
        version_id, version_number = repo.create_version(
            suggestion_id=suggestion_id, conn=conn, origin="edited",
            gap_type=current.get("gap_type") or bundle.decision.gap_type,
            summary=body.summary if body.summary is not None else current.get("summary"),
            reasoning_summary=current.get("reasoning_summary") or "",
            confidence=current.get("confidence"),
            wazuh_xml=(body.wazuh_xml if body.wazuh_xml is not None
                       else current.get("wazuh_xml")),
            wazuh_meta=current.get("wazuh_meta") or {},
            sigma_yaml=(body.sigma_yaml if body.sigma_yaml is not None
                        else current.get("sigma_yaml")),
            sigma_meta=current.get("sigma_meta") or {},
            telemetry=current.get("telemetry_recommendations") or [],
            assumptions=current.get("assumptions") or [],
            required_data_sources=current.get("required_data_sources") or [],
            false_positives=(body.false_positives if body.false_positives is not None
                             else current.get("false_positives") or []),
            tuning_notes=(body.tuning_notes if body.tuning_notes is not None
                          else current.get("tuning_notes") or []),
            deployment_risks=current.get("deployment_risks") or [],
            mitre=current.get("mitre") or {},
            engineer_feedback=body.comment,
            generated_by=actor.email,
        )
        repo.update_suggestion(suggestion_id, conn, current_version=version_number,
                               status="draft")
        repo.record_action(
            suggestion_id=suggestion_id, version_id=version_id, action="edited",
            actor=actor.email, comment=body.comment or "", conn=conn,
            metadata={"fields": changed},
        )
        refreshed = _suggestion_or_404(suggestion_id, conn)
        version = repo.get_version(version_id, conn)
        _validate_version(conn=conn, suggestion=refreshed, version=version,
                          bundle=bundle, actor=actor)

    conn = get_connection()
    try:
        return _payload(_suggestion_or_404(suggestion_id, conn), bundle, actor, conn)
    finally:
        conn.close()


# ── Validate ─────────────────────────────────────────────────────────────────

@router.post("/rule-suggestions/{suggestion_id}/validate")
def validate(suggestion_id: int, request: Request) -> dict:
    """Re-run every validation check against the current draft version."""
    actor = require_actor(request)
    suggestion = _suggestion_or_404(suggestion_id)
    bundle = _decision_for(suggestion)
    current = repo.get_current_version(suggestion)
    if current is None:
        raise HTTPException(status_code=409, detail="There is no draft to validate yet.")

    with repo.transaction() as conn:
        result = _validate_version(conn=conn, suggestion=suggestion, version=current,
                                   bundle=bundle, actor=actor)

    conn = get_connection()
    try:
        payload = _payload(_suggestion_or_404(suggestion_id, conn), bundle, actor, conn)
    finally:
        conn.close()
    payload["validation"] = result
    return payload


# ── Approve / reject ─────────────────────────────────────────────────────────

@router.post("/rule-suggestions/{suggestion_id}/approve")
def approve(suggestion_id: int, body: ApproveRequest, request: Request) -> dict:
    """Approve a validated draft. Approval never deploys anything."""
    actor = require_reviewer(request)
    suggestion = _suggestion_or_404(suggestion_id)
    bundle = _decision_for(suggestion)

    if not bundle.decision.approval_allowed:
        raise HTTPException(
            status_code=409,
            detail=("This recommendation cannot be approved: " + bundle.decision.message),
        )

    current = repo.get_current_version(suggestion)
    if current is None:
        raise HTTPException(status_code=409, detail="There is no draft to approve yet.")
    validation = current.get("validation_result")
    if not validation:
        raise HTTPException(
            status_code=409,
            detail="Validate the draft before approving it.")
    if not validation.get("ready_for_review"):
        errors = "; ".join(validation.get("errors", [])[:5]) or "validation did not pass"
        raise HTTPException(
            status_code=409,
            detail=f"The draft did not pass validation and cannot be approved: {errors}")

    with repo.transaction() as conn:
        repo.update_suggestion(suggestion_id, conn, status="approved")
        repo.record_action(
            suggestion_id=suggestion_id, version_id=current["version_id"],
            action="approved", actor=actor.email, comment=body.comment or "", conn=conn,
            metadata={"version_number": current["version_number"]},
        )

    conn = get_connection()
    try:
        payload = _payload(_suggestion_or_404(suggestion_id, conn), bundle, actor, conn)
    finally:
        conn.close()
    payload["message"] = (
        "Approved. Deployment is a separate, explicitly confirmed action — nothing "
        "has been written to the Wazuh Manager."
    )
    return payload


@router.post("/rule-suggestions/{suggestion_id}/reject")
def reject(suggestion_id: int, body: RejectRequest, request: Request) -> dict:
    """Reject a draft. A non-empty reason is required and is stored."""
    actor = require_reviewer(request)
    suggestion = _suggestion_or_404(suggestion_id)
    bundle = _decision_for(suggestion)
    current = repo.get_current_version(suggestion)

    with repo.transaction() as conn:
        repo.update_suggestion(suggestion_id, conn, status="rejected")
        repo.record_action(
            suggestion_id=suggestion_id,
            version_id=(current or {}).get("version_id"),
            action="rejected", actor=actor.email, comment=body.reason, conn=conn,
            metadata={"version_number": (current or {}).get("version_number")},
        )

    conn = get_connection()
    try:
        return _payload(_suggestion_or_404(suggestion_id, conn), bundle, actor, conn)
    finally:
        conn.close()


# ── Save to platform ─────────────────────────────────────────────────────────

_SEVERITY_BY_LEVEL = ((13, "critical"), (10, "high"), (7, "medium"), (0, "low"))


def _severity_for(version: dict, bundle) -> str:
    level = (version.get("wazuh_meta") or {}).get("level")
    if isinstance(level, int):
        for threshold, name in _SEVERITY_BY_LEVEL:
            if level >= threshold:
                return name
    document, _ = parse_sigma_yaml(version.get("sigma_yaml") or "")
    if document:
        level_name = str(document.get("level", "")).lower()
        if level_name in ("critical", "high", "medium", "low", "informational"):
            return "medium" if level_name == "informational" else level_name
    return "medium"


_PLATFORM_BY_SURFACE = {"ad": "windows", "windows": "windows",
                        "linux": "linux", "web": "linux"}


@router.post("/rule-suggestions/{suggestion_id}/save-to-platform")
def save_to_platform(suggestion_id: int, body: SaveToPlatformRequest,
                     request: Request) -> dict:
    """Insert the reviewed rule into the existing detection store as a draft.

    Idempotent per (suggestion, version): clicking twice returns the detection
    that was already created rather than inserting a duplicate.
    """
    actor = require_reviewer(request)
    suggestion = _suggestion_or_404(suggestion_id)
    bundle = _decision_for(suggestion)
    current = repo.get_current_version(suggestion)
    if current is None:
        raise HTTPException(status_code=409, detail="There is no draft to save yet.")
    if not (current.get("sigma_yaml") or current.get("wazuh_xml")):
        raise HTTPException(
            status_code=409,
            detail=("This recommendation contains telemetry or evaluator guidance "
                    "only — there is no rule to save to the detection store."))

    existing = repo.existing_platform_save(suggestion_id, current["version_id"])
    if existing:
        conn = get_connection()
        try:
            payload = _payload(suggestion, bundle, actor, conn)
        finally:
            conn.close()
        payload["detection_id"] = existing["detection_id"]
        payload["already_saved"] = True
        payload["message"] = (
            f"Version {current['version_number']} is already saved as detection "
            f"#{existing['detection_id']}.")
        return payload

    sigma_document, _ = parse_sigma_yaml(current.get("sigma_yaml") or "")
    sigma_document = sigma_document or {}
    wazuh_meta = current.get("wazuh_meta") or {}
    mitre = current.get("mitre") or bundle.mitre or {}
    technique = mitre.get("technique_id") or ""

    title = (sigma_document.get("title") or wazuh_meta.get("title")
             or f"AI draft — {bundle.attack_name}")
    description = (sigma_document.get("description") or wazuh_meta.get("description")
                   or current.get("summary") or "")
    tags = sorted({
        *(f"attack.{technique.lower()}" for _ in [0] if technique),
        *(str(t).lower() for t in (sigma_document.get("tags") or [])),
        "absega.ai_generated",
        f"absega.surface.{bundle.surface}",
        f"absega.attack.{bundle.attack_id}",
        f"absega.ai_suggestion.{suggestion_id}",
        f"absega.ai_version.{current['version_number']}",
    })
    logsource = sigma_document.get("logsource") or {}
    logsource_text = ", ".join(f"{k}={v}" for k, v in logsource.items()) if logsource else ""
    false_positives = current.get("false_positives") or sigma_document.get("falsepositives") or []
    tuning = current.get("tuning_notes") or []
    notes = "\n".join(
        ["False positives:"] + [f"- {f}" for f in false_positives]
        + (["", "Tuning notes:"] + [f"- {t}" for t in tuning] if tuning else [])
    ) if false_positives or tuning else ""

    with repo.transaction() as conn:
        cursor = conn.execute(
            "INSERT INTO detections "
            "(title, description, rule_logic, severity, status, author, platform, "
            " sigma_id, logsource, falsepositives, tags, raw_yaml, created_at, updated_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now()::text,now()::text) "
            "RETURNING detection_id",
            (
                title,
                description,
                current.get("wazuh_xml") or "",
                _severity_for(current, bundle),
                # Never production — the engineer promotes it after re-testing.
                "test",
                f"ABSEGA AI ({actor.email})",
                _PLATFORM_BY_SURFACE.get(bundle.surface, "windows"),
                str(sigma_document.get("id") or ""),
                logsource_text,
                notes,
                ",".join(tags),
                current.get("sigma_yaml") or "",
            ),
        )
        detection_id = int(cursor.fetchone()[0])

        if technique:
            try:
                conn.execute(
                    "INSERT INTO detection_technique_mapping (detection_id, technique_id) "
                    "VALUES (%s,%s)",
                    (detection_id, technique),
                )
            except Exception:
                # The mapping table has a FK to mitre_techniques; a technique the
                # catalogue does not know about must not fail the save.
                logger.info("technique mapping skipped for %s", technique)

        repo.record_platform_save(
            suggestion_id=suggestion_id, version_id=current["version_id"],
            detection_id=detection_id, created_by=actor.email, conn=conn)
        repo.update_suggestion(suggestion_id, conn, status="saved_to_platform")
        repo.record_action(
            suggestion_id=suggestion_id, version_id=current["version_id"],
            action="saved_to_platform", actor=actor.email, comment=body.comment or "",
            conn=conn, metadata={"detection_id": detection_id,
                                 "status": "test",
                                 "version_number": current["version_number"]},
        )

    conn = get_connection()
    try:
        payload = _payload(_suggestion_or_404(suggestion_id, conn), bundle, actor, conn)
    finally:
        conn.close()
    payload["detection_id"] = detection_id
    payload["already_saved"] = False
    payload["message"] = (
        f"Saved to the detection store as #{detection_id} with status 'test'. "
        "Promote it to active only after re-running the attack.")
    return payload


_DETECTION_CHILD_TABLES = (
    "detection_technique_mapping", "detection_telemetry", "validation_cases",
    "simulation_results", "atomic_runs", "ad_rule_comparisons",
)


def _delete_detection(conn, detection_id: int) -> None:
    for table in _DETECTION_CHILD_TABLES:
        conn.execute(f"DELETE FROM {table} WHERE detection_id=%s", (detection_id,))
    conn.execute("DELETE FROM detections WHERE detection_id=%s", (detection_id,))


@router.delete("/rule-suggestions/{suggestion_id}/platform-save")
def delete_platform_save(suggestion_id: int, request: Request) -> dict:
    """Testing-only: undo a save-to-platform by deleting the saved detection(s).

    Lets a Detection Engineer re-run "generate -> approve -> save -> relaunch
    attack" against the same recommendation without hand-editing the database
    between attempts. Refuses once the suggestion has moved past
    saved_to_platform (staged/deployed/...) so this can't silently orphan a
    live deployment's bookkeeping — roll that back through the normal flow
    first.
    """
    actor = require_reviewer(request)
    suggestion = _suggestion_or_404(suggestion_id)
    if suggestion["status"] != "saved_to_platform":
        raise HTTPException(
            status_code=409,
            detail=(f"Suggestion status is '{suggestion['status']}', not "
                    "'saved_to_platform' — there is nothing to delete, or it "
                    "has moved past this step (e.g. staged/deployed) and must "
                    "be rolled back through that flow instead."),
        )
    current = repo.get_current_version(suggestion)

    with repo.transaction() as conn:
        detection_ids = repo.delete_platform_saves(suggestion_id, conn)
        for detection_id in detection_ids:
            _delete_detection(conn, detection_id)
        repo.update_suggestion(suggestion_id, conn, status="approved")
        repo.record_action(
            suggestion_id=suggestion_id,
            version_id=current["version_id"] if current else None,
            action="platform_save_deleted", actor=actor.email, comment="",
            conn=conn, metadata={"detection_ids": detection_ids},
        )

    conn = get_connection()
    try:
        suggestion = _suggestion_or_404(suggestion_id, conn)
        bundle = _decision_for(suggestion)
        payload = _payload(suggestion, bundle, actor, conn)
    finally:
        conn.close()
    payload["deleted_detection_ids"] = detection_ids
    payload["message"] = (
        f"Deleted {len(detection_ids)} saved detection(s) "
        f"({', '.join('#' + str(d) for d in detection_ids)}). Save to "
        "Platform is available again.")
    return payload


# ── Deploy ───────────────────────────────────────────────────────────────────

@router.get("/rule-suggestions/{suggestion_id}/deployment-preview")
def preview_deployment(suggestion_id: int, request: Request) -> dict:
    """What the confirmation dialog shows before any change is made."""
    actor = require_actor(request)
    suggestion = _suggestion_or_404(suggestion_id)
    current = repo.get_current_version(suggestion)
    if current is None or not current.get("wazuh_xml"):
        raise HTTPException(status_code=409,
                            detail="There is no Wazuh rule draft to deploy.")
    validation = current.get("validation_result") or {}
    preview = deployment_preview(current["wazuh_xml"])
    preview["validation_status"] = {
        "ready_for_deployment": bool(validation.get("ready_for_deployment")),
        "errors": validation.get("errors", []),
        "warnings": validation.get("warnings", []),
    }
    preview["suggestion_status"] = suggestion.get("status")
    preview["may_deploy"] = actor.may_deploy()
    return preview


@router.post("/rule-suggestions/{suggestion_id}/deploy-to-wazuh")
def deploy(suggestion_id: int, body: DeployRequest, request: Request) -> dict:
    """Deploy an approved, validated Wazuh rule. Requires explicit confirmation."""
    actor = require_deployer(request)
    if not body.confirm:
        raise HTTPException(
            status_code=400,
            detail=("Deployment requires explicit confirmation. Re-send with "
                    "confirm=true after the engineer accepts the confirmation dialog."))

    suggestion = _suggestion_or_404(suggestion_id)
    bundle = _decision_for(suggestion)
    if not bundle.decision.deployment_allowed:
        raise HTTPException(
            status_code=409,
            detail=("This recommendation may not be deployed to Wazuh: "
                    + bundle.decision.message))

    current = repo.get_current_version(suggestion)
    if current is None or not (current.get("wazuh_xml") or "").strip():
        raise HTTPException(status_code=409, detail="There is no Wazuh rule draft to deploy.")
    if suggestion.get("status") not in ("approved", "saved_to_platform",
                                        "deployment_failed", "rolled_back"):
        raise HTTPException(
            status_code=409,
            detail=("The draft must be approved before it can be deployed "
                    f"(current status: {suggestion.get('status')})."))

    validation = current.get("validation_result") or {}
    if not validation.get("ready_for_deployment"):
        errors = "; ".join(validation.get("errors", [])[:5]) or \
            "the draft has not passed Wazuh XML validation"
        raise HTTPException(
            status_code=409,
            detail=f"Deployment blocked: {errors}.")
    if not bundle.telemetry.get("available"):
        raise HTTPException(
            status_code=409,
            detail=("Deployment blocked: the telemetry this rule depends on is not "
                    f"available. {bundle.telemetry.get('reason', '')}"))

    from app.services.rule_validation_service import positive_test_event

    with repo.transaction() as conn:
        repo.update_suggestion(suggestion_id, conn, status="staged_for_wazuh")
        repo.record_action(
            suggestion_id=suggestion_id, version_id=current["version_id"],
            action="deployment_requested", actor=actor.email,
            comment=body.comment or "", conn=conn,
            metadata={"rule_ids": rule_ids_from_xml(current["wazuh_xml"])},
        )

    try:
        result = deploy_rule(
            rule_xml=current["wazuh_xml"],
            positive_event=positive_test_event(bundle.evidence),
            surface=bundle.surface, actor=actor.email,
        )
    except DeploymentError as exc:
        with repo.transaction() as conn:
            repo.update_suggestion(suggestion_id, conn, status="deployment_failed")
            repo.record_action(
                suggestion_id=suggestion_id, version_id=current["version_id"],
                action="deployment_failed", actor=actor.email,
                comment=str(exc), conn=conn, metadata={},
            )
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    with repo.transaction() as conn:
        if result.success:
            repo.update_suggestion(suggestion_id, conn, status="deployed")
            repo.record_action(
                suggestion_id=suggestion_id, version_id=current["version_id"],
                action="deployed", actor=actor.email, comment=result.message,
                conn=conn, metadata=result.to_dict(),
            )
        else:
            status = "rolled_back" if result.rolled_back else "deployment_failed"
            repo.update_suggestion(suggestion_id, conn, status=status)
            repo.record_action(
                suggestion_id=suggestion_id, version_id=current["version_id"],
                action="rolled_back" if result.rolled_back else "deployment_failed",
                actor=actor.email, comment=result.message, conn=conn,
                metadata=result.to_dict(),
            )

    conn = get_connection()
    try:
        payload = _payload(_suggestion_or_404(suggestion_id, conn), bundle, actor, conn)
    finally:
        conn.close()
    payload["deployment"] = result.to_dict()
    payload["message"] = result.message
    payload["next_step"] = (
        "Re-run the original attack and re-validate to confirm the gap is actually "
        "closed. Nothing here proves the rule fires in production."
    )
    return payload


@router.post("/rule-suggestions/{suggestion_id}/rollback")
def rollback(suggestion_id: int, body: DeployRequest, request: Request) -> dict:
    """Remove previously deployed AI rules from the Wazuh Manager."""
    actor = require_deployer(request)
    if not body.confirm:
        raise HTTPException(status_code=400,
                            detail="Rollback requires explicit confirmation.")
    suggestion = _suggestion_or_404(suggestion_id)
    bundle = _decision_for(suggestion)
    current = repo.get_current_version(suggestion)
    if current is None or not current.get("wazuh_xml"):
        raise HTTPException(status_code=409, detail="There is no deployed Wazuh rule to roll back.")

    rule_ids = rule_ids_from_xml(current["wazuh_xml"])
    try:
        result = rollback_deployment(rule_ids=rule_ids, actor=actor.email)
    except DeploymentError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    with repo.transaction() as conn:
        repo.update_suggestion(suggestion_id, conn, status="rolled_back")
        repo.record_action(
            suggestion_id=suggestion_id, version_id=current["version_id"],
            action="rolled_back", actor=actor.email,
            comment=body.comment or result.message, conn=conn,
            metadata=result.to_dict(),
        )

    conn = get_connection()
    try:
        payload = _payload(_suggestion_or_404(suggestion_id, conn), bundle, actor, conn)
    finally:
        conn.close()
    payload["deployment"] = result.to_dict()
    payload["message"] = result.message
    return payload
