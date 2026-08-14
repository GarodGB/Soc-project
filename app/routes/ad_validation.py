from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Mapping

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.database import get_connection
from app.services.ad_catalog import mask_sensitive
from app.services.auth_service import ROLE_ADMIN, current_actor, require_read_access, require_write_access
from app.services.rule_content_compare import compare_rule_content
from app.services.sigma_rule_normalizer import (
    EVALUATOR_INVALID_RULE,
    EVALUATOR_MATCH,
    EVALUATOR_NO_MATCH,
    EVALUATOR_UNSUPPORTED,
    evaluate_sigma_rule as evaluate_sigma_rule_canonical,
    normalize_sigma_rule,
)
from app.services.wazuh_event_normalizer import normalize_wazuh_event
from app.services.wazuh_rule_normalizer import upsert_wazuh_catalog


router = APIRouter(prefix="/api/ad-validation", tags=["AD Validation"],
                    dependencies=[Depends(require_read_access)])


class CompareRequest(BaseModel):
    wazuh_rule_id: int
    detection_id: int
    run_id: str | None = None


class ValidateEventRequest(BaseModel):
    detection_id: int
    event: dict[str, Any]
    run_id: str | None = None


class CatalogRebuildRequest(BaseModel):
    rules: list[dict[str, Any]] | None = Field(
        default=None,
        description=(
            "Optional test/import payload. Omit to reuse "
            "app.wazuh_client.fetch_all_rules()."
        ),
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_load(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default

    if isinstance(value, (dict, list)):
        return value

    try:
        return json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def _row_to_wazuh_rule(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "wazuh_rule_id": row["wazuh_rule_id"],
        "rule_id": row["wazuh_rule_id"],
        "level": row["level"],
        "description": row["description"],
        "filename": row["filename"],
        "relative_dir": row["relative_dir"],
        "groups": _json_load(row["groups_json"], []),
        "mitre": _json_load(row["mitre_json"], {}),
        "details": _json_load(row["details_json"], {}),
        "effective_logic": _json_load(row["effective_logic_json"], {}),
        "raw_rule": _json_load(row["raw_rule_json"], {}),
        "content_hash": row["content_hash"],
        "imported_at": row["imported_at"],
    }


def _extract_rules(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [
            dict(item)
            for item in payload
            if isinstance(item, Mapping)
        ]

    if not isinstance(payload, Mapping):
        return []

    candidates = [
        payload.get("affected_items"),
        payload.get("items"),
        payload.get("rules"),
        (
            (payload.get("data") or {}).get("affected_items")
            if isinstance(payload.get("data"), Mapping)
            else None
        ),
        (
            (payload.get("data") or {}).get("items")
            if isinstance(payload.get("data"), Mapping)
            else None
        ),
    ]

    for candidate in candidates:
        if isinstance(candidate, list):
            return [
                dict(item)
                for item in candidate
                if isinstance(item, Mapping)
            ]

    return []


def _fetch_rules_with_existing_client() -> list[dict[str, Any]]:
    # Lazy import keeps application startup stable and reuses
    # the project's existing Wazuh client.
    from app import wazuh_client

    fetcher = getattr(
        wazuh_client,
        "fetch_all_rules",
        None,
    )

    if not callable(fetcher):
        raise HTTPException(
            status_code=500,
            detail=(
                "app.wazuh_client.fetch_all_rules() was not found. "
                "Expose the existing rule-fetch function instead of "
                "creating a second client."
            ),
        )

    payload = fetcher()
    rules = _extract_rules(payload)

    if not rules:
        raise HTTPException(
            status_code=502,
            detail="Existing Wazuh client returned no rule objects",
        )

    return rules


def _insert_comparison(
    connection: Any,
    *,
    request: CompareRequest,
    comparison: Mapping[str, Any],
    wazuh_fired: int | None = None,
    sigma_matched: int | None = None,
    behavioral_verdict: str | None = None,
    tuning_notes: str | None = None,
) -> int:
    scores = comparison["scores"]

    cursor = connection.execute(
        """
        INSERT INTO ad_rule_comparisons (
            run_id,
            wazuh_rule_id,
            detection_id,
            logsource_score,
            event_id_score,
            field_score,
            value_score,
            dependency_score,
            mitre_score,
            total_score,
            static_verdict,
            wazuh_fired,
            sigma_matched,
            behavioral_verdict,
            matched_fields_json,
            missing_fields_json,
            tuning_notes,
            compared_at
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        RETURNING comparison_id
        """,
        (
            request.run_id,
            request.wazuh_rule_id,
            request.detection_id,
            scores["logsource"],
            scores["event_id"],
            scores["field"],
            scores["value"],
            scores["dependency"],
            scores["mitre"],
            scores["total"],
            comparison["verdict"],
            wazuh_fired,
            sigma_matched,
            behavioral_verdict,
            json.dumps(
                comparison.get("matched_fields", []),
                ensure_ascii=False,
            ),
            json.dumps(
                comparison.get("missing_fields", []),
                ensure_ascii=False,
            ),
            tuning_notes,
            _utc_now(),
        ),
    )

    return int(cursor.fetchone()[0])


@router.get("/health")
def health() -> dict[str, Any]:
    required = [
        "wazuh_rule_catalog",
        "ad_attack_tests",
        "ad_validation_runs",
        "ad_evidence",
        "ad_rule_comparisons",
    ]

    connection = get_connection()

    try:
        existing = {
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                """
            ).fetchall()
        }

        counts: dict[str, int | None] = {}

        for table in required:
            if table in existing:
                row = connection.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()

                counts[table] = int(row[0])
            else:
                counts[table] = None

        return {
            "status": (
                "ok"
                if all(table in existing for table in required)
                else "migration_required"
            ),
            "tables": {
                table: table in existing
                for table in required
            },
            "counts": counts,
        }

    finally:
        connection.close()


@router.post("/wazuh/catalog/rebuild", dependencies=[Depends(require_write_access)])
def rebuild_wazuh_catalog(
    request: CatalogRebuildRequest,
) -> dict[str, Any]:
    rules = request.rules or _fetch_rules_with_existing_client()

    connection = get_connection()

    try:
        summary = upsert_wazuh_catalog(
            connection,
            rules,
        )

        return {
            "status": "ok",
            "source": (
                "request_body"
                if request.rules is not None
                else "existing_wazuh_client"
            ),
            "received": len(rules),
            **summary,
        }

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


@router.get("/wazuh/catalog/{rule_id}")
def get_wazuh_catalog_rule(
    rule_id: int,
) -> dict[str, Any]:
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM wazuh_rule_catalog
            WHERE wazuh_rule_id = %s
            """,
            (rule_id,),
        ).fetchone()

        if row is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"Wazuh rule {rule_id} "
                    "is not in the catalog"
                ),
            )

        return _row_to_wazuh_rule(
            dict(row)
        )

    finally:
        connection.close()


@router.post("/compare", dependencies=[Depends(require_write_access)])
def compare_rules(
    request: CompareRequest,
) -> dict[str, Any]:
    connection = get_connection()

    try:
        # Load the Wazuh rule from the normalized catalog.
        wazuh_row = connection.execute(
            """
            SELECT *
            FROM wazuh_rule_catalog
            WHERE wazuh_rule_id = %s
            """,
            (request.wazuh_rule_id,),
        ).fetchone()

        if wazuh_row is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    "Wazuh rule is not in "
                    "wazuh_rule_catalog"
                ),
            )

        # Load all Sigma fields required by the normalizer.
        detection = connection.execute(
            """
            SELECT
                detection_id,
                title,
                raw_yaml,
                logsource,
                rule_logic,
                tags,
                falsepositives
            FROM detections
            WHERE detection_id = %s
            """,
            (request.detection_id,),
        ).fetchone()

        if detection is None:
            raise HTTPException(
                status_code=404,
                detail="Sigma detection was not found",
            )

        detection = dict(detection)
        detection_id = int(detection["detection_id"])

        if not detection.get("raw_yaml"):
            raise HTTPException(
                status_code=422,
                detail="Detection has no full Sigma YAML",
            )

        # Normalize complete Sigma content.
        sigma_normalized = normalize_sigma_rule(
            str(detection.get("raw_yaml") or ""),
            logsource=detection.get("logsource"),
            rule_logic=detection.get("rule_logic"),
            tags=detection.get("tags"),
            falsepositives=detection.get(
                "falsepositives"
            ),
        )

        # Guarantee that the normalized object keeps its identity.
        sigma_normalized["detection_id"] = detection_id

        # Build reliable Sigma source labels from all available
        # normalized metadata.
        sigma_sources = {
            str(source).strip().lower()
            for source in (
                sigma_normalized.get("sources") or []
            )
            if str(source).strip()
        }

        product = str(
            sigma_normalized.get("product") or ""
        ).strip().lower()

        category = str(
            sigma_normalized.get("category") or ""
        ).strip().lower()

        if product:
            sigma_sources.add(product)

        if category:
            sigma_sources.add(category)

        for channel in (
            sigma_normalized.get("channels") or []
        ):
            channel_text = str(channel).casefold()

            if "windows" in channel_text:
                sigma_sources.add("windows")

            if "sysmon" in channel_text:
                sigma_sources.add("sysmon")

            if "powershell" in channel_text:
                sigma_sources.add("powershell")

        sigma_normalized["sources"] = sorted(
            sigma_sources
        )

        # Normalize Wazuh catalog content.
        wazuh_normalized = _row_to_wazuh_rule(
            dict(wazuh_row)
        )

        # Compare normalized Wazuh content with normalized Sigma
        # content. Convert the result to a mutable dictionary.
        comparison_result = dict(
            compare_rule_content(
                wazuh_normalized,
                sigma_normalized,
            )
        )

        # The request and database row are authoritative for IDs.
        comparison_result["wazuh_rule_id"] = int(
            request.wazuh_rule_id
        )
        comparison_result["detection_id"] = detection_id

        # Guarantee that the response evidence contains the
        # normalized Sigma metadata.
        evidence = comparison_result.setdefault(
            "evidence",
            {},
        )

        if isinstance(evidence, dict):
            evidence["sigma_sources"] = list(
                sigma_normalized.get("sources") or []
            )
            evidence["sigma_event_ids"] = list(
                sigma_normalized.get("event_ids") or []
            )
            evidence["sigma_mitre"] = list(
                sigma_normalized.get("mitre") or []
            )
            evidence["sigma_channels"] = list(
                sigma_normalized.get("channels") or []
            )
            evidence["sigma_operators"] = list(
                sigma_normalized.get("operators") or []
            )

        comparison_id = _insert_comparison(
            connection,
            request=request,
            comparison=comparison_result,
        )

        connection.commit()

        # Explicit IDs are placed after the comparison dictionary
        # so no helper result can overwrite them with null.
        return {
            **comparison_result,
            "comparison_id": comparison_id,
            "wazuh_rule_id": int(
                request.wazuh_rule_id
            ),
            "detection_id": detection_id,
        }

    except HTTPException:
        connection.rollback()
        raise

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

@router.post("/validate-event", dependencies=[Depends(require_write_access)])
def validate_event(
    request: ValidateEventRequest,
) -> dict[str, Any]:
    normalized_event = normalize_wazuh_event(
        request.event
    )

    connection = get_connection()

    try:
        # Load the Sigma detection and all fields required by
        # normalization and event evaluation.
        detection = connection.execute(
            """
            SELECT
                detection_id,
                title,
                raw_yaml,
                logsource,
                rule_logic,
                tags,
                falsepositives
            FROM detections
            WHERE detection_id = %s
            """,
            (request.detection_id,),
        ).fetchone()

        if detection is None:
            raise HTTPException(
                status_code=404,
                detail="Sigma detection was not found",
            )

        detection = dict(detection)
        detection_id = int(
            detection["detection_id"]
        )

        if not detection.get("raw_yaml"):
            raise HTTPException(
                status_code=422,
                detail="Detection has no full Sigma YAML",
            )

        # Evaluate the Sigma rule against the same real event
        # contained in the Wazuh alert.
        sigma_result = evaluate_sigma_rule_canonical(
            str(detection.get("raw_yaml") or ""),
            normalized_event["sigma_event"],
            logsource=detection.get("logsource"),
            rule_logic=detection.get("rule_logic"),
            tags=detection.get("tags"),
            falsepositives=detection.get(
                "falsepositives"
            ),
        )

        sigma_status = sigma_result.get(
            "status"
        )
        sigma_matched = sigma_result.get(
            "matched"
        )
        tuning_notes: str | None = None

        if sigma_status == EVALUATOR_UNSUPPORTED:
            sigma_matched = None
            behavioral_verdict = EVALUATOR_UNSUPPORTED
            tuning_notes = sigma_result.get(
                "reason",
                (
                    "The Sigma condition uses features that "
                    "are not supported by the evaluator."
                ),
            )

        elif sigma_status == EVALUATOR_INVALID_RULE:
            sigma_matched = None
            behavioral_verdict = EVALUATOR_INVALID_RULE
            tuning_notes = sigma_result.get(
                "reason",
                (
                    "The Sigma YAML or detection condition "
                    "is invalid."
                ),
            )

        elif sigma_status == EVALUATOR_MATCH:
            sigma_matched = True

            behavioral_verdict = (
                "both_fired_on_same_event"
                if normalized_event.get(
                    "wazuh_rule_id"
                ) is not None
                else "sigma_matched_raw_event"
            )

        elif sigma_status == EVALUATOR_NO_MATCH:
            sigma_matched = False

            behavioral_verdict = (
                "wazuh_only_on_event"
                if normalized_event.get(
                    "wazuh_rule_id"
                ) is not None
                else "sigma_missed_raw_event"
            )

        else:
            # Unknown evaluator results must never become
            # an incorrect Sigma miss.
            sigma_matched = None
            behavioral_verdict = EVALUATOR_INVALID_RULE
            tuning_notes = (
                "The Sigma evaluator returned an unknown "
                f"status: {sigma_status!r}."
            )

        wazuh_rule_id = normalized_event.get(
            "wazuh_rule_id"
        )

        wazuh_fired = (
            1
            if wazuh_rule_id is not None
            else 0
        )

        # Preserve all three evaluator states in SQLite:
        # True -> 1
        # False -> 0
        # None -> NULL
        sigma_matched_sql = (
            1
            if sigma_matched is True
            else 0
            if sigma_matched is False
            else None
        )

        comparison: dict[str, Any] | None = None
        comparison_id: int | None = None

        if wazuh_rule_id is not None:
            wazuh_row = connection.execute(
                """
                SELECT *
                FROM wazuh_rule_catalog
                WHERE wazuh_rule_id = %s
                """,
                (wazuh_rule_id,),
            ).fetchone()

            if wazuh_row is not None:
                sigma_normalized = normalize_sigma_rule(
                    str(
                        detection.get("raw_yaml") or ""
                    ),
                    logsource=detection.get(
                        "logsource"
                    ),
                    rule_logic=detection.get(
                        "rule_logic"
                    ),
                    tags=detection.get("tags"),
                    falsepositives=detection.get(
                        "falsepositives"
                    ),
                )

                sigma_normalized[
                    "detection_id"
                ] = detection_id

                # Build complete Sigma source metadata.
                sigma_sources = {
                    str(source).strip().lower()
                    for source in (
                        sigma_normalized.get(
                            "sources"
                        ) or []
                    )
                    if str(source).strip()
                }

                product = str(
                    sigma_normalized.get(
                        "product"
                    ) or ""
                ).strip().lower()

                category = str(
                    sigma_normalized.get(
                        "category"
                    ) or ""
                ).strip().lower()

                if product:
                    sigma_sources.add(product)

                if category:
                    sigma_sources.add(category)

                for channel in (
                    sigma_normalized.get(
                        "channels"
                    ) or []
                ):
                    channel_text = str(
                        channel
                    ).casefold()

                    if "windows" in channel_text:
                        sigma_sources.add(
                            "windows"
                        )

                    if "sysmon" in channel_text:
                        sigma_sources.add(
                            "sysmon"
                        )

                    if "powershell" in channel_text:
                        sigma_sources.add(
                            "powershell"
                        )

                sigma_normalized["sources"] = sorted(
                    sigma_sources
                )

                comparison = dict(
                    compare_rule_content(
                        _row_to_wazuh_rule(
                            dict(wazuh_row)
                        ),
                        sigma_normalized,
                    )
                )

                # Preserve authoritative IDs.
                comparison["wazuh_rule_id"] = int(
                    wazuh_rule_id
                )
                comparison[
                    "detection_id"
                ] = detection_id

                # Preserve complete normalized Sigma evidence
                # in the nested static comparison.
                static_evidence = (
                    comparison.setdefault(
                        "evidence",
                        {},
                    )
                )

                if isinstance(
                    static_evidence,
                    dict,
                ):
                    static_evidence[
                        "sigma_sources"
                    ] = list(
                        sigma_normalized.get(
                            "sources"
                        ) or []
                    )

                    static_evidence[
                        "sigma_event_ids"
                    ] = list(
                        sigma_normalized.get(
                            "event_ids"
                        ) or []
                    )

                    static_evidence[
                        "sigma_mitre"
                    ] = list(
                        sigma_normalized.get(
                            "mitre"
                        ) or []
                    )

                    static_evidence[
                        "sigma_channels"
                    ] = list(
                        sigma_normalized.get(
                            "channels"
                        ) or []
                    )

                    static_evidence[
                        "sigma_operators"
                    ] = list(
                        sigma_normalized.get(
                            "operators"
                        ) or []
                    )

                comparison_id = _insert_comparison(
                    connection,
                    request=CompareRequest(
                        wazuh_rule_id=int(
                            wazuh_rule_id
                        ),
                        detection_id=detection_id,
                        run_id=request.run_id,
                    ),
                    comparison=comparison,
                    wazuh_fired=wazuh_fired,
                    sigma_matched=sigma_matched_sql,
                    behavioral_verdict=(
                        behavioral_verdict
                    ),
                    tuning_notes=tuning_notes,
                )

        evidence_id: int | None = None

        if request.run_id:
            run_exists = connection.execute(
                """
                SELECT 1
                FROM ad_validation_runs
                WHERE run_id = %s
                """,
                (request.run_id,),
            ).fetchone()

            if run_exists is None:
                raise HTTPException(
                    status_code=404,
                    detail=(
                        "run_id was not found in "
                        "ad_validation_runs"
                    ),
                )

            cursor = connection.execute(
                """
                INSERT INTO ad_evidence (
                    run_id,
                    evidence_type,
                    original_filename,
                    event_fingerprint,
                    agent_name,
                    channel,
                    event_id,
                    event_timestamp,
                    wazuh_rule_id,
                    payload_json,
                    imported_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s
                )
                RETURNING evidence_id
                """,
                (
                    request.run_id,
                    normalized_event.get(
                        "event_type"
                    ),
                    None,
                    normalized_event.get(
                        "event_fingerprint"
                    ),
                    normalized_event.get(
                        "agent_name"
                    ),
                    (
                        normalized_event.get(
                            "fields"
                        ) or {}
                    ).get("channel"),
                    (
                        normalized_event.get(
                            "fields"
                        ) or {}
                    ).get("event_id"),
                    normalized_event.get(
                        "timestamp"
                    ),
                    wazuh_rule_id,
                    json.dumps(
                        request.event,
                        ensure_ascii=False,
                    ),
                    _utc_now(),
                ),
            )

            evidence_id = int(
                cursor.fetchone()[0]
            )

        connection.commit()

        verdict = (
            "FIRED"
            if sigma_matched is True
            else "NOT_FIRED"
            if sigma_matched is False
            else "UNSUPPORTED"
            if sigma_status == EVALUATOR_UNSUPPORTED
            else "INVALID_RULE"
        )

        # Return only a compact, PowerShell-safe event summary.
        # The internal sigma_event contains both Channel/channel
        # and similar case-variant keys. Windows PowerShell treats
        # those keys as duplicates and cannot parse the response.
        response_normalized_event = {
            "event_type": normalized_event.get(
                "event_type"
            ),
            "timestamp": normalized_event.get(
                "timestamp"
            ),
            "agent_name": normalized_event.get(
                "agent_name"
            ),
            "agent_ip": normalized_event.get(
                "agent_ip"
            ),
            "wazuh_rule_id": normalized_event.get(
                "wazuh_rule_id"
            ),
            "wazuh_rule_level": normalized_event.get(
                "wazuh_rule_level"
            ),
            "wazuh_rule_description": (
                normalized_event.get(
                    "wazuh_rule_description"
                )
            ),
            "fields": normalized_event.get(
                "fields",
                {},
            ),
            "event_fingerprint": (
                normalized_event.get(
                    "event_fingerprint"
                )
            ),
        }

        return {
            "verdict": verdict,
            "sigma_status": sigma_status,
            "sigma_matched": sigma_matched,
            "wazuh_fired": bool(wazuh_fired),
            "behavioral_verdict": (
                behavioral_verdict
            ),
            "tuning_notes": tuning_notes,
            "detection_id": detection_id,
            "wazuh_rule_id": wazuh_rule_id,
            "normalized_event": (
                response_normalized_event
            ),
            "evaluator_details": sigma_result,
            "static_comparison": comparison,
            "comparison_id": comparison_id,
            "evidence_id": evidence_id,
        }

    except HTTPException:
        connection.rollback()
        raise

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

# ==========================================================================
#  REPLACEMENT for the existing list_validation_runs() in
#  app/routes/ad_validation.py
#
#  Delete your current  @router.get("/runs")  def list_validation_runs(...)
#  function and paste THIS one in its place. Everything else stays the same.
#
#  What changed: each run row now also carries the LATEST comparison's
#  wazuh_rule_id, detection_id, static_score (0-100), wazuh_fired,
#  sigma_matched, fields_matched, plus the latest evidence channel/event_id
#  as log_source / event_ids. This makes the AD Validation table columns
#  fill in instead of showing "—". No frontend change is required.
# ==========================================================================

@router.get("/runs")
def list_validation_runs(
    limit: int = 50,
    offset: int = 0,
    status: str | None = None,
) -> dict[str, Any]:
    if limit < 1 or limit > 200:
        raise HTTPException(
            status_code=422,
            detail="limit must be between 1 and 200",
        )

    if offset < 0:
        raise HTTPException(
            status_code=422,
            detail="offset must be zero or greater",
        )

    connection = get_connection()

    try:
        where_clause = "WHERE r.status != 'superseded'"
        parameters: list[Any] = []

        if status:
            where_clause = "WHERE r.status = %s AND r.status != 'superseded'"
            parameters.append(status)

        total_query = """
            SELECT COUNT(*)
            FROM ad_validation_runs AS r
            WHERE r.status != 'superseded'
        """

        if status:
            total_query += " AND r.status = %s"

        total_row = connection.execute(
            total_query,
            tuple(parameters),
        ).fetchone()

        total = int(total_row[0])

        rows = connection.execute(
            f"""
            SELECT
                r.run_id,
                r.test_id,
                r.started_at,
                r.ended_at,
                r.source_host,
                r.target_host,
                r.source_ip,
                r.status,
                r.notes,
                t.behavior_name,
                t.technique_id,
                t.risk_tier,
                (
                    SELECT COUNT(*)
                    FROM ad_evidence AS e
                    WHERE e.run_id = r.run_id
                ) AS evidence_count,
                (
                    SELECT COUNT(*)
                    FROM ad_rule_comparisons AS c
                    WHERE c.run_id = r.run_id
                ) AS comparison_count,
                (
                    SELECT c.behavioral_verdict
                    FROM ad_rule_comparisons AS c
                    WHERE c.run_id = r.run_id
                    ORDER BY c.comparison_id DESC
                    LIMIT 1
                ) AS latest_behavioral_verdict,
                (
                    SELECT c.static_verdict
                    FROM ad_rule_comparisons AS c
                    WHERE c.run_id = r.run_id
                    ORDER BY c.comparison_id DESC
                    LIMIT 1
                ) AS latest_static_verdict,
                (
                    SELECT c.wazuh_rule_id
                    FROM ad_rule_comparisons AS c
                    WHERE c.run_id = r.run_id
                    ORDER BY c.comparison_id DESC
                    LIMIT 1
                ) AS wazuh_rule_id,
                (
                    SELECT c.detection_id
                    FROM ad_rule_comparisons AS c
                    WHERE c.run_id = r.run_id
                    ORDER BY c.comparison_id DESC
                    LIMIT 1
                ) AS detection_id,
                (
                    SELECT c.total_score
                    FROM ad_rule_comparisons AS c
                    WHERE c.run_id = r.run_id
                    ORDER BY c.comparison_id DESC
                    LIMIT 1
                ) AS latest_total_score,
                (
                    SELECT c.wazuh_fired
                    FROM ad_rule_comparisons AS c
                    WHERE c.run_id = r.run_id
                    ORDER BY c.comparison_id DESC
                    LIMIT 1
                ) AS wazuh_fired,
                (
                    SELECT c.sigma_matched
                    FROM ad_rule_comparisons AS c
                    WHERE c.run_id = r.run_id
                    ORDER BY c.comparison_id DESC
                    LIMIT 1
                ) AS sigma_matched,
                (
                    SELECT c.matched_fields_json
                    FROM ad_rule_comparisons AS c
                    WHERE c.run_id = r.run_id
                    ORDER BY c.comparison_id DESC
                    LIMIT 1
                ) AS matched_fields_json,
                (
                    SELECT e.channel
                    FROM ad_evidence AS e
                    WHERE e.run_id = r.run_id
                    ORDER BY e.evidence_id DESC
                    LIMIT 1
                ) AS log_source,
                (
                    SELECT e.event_id
                    FROM ad_evidence AS e
                    WHERE e.run_id = r.run_id
                    ORDER BY e.evidence_id DESC
                    LIMIT 1
                ) AS event_ids
            FROM ad_validation_runs AS r
            LEFT JOIN ad_attack_tests AS t
                ON t.test_id = r.test_id
            {where_clause}
            ORDER BY r.started_at DESC
            LIMIT %s
            OFFSET %s
            """,
            tuple(
                [
                    *parameters,
                    limit,
                    offset,
                ]
            ),
        ).fetchall()

        items: list[dict[str, Any]] = []

        for row in rows:
            item = dict(row)

            # Derive fields_matched count from the latest comparison.
            matched = _json_load(
                item.pop("matched_fields_json", None), []
            )
            item["fields_matched"] = (
                len(matched) if isinstance(matched, list) else None
            )

            # Scale the 0-1 content score to the 0-100 the UI expects.
            total_score = item.pop("latest_total_score", None)
            item["static_score"] = (
                round(total_score * 100)
                if isinstance(total_score, (int, float))
                else None
            )

            # Normalize SQLite integers to booleans for the UI.
            if item.get("wazuh_fired") is not None:
                item["wazuh_fired"] = bool(item["wazuh_fired"])
            if item.get("sigma_matched") is not None:
                item["sigma_matched"] = bool(item["sigma_matched"])

            items.append(item)

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": items,
        }

    finally:
        connection.close()


# =============================================================================
#  ABSEGA | AD Validation detail-page builder (deterministic, authoritative)
#  Produces ONE backend-computed "detail" object for the run drawer so the
#  frontend only renders (never infers recommendation / verdict / coverage).
# =============================================================================


def _ad_extract_techniques(tags: Any) -> list[str]:
    """Pull ATT&CK technique IDs (e.g. T1110.003) from a detection's tags."""
    import re as _re
    if not tags:
        return []
    text = tags if isinstance(tags, str) else " ".join(str(x) for x in tags)
    out: list[str] = []
    for m in _re.findall(r"[tT](\d{4}(?:\.\d{3})?)", text):
        out.append("T" + m)
    # de-dup, preserve order
    seen: set[str] = set()
    result: list[str] = []
    for t in out:
        if t not in seen:
            seen.add(t)
            result.append(t)
    return result


def _ad_base_technique(technique: str) -> str:
    return (technique or "").split(".")[0].upper()


def _ad_mitre_compatible(expected: str, detection_techniques: list[str]):
    """True / False / None(unknown). Compatible if the expected technique or its
    base (parent) technique is present in the detection's tags."""
    if not detection_techniques:
        return None
    if not expected:
        return None
    expected = expected.upper()
    base = _ad_base_technique(expected)
    for t in detection_techniques:
        tu = t.upper()
        if tu == expected or _ad_base_technique(tu) == base:
            return True
    return False


def _ad_detail_state_machine(
    evidence_present: bool,
    wazuh_fired: bool,
    sigma_matched,
    evaluator_status,
    mitre_compatible,
    has_candidate: bool,
):
    """Deterministic (result_state, recommendation, reason)."""
    if not evidence_present:
        return (
            "INCOMPLETE_NO_EVIDENCE",
            "Re-run",
            "No stored real event for this run; runtime validation was not performed.",
        )

    if evaluator_status == EVALUATOR_UNSUPPORTED:
        if wazuh_fired:
            return (
                "WAZUH_ONLY",
                "Tune / Verify",
                "Wazuh detected the behavior; the Sigma candidate uses conditions the "
                "evaluator cannot assess (e.g. aggregation/threshold).",
            )
        return (
            "EVALUATOR_UNSUPPORTED",
            "Tune / Verify",
            "The Sigma candidate uses unsupported conditions (e.g. aggregation) and "
            "could not be evaluated.",
        )

    # A Sigma match on a MITRE-incompatible rule is NOT real behavioral coverage.
    effective_sigma = bool(sigma_matched) and (mitre_compatible is not False)

    if wazuh_fired and effective_sigma:
        return (
            "VERIFIED_OVERLAP",
            "Keep",
            "Wazuh and a MITRE-compatible Sigma rule both matched the same real event.",
        )
    if wazuh_fired and not effective_sigma:
        if (not has_candidate) or (mitre_compatible is False):
            return (
                "WAZUH_ONLY",
                "Create rule",
                "Wazuh detected the behavior; no suitable (MITRE-compatible) Sigma rule "
                "matched this event.",
            )
        return (
            "WAZUH_ONLY",
            "Tune / Verify",
            "Wazuh detected the behavior; a MITRE-compatible Sigma candidate exists but "
            "did not match this event — tune it.",
        )
    if (not wazuh_fired) and effective_sigma:
        return (
            "SIGMA_ONLY",
            "Create rule",
            "A MITRE-compatible Sigma rule matched the real event; Wazuh has no genuine "
            "detection — create/deploy a Wazuh rule.",
        )
    if sigma_matched and mitre_compatible is False:
        return (
            "MAPPING_ONLY",
            "Review",
            "Only a MITRE-incompatible Sigma rule matched; this is a mapping overlap, "
            "not behavioral coverage.",
        )
    return (
        "NO_DETECTION_IN_EITHER",
        "Create rule",
        "Neither Wazuh nor a suitable Sigma rule detected this behavior.",
    )


def _build_run_detail(connection, run, evidence_rows, comparisons):
    """Assemble the authoritative detail object for the run drawer."""
    import json as _json

    expected_technique = str(run.get("technique_id") or "")

    # ---- authoritative comparison = newest for THIS run ----
    cmp = comparisons[0] if comparisons else {}
    wazuh_rule_id = cmp.get("wazuh_rule_id")
    detection_id = cmp.get("detection_id")
    wazuh_fired = bool(cmp.get("wazuh_fired")) if cmp.get("wazuh_fired") is not None else False
    sigma_matched = cmp.get("sigma_matched")

    # ---- evidence (newest with a stored payload) ----
    stored = None
    for ev in evidence_rows:
        if ev.get("payload_json"):
            stored = ev
            break
    evidence_present = stored is not None
    normalized_event = None
    raw_event = None
    if evidence_present:
        try:
            raw_event = _json.loads(stored["payload_json"])
            normalized_event = normalize_wazuh_event(raw_event)
        except Exception:
            raw_event = None
            normalized_event = None

    evidence_detail = {
        "state": "STORED" if evidence_present else "MISSING",
        "reason": None if evidence_present
        else "No raw Wazuh event was stored for this run; nothing to evaluate.",
        "event_id": (stored or {}).get("event_id"),
        "channel": (stored or {}).get("channel"),
        "agent_name": (stored or {}).get("agent_name"),
        "normalized_event": (normalized_event or {}).get("sigma_event") if normalized_event else None,
    }

    # ---- Wazuh rule (raw + effective) ----
    wazuh_detail = {"rule_id": wazuh_rule_id, "state": None, "reason": None,
                    "raw_rule": None, "effective_logic": None}
    if wazuh_rule_id is None:
        wazuh_detail["state"] = "NO_RULE"
        wazuh_detail["reason"] = "No Wazuh rule was recorded as a genuine detection for this event."
    else:
        wrow = connection.execute(
            "SELECT raw_rule_json, effective_logic_json FROM wazuh_rule_catalog WHERE wazuh_rule_id = %s",
            (wazuh_rule_id,),
        ).fetchone()
        if wrow is None:
            wazuh_detail["state"] = "NOT_IN_CATALOG"
            wazuh_detail["reason"] = f"Rule {wazuh_rule_id} is not present in the imported Wazuh catalog."
        else:
            wrow = dict(wrow)
            try:
                wazuh_detail["raw_rule"] = _json.loads(wrow.get("raw_rule_json") or "null")
            except Exception:
                wazuh_detail["raw_rule"] = wrow.get("raw_rule_json")
            try:
                wazuh_detail["effective_logic"] = _json.loads(wrow.get("effective_logic_json") or "null")
            except Exception:
                wazuh_detail["effective_logic"] = wrow.get("effective_logic_json")
            wazuh_detail["state"] = "PRESENT"

    # ---- Sigma detection (raw + normalized) ----
    sigma_detail = {"detection_id": detection_id, "title": None, "state": None, "reason": None,
                    "raw_yaml": None, "normalized": None, "unsupported_reasons": [],
                    "techniques": []}
    detection_row = None
    if detection_id is not None:
        detection_row = connection.execute(
            "SELECT detection_id, title, raw_yaml, logsource, rule_logic, tags, falsepositives "
            "FROM detections WHERE detection_id = %s",
            (detection_id,),
        ).fetchone()
    if detection_id is None:
        sigma_detail["state"] = "NO_CANDIDATE"
        sigma_detail["reason"] = "No Sigma detection was selected as a candidate for this run."
    elif detection_row is None:
        sigma_detail["state"] = "NOT_FOUND"
        sigma_detail["reason"] = f"Sigma detection {detection_id} no longer exists."
    else:
        detection_row = dict(detection_row)
        sigma_detail["title"] = detection_row.get("title")
        sigma_detail["techniques"] = _ad_extract_techniques(detection_row.get("tags"))
        sigma_detail["raw_yaml"] = detection_row.get("raw_yaml")
        if not detection_row.get("raw_yaml"):
            sigma_detail["state"] = "YAML_MISSING"
            sigma_detail["reason"] = "The detection has no full Sigma YAML stored."
        else:
            try:
                norm = normalize_sigma_rule(
                    str(detection_row.get("raw_yaml") or ""),
                    logsource=detection_row.get("logsource"),
                    rule_logic=detection_row.get("rule_logic"),
                    tags=detection_row.get("tags"),
                    falsepositives=detection_row.get("falsepositives"),
                )
                sigma_detail["normalized"] = norm
                if norm.get("status") == EVALUATOR_UNSUPPORTED:
                    sigma_detail["state"] = "UNSUPPORTED"
                    sigma_detail["unsupported_reasons"] = norm.get("unsupported_reasons", [])
                    sigma_detail["reason"] = "Sigma normalized, but uses conditions the evaluator cannot assess."
                else:
                    sigma_detail["state"] = "PRESENT"
            except Exception as exc:
                sigma_detail["state"] = "NORMALIZE_FAILED"
                sigma_detail["reason"] = f"Sigma normalization raised: {exc}"

    # ---- MITRE compatibility ----
    mitre_compatible = _ad_mitre_compatible(expected_technique, sigma_detail["techniques"])
    if sigma_detail["techniques"]:
        if mitre_compatible:
            mitre_reason = f"Detection is tagged {', '.join(sigma_detail['techniques'])}, compatible with {expected_technique}."
        else:
            mitre_reason = (f"Detection is tagged {', '.join(sigma_detail['techniques'])}, which does NOT match the "
                            f"expected technique {expected_technique}.")
    else:
        mitre_reason = "Detection has no ATT&CK tags; MITRE compatibility is unknown."
    mitre_detail = {
        "expected_technique": expected_technique or None,
        "detection_techniques": sigma_detail["techniques"],
        "compatible": mitre_compatible,
        "reason": mitre_reason,
    }

    # ---- live condition evaluation against the stored event ----
    evaluator_status = None
    matched_conditions: list[str] = []
    failed_conditions: list[str] = []
    cond_state = None
    cond_reason = None
    if not evidence_present:
        cond_state = "NOT_EVALUATED_NO_EVENT"
        cond_reason = "No stored event; Sigma conditions were not evaluated."
    elif detection_row is None or not detection_row.get("raw_yaml"):
        cond_state = "NOT_EVALUATED_NO_LOGIC"
        cond_reason = "No Sigma logic available to evaluate."
    else:
        try:
            result = evaluate_sigma_rule_canonical(
                str(detection_row.get("raw_yaml") or ""),
                (normalized_event or {}).get("sigma_event", {}),
                logsource=detection_row.get("logsource"),
                rule_logic=detection_row.get("rule_logic"),
                tags=detection_row.get("tags"),
                falsepositives=detection_row.get("falsepositives"),
            )
            evaluator_status = result.get("status")
            sel = result.get("selection_results") or {}
            for name, ok in sel.items():
                (matched_conditions if ok else failed_conditions).append(str(name))
            if evaluator_status == EVALUATOR_UNSUPPORTED:
                cond_state = "EVALUATOR_UNSUPPORTED"
                cond_reason = result.get("reason") or "Unsupported Sigma condition."
            elif result.get("matched") is True:
                cond_state = "EVALUATED_MATCHED"
                sigma_matched = True
            else:
                cond_state = "EVALUATED_FAILED"
                if result.get("matched") is False:
                    sigma_matched = False
        except Exception as exc:
            cond_state = "NOT_EVALUATED_ERROR"
            cond_reason = f"Evaluation error: {exc}"

    # ---- candidate classification ----
    if detection_id is None:
        candidate_classification = "NO_SIGMA_CANDIDATE"
    elif mitre_compatible is False:
        candidate_classification = "CANDIDATE_ONLY_MITRE_MISMATCH"
    elif sigma_matched:
        candidate_classification = "SIGMA_COVERAGE"
    else:
        candidate_classification = "CANDIDATE_ONLY"

    has_candidate = detection_id is not None and mitre_compatible is not False

    # ---- deterministic verdict + recommendation ----
    result_state, recommendation, rec_reason = _ad_detail_state_machine(
        evidence_present=evidence_present,
        wazuh_fired=wazuh_fired,
        sigma_matched=sigma_matched,
        evaluator_status=evaluator_status,
        mitre_compatible=mitre_compatible,
        has_candidate=has_candidate,
    )

    return {
        "authoritative_comparison_id": cmp.get("comparison_id"),
        "host": {"source": run.get("source_host"), "target": run.get("target_host"),
                 "source_ip": run.get("source_ip")},
        "evidence": evidence_detail,
        "wazuh": wazuh_detail,
        "sigma": sigma_detail,
        "mitre": mitre_detail,
        "candidate_classification": candidate_classification,
        "condition_evaluation": {
            "state": cond_state,
            "reason": cond_reason,
            "matched_conditions": matched_conditions,
            "failed_conditions": failed_conditions,
        },
        "wazuh_fired": wazuh_fired,
        "sigma_matched": sigma_matched,
        "result_state": result_state,
        "recommendation": recommendation,
        "recommendation_reason": rec_reason,
        "false_positive_notes": (detection_row or {}).get("falsepositives") if detection_row else None,
        "static_score": cmp.get("total_score"),
    }


@router.get("/runs/{run_id}")
def get_validation_run(
    run_id: str,
) -> dict[str, Any]:
    connection = get_connection()

    try:
        run_row = connection.execute(
            """
            SELECT
                r.run_id,
                r.test_id,
                r.started_at,
                r.ended_at,
                r.source_host,
                r.target_host,
                r.source_ip,
                r.status,
                r.notes,
                r.created_at,
                t.behavior_name,
                t.technique_id,
                t.execution_host,
                t.target_host AS expected_target_host,
                t.expected_channels_json,
                t.expected_event_ids_json,
                t.expected_fields_json,
                t.simulation_command,
                t.cleanup_command,
                t.risk_tier,
                t.enabled
            FROM ad_validation_runs AS r
            LEFT JOIN ad_attack_tests AS t
                ON t.test_id = r.test_id
            WHERE r.run_id = %s
            """,
            (run_id,),
        ).fetchone()

        if run_row is None:
            raise HTTPException(
                status_code=404,
                detail="Validation run was not found",
            )

        run = dict(run_row)

        run["expected_channels"] = _json_load(
            run.pop(
                "expected_channels_json",
                None,
            ),
            [],
        )

        run["expected_event_ids"] = _json_load(
            run.pop(
                "expected_event_ids_json",
                None,
            ),
            [],
        )

        run["expected_fields"] = _json_load(
            run.pop(
                "expected_fields_json",
                None,
            ),
            {},
        )

        evidence_rows = connection.execute(
            """
            SELECT
                evidence_id,
                run_id,
                evidence_type,
                original_filename,
                event_fingerprint,
                agent_name,
                channel,
                event_id,
                event_timestamp,
                wazuh_rule_id,
                imported_at,
                payload_json
            FROM ad_evidence
            WHERE run_id = %s
            ORDER BY evidence_id DESC
            """,
            (run_id,),
        ).fetchall()

        comparison_rows = connection.execute(
            """
            SELECT
                comparison_id,
                run_id,
                wazuh_rule_id,
                detection_id,
                logsource_score,
                event_id_score,
                field_score,
                value_score,
                dependency_score,
                mitre_score,
                total_score,
                static_verdict,
                wazuh_fired,
                sigma_matched,
                behavioral_verdict,
                matched_fields_json,
                missing_fields_json,
                tuning_notes,
                compared_at
            FROM ad_rule_comparisons
            WHERE run_id = %s
            ORDER BY comparison_id DESC
            """,
            (run_id,),
        ).fetchall()

        comparisons: list[dict[str, Any]] = []

        for row in comparison_rows:
            comparison = dict(row)

            comparison["matched_fields"] = _json_load(
                comparison.pop(
                    "matched_fields_json",
                    None,
                ),
                [],
            )

            comparison["missing_fields"] = _json_load(
                comparison.pop(
                    "missing_fields_json",
                    None,
                ),
                [],
            )

            if comparison["wazuh_fired"] is not None:
                comparison["wazuh_fired"] = bool(
                    comparison["wazuh_fired"]
                )

            if comparison["sigma_matched"] is not None:
                comparison["sigma_matched"] = bool(
                    comparison["sigma_matched"]
                )

            comparisons.append(comparison)

        evidence = [
            dict(row)
            for row in evidence_rows
        ]

        detail = _build_run_detail(connection, run, evidence, comparisons)

        # keep the public evidence list lightweight (no raw payload dump)
        evidence_public = [
            {k: v for k, v in ev.items() if k != "payload_json"}
            for ev in evidence
        ]

        return {
            "run": run,
            "evidence_count": len(evidence),
            "comparison_count": len(comparisons),
            "evidence": evidence_public,
            "comparisons": comparisons,
            "detail": detail,
        }

    finally:
        connection.close()


@router.get("/evidence/{evidence_id}")
def get_validation_evidence(
    evidence_id: int,
    request: Request,
) -> dict[str, Any]:
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT
                evidence_id,
                run_id,
                evidence_type,
                original_filename,
                event_fingerprint,
                agent_name,
                channel,
                event_id,
                event_timestamp,
                wazuh_rule_id,
                payload_json,
                imported_at
            FROM ad_evidence
            WHERE evidence_id = %s
            """,
            (evidence_id,),
        ).fetchone()

        if row is None:
            raise HTTPException(
                status_code=404,
                detail="Validation evidence was not found",
            )

        evidence = dict(row)

        # Keep the original payload as a JSON string.
        # JavaScript can parse this safely, while PowerShell
        # will not fail on case-sensitive event field names.
        payload = evidence.get("payload_json") or "{}"
        if current_actor(request).role != ROLE_ADMIN:
            try:
                payload = json.dumps(mask_sensitive(json.loads(payload)))
            except Exception:
                pass
        evidence["payload_json"] = payload

        return evidence

    finally:
        connection.close()



# ==========================================================================
#  STEP 10 — Additional AD Validation endpoints
#  Appended below the existing routes. Reuses the same router, DB helper,
#  services, and helper functions already defined in this module.
# ==========================================================================


class SyncRulesRequest(BaseModel):
    rules: list[dict[str, Any]] | None = Field(
        default=None,
        description=(
            "Optional Wazuh rule payload for testing/imports. "
            "Omit to reuse app.wazuh_client.fetch_all_rules()."
        ),
    )


class RunCreateRequest(BaseModel):
    test_id: str
    run_id: str | None = None
    source_host: str | None = None
    target_host: str | None = None
    source_ip: str | None = None
    status: str = "running"
    notes: str | None = None


class EvidenceCreateRequest(BaseModel):
    event: dict[str, Any]
    evidence_type: str | None = None
    original_filename: str | None = None


class RunCompareRequest(BaseModel):
    wazuh_rule_id: int
    detection_id: int


@router.post("/sync-rules", dependencies=[Depends(require_write_access)])
def sync_rules(
    request: SyncRulesRequest | None = None,
) -> dict[str, Any]:
    body = request or SyncRulesRequest()
    rules = body.rules or _fetch_rules_with_existing_client()
    received = len(rules)

    connection = get_connection()

    try:
        summary = upsert_wazuh_catalog(connection, rules)
        stored = int(summary.get("stored", 0))

        effective_built = int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM wazuh_rule_catalog
                WHERE effective_logic_json IS NOT NULL
                  AND effective_logic_json != '{}'
                """
            ).fetchone()[0]
        )

        sigma_available = int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM detections
                WHERE raw_yaml IS NOT NULL
                  AND raw_yaml != ''
                """
            ).fetchone()[0]
        )

        errors = max(0, received - stored)

        return {
            "wazuh_rules_imported": stored,
            "sigma_rules_available": sigma_available,
            "wazuh_effective_rules_built": effective_built,
            "errors": errors,
        }

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


@router.get("/summary")
def validation_summary() -> dict[str, Any]:
    connection = get_connection()

    try:
        def one(query: str, params: tuple[Any, ...] = ()) -> int:
            return int(
                connection.execute(query, params).fetchone()[0]
            )

        catalog_rules = one(
            "SELECT COUNT(*) FROM wazuh_rule_catalog"
        )

        wazuh_fired_rules = one(
            """
            SELECT COUNT(DISTINCT wazuh_rule_id)
            FROM ad_rule_comparisons
            WHERE wazuh_fired = 1
              AND wazuh_rule_id IS NOT NULL
            """
        )

        sigma_available = one(
            """
            SELECT COUNT(*)
            FROM detections
            WHERE raw_yaml IS NOT NULL
              AND raw_yaml != ''
            """
        )

        sigma_compared = one(
            """
            SELECT COUNT(DISTINCT detection_id)
            FROM ad_rule_comparisons
            WHERE detection_id IS NOT NULL
            """
        )

        static_overlaps = one(
            """
            SELECT COUNT(*)
            FROM ad_rule_comparisons
            WHERE static_verdict IN (
    'STRONG_STATIC_OVERLAP',
    'LIKELY_STATIC_OVERLAP',
    'PARTIAL_OVERLAP'
)
            """
        )

        verified = one(
            """
            SELECT COUNT(*)
            FROM ad_rule_comparisons
            WHERE behavioral_verdict IN (
                'both_fired_on_same_event', 'VERIFIED_OVERLAP'
            )
            """
        )

        wazuh_only = one(
            """
            SELECT COUNT(*)
            FROM ad_rule_comparisons
            WHERE behavioral_verdict LIKE '%wazuh_only%'
            """
        )

        sigma_only = one(
            """
            SELECT COUNT(*)
            FROM ad_rule_comparisons
            WHERE behavioral_verdict LIKE '%sigma_matched_raw%'
               OR behavioral_verdict LIKE '%sigma_only%'
            """
        )

        missing = one(
            """
            SELECT COUNT(*)
            FROM ad_rule_comparisons
            WHERE (wazuh_fired = 0 OR wazuh_fired IS NULL)
              AND (sigma_matched = 0 OR sigma_matched IS NULL)
            """
        )

        telemetry_gaps = one(
            """
            SELECT COUNT(*)
            FROM ad_validation_runs AS r
            WHERE r.status NOT LIKE '%NOT_EXECUTED%'
              AND r.status NOT LIKE '%skip%'
              AND (
                SELECT COUNT(*)
                FROM ad_evidence AS e
                WHERE e.run_id = r.run_id
            ) = 0
            """
        )

        runs_total = one(
            "SELECT COUNT(*) FROM ad_validation_runs"
        )

        comparisons_total = one(
            "SELECT COUNT(*) FROM ad_rule_comparisons"
        )

        return {
            "wazuh_ad_rules": wazuh_fired_rules or catalog_rules,
            "wazuh_catalog_rules": catalog_rules,
            "sigma_rules": sigma_compared,
            "sigma_rules_available": sigma_available,
            "static_overlaps": static_overlaps,
            "verified_overlaps": verified,
            "wazuh_only_behaviors": wazuh_only,
            "sigma_only_behaviors": sigma_only,
            "telemetry_gaps": telemetry_gaps,
            "missing_rules": missing,
            "runs_total": runs_total,
            "comparisons_total": comparisons_total,
        }

    finally:
        connection.close()


@router.get("/comparisons")
def list_comparisons(
    limit: int = 100,
    offset: int = 0,
    run_id: str | None = None,
) -> dict[str, Any]:
    if limit < 1 or limit > 500:
        raise HTTPException(
            status_code=422,
            detail="limit must be between 1 and 500",
        )

    if offset < 0:
        raise HTTPException(
            status_code=422,
            detail="offset must be zero or greater",
        )

    connection = get_connection()

    try:
        where_clause = ""
        parameters: list[Any] = []

        if run_id:
            where_clause = "WHERE c.run_id = %s"
            parameters.append(run_id)

        total = int(
            connection.execute(
                f"""
                SELECT COUNT(*)
                FROM ad_rule_comparisons AS c
                {where_clause}
                """,
                tuple(parameters),
            ).fetchone()[0]
        )

        rows = connection.execute(
            f"""
            SELECT
                c.comparison_id,
                c.run_id,
                c.wazuh_rule_id,
                c.detection_id,
                c.logsource_score,
                c.event_id_score,
                c.field_score,
                c.value_score,
                c.dependency_score,
                c.mitre_score,
                c.total_score,
                c.static_verdict,
                c.wazuh_fired,
                c.sigma_matched,
                c.behavioral_verdict,
                c.matched_fields_json,
                c.missing_fields_json,
                c.tuning_notes,
                c.compared_at,
                t.behavior_name,
                t.technique_id,
                d.title AS detection_title,
                w.description AS wazuh_description
            FROM ad_rule_comparisons AS c
            LEFT JOIN ad_validation_runs AS r
                ON r.run_id = c.run_id
            LEFT JOIN ad_attack_tests AS t
                ON t.test_id = r.test_id
            LEFT JOIN detections AS d
                ON d.detection_id = c.detection_id
            LEFT JOIN wazuh_rule_catalog AS w
                ON w.wazuh_rule_id = c.wazuh_rule_id
            {where_clause}
            ORDER BY c.comparison_id DESC
            LIMIT %s
            OFFSET %s
            """,
            tuple([*parameters, limit, offset]),
        ).fetchall()

        items: list[dict[str, Any]] = []

        for row in rows:
            item = dict(row)

            matched = _json_load(
                item.pop("matched_fields_json", None), []
            )
            missing = _json_load(
                item.pop("missing_fields_json", None), []
            )

            item["matched_fields"] = matched
            item["missing_fields"] = missing
            item["fields_matched"] = (
                len(matched) if isinstance(matched, list) else None
            )

            if item.get("wazuh_fired") is not None:
                item["wazuh_fired"] = bool(item["wazuh_fired"])

            if item.get("sigma_matched") is not None:
                item["sigma_matched"] = bool(item["sigma_matched"])

            items.append(item)

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": items,
        }

    finally:
        connection.close()


@router.post("/runs", dependencies=[Depends(require_write_access)])
def create_validation_run(
    request: RunCreateRequest,
) -> dict[str, Any]:
    connection = get_connection()

    try:
        test_row = connection.execute(
            """
            SELECT test_id, behavior_name, technique_id
            FROM ad_attack_tests
            WHERE test_id = %s
            """,
            (request.test_id,),
        ).fetchone()

        if test_row is None:
            raise HTTPException(
                status_code=404,
                detail="test_id was not found in ad_attack_tests",
            )

        test = dict(test_row)

        run_id = request.run_id

        if not run_id:
            technique = str(
                test.get("technique_id") or request.test_id
            ).replace(".", "-")

            base = (
                f"RUN-{technique}-"
                f"{datetime.now(timezone.utc):%Y%m%d-%H%M%S}"
            )

            run_id = base
            suffix = 1

            while connection.execute(
                "SELECT 1 FROM ad_validation_runs WHERE run_id = %s",
                (run_id,),
            ).fetchone():
                suffix += 1
                run_id = f"{base}-{suffix}"
        else:
            if connection.execute(
                "SELECT 1 FROM ad_validation_runs WHERE run_id = %s",
                (run_id,),
            ).fetchone():
                raise HTTPException(
                    status_code=409,
                    detail="run_id already exists",
                )

        now = _utc_now()

        connection.execute(
            """
            INSERT INTO ad_validation_runs (
                run_id,
                test_id,
                started_at,
                ended_at,
                source_host,
                target_host,
                source_ip,
                status,
                notes,
                created_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            """,
            (
                run_id,
                request.test_id,
                now,
                None,
                request.source_host,
                request.target_host,
                request.source_ip,
                request.status,
                request.notes,
                now,
            ),
        )

        connection.commit()

        return {
            "run_id": run_id,
            "test_id": request.test_id,
            "behavior_name": test.get("behavior_name"),
            "technique_id": test.get("technique_id"),
            "source_host": request.source_host,
            "target_host": request.target_host,
            "source_ip": request.source_ip,
            "status": request.status,
            "notes": request.notes,
            "started_at": now,
            "created_at": now,
        }

    except HTTPException:
        connection.rollback()
        raise

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


@router.post("/runs/{run_id}/evidence", dependencies=[Depends(require_write_access)])
def add_run_evidence(
    run_id: str,
    request: EvidenceCreateRequest,
) -> dict[str, Any]:
    connection = get_connection()

    try:
        run_exists = connection.execute(
            "SELECT 1 FROM ad_validation_runs WHERE run_id = %s",
            (run_id,),
        ).fetchone()

        if run_exists is None:
            raise HTTPException(
                status_code=404,
                detail="run_id was not found in ad_validation_runs",
            )

        normalized = normalize_wazuh_event(request.event)
        fields = normalized.get("fields") or {}

        cursor = connection.execute(
            """
            INSERT INTO ad_evidence (
                run_id,
                evidence_type,
                original_filename,
                event_fingerprint,
                agent_name,
                channel,
                event_id,
                event_timestamp,
                wazuh_rule_id,
                payload_json,
                imported_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            RETURNING evidence_id
            """,
            (
                run_id,
                request.evidence_type
                or normalized.get("event_type")
                or "event",
                request.original_filename,
                normalized.get("event_fingerprint"),
                normalized.get("agent_name"),
                fields.get("channel"),
                fields.get("event_id"),
                normalized.get("timestamp"),
                normalized.get("wazuh_rule_id"),
                json.dumps(request.event, ensure_ascii=False),
                _utc_now(),
            ),
        )

        evidence_id = int(cursor.fetchone()[0])
        connection.commit()

        return {
            "evidence_id": evidence_id,
            "run_id": run_id,
            "evidence_type": (
                request.evidence_type
                or normalized.get("event_type")
                or "event"
            ),
            "wazuh_rule_id": normalized.get("wazuh_rule_id"),
            "channel": fields.get("channel"),
            "event_id": fields.get("event_id"),
            "agent_name": normalized.get("agent_name"),
            "event_fingerprint": normalized.get(
                "event_fingerprint"
            ),
        }

    except HTTPException:
        connection.rollback()
        raise

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


@router.post("/runs/{run_id}/compare", dependencies=[Depends(require_write_access)])
def compare_within_run(
    run_id: str,
    request: RunCompareRequest,
) -> dict[str, Any]:
    connection = get_connection()

    try:
        run_exists = connection.execute(
            "SELECT 1 FROM ad_validation_runs WHERE run_id = %s",
            (run_id,),
        ).fetchone()

        if run_exists is None:
            raise HTTPException(
                status_code=404,
                detail="run_id was not found in ad_validation_runs",
            )
    finally:
        connection.close()

    # Reuse the existing, fully-tested static comparison flow,
    # binding the comparison to this run.
    return compare_rules(
        CompareRequest(
            wazuh_rule_id=request.wazuh_rule_id,
            detection_id=request.detection_id,
            run_id=run_id,
        )
    )


@router.get("/export.csv")
def export_comparisons_csv(run_id: str | None = None):
    import csv
    import io

    from fastapi.responses import Response

    connection = get_connection()

    try:
        where_clause = ""
        parameters: list[Any] = []

        if run_id:
            where_clause = "WHERE c.run_id = %s"
            parameters.append(run_id)

        rows = connection.execute(
            f"""
            SELECT
                c.comparison_id,
                c.run_id,
                t.behavior_name,
                t.technique_id,
                c.wazuh_rule_id,
                c.detection_id,
                d.title AS detection_title,
                c.total_score,
                c.static_verdict,
                c.wazuh_fired,
                c.sigma_matched,
                c.behavioral_verdict,
                c.tuning_notes,
                c.compared_at
            FROM ad_rule_comparisons AS c
            LEFT JOIN ad_validation_runs AS r
                ON r.run_id = c.run_id
            LEFT JOIN ad_attack_tests AS t
                ON t.test_id = r.test_id
            LEFT JOIN detections AS d
                ON d.detection_id = c.detection_id
            {where_clause}
            ORDER BY c.comparison_id DESC
            """,
            tuple(parameters),
        ).fetchall()

    finally:
        connection.close()

    buffer = io.StringIO()
    writer = csv.writer(buffer)

    writer.writerow(
        [
            "comparison_id",
            "run_id",
            "behavior_name",
            "technique_id",
            "wazuh_rule_id",
            "detection_id",
            "detection_title",
            "total_score",
            "static_verdict",
            "wazuh_fired",
            "sigma_matched",
            "behavioral_verdict",
            "tuning_notes",
            "compared_at",
        ]
    )

    for row in rows:
        record = dict(row)
        writer.writerow(
            [
                record.get("comparison_id"),
                record.get("run_id"),
                record.get("behavior_name"),
                record.get("technique_id"),
                record.get("wazuh_rule_id"),
                record.get("detection_id"),
                record.get("detection_title"),
                record.get("total_score"),
                record.get("static_verdict"),
                record.get("wazuh_fired"),
                record.get("sigma_matched"),
                record.get("behavioral_verdict"),
                record.get("tuning_notes"),
                record.get("compared_at"),
            ]
        )

    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                "attachment; "
                "filename=ad_validation_comparisons.csv"
            )
        },
    )
# =============================================================================
#  ABSEGA | AS-REP / Wazuh-gap comparison endpoint (additive - Step B/C)
#  Records a comparison for a behavior where NO Wazuh rule fired AND no Wazuh
#  catalog rule covers the event (a pure WAZUH_DETECTION_GAP). Reuses the
#  existing event normalizer, Sigma evaluator and _insert_comparison writer.
#  Touches no existing endpoint.
# =============================================================================


class WazuhGapCompareRequest(BaseModel):
    detection_id: int


@router.post("/runs/{run_id}/compare-wazuh-gap", dependencies=[Depends(require_write_access)])
def compare_within_run_wazuh_gap(
    run_id: str,
    request: WazuhGapCompareRequest,
) -> dict[str, Any]:
    from types import SimpleNamespace

    connection = get_connection()

    try:
        run_row = connection.execute(
            "SELECT run_id FROM ad_validation_runs WHERE run_id = %s",
            (run_id,),
        ).fetchone()

        if run_row is None:
            raise HTTPException(
                status_code=404,
                detail="run_id was not found in ad_validation_runs",
            )

        evidence_row = connection.execute(
            """
            SELECT payload_json
            FROM ad_evidence
            WHERE run_id = %s
            ORDER BY evidence_id DESC
            LIMIT 1
            """,
            (run_id,),
        ).fetchone()

        if evidence_row is None or not evidence_row["payload_json"]:
            raise HTTPException(
                status_code=422,
                detail="Run has no stored raw evidence to evaluate",
            )

        raw_event = json.loads(evidence_row["payload_json"])

        detection = connection.execute(
            """
            SELECT
                detection_id,
                title,
                raw_yaml,
                logsource,
                rule_logic,
                tags,
                falsepositives
            FROM detections
            WHERE detection_id = %s
            """,
            (request.detection_id,),
        ).fetchone()

        if detection is None:
            raise HTTPException(
                status_code=404,
                detail="Sigma detection was not found",
            )

        detection = dict(detection)

        if not detection.get("raw_yaml"):
            raise HTTPException(
                status_code=422,
                detail="Detection has no full Sigma YAML",
            )

        # Reuse the existing normalizer + evaluator on the real event.
        normalized_event = normalize_wazuh_event(raw_event)

        sigma_result = evaluate_sigma_rule_canonical(
            str(detection.get("raw_yaml") or ""),
            normalized_event["sigma_event"],
            logsource=detection.get("logsource"),
            rule_logic=detection.get("rule_logic"),
            tags=detection.get("tags"),
            falsepositives=detection.get("falsepositives"),
        )

        sigma_status = sigma_result.get("status")
        sigma_matched = sigma_result.get("matched")

        # No Wazuh rule fired and none exists in the catalog for this event.
        wazuh_fired = 0

        if sigma_status == EVALUATOR_UNSUPPORTED:
            sigma_matched_sql = None
            behavioral_verdict = "EVALUATOR_UNSUPPORTED"
            tuning = sigma_result.get(
                "reason",
                "The Sigma condition uses features the evaluator does not support.",
            )

        elif sigma_status == EVALUATOR_MATCH or sigma_matched is True:
            sigma_matched_sql = 1
            behavioral_verdict = "SIGMA_ONLY"
            tuning = (
                "SIGMA_ONLY / WAZUH_DETECTION_GAP. Real-event telemetry is present "
                "(telemetry_gap=false). No Wazuh rule fired on the event and no "
                "matching rule exists in the Wazuh catalog. Sigma detection "
                f"{request.detection_id} evaluated TRUE against the same real event."
            )

        elif sigma_status == EVALUATOR_NO_MATCH or sigma_matched is False:
            sigma_matched_sql = 0
            behavioral_verdict = "NO_DETECTION_IN_EITHER"
            tuning = (
                "NO_DETECTION_IN_EITHER. Telemetry present but neither Wazuh nor the "
                "candidate Sigma detection matched the real event."
            )

        else:
            sigma_matched_sql = None
            behavioral_verdict = "EVALUATOR_INVALID_RULE"
            tuning = (
                "The Sigma evaluator returned an unknown status: "
                f"{sigma_status!r}."
            )

        comparison = {
            "scores": {
                "logsource": 0,
                "event_id": 0,
                "field": 0,
                "value": 0,
                "dependency": 0,
                "mitre": 0,
                "total": 0,
            },
            "verdict": "NO_CONTENT_OVERLAP",
            "matched_fields": sigma_result.get("matched_fields", []) or [],
            "missing_fields": [],
        }

        insert_request = SimpleNamespace(
            run_id=run_id,
            wazuh_rule_id=None,
            detection_id=int(detection["detection_id"]),
        )

        comparison_id = _insert_comparison(
            connection,
            request=insert_request,
            comparison=comparison,
            wazuh_fired=wazuh_fired,
            sigma_matched=sigma_matched_sql,
            behavioral_verdict=behavioral_verdict,
            tuning_notes=tuning,
        )

        connection.commit()

        return {
            "comparison_id": comparison_id,
            "run_id": run_id,
            "wazuh_rule_id": None,
            "detection_id": int(detection["detection_id"]),
            "static_verdict": "NO_CONTENT_OVERLAP",
            "wazuh_fired": bool(wazuh_fired),
            "sigma_matched": (
                None if sigma_matched_sql is None else bool(sigma_matched_sql)
            ),
            "behavioral_verdict": behavioral_verdict,
            "tuning_notes": tuning,
        }

    except HTTPException:
        connection.rollback()
        raise

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

# =============================================================================
#  ABSEGA | RE-CHECK endpoints (additive)
#  Re-evaluate a run's STORED real event against the CURRENT Wazuh catalog and
#  the CURRENT platform Sigma detection, then rewrite that run's comparison.
#  Use after adding/tuning a Wazuh or Sigma rule to see if it now detects.
#  Reuses normalize_wazuh_event, evaluate_sigma_rule_canonical,
#  normalize_sigma_rule, _row_to_wazuh_rule, compare_rule_content,
#  _insert_comparison. Touches no existing endpoint.
# =============================================================================


def _wazuh_rule_targets_event_id(wazuh_row: Mapping[str, Any], event_id: Any) -> bool:
    """True only if the fired Wazuh rule's effective logic actually keys on this
    Event ID. Prevents a generic co-fire (e.g. 60107 keying on 577/4673 while the
    attack is 4769) from being scored as a real Wazuh detection."""
    import json as _json
    import re as _re
    if not event_id:
        return False
    eid = str(event_id)
    raw = ""
    try:
        raw = wazuh_row.get("effective_logic_json") or ""
        logic = _json.loads(raw)
        for cond in (logic.get("conditions", {}) or {}).get("fields", []) or []:
            field = str(cond.get("field") or "")
            if "eventID" in field or "event_id" in field or field.endswith(".event"):
                value = str(cond.get("value") or "")
                if _re.search(r"(^|\|)\^?" + _re.escape(eid) + r"\$?(\||$)", value):
                    return True
                if eid == value.strip():
                    return True
    except Exception:
        # Fallback: literal ^EID$ token anywhere in the raw effective logic.
        if _re.search(r"\^" + _re.escape(eid) + r"\$", raw):
            return True
    return False


def _recheck_single_run(connection, run_id: str) -> dict[str, Any]:
    from types import SimpleNamespace

    evidence_row = connection.execute(
        """
        SELECT payload_json FROM ad_evidence
        WHERE run_id = %s ORDER BY evidence_id DESC LIMIT 1
        """,
        (run_id,),
    ).fetchone()
    if evidence_row is None or not evidence_row["payload_json"]:
        return {"run_id": run_id, "status": "skipped", "reason": "no stored evidence"}

    det_row = connection.execute(
        """
        SELECT detection_id FROM ad_rule_comparisons
        WHERE run_id = %s AND detection_id IS NOT NULL
        ORDER BY comparison_id DESC LIMIT 1
        """,
        (run_id,),
    ).fetchone()
    if det_row is None:
        return {"run_id": run_id, "status": "skipped", "reason": "no candidate Sigma detection on record"}

    detection_id = int(det_row["detection_id"])
    raw_event = json.loads(evidence_row["payload_json"])

    detection = connection.execute(
        """
        SELECT detection_id, title, raw_yaml, logsource, rule_logic, tags, falsepositives
        FROM detections WHERE detection_id = %s
        """,
        (detection_id,),
    ).fetchone()
    if detection is None or not dict(detection).get("raw_yaml"):
        return {"run_id": run_id, "status": "skipped", "reason": "Sigma detection missing or has no YAML"}
    detection = dict(detection)

    normalized_event = normalize_wazuh_event(raw_event)
    wazuh_rule_id = normalized_event.get("wazuh_rule_id")

    sigma_result = evaluate_sigma_rule_canonical(
        str(detection.get("raw_yaml") or ""),
        normalized_event["sigma_event"],
        logsource=detection.get("logsource"),
        rule_logic=detection.get("rule_logic"),
        tags=detection.get("tags"),
        falsepositives=detection.get("falsepositives"),
    )
    sigma_status = sigma_result.get("status")
    sigma_matched = sigma_result.get("matched")

    if sigma_status == EVALUATOR_UNSUPPORTED:
        sigma_matched_sql = None
    elif sigma_matched is True:
        sigma_matched_sql = 1
    elif sigma_matched is False:
        sigma_matched_sql = 0
    else:
        sigma_matched_sql = None

    wazuh_row = None
    if wazuh_rule_id is not None:
        wazuh_row = connection.execute(
            "SELECT * FROM wazuh_rule_catalog WHERE wazuh_rule_id = %s",
            (wazuh_rule_id,),
        ).fetchone()

    # Fresh comparison: remove this run's old rows first (keeps one clean row).
    connection.execute("DELETE FROM ad_rule_comparisons WHERE run_id = %s", (run_id,))

    # Strict semantics: a Wazuh co-fire only counts as a real detection if the fired
    # rule actually keys on the attack's Event ID, OR the static content overlap is
    # materially high. This keeps PsExec (rule keys on 7045) and PowerShell (high score)
    # VERIFIED, while a generic co-fire (60107 keying on 577/4673, not 4769) stays
    # SIGMA_ONLY for Kerberoasting.
    VERIFY_MIN_STATIC = 0.40

    event_eid = None
    try:
        event_eid = str(
            (((raw_event.get("data") or {}).get("win") or {}).get("system") or {}).get("eventID") or ""
        ) or None
    except Exception:
        event_eid = None

    zero_comparison = {
        "scores": {"logsource": 0, "event_id": 0, "field": 0, "value": 0,
                   "dependency": 0, "mitre": 0, "total": 0},
        "verdict": "NO_CONTENT_OVERLAP",
        "matched_fields": sigma_result.get("matched_fields", []) or [],
        "missing_fields": [],
    }

    genuine = False
    static_total = 0.0
    comparison = zero_comparison
    cofire_note = ""

    if wazuh_row is not None:
        sigma_norm = normalize_sigma_rule(
            str(detection.get("raw_yaml") or ""),
            logsource=detection.get("logsource"),
            rule_logic=detection.get("rule_logic"),
            tags=detection.get("tags"),
            falsepositives=detection.get("falsepositives"),
        )
        sigma_norm["detection_id"] = detection_id
        full_comparison = dict(compare_rule_content(_row_to_wazuh_rule(dict(wazuh_row)), sigma_norm))
        try:
            static_total = float((full_comparison.get("scores") or {}).get("total") or 0.0)
        except Exception:
            static_total = 0.0
        keys_eid = _wazuh_rule_targets_event_id(dict(wazuh_row), event_eid)
        genuine = bool(keys_eid or static_total >= VERIFY_MIN_STATIC)
        if genuine:
            comparison = full_comparison
        else:
            cofire_note = (
                f" Generic co-fire: Wazuh rule {int(wazuh_rule_id)} did not key on "
                f"EventID {event_eid} and static overlap {round(static_total, 3)} < "
                f"{VERIFY_MIN_STATIC}; not counted as a Wazuh detection."
            )

    if genuine:
        wazuh_fired = 1
        wid = int(wazuh_rule_id)
        if sigma_status == EVALUATOR_UNSUPPORTED:
            verdict = "EVALUATOR_UNSUPPORTED"
        elif sigma_matched is True:
            verdict = "VERIFIED_OVERLAP"
        else:
            verdict = "WAZUH_ONLY"
    else:
        wazuh_fired = 0
        wid = None
        if sigma_status == EVALUATOR_UNSUPPORTED:
            verdict = "EVALUATOR_UNSUPPORTED"
        elif sigma_matched is True:
            verdict = "SIGMA_ONLY"
        else:
            verdict = "NO_DETECTION_IN_EITHER"

    tuning = (
        f"Re-checked {_utc_now()} against current Wazuh catalog and Sigma detection "
        f"{detection_id}. wazuh_fired={bool(wazuh_fired)}, sigma_matched={sigma_matched}."
        + cofire_note
    )

    ins = SimpleNamespace(run_id=run_id, wazuh_rule_id=wid, detection_id=detection_id)
    comparison_id = _insert_comparison(
        connection, request=ins, comparison=comparison,
        wazuh_fired=wazuh_fired, sigma_matched=sigma_matched_sql,
        behavioral_verdict=verdict, tuning_notes=tuning,
    )
    return {
        "run_id": run_id, "status": "rechecked", "comparison_id": comparison_id,
        "detection_id": detection_id, "wazuh_rule_id": wid,
        "wazuh_fired": bool(wazuh_fired),
        "sigma_matched": (None if sigma_matched_sql is None else bool(sigma_matched_sql)),
        "behavioral_verdict": verdict,
    }


@router.post("/runs/{run_id}/recheck", dependencies=[Depends(require_write_access)])
def recheck_run(run_id: str) -> dict[str, Any]:
    connection = get_connection()
    try:
        exists = connection.execute(
            "SELECT 1 FROM ad_validation_runs WHERE run_id = %s", (run_id,)
        ).fetchone()
        if exists is None:
            raise HTTPException(status_code=404, detail="run_id was not found")
        result = _recheck_single_run(connection, run_id)
        connection.commit()
        return result
    except HTTPException:
        connection.rollback(); raise
    except Exception:
        connection.rollback(); raise
    finally:
        connection.close()


@router.post("/recheck-all", dependencies=[Depends(require_write_access)])
def recheck_all() -> dict[str, Any]:
    connection = get_connection()
    try:
        run_ids = [r["run_id"] for r in connection.execute(
            "SELECT run_id FROM ad_validation_runs ORDER BY run_id"
        ).fetchall()]
        results = []
        for rid in run_ids:
            try:
                results.append(_recheck_single_run(connection, rid))
            except Exception as exc:  # keep going; report per-run
                results.append({"run_id": rid, "status": "error", "reason": str(exc)})
        connection.commit()
        rechecked = sum(1 for r in results if r.get("status") == "rechecked")
        return {"total_runs": len(run_ids), "rechecked": rechecked, "results": results}
    except Exception:
        connection.rollback(); raise
    finally:
        connection.close()


# =============================================================================
#  ABSEGA | Wazuh <-> Sigma similarity summary (additive, read-only)
#  Plain-language rule comparison: exact event/rule numbers, what matched vs
#  differed, WHY each behaviour is verified / wazuh-only / sigma-only, and an
#  overall content-overlap figure between the two rulesets.
# =============================================================================


def _sim_band(score: float) -> str:
    if score >= 0.80:
        return "match"
    if score >= 0.30:
        return "partial"
    return "none"


def _sim_overall_band(pct: float) -> str:
    if pct >= 80:
        return "STRONG"
    if pct >= 60:
        return "LIKELY"
    if pct >= 40:
        return "PARTIAL"
    return "LOW"


def _sim_word(pct: float) -> str:
    if pct >= 80:
        return "Strong"
    if pct >= 60:
        return "Good"
    if pct >= 30:
        return "Partial"
    return "Weak"


def _sim_explanation(rel, event_id, w_rule, s_det, s_title, mitre_ok,
                     expected_tech, sigma_techs, agree, differ):
    ev = ("Windows " + str(event_id)) if event_id else "the real event"
    w = ("Wazuh rule " + str(w_rule)) if w_rule else "Wazuh"
    s = ("Sigma rule " + str(s_det)) if s_det else "the Sigma candidate"
    sigma_tech_str = ", ".join(sigma_techs) if sigma_techs else "no ATT&CK tag"
    if rel == "VERIFIED_OVERLAP":
        return (f"Both sides detected the same real {ev} event. {w} and {s} agree "
                f"on this behaviour \u2014 keep both.")
    if rel == "WAZUH_ONLY":
        if mitre_ok is False:
            base = (f"{w} detected this {ev} event. The candidate {s} is built for "
                    f"{sigma_tech_str} \u2014 a different technique than {expected_tech} "
                    f"\u2014 so it did not match.")
            if "Event ID" in agree:
                base += (" They only share the event type; the specific field values "
                         "this Sigma rule looks for are not present in a spray/"
                         "this event.")
            base += f" No suitable Sigma rule exists for {expected_tech} \u2014 create one."
            return base
        return (f"{w} detected this {ev} event, but the compatible {s} did not match "
                f"it (its field conditions expect different values). Tune the Sigma rule.")
    if rel == "SIGMA_ONLY":
        return (f"{s} matched the real {ev} event, but Wazuh has no genuine rule that "
                f"detects it \u2014 create/deploy a Wazuh rule.")
    if rel == "NO_DETECTION_IN_EITHER":
        return f"Neither Wazuh nor a suitable Sigma rule detected this {ev} event."
    return f"Comparison recorded for {ev}."


@router.get("/similarity-summary")
def similarity_summary() -> dict[str, Any]:
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT
                t.behavior_name, t.technique_id,
                c.wazuh_rule_id, c.detection_id,
                d.title AS sigma_title, d.tags AS sigma_tags,
                c.logsource_score, c.event_id_score, c.field_score,
                c.value_score, c.mitre_score, c.dependency_score,
                c.total_score, c.behavioral_verdict, c.wazuh_fired,
                c.sigma_matched, c.run_id, c.comparison_id
            FROM ad_rule_comparisons c
            LEFT JOIN ad_validation_runs r ON r.run_id = c.run_id
            LEFT JOIN ad_attack_tests    t ON t.test_id = r.test_id
            LEFT JOIN detections         d ON d.detection_id = c.detection_id
            WHERE c.run_id IS NOT NULL
              AND (r.status IS NULL OR r.status != 'superseded')
            ORDER BY c.comparison_id DESC
            """
        ).fetchall()

        comp_keys = [
            ("Log source", "logsource_score"),
            ("Event ID", "event_id_score"),
            ("Fields", "field_score"),
            ("Values", "value_score"),
            ("MITRE", "mitre_score"),
            ("Dependency", "dependency_score"),
        ]

        seen_runs: set[str] = set()
        behaviors: list[dict[str, Any]] = []
        for row in rows:
            r = dict(row)
            run_id = r.get("run_id")
            if run_id in seen_runs:
                continue
            seen_runs.add(run_id)

            ev_row = connection.execute(
                "SELECT event_id, channel FROM ad_evidence WHERE run_id = %s "
                "ORDER BY evidence_id DESC LIMIT 1",
                (run_id,),
            ).fetchone()
            event_id = ev_row["event_id"] if ev_row else None
            channel = ev_row["channel"] if ev_row else None

            components = {}
            agree, differ = [], []
            for label, col in comp_keys:
                score = float(r.get(col) or 0.0)
                band = _sim_band(score)
                components[label] = {"score": round(score, 4),
                                     "pct": round(score * 100), "band": band}
                if band == "match":
                    agree.append(label)
                elif band == "none":
                    differ.append(label)

            similarity_pct = round(float(r.get("total_score") or 0.0) * 100)
            sigma_techs = _ad_extract_techniques(r.get("sigma_tags"))
            mitre_ok = _ad_mitre_compatible(r.get("technique_id") or "", sigma_techs)
            rel = r.get("behavioral_verdict")

            behaviors.append({
                "behavior": r.get("behavior_name"),
                "technique": r.get("technique_id"),
                "event_id": event_id,
                "channel": channel,
                "wazuh_rule_id": r.get("wazuh_rule_id"),
                "detection_id": r.get("detection_id"),
                "sigma_title": r.get("sigma_title"),
                "sigma_techniques": sigma_techs,
                "mitre_compatible": mitre_ok,
                "wazuh_detected": bool(r.get("wazuh_fired")) if r.get("wazuh_fired") is not None else False,
                "sigma_detected": (None if r.get("sigma_matched") is None else bool(r.get("sigma_matched"))),
                "components": components,
                "agree_dimensions": agree,
                "differ_dimensions": differ,
                "similarity_pct": similarity_pct,
                "similarity_word": _sim_word(similarity_pct),
                "band": _sim_overall_band(similarity_pct),
                "relation": rel,
                "explanation": _sim_explanation(
                    rel, event_id, r.get("wazuh_rule_id"), r.get("detection_id"),
                    r.get("sigma_title"), mitre_ok, r.get("technique_id") or "?",
                    sigma_techs, agree, differ),
            })

        n = len(behaviors) or 1
        component_averages = {}
        for label, _ in comp_keys:
            component_averages[label] = round(
                sum(b["components"][label]["pct"] for b in behaviors) / n)
        avg_similarity = round(sum(b["similarity_pct"] for b in behaviors) / n)

        relation_counts: dict[str, int] = {}
        for b in behaviors:
            rel = b["relation"] or "unknown"
            relation_counts[rel] = relation_counts.get(rel, 0) + 1

        return {
            "behaviors": behaviors,
            "aggregate": {
                "behaviors_count": len(behaviors),
                "avg_similarity_pct": avg_similarity,
                "avg_similarity_word": _sim_word(avg_similarity),
                "overall_band": _sim_overall_band(avg_similarity),
                "component_averages": component_averages,
                "relation_counts": relation_counts,
                "wazuh_rules_total": connection.execute(
                    "SELECT COUNT(*) FROM wazuh_rule_catalog").fetchone()[0],
                "sigma_rules_total": connection.execute(
                    "SELECT COUNT(*) FROM detections").fetchone()[0],
            },
        }
    finally:
        connection.close()


# =============================================================================
#  ABSEGA | Detection Health + Priority Actions (additive, read-only)
#  Turns validation results into (a) a 0-100 Detection Health Score and
#  (b) a prioritised, action-driven recommendation list ("what to fix next").
# =============================================================================


_HEALTH_POINTS = {
    "VERIFIED_OVERLAP": 100,
    "WAZUH_ONLY": 65,
    "SIGMA_ONLY": 65,
    "MAPPING_ONLY": 40,
    "EVALUATOR_UNSUPPORTED": 50,
    "NO_DETECTION_IN_EITHER": 10,
    "INCOMPLETE_NO_EVIDENCE": 25,
}


def _health_band(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 60:
        return "Fair"
    if score >= 40:
        return "Needs work"
    return "Poor"


@router.get("/action-summary")
def action_summary() -> dict[str, Any]:
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT t.behavior_name, t.technique_id,
                   c.wazuh_rule_id, c.detection_id, d.tags AS sigma_tags,
                   c.wazuh_fired, c.sigma_matched, c.behavioral_verdict,
                   c.total_score, c.run_id, c.comparison_id
            FROM ad_rule_comparisons c
            LEFT JOIN ad_validation_runs r ON r.run_id = c.run_id
            LEFT JOIN ad_attack_tests    t ON t.test_id = r.test_id
            LEFT JOIN detections         d ON d.detection_id = c.detection_id
            WHERE c.run_id IS NOT NULL
              AND (r.status IS NULL OR r.status != 'superseded')
            ORDER BY c.comparison_id DESC
            """
        ).fetchall()

        seen: set[str] = set()
        behaviors: list[dict[str, Any]] = []
        for row in rows:
            r = dict(row)
            if r["run_id"] in seen:
                continue
            seen.add(r["run_id"])
            behaviors.append(r)

        total = len(behaviors) or 1

        # ---- Detection Health Score ----
        points = 0
        detected_either = 0
        verified = 0
        for b in behaviors:
            verdict = b.get("behavioral_verdict") or "NO_DETECTION_IN_EITHER"
            points += _HEALTH_POINTS.get(verdict, 30)
            if verdict == "VERIFIED_OVERLAP":
                verified += 1
            if b.get("wazuh_fired") or b.get("sigma_matched"):
                detected_either += 1
        health_score = round(points / total)

        coverage_pct = round(detected_either / total * 100)
        verified_pct = round(verified / total * 100)

        # ---- Priority actions ----
        high: list[dict[str, Any]] = []
        medium: list[dict[str, Any]] = []
        low: list[dict[str, Any]] = []

        for b in behaviors:
            verdict = b.get("behavioral_verdict")
            name = b.get("behavior_name")
            tech = b.get("technique_id")
            sim = round(float(b.get("total_score") or 0.0) * 100)
            base = {"behavior": name, "technique": tech, "verdict": verdict,
                    "wazuh_rule_id": b.get("wazuh_rule_id"),
                    "detection_id": b.get("detection_id")}

            if verdict == "NO_DETECTION_IN_EITHER":
                high.append({**base, "action": f"Create a detection for {name}",
                             "reason": "Neither Wazuh nor Sigma detects this attack.",
                             "category": "missing", "effort": "30 min"})
            elif verdict == "INCOMPLETE_NO_EVIDENCE":
                high.append({**base, "action": f"Fix telemetry / re-run {name}",
                             "reason": "No real event was captured for this run.",
                             "category": "telemetry", "effort": "20 min"})
            elif verdict == "SIGMA_ONLY":
                medium.append({**base, "action": f"Create a Wazuh rule for {name}",
                               "reason": "Sigma detects it but Wazuh is blind.",
                               "category": "sigma_only", "effort": "20 min"})
            elif verdict == "WAZUH_ONLY":
                medium.append({**base, "action": f"Create a Sigma detection for {name}",
                               "reason": "Wazuh detects it but the platform has no matching rule.",
                               "category": "wazuh_only", "effort": "20 min"})
            elif verdict == "EVALUATOR_UNSUPPORTED":
                medium.append({**base, "action": f"Tune the Sigma rule for {name}",
                               "reason": "The candidate rule uses conditions we cannot evaluate.",
                               "category": "tune", "effort": "15 min"})
            elif verdict == "MAPPING_ONLY":
                medium.append({**base, "action": f"Review MITRE mapping for {name}",
                               "reason": "Only a technique-tag overlap; not behavioural coverage.",
                               "category": "review", "effort": "10 min"})
            elif verdict == "VERIFIED_OVERLAP":
                if sim < 30:
                    low.append({**base, "action": f"Review weak overlap for {name}",
                                "reason": f"Both detect it, but rule content overlap is low ({sim}%).",
                                "category": "review", "effort": "5 min"})
                else:
                    low.append({**base, "action": f"Keep {name}",
                                "reason": "Validated by both Wazuh and Sigma.",
                                "category": "keep", "effort": "\u2014"})

        return {
            "health": {
                "score": health_score,
                "band": _health_band(health_score),
                "components": {
                    "coverage_pct": coverage_pct,
                    "verified_pct": verified_pct,
                    "behaviors": len(behaviors),
                    "verified": verified,
                    "detected_either": detected_either,
                },
            },
            "priorities": {"high": high, "medium": medium, "low": low},
            "counts": {"high": len(high), "medium": len(medium), "low": len(low)},
        }
    finally:
        connection.close()
