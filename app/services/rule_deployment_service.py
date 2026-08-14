"""Safe deployment of an approved Wazuh rule to the Wazuh Manager.

Deployment is a human action. This module is only ever reached from an
explicitly confirmed request made by an authorised Detection Engineer or
Administrator — Gemini has no path to it, and approval alone never triggers it.

The sequence, in order, with rollback on any failure:

1. read the current ``absega_ai_rules.xml`` from the manager and keep it as a
   timestamped backup;
2. stage the merged file (existing AI rules + the new rule);
3. ask the manager to validate its configuration;
4. run the captured positive event through ``wazuh-logtest``;
5. restart the manager and check its daemons;
6. restore the backup and restart again if anything above fails.

Default Wazuh rule files are never touched: all AI content lives in one
dedicated custom file.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.config import deployment_settings, scrub_secrets
from app.services.rule_validation_service import (
    RULE_ID_PLACEHOLDER,
    parse_wazuh_xml,
)

logger = logging.getLogger(__name__)

_HEADER = (
    "<!--\n"
    "  ABSEGA Detection Engineering Platform — AI-drafted Wazuh rules.\n"
    "  Managed by the AI Detection Rule Recommendation workflow.\n"
    "  Every rule here was reviewed and approved by a Detection Engineer before\n"
    "  deployment. Edit through the platform so the audit trail stays accurate.\n"
    "-->\n"
)


class DeploymentError(Exception):
    """Deployment failed. The message is always safe to show the engineer."""


@dataclass
class DeploymentResult:
    success: bool
    stage: str
    message: str
    target_file: str = ""
    manager: str = ""
    rule_ids: list[int] = field(default_factory=list)
    backup_name: str = ""
    backup_taken: bool = False
    rolled_back: bool = False
    restarted: bool = False
    validation: dict[str, Any] = field(default_factory=dict)
    logtest: dict[str, Any] = field(default_factory=dict)
    health: dict[str, Any] = field(default_factory=dict)
    steps: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "stage": self.stage,
            "message": self.message,
            "target_file": self.target_file,
            "manager": self.manager,
            "rule_ids": self.rule_ids,
            "backup_name": self.backup_name,
            "backup_taken": self.backup_taken,
            "rolled_back": self.rolled_back,
            "restarted": self.restarted,
            "validation": self.validation,
            "logtest": self.logtest,
            "health": self.health,
            "steps": self.steps,
        }


# ── File assembly ────────────────────────────────────────────────────────────

def _rule_ids_in(xml_text: str) -> list[int]:
    return [int(m) for m in re.findall(r'<rule\s+id="(\d+)"', xml_text or "")]


def merge_rule_file(existing: str | None, new_group_xml: str) -> tuple[str, list[int]]:
    """Append *new_group_xml* to the managed AI rules file.

    Rules whose IDs already appear in the file are replaced rather than
    duplicated, so redeploying a revised version of the same rule is safe.
    """
    group, problems = parse_wazuh_xml(new_group_xml)
    if group is None:
        raise DeploymentError("Cannot deploy: " + "; ".join(problems))

    new_ids = _rule_ids_in(new_group_xml)
    if not new_ids:
        raise DeploymentError(
            "Cannot deploy: the rule XML has no numeric rule ID "
            f"(the {RULE_ID_PLACEHOLDER} placeholder was never replaced)."
        )

    body = (existing or "").strip()
    if not body:
        return _HEADER + new_group_xml.strip() + "\n", new_ids

    # Drop any <group> block that only contains rules we are re-deploying.
    kept_blocks: list[str] = []
    for block in re.findall(r"<group\b.*?</group>", body, re.DOTALL | re.IGNORECASE):
        block_ids = set(_rule_ids_in(block))
        if block_ids and block_ids.issubset(set(new_ids)):
            continue
        kept_blocks.append(block.strip())

    kept_blocks.append(new_group_xml.strip())
    return _HEADER + "\n\n".join(kept_blocks) + "\n", new_ids


def deployment_preview(rule_xml: str) -> dict[str, Any]:
    """What the confirmation dialog shows before anything is written."""
    settings = deployment_settings()
    group, problems = parse_wazuh_xml(rule_xml or "")
    rules: list[dict[str, Any]] = []
    if group is not None:
        for element in group.findall("rule"):
            rules.append({
                "rule_id": element.get("id"),
                "level": element.get("level"),
                "title": (element.findtext("description") or "").strip(),
            })
    manager = ""
    try:
        from app.wazuh_client import _config
        manager = _config()["url"]
    except Exception:
        manager = "(WAZUH_URL is not configured)"
    return {
        "manager": manager,
        "target_file": settings.manager_path,
        "rules": rules,
        "problems": problems,
        "restart_required": settings.restart_manager,
        "warning": (
            "Deploying writes the managed AI rules file on the Wazuh Manager and "
            + ("restarts wazuh-manager, which briefly interrupts alert processing."
               if settings.restart_manager else
               "reloads the manager configuration.")
        ),
    }


# ── Deployment ───────────────────────────────────────────────────────────────

def deploy_rule(*, rule_xml: str, positive_event: str = "",
                surface: str = "", actor: str = "") -> DeploymentResult:
    """Deploy one approved Wazuh rule, rolling back on any failure."""
    settings = deployment_settings()
    filename = settings.rules_filename
    result = DeploymentResult(
        success=False, stage="starting", message="",
        target_file=settings.manager_path,
    )

    def step(name: str, ok: bool, detail: str = "") -> None:
        result.steps.append({"step": name, "ok": ok, "detail": scrub_secrets(detail)})

    try:
        from app.wazuh_client import (
            WazuhError,
            delete_rule_file,
            logtest,
            manager_info,
            manager_status,
            read_rule_file,
            restart_manager,
            validate_configuration,
            write_rule_file,
        )
    except Exception as exc:  # pragma: no cover
        raise DeploymentError(
            f"Wazuh client unavailable: {scrub_secrets(str(exc))}") from exc

    # 0) Reachability — never start writing to a manager we cannot talk to.
    result.stage = "connect"
    try:
        info = manager_info()
        result.manager = info.get("url", "")
        step("connect", True, f"Wazuh API {info.get('api_version') or ''}".strip())
    except Exception as exc:
        raise DeploymentError(
            "Cannot reach the Wazuh Manager API — deployment aborted before any "
            f"change was made. {scrub_secrets(str(exc))}"
        ) from exc

    # 1) Backup.
    result.stage = "backup"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    result.backup_name = f"{filename.rsplit('.', 1)[0]}.backup_{timestamp}.xml"
    try:
        existing = read_rule_file(filename)
        result.backup_taken = True
        step("backup", True,
             f"captured {len(existing or '')} bytes of the existing managed file"
             if existing else "no existing managed file (first deployment)")
    except Exception as exc:
        raise DeploymentError(
            f"Could not read the existing rules file for backup: {scrub_secrets(str(exc))}"
        ) from exc

    had_existing = bool((existing or "").strip())

    def rollback(reason: str) -> None:
        result.rolled_back = True
        try:
            if had_existing:
                write_rule_file(filename, existing or "")
                step("rollback", True, "restored the previous managed rules file")
            else:
                delete_rule_file(filename)
                step("rollback", True, "removed the managed rules file created by this deployment")
            if settings.restart_manager and result.restarted:
                restart_manager()
                step("rollback_restart", True, "restarted the manager on the restored configuration")
        except Exception as exc:
            step("rollback", False, str(exc))
            logger.error("rollback after deployment failure also failed: %s",
                         scrub_secrets(str(exc)))
        result.message = scrub_secrets(reason)

    # 2) Stage.
    result.stage = "stage"
    try:
        merged, rule_ids = merge_rule_file(existing, rule_xml)
        result.rule_ids = rule_ids
        write_rule_file(filename, merged)
        step("stage", True, f"wrote {len(merged)} bytes containing rule(s) "
                            + ", ".join(str(i) for i in rule_ids))
    except DeploymentError:
        raise
    except Exception as exc:
        raise DeploymentError(
            f"Could not write the rules file to the manager: {scrub_secrets(str(exc))}"
        ) from exc

    # 3) Configuration validation — never restart onto an invalid config.
    result.stage = "validate"
    try:
        validation = validate_configuration()
        result.validation = {"valid": validation["valid"], "errors": validation["errors"]}
        if not validation["valid"]:
            step("validate", False, "; ".join(validation["errors"]) or "validation failed")
            rollback(
                "Wazuh rejected the configuration with the new rule: "
                + ("; ".join(validation["errors"]) or "no detail returned") +
                ". The previous rules file was restored and the manager was not "
                "restarted."
            )
            result.stage = "validate"
            return result
        step("validate", True, "manager configuration is valid")
    except Exception as exc:
        rollback(f"Configuration validation could not run: {scrub_secrets(str(exc))}")
        result.stage = "validate"
        return result

    # 4) Restart so the new rule is actually loaded.
    if settings.restart_manager:
        result.stage = "restart"
        try:
            restart_manager()
            result.restarted = True
            step("restart", True, "manager restart requested")
        except Exception as exc:
            rollback(f"Manager restart failed: {scrub_secrets(str(exc))}")
            result.stage = "restart"
            return result

        # 5) Health check.
        result.stage = "health"
        try:
            health = manager_status()
            result.health = health
            if not health.get("healthy", False):
                step("health", False, "unhealthy daemons: " + ", ".join(health.get("unhealthy", [])))
                rollback(
                    "The Wazuh manager came back unhealthy after the restart "
                    f"({', '.join(health.get('unhealthy', []))}). The previous "
                    "rules file was restored."
                )
                result.stage = "health"
                return result
            step("health", True, "all critical daemons are running")
        except Exception as exc:
            rollback(f"Post-restart health check failed: {scrub_secrets(str(exc))}")
            result.stage = "health"
            return result

    # 6) Post-deployment logtest against the real captured event.
    result.stage = "logtest"
    if positive_event:
        try:
            from app.services.rule_validation_service import logtest_format
            outcome = logtest(positive_event, log_format=logtest_format(surface),
                              location=f"absega-ai-{surface or 'deploy'}")
            fired = str(outcome.get("rule_id") or "")
            matched = fired in {str(i) for i in result.rule_ids}
            result.logtest = {
                "executed": True,
                "fired_rule_id": outcome.get("rule_id"),
                "matched_deployed_rule": matched,
                "description": outcome.get("description"),
                "level": outcome.get("level"),
            }
            step("logtest", True,
                 f"rule {fired or 'none'} fired on the captured event"
                 + ("" if matched else " (not the deployed rule)"))
        except Exception as exc:
            result.logtest = {"executed": False,
                              "reason": scrub_secrets(str(exc))}
            step("logtest", False, str(exc))
    else:
        result.logtest = {
            "executed": False,
            "reason": "No captured event is stored for this attack, so the "
                      "post-deployment log test did not run.",
        }
        step("logtest", False, result.logtest["reason"])

    result.success = True
    result.stage = "deployed"
    result.message = (
        f"Rule(s) {', '.join(str(i) for i in result.rule_ids)} deployed to "
        f"{settings.manager_path}"
        + (" and the manager was restarted." if result.restarted else ".")
        + " Re-run the original attack to confirm the gap is actually closed."
    )
    return result


def rollback_deployment(*, rule_ids: list[int], actor: str = "") -> DeploymentResult:
    """Remove previously deployed AI rules from the managed file."""
    settings = deployment_settings()
    filename = settings.rules_filename
    result = DeploymentResult(
        success=False, stage="starting", message="",
        target_file=settings.manager_path, rule_ids=list(rule_ids),
    )

    def step(name: str, ok: bool, detail: str = "") -> None:
        result.steps.append({"step": name, "ok": ok, "detail": scrub_secrets(detail)})

    from app.wazuh_client import (
        delete_rule_file,
        manager_status,
        read_rule_file,
        restart_manager,
        validate_configuration,
        write_rule_file,
    )

    result.stage = "read"
    try:
        existing = read_rule_file(filename)
    except Exception as exc:
        raise DeploymentError(
            f"Could not read the managed rules file: {scrub_secrets(str(exc))}") from exc
    if not (existing or "").strip():
        result.success = True
        result.stage = "rolled_back"
        result.message = "The managed AI rules file is already empty — nothing to roll back."
        return result

    targets = {int(i) for i in rule_ids}
    kept = [
        block.strip()
        for block in re.findall(r"<group\b.*?</group>", existing, re.DOTALL | re.IGNORECASE)
        if not (set(_rule_ids_in(block)) and set(_rule_ids_in(block)).issubset(targets))
    ]

    result.stage = "write"
    try:
        if kept:
            write_rule_file(filename, _HEADER + "\n\n".join(kept) + "\n")
            step("write", True, f"{len(kept)} group block(s) retained")
        else:
            delete_rule_file(filename)
            step("write", True, "managed rules file removed (no AI rules remain)")
    except Exception as exc:
        raise DeploymentError(
            f"Could not write the rolled-back rules file: {scrub_secrets(str(exc))}") from exc

    result.stage = "validate"
    validation = validate_configuration()
    result.validation = {"valid": validation["valid"], "errors": validation["errors"]}
    if not validation["valid"]:
        write_rule_file(filename, existing)
        raise DeploymentError(
            "Rolling back produced an invalid configuration; the previous file "
            "was restored. " + "; ".join(validation["errors"])
        )
    step("validate", True, "manager configuration is valid")

    if settings.restart_manager:
        result.stage = "restart"
        restart_manager()
        result.restarted = True
        result.health = manager_status()
        step("restart", True, "manager restarted on the rolled-back configuration")

    result.success = True
    result.rolled_back = True
    result.stage = "rolled_back"
    result.message = (
        "Rule(s) " + ", ".join(str(i) for i in rule_ids) +
        f" removed from {settings.manager_path}."
    )
    return result


def rule_ids_from_xml(xml_text: str) -> list[int]:
    """Public helper — numeric rule IDs present in a draft."""
    return _rule_ids_in(xml_text)


def rule_titles_from_xml(xml_text: str) -> list[str]:
    group, _ = parse_wazuh_xml(xml_text or "")
    if group is None:
        return []
    return [(e.findtext("description") or "").strip() for e in group.findall("rule")]
