"""
Sigma rule evaluator backed by pySigma.

Public API (unchanged):
    evaluate_sigma_rule(raw_yaml, sample_event) -> dict
    class SigmaEvaluationError

The evaluator parses a Sigma rule with pySigma (so every modifier, wildcard
and condition is interpreted exactly as the Sigma spec defines), then walks
the parsed condition AST against the sample event and returns a verdict.
"""
from __future__ import annotations

import ipaddress
import json
import re
from functools import lru_cache
from typing import Any

import yaml

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.exceptions import SigmaError
from sigma.types import (
    SigmaBool,
    SigmaCIDRExpression,
    SigmaCasedString,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
)


class SigmaEvaluationError(Exception):
    pass


# Common SIEM field aliases. pySigma usually relies on processing pipelines
# for this; we apply a lightweight version here so rules written against
# raw Sysmon fields still match ECS/winlog samples (and vice-versa).
FIELD_ALIASES: dict[str, list[str]] = {
    "commandline": [
        "CommandLine", "ProcessCommandLine", "Process_Command_Line",
        "process.command_line", "cmdline", "cmd",
    ],
    "image": [
        "Image", "NewProcessName", "process.executable", "process.path",
        "ProcessPath",
    ],
    "originalfilename": ["OriginalFileName", "process.pe.original_file_name"],
    "parentimage": [
        "ParentImage", "ParentProcessName", "process.parent.executable",
    ],
    "eventid": ["EventID", "EventId", "event.code", "event_id"],
    "provider_name": [
        "Provider_Name", "ProviderName", "provider_name",
        "winlog.provider_name",
    ],
    "targetimage": [
        "TargetImage", "TargetProcessName", "process.target.executable",
    ],
    "sourceimage": [
        "SourceImage", "SourceProcessName", "process.source.executable",
    ],
    "targetobject": [
        "TargetObject", "registry.path", "winlog.event_data.TargetObject",
    ],
    "details": [
        "Details", "registry.data.strings", "winlog.event_data.Details",
    ],
    "scriptblocktext": [
        "ScriptBlockText", "script_block_text",
        "powershell.file.script_block_text",
    ],
    "data": ["Data", "Message", "message", "__raw__"],
    "eventtype": ["eventType", "event.type", "event_type"],
    "user": ["User", "TargetUserName", "SubjectUserName", "user.name"],
}


# ── Public entry point ───────────────────────────────────────────────────────

@lru_cache(maxsize=4096)
def _parse_rule_cached(raw_yaml: str):
    """Parse + condition-resolve a rule once, then reuse for every sample run."""
    try:
        collection = SigmaCollection.from_yaml(raw_yaml)
    except (SigmaError, yaml.YAMLError) as exc:
        raise SigmaEvaluationError(f"Invalid Sigma YAML: {exc}") from exc
    if not collection.rules:
        raise SigmaEvaluationError("Sigma YAML contains no rules")
    rule = collection.rules[0]
    if not rule.detection or not rule.detection.detections:
        raise SigmaEvaluationError("Sigma rule has no detection block")
    if not rule.detection.parsed_condition:
        raise SigmaEvaluationError("Sigma rule has no condition")
    try:
        tree = rule.detection.parsed_condition[0].parse()
    except SigmaError as exc:
        raise SigmaEvaluationError(f"Could not parse condition: {exc}") from exc
    return rule, tree


def evaluate_sigma_rule(raw_yaml: str, sample_event: str) -> dict:
    if not raw_yaml:
        raise SigmaEvaluationError("Detection rule has no Sigma YAML")

    rule, tree = _parse_rule_cached(raw_yaml)

    event = _parse_event(sample_event or "")
    ctx = _EvalContext(event=event)

    matched = _eval_node(tree, ctx)

    # Re-evaluate each named selection on its own so the UI can show which
    # buckets fired and why.
    selection_results: dict[str, bool] = {}
    selection_details: dict[str, dict] = {}
    for name, detection in rule.detection.detections.items():
        sub_ctx = _EvalContext(event=event)
        matched_sel = _eval_detection(detection, sub_ctx)
        selection_results[name] = matched_sel
        selection_details[name] = {
            "matched": matched_sel,
            "reasons": sub_ctx.last_reasons[:8],
        }

    failure_reasons = _failure_reasons(selection_details, ctx)
    condition_str = " | ".join(rule.detection.condition) if rule.detection.condition else ""

    return {
        "matched": bool(matched),
        "condition": condition_str,
        "matched_selections": [n for n, v in selection_results.items() if v],
        "unmatched_selections": [n for n, v in selection_results.items() if not v],
        "selection_details": selection_details,
        "failure_reasons": failure_reasons[:8],
        "event_fields": sorted(k for k in event if not k.startswith("__"))[:80],
        "engine": "pysigma",
    }


# ── Event parser ─────────────────────────────────────────────────────────────

def _parse_event(sample: str) -> dict:
    """Turn a free-form sample (JSON, key=value, or raw text) into a flat dict."""
    sample = sample.strip()
    parsed: Any = None
    if sample.startswith(("{", "[")):
        try:
            parsed = json.loads(sample)
        except json.JSONDecodeError:
            parsed = None

    flat: dict[str, Any] = {"__raw__": sample}
    if isinstance(parsed, dict):
        _flatten_json(parsed, flat)
    elif isinstance(parsed, list):
        flat["__json__"] = parsed

    # key=value / key="value" / key='value' tokens (Sysmon-ish text logs)
    pattern = r'([A-Za-z0-9_.:-]+)=((?:"(?:\\.|[^"])*")|(?:\'[^\']*\')|[^\s]+)'
    for key, value in re.findall(pattern, sample):
        if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
            value = value[1:-1]
        flat[key] = value
    return flat


def _flatten_json(value: Any, out: dict, prefix: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            full = f"{prefix}.{key}" if prefix else str(key)
            _flatten_json(child, out, full)
            if not isinstance(child, (dict, list)):
                out[str(key)] = child
    elif isinstance(value, list):
        out[prefix] = value
        for idx, child in enumerate(value):
            _flatten_json(child, out, f"{prefix}.{idx}" if prefix else str(idx))
    else:
        out[prefix] = value


# ── AST evaluator ────────────────────────────────────────────────────────────

class _EvalContext:
    def __init__(self, event: dict):
        self.event = event
        self.last_reasons: list[str] = []

    def note(self, reason: str) -> None:
        self.last_reasons.append(reason)


def _eval_node(node: Any, ctx: _EvalContext) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval_node(child, ctx) for child in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval_node(child, ctx) for child in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval_node(node.args[0], ctx)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _eval_field_value(node.field, node.value, ctx)
    if isinstance(node, ConditionValueExpression):
        # Keyword search across the raw event text.
        haystack = str(ctx.event.get("__raw__", "")).lower()
        needle = _sigma_string_to_pattern(node.value, ctx)
        if needle is None:
            return False
        try:
            return re.search(needle, haystack) is not None
        except re.error:
            return False
    # Unknown node — fall back to False but note it so the caller can see.
    ctx.note(f"unsupported condition node: {type(node).__name__}")
    return False


def _eval_detection(detection, ctx: _EvalContext) -> bool:
    """Evaluate a single SigmaDetection (one bucket like `selection_a`)."""
    from sigma.conditions import ConditionAND as _AND, ConditionOR as _OR
    item_link = detection.item_linking
    item_results: list[bool] = []
    for item in detection.detection_items:
        if hasattr(item, "detection_items"):
            # Nested detection (rare, e.g. lists of dicts).
            item_results.append(_eval_detection(item, ctx))
            continue
        item_results.append(_eval_detection_item(item, ctx))
    if not item_results:
        return False
    if item_link is _OR:
        return any(item_results)
    return all(item_results)


def _eval_detection_item(item, ctx: _EvalContext) -> bool:
    from sigma.conditions import ConditionAND as _AND, ConditionOR as _OR
    values = item.value if isinstance(item.value, list) else [item.value]
    if not values:
        return False
    if item.field is None:
        results = [_match_value_against_raw(v, ctx) for v in values]
    else:
        results = [_eval_field_value(item.field, v, ctx) for v in values]
    if item.value_linking is _AND:
        return all(results)
    return any(results)


def _eval_field_value(field: str, value: Any, ctx: _EvalContext) -> bool:
    actual, actual_field = _lookup_field(field, ctx.event)
    exists = actual is not None

    if isinstance(value, SigmaExists):
        matched = exists is bool(value.exists)
        if not matched:
            ctx.note(f"{field}: expected exists={value.exists}, got {exists}")
        return matched

    if isinstance(value, SigmaNull):
        matched = actual is None
        if not matched:
            ctx.note(f"{field}: expected null, got {actual!r}")
        return matched

    if not exists:
        ctx.note(f"{field}: field missing from event")
        return False

    actual_values = actual if isinstance(actual, list) else [actual]

    # Each Sigma value is compared against every event value — match if any pair matches.
    for av in actual_values:
        if _match_one_value(av, value, ctx, field):
            return True
    ctx.note(f"{field} ({actual_field}): no value matched {_describe_value(value)} (got {actual_values[:3]})")
    return False


def _match_one_value(actual: Any, sigma_value: Any, ctx: _EvalContext, field: str) -> bool:
    if isinstance(sigma_value, SigmaExpansion):
        # SigmaExpansion is emitted by modifiers like `windash` and
        # `base64offset` — its `values` are OR-linked variants.
        return any(_match_one_value(actual, sv, ctx, field) for sv in sigma_value.values)

    if isinstance(sigma_value, SigmaCompareExpression):
        try:
            a = float(actual)
            b = float(sigma_value.number.number)
        except (TypeError, ValueError):
            return False
        op = sigma_value.op
        op_name = getattr(op, "name", str(op))
        if op_name == "GT":  return a > b
        if op_name == "GTE": return a >= b
        if op_name == "LT":  return a < b
        if op_name == "LTE": return a <= b
        return False

    if isinstance(sigma_value, SigmaCIDRExpression):
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(
                str(sigma_value.cidr), strict=False
            )
        except ValueError:
            return False

    if isinstance(sigma_value, SigmaNumber):
        try:
            return float(actual) == float(sigma_value.number)
        except (TypeError, ValueError):
            return str(actual) == str(sigma_value.number)

    if isinstance(sigma_value, SigmaBool):
        return _coerce_bool(actual) == bool(sigma_value.boolean)

    if isinstance(sigma_value, SigmaRegularExpression):
        pattern = str(sigma_value.regexp)
        flags = re.IGNORECASE
        try:
            return re.search(pattern, str(actual), flags) is not None
        except re.error:
            return False

    if isinstance(sigma_value, SigmaCasedString):
        pattern = _sigma_string_to_pattern(sigma_value, ctx, case_sensitive=True)
        if pattern is None:
            return False
        try:
            return re.fullmatch(pattern, str(actual)) is not None
        except re.error:
            return False

    if isinstance(sigma_value, SigmaString):
        pattern = _sigma_string_to_pattern(sigma_value, ctx)
        if pattern is None:
            return False
        try:
            return re.fullmatch(pattern, str(actual), re.IGNORECASE | re.DOTALL) is not None
        except re.error:
            return False

    # Unsupported value type — fall back to string equality.
    return str(actual).lower() == str(sigma_value).lower()


def _match_value_against_raw(sigma_value: Any, ctx: _EvalContext) -> bool:
    """For unkeyed selections (`keywords:` blocks) — search the raw sample."""
    raw = str(ctx.event.get("__raw__", ""))
    if isinstance(sigma_value, SigmaString):
        # A keyword search ignores leading/trailing wildcards — Sigma defines
        # the value as a *substring* of the event.
        needle = _sigma_string_to_pattern(sigma_value, ctx, anchor=False)
        if needle is None:
            return False
        try:
            return re.search(needle, raw, re.IGNORECASE | re.DOTALL) is not None
        except re.error:
            return False
    if isinstance(sigma_value, SigmaRegularExpression):
        try:
            return re.search(str(sigma_value.regexp), raw, re.IGNORECASE) is not None
        except re.error:
            return False
    if isinstance(sigma_value, SigmaNumber):
        return str(sigma_value.number) in raw
    return str(sigma_value).lower() in raw.lower()


# ── Helpers ──────────────────────────────────────────────────────────────────

def _sigma_string_to_pattern(value: SigmaString, ctx: _EvalContext,
                             case_sensitive: bool = False,
                             anchor: bool = True) -> str | None:
    """Convert a SigmaString (with * and ?) to a Python regex pattern."""
    try:
        regex_value = value.to_regex()  # turns wildcards into . / .*
        pattern = str(regex_value.regexp)
    except Exception:
        ctx.note("could not convert SigmaString to regex")
        return None
    return pattern  # to_regex already escapes literals; flags applied by caller


def _lookup_field(field: str, event: dict) -> tuple[Any, str | None]:
    candidates = [field]
    candidates.extend(FIELD_ALIASES.get(_field_key(field), []))
    for cand in candidates:
        if cand in event:
            return event[cand], cand
    lower = field.lower()
    lowered_candidates = {c.lower() for c in candidates}
    for key, value in event.items():
        kl = key.lower()
        if kl in lowered_candidates or kl == lower or kl.endswith("." + lower):
            return value, key
    return None, None


def _field_key(field: str) -> str:
    return re.sub(r"[^a-z0-9]", "", field.lower())


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return bool(value)


def _describe_value(value: Any) -> str:
    if isinstance(value, SigmaString):
        return f"string '{value.convert()}'"
    if isinstance(value, SigmaRegularExpression):
        return f"regex '{value.regexp}'"
    if isinstance(value, SigmaNumber):
        return f"number {value.number}"
    if isinstance(value, SigmaCIDRExpression):
        return f"cidr {value.cidr}"
    if isinstance(value, SigmaCompareExpression):
        return f"compare {getattr(value.op,'name',value.op)} {value.number.number}"
    if isinstance(value, SigmaExists):
        return f"exists={value.exists}"
    if isinstance(value, SigmaNull):
        return "null"
    if isinstance(value, SigmaBool):
        return f"bool {value.boolean}"
    return type(value).__name__


def _failure_reasons(selection_details: dict, ctx: _EvalContext) -> list[str]:
    out: list[str] = []
    for name, detail in selection_details.items():
        if detail.get("matched"):
            continue
        for reason in detail.get("reasons", []):
            out.append(f"{name}: {reason}")
    for reason in ctx.last_reasons:
        if reason not in out:
            out.append(reason)
    return out
