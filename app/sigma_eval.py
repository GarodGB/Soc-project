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
from datetime import datetime, timezone
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

# Some model-drafted rules wrap a quantifier's wildcard in parentheses
# ("all of (selection_*)"), which real Sigma condition grammar doesn't
# accept — parens there are a hard syntax error, not just a style choice.
# Strip them so an otherwise-valid rule isn't rejected as "evaluator
# unsupported" over a cosmetic mistake.
_QUANT_PAREN_RE = re.compile(
    r"\b(\d+|all|any)\s+of\s*\(\s*([A-Za-z0-9_*]+)\s*\)", re.IGNORECASE)


def _normalize_condition_syntax(raw_yaml: str) -> str:
    return _QUANT_PAREN_RE.sub(lambda m: f"{m.group(1)} of {m.group(2)}", raw_yaml)


def _drop_invalid_tags(raw_yaml: str) -> str:
    """Drop tags pySigma's strict `namespace.tag` validator would reject
    outright (e.g. a bare 'ssh' or 'brute-force' instead of 'attack.t1110').
    Tags are pure metadata — irrelevant to whether the detection logic
    itself is evaluable — so one malformed tag must not fail the whole rule.
    """
    try:
        doc = yaml.safe_load(raw_yaml)
    except yaml.YAMLError:
        return raw_yaml
    if not isinstance(doc, dict):
        return raw_yaml
    tags = doc.get("tags")
    if not isinstance(tags, list):
        return raw_yaml
    valid = [t for t in tags if isinstance(t, str) and "." in t]
    if len(valid) == len(tags):
        return raw_yaml
    doc["tags"] = valid
    return yaml.safe_dump(doc, sort_keys=False)


@lru_cache(maxsize=4096)
def _parse_rule_cached(raw_yaml: str):
    """Parse + condition-resolve a rule once, then reuse for every sample run."""
    raw_yaml = _drop_invalid_tags(raw_yaml)
    raw_yaml = _normalize_condition_syntax(raw_yaml)
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


# ── Aggregation (threshold/frequency) conditions ────────────────────────────
#
# Sigma's `<selection> | count() [by <field>] <op> <threshold> [in <window>]`
# syntax (used for brute-force/threshold rules) is not a per-event boolean
# check — it needs the *whole batch* of captured events for one attack run,
# grouped and counted. pySigma's own condition parser refuses this syntax
# outright ("pipe syntax ... deprecated"), so it's handled separately here:
# the boolean part left of `|` is evaluated per-event with the exact same
# machinery as evaluate_sigma_rule (by re-parsing the rule with its condition
# replaced by just that left-hand expression), and the aggregation itself
# (grouping, windowing, threshold comparison) is done in pure Python.
#
# Only count() is implemented — sum()/min()/max()/avg() need a numeric field
# value per event, which nothing upstream reliably extracts from raw text
# logs, so those are reported as unsupported rather than guessed at.

_AGG_TIME_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}

_AGG_CLAUSE_RE = re.compile(
    r"^(?P<left>.*?)\|\s*(?P<func>count|sum|min|max|avg)\s*\(\s*(?P<field>[^)]*)\s*\)\s*"
    r"(?:by\s+(?P<by>[A-Za-z0-9_.]+)\s*)?"
    r"(?P<op>>=|<=|==|!=|>|<)\s*(?P<threshold>-?\d+(?:\.\d+)?)\s*"
    r"(?:in\s+(?P<window>\d+)\s*(?P<unit>[smhd]))?\s*$",
    re.IGNORECASE,
)

#: Fields commonly used in `by <field>` that raw text logs never expose as a
#: literal `field=value` token — extracted from the raw line via a generic
#: pattern instead of the usual key=value parser.
_AGG_IP_FIELD_NAMES = {"source_ip", "src_ip", "srcip", "client_ip", "remote_ip", "ip"}
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class SigmaAggregationUnsupported(Exception):
    """The condition needs an aggregation function this evaluator can't run."""


def _parse_aggregation_clause(condition_str: str) -> dict[str, Any] | None:
    match = _AGG_CLAUSE_RE.match((condition_str or "").strip())
    if not match:
        return None
    func = match.group("func").lower()
    if func != "count":
        raise SigmaAggregationUnsupported(
            f"aggregation function '{func}()' is not supported (only count() is)"
        )
    window_s = None
    if match.group("window"):
        window_s = int(match.group("window")) * _AGG_TIME_UNITS[match.group("unit").lower()]
    return {
        "left": match.group("left").strip(),
        "by": match.group("by"),
        "op": match.group("op"),
        "threshold": float(match.group("threshold")),
        "window_s": window_s,
    }


def has_aggregation_condition(raw_yaml: str) -> bool:
    """True if this rule's condition uses `| count(...)`-style syntax."""
    try:
        doc = yaml.safe_load(raw_yaml) or {}
    except yaml.YAMLError:
        return False
    condition = (doc.get("detection") or {}).get("condition")
    if isinstance(condition, list):
        condition = condition[0] if condition else ""
    return "|" in str(condition or "")


def _left_only_yaml(raw_yaml: str, left_expr: str) -> str:
    doc = yaml.safe_load(raw_yaml) or {}
    doc.setdefault("detection", {})["condition"] = left_expr
    return yaml.safe_dump(doc, sort_keys=False)


def _resolve_group_key(event: dict, field: str | None) -> str | None:
    if not field:
        return "*"
    for key in (field, field.lower(), field.upper()):
        if key in event and event[key] not in (None, ""):
            return str(event[key])
    if field.lower() in _AGG_IP_FIELD_NAMES:
        m = _IPV4_RE.search(str(event.get("__raw__", "")))
        if m:
            return m.group(0)
    return None


def _parse_event_timestamp(event: dict) -> float | None:
    raw = event.get("timestamp") or event.get("@timestamp")
    if not raw:
        return None
    try:
        text = str(raw).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text).timestamp()
    except (ValueError, TypeError):
        return None


def evaluate_sigma_rule_over_events(raw_yaml: str, sample_events: list[str]) -> dict:
    """Evaluate an aggregation (`| count() ...`) rule against a batch of
    captured events for one attack run. Each entry in ``sample_events`` is a
    JSON string in the same shape ``evaluate_sigma_rule`` accepts, ideally
    including a ``timestamp`` field so the time window can be honoured.
    """
    if not raw_yaml:
        raise SigmaEvaluationError("Detection rule has no Sigma YAML")

    doc = yaml.safe_load(raw_yaml) or {}
    condition = (doc.get("detection") or {}).get("condition")
    if isinstance(condition, list):
        condition = condition[0] if condition else ""
    agg = _parse_aggregation_clause(str(condition or ""))
    if agg is None:
        raise SigmaEvaluationError("No aggregation clause found in condition")

    left_yaml = _left_only_yaml(raw_yaml, agg["left"])
    rule, tree = _parse_rule_cached(left_yaml)

    groups: dict[str, list[float]] = {}
    ungroupable = 0
    for raw_event in sample_events:
        event = _parse_event(raw_event or "")
        ctx = _EvalContext(event=event)
        if not _eval_node(tree, ctx):
            continue
        key = _resolve_group_key(event, agg["by"])
        if key is None:
            ungroupable += 1
            continue
        ts = _parse_event_timestamp(event)
        groups.setdefault(key, []).append(ts if ts is not None else 0.0)

    def compare(value: float) -> bool:
        op = agg["op"]
        t = agg["threshold"]
        if op == ">":
            return value > t
        if op == ">=":
            return value >= t
        if op == "<":
            return value < t
        if op == "<=":
            return value <= t
        if op == "==":
            return value == t
        return value != t

    group_counts: dict[str, int] = {}
    matched = False
    for key, timestamps in groups.items():
        timestamps.sort()
        if agg["window_s"] is None:
            best = len(timestamps)
        else:
            best, left = 0, 0
            for right in range(len(timestamps)):
                while timestamps[right] - timestamps[left] > agg["window_s"]:
                    left += 1
                best = max(best, right - left + 1)
        group_counts[key] = best
        if compare(best):
            matched = True

    return {
        "matched": matched,
        "engine": "pysigma-aggregate",
        "function": "count",
        "by": agg["by"],
        "op": agg["op"],
        "threshold": agg["threshold"],
        "window_s": agg["window_s"],
        "group_counts": group_counts,
        "events_considered": len(sample_events),
        "events_ungroupable": ungroupable,
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
        # Keyword search across the raw event text. Delegate to the same
        # matcher unfielded selection items use (_match_value_against_raw) —
        # it already does this correctly (case-insensitive via re.IGNORECASE).
        # An earlier version of this branch lowercased the haystack but not
        # the search pattern, so any keyword containing an uppercase letter
        # (e.g. "Failed password") could never match.
        return _match_value_against_raw(node.value, ctx)
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
