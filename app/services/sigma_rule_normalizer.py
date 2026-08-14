"""Sigma rule normalization and safe evaluation for ABSEGA AD validation.

Supported condition features:
- exact, contains, contains|all, startswith, endswith, re/regex
- boolean and/or/not with parentheses
- all of selection*, 1 of selection*, and not filter*

Anything outside the supported subset returns EVALUATOR_UNSUPPORTED.  It is
never converted into a detection miss.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

import yaml

from app.services.sigma_field_mapping import (
    SIGMA_FIELD_TO_CANONICAL,
    build_canonical_event,
    get_sigma_field_value,
)


EVALUATOR_MATCH = "MATCH"
EVALUATOR_NO_MATCH = "NO_MATCH"
EVALUATOR_UNSUPPORTED = "EVALUATOR_UNSUPPORTED"
EVALUATOR_INVALID_RULE = "INVALID_RULE"


class SigmaUnsupportedError(ValueError):
    """Raised when a Sigma feature cannot be evaluated safely."""


class SigmaInvalidRuleError(ValueError):
    """Raised when the YAML/rule structure is invalid."""


@dataclass(frozen=True)
class Token:
    kind: str
    value: str


@dataclass
class ConditionParser:
    tokens: list[Token]
    selection_names: list[str]
    position: int = 0

    def parse(self) -> dict[str, Any]:
        if not self.tokens:
            raise SigmaInvalidRuleError("Sigma condition is empty")
        node = self._parse_or()
        if self.position != len(self.tokens):
            token = self.tokens[self.position]
            raise SigmaUnsupportedError(
                f"Unsupported or unexpected condition token: {token.value!r}"
            )
        return node

    def _peek(self, kind: str | None = None) -> Token | None:
        if self.position >= len(self.tokens):
            return None
        token = self.tokens[self.position]
        if kind is not None and token.kind != kind:
            return None
        return token

    def _take(self, kind: str | None = None) -> Token:
        token = self._peek(kind)
        if token is None:
            expected = kind or "token"
            raise SigmaInvalidRuleError(f"Expected {expected} in Sigma condition")
        self.position += 1
        return token

    def _parse_or(self) -> dict[str, Any]:
        nodes = [self._parse_and()]
        while self._peek("OR"):
            self._take("OR")
            nodes.append(self._parse_and())
        return nodes[0] if len(nodes) == 1 else {"type": "or", "children": nodes}

    def _parse_and(self) -> dict[str, Any]:
        nodes = [self._parse_not()]
        while self._peek("AND"):
            self._take("AND")
            nodes.append(self._parse_not())
        return nodes[0] if len(nodes) == 1 else {"type": "and", "children": nodes}

    def _parse_not(self) -> dict[str, Any]:
        if self._peek("NOT"):
            self._take("NOT")
            return {"type": "not", "child": self._parse_not()}
        return self._parse_primary()

    def _parse_primary(self) -> dict[str, Any]:
        if self._peek("LPAREN"):
            self._take("LPAREN")
            node = self._parse_or()
            self._take("RPAREN")
            return node

        if self._peek("QUANTIFIER"):
            token = self._take("QUANTIFIER")
            amount, pattern = token.value.split("\u0000", 1)
            return self._expand_pattern(pattern, all_required=(amount == "all"))

        if self._peek("IDENT"):
            token = self._take("IDENT")
            if "*" in token.value or "?" in token.value:
                # A bare wildcard reference means any matching selection.  This
                # makes `not filter*` equivalent to NOT(any matching filter).
                return self._expand_pattern(token.value, all_required=False)
            if token.value not in self.selection_names:
                raise SigmaInvalidRuleError(
                    f"Condition references missing selection: {token.value}"
                )
            return {"type": "selection", "name": token.value}

        token = self._peek()
        raise SigmaUnsupportedError(
            f"Unsupported Sigma condition near: {token.value if token else '<end>'}"
        )

    def _expand_pattern(self, pattern: str, *, all_required: bool) -> dict[str, Any]:
        if pattern.casefold() == "them":
            matches = list(self.selection_names)
        else:
            matches = [
                name
                for name in self.selection_names
                if fnmatch.fnmatchcase(name.casefold(), pattern.casefold())
            ]
        if not matches:
            raise SigmaInvalidRuleError(
                f"Condition pattern {pattern!r} matched no selections"
            )
        children = [{"type": "selection", "name": name} for name in matches]
        if len(children) == 1:
            return children[0]
        return {
            "type": "and" if all_required else "or",
            "children": children,
        }


_TOKEN_RE = re.compile(
    r"\s*(?:"
    r"(?P<LPAREN>\()|"
    r"(?P<RPAREN>\))|"
    r"(?P<QUANTIFIER>(?:all|1)\s+of\s+[A-Za-z0-9_.?*\-]+)|"
    r"(?P<AND>and\b)|"
    r"(?P<OR>or\b)|"
    r"(?P<NOT>not\b)|"
    r"(?P<IDENT>[A-Za-z0-9_.?*\-]+)|"
    r"(?P<OTHER>\S+)"
    r")",
    flags=re.IGNORECASE,
)


def _tokenize_condition(expression: str) -> list[Token]:
    # Aggregation, temporal, and correlation syntax must not be simplified into
    # a false negative.
    unsupported_markers = (
        "| count(",
        "|count(",
        " near ",
        " followed_by ",
        " timeframe",
    )
    lowered = f" {expression.casefold()} "
    if any(marker in lowered for marker in unsupported_markers):
        raise SigmaUnsupportedError(
            "Aggregation, temporal, or correlation Sigma conditions are unsupported"
        )

    tokens: list[Token] = []
    offset = 0
    while offset < len(expression):
        match = _TOKEN_RE.match(expression, offset)
        if not match:
            raise SigmaUnsupportedError(
                f"Unsupported Sigma condition syntax near {expression[offset:]!r}"
            )
        offset = match.end()
        kind = match.lastgroup or "OTHER"
        value = match.group(kind)
        if kind == "OTHER":
            raise SigmaUnsupportedError(f"Unsupported condition token: {value!r}")
        if kind == "QUANTIFIER":
            parts = re.split(r"\s+of\s+", value, maxsplit=1, flags=re.IGNORECASE)
            amount = parts[0].casefold()
            pattern = parts[1]
            tokens.append(Token("QUANTIFIER", f"{amount}\u0000{pattern}"))
        else:
            tokens.append(Token(kind.upper(), value))
    return tokens


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _string_values(values: Iterable[Any]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        if value is None or isinstance(value, (dict, list, tuple, set)):
            raise SigmaUnsupportedError(
                "Nested or null Sigma field values are unsupported"
            )
        normalized.append(str(value))
    return normalized


def _parse_field_key(field_key: str) -> tuple[str, str, bool]:
    parts = [part.strip() for part in str(field_key).split("|")]
    field = parts[0]
    modifiers = [part.casefold() for part in parts[1:] if part]

    supported = {"contains", "startswith", "endswith", "re", "regex", "all", "cased"}
    unknown = [modifier for modifier in modifiers if modifier not in supported]
    if unknown:
        raise SigmaUnsupportedError(
            f"Unsupported Sigma field modifier(s) on {field}: {', '.join(unknown)}"
        )

    operator_modifiers = [
        modifier
        for modifier in modifiers
        if modifier in {"contains", "startswith", "endswith", "re", "regex"}
    ]
    if len(operator_modifiers) > 1:
        raise SigmaUnsupportedError(
            f"Conflicting Sigma field modifiers on {field}: {operator_modifiers}"
        )

    base_operator = operator_modifiers[0] if operator_modifiers else "exact"
    if base_operator == "regex":
        base_operator = "re"

    require_all = "all" in modifiers
    case_sensitive = "cased" in modifiers

    if require_all:
        if base_operator == "contains":
            operator = "contains_all"
        else:
            operator = f"{base_operator}_all"
    else:
        operator = base_operator

    return field, operator, case_sensitive


def _normalize_field_condition(field_key: str, raw_value: Any) -> dict[str, Any]:
    field, operator, case_sensitive = _parse_field_key(field_key)
    values = _string_values(_as_list(raw_value))
    if not values:
        raise SigmaInvalidRuleError(f"Sigma field {field!r} has no values")

    # Exact Sigma values may contain wildcard syntax. Keep it explicit so the
    # evaluator does not accidentally treat a wildcard as a literal exact match.
    if operator in {"exact", "exact_all"} and any(
        "*" in value or "?" in value for value in values
    ):
        operator = "wildcard" if operator == "exact" else "wildcard_all"

    return {
        "field": field,
        "canonical_field": SIGMA_FIELD_TO_CANONICAL.get(field, field),
        "operator": operator,
        "values": values,
        "case_sensitive": case_sensitive,
    }


def _normalize_selection(name: str, raw_selection: Any) -> dict[str, Any]:
    if isinstance(raw_selection, Mapping):
        conditions = [
            _normalize_field_condition(field, value)
            for field, value in raw_selection.items()
        ]
        if not conditions:
            raise SigmaInvalidRuleError(f"Selection {name!r} is empty")
        return {"name": name, "type": "and", "conditions": conditions}

    if isinstance(raw_selection, list) and all(
        isinstance(item, Mapping) for item in raw_selection
    ):
        branches = []
        for index, item in enumerate(raw_selection):
            branch = _normalize_selection(f"{name}[{index}]", item)
            branches.append(branch["conditions"])
        return {"name": name, "type": "or", "branches": branches}

    raise SigmaUnsupportedError(
        f"Selection {name!r} must be a field mapping or list of field mappings"
    )


def _normalize_logsource(rule: Mapping[str, Any], stored_logsource: Any = None) -> dict[str, Any]:
    raw = rule.get("logsource")
    if not isinstance(raw, Mapping) and stored_logsource:
        if isinstance(stored_logsource, str):
            try:
                parsed = yaml.safe_load(stored_logsource)
            except yaml.YAMLError:
                parsed = None
            raw = parsed if isinstance(parsed, Mapping) else {}
        elif isinstance(stored_logsource, Mapping):
            raw = stored_logsource
    if not isinstance(raw, Mapping):
        raw = {}

    product = raw.get("product")
    category = raw.get("category")
    service = raw.get("service")

    channels: list[str] = []
    if product and str(product).casefold() == "windows":
        if category and str(category).casefold() == "process_creation":
            channels.append("Microsoft-Windows-Sysmon/Operational")
        elif service and str(service).casefold() in {"sysmon", "sysmon_operational"}:
            channels.append("Microsoft-Windows-Sysmon/Operational")
        elif service and str(service).casefold() == "security":
            channels.append("Security")
        elif service and str(service).casefold() == "system":
            channels.append("System")
        elif service and "powershell" in str(service).casefold():
            channels.append("Microsoft-Windows-PowerShell/Operational")

    return {
        "product": str(product).casefold() if product is not None else None,
        "category": str(category).casefold() if category is not None else None,
        "service": str(service).casefold() if service is not None else None,
        "channels": channels,
    }


def _extract_mitre(rule: Mapping[str, Any], stored_tags: Any = None) -> list[str]:
    tags = rule.get("tags", stored_tags or [])
    if isinstance(tags, str):
        try:
            parsed = json.loads(tags)
            tags = parsed if isinstance(parsed, list) else re.split(r"[,\s]+", tags)
        except json.JSONDecodeError:
            tags = re.split(r"[,\s]+", tags)
    if not isinstance(tags, Sequence):
        tags = []

    techniques: set[str] = set()
    for tag in tags:
        match = re.search(r"(?:attack\.)?(T\d{4}(?:\.\d{3})?)", str(tag), re.IGNORECASE)
        if match:
            techniques.add(match.group(1).upper())
    return sorted(techniques)


def _condition_fields(selection_groups: Mapping[str, Any]) -> list[dict[str, Any]]:
    conditions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for group in selection_groups.values():
        group_conditions: list[dict[str, Any]] = []
        if group["type"] == "and":
            group_conditions.extend(group["conditions"])
        else:
            for branch in group["branches"]:
                group_conditions.extend(branch)
        for condition in group_conditions:
            key = json.dumps(condition, sort_keys=True)
            if key not in seen:
                conditions.append(condition)
                seen.add(key)
    return conditions


def _extract_event_ids(conditions: Sequence[Mapping[str, Any]]) -> list[str]:
    event_ids: set[str] = set()
    for condition in conditions:
        if str(condition.get("field", "")).casefold() == "eventid":
            event_ids.update(str(value) for value in condition.get("values", []))
    return sorted(event_ids)


def normalize_sigma_rule(
    raw_yaml: str,
    *,
    logsource: Any = None,
    rule_logic: Any = None,
    tags: Any = None,
    falsepositives: Any = None,
) -> dict[str, Any]:
    """Normalize a Sigma rule into ABSEGA's canonical comparison model."""

    try:
        parsed = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as exc:
        return {
            "status": EVALUATOR_INVALID_RULE,
            "supported": False,
            "unsupported_reasons": [f"Invalid Sigma YAML: {exc}"],
        }

    if not isinstance(parsed, Mapping):
        return {
            "status": EVALUATOR_INVALID_RULE,
            "supported": False,
            "unsupported_reasons": ["Sigma YAML root must be a mapping"],
        }

    detection = parsed.get("detection")
    if not isinstance(detection, Mapping):
        return {
            "status": EVALUATOR_INVALID_RULE,
            "supported": False,
            "unsupported_reasons": ["Sigma detection section is missing or invalid"],
        }

    expression = detection.get("condition")
    if not isinstance(expression, str) or not expression.strip():
        return {
            "status": EVALUATOR_INVALID_RULE,
            "supported": False,
            "unsupported_reasons": ["Sigma detection.condition is missing"],
        }

    selection_names = [name for name in detection if name != "condition"]

    try:
        selection_groups = {
            name: _normalize_selection(name, detection[name])
            for name in selection_names
        }
        condition_ast = ConditionParser(
            _tokenize_condition(expression), selection_names
        ).parse()
    except (SigmaUnsupportedError, SigmaInvalidRuleError) as exc:
        status = (
            EVALUATOR_UNSUPPORTED
            if isinstance(exc, SigmaUnsupportedError)
            else EVALUATOR_INVALID_RULE
        )
        return {
            "status": status,
            "supported": False,
            "unsupported_reasons": [str(exc)],
            "condition_expression": expression,
        }

    conditions = _condition_fields(selection_groups)
    normalized_logsource = _normalize_logsource(parsed, logsource)
    event_ids = _extract_event_ids(conditions)
    if (
        not event_ids
        and normalized_logsource["product"] == "windows"
        and normalized_logsource["category"] == "process_creation"
    ):
        # In ABSEGA's current Windows pipeline, process_creation is collected
        # from Sysmon Operational and therefore corresponds to Sysmon Event 1.
        event_ids = ["1"]

    source_tokens = {
        value
        for value in (
            normalized_logsource["product"],
            normalized_logsource["category"],
            normalized_logsource["service"],
        )
        if value
    }
    if any("sysmon" in channel.casefold() for channel in normalized_logsource["channels"]):
        source_tokens.add("sysmon")

    canonical_fields = sorted(
        {str(condition["canonical_field"]) for condition in conditions}
    )
    flattened_values = sorted(
        {str(value) for condition in conditions for value in condition["values"]}
    )
    operators = sorted({str(condition["operator"]) for condition in conditions})

    return {
        "status": "NORMALIZED",
        "supported": True,
        "product": normalized_logsource["product"],
        "category": normalized_logsource["category"],
        "service": normalized_logsource["service"],
        "channels": normalized_logsource["channels"],
        "event_ids": event_ids,
        "conditions": conditions,
        # Compatibility keys used by ABSEGA's existing static comparison layer.
        "sources": sorted(source_tokens),
        "fields": canonical_fields,
        "values": flattened_values,
        "operators": operators,
        "selection_groups": selection_groups,
        "condition_expression": expression,
        "condition_ast": condition_ast,
        "mitre": _extract_mitre(parsed, tags),
        "falsepositives": parsed.get("falsepositives", falsepositives or []),
        "rule_logic": rule_logic,
    }


def _actual_values(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _normalize_compare_value(value: Any, *, case_sensitive: bool) -> str:
    text = str(value)
    return text if case_sensitive else text.casefold()


def _wildcard_match(actual: str, expected: str, *, case_sensitive: bool) -> bool:
    if not case_sensitive:
        actual = actual.casefold()
        expected = expected.casefold()
    return fnmatch.fnmatchcase(actual, expected)


def _condition_matches(condition: Mapping[str, Any], event: Mapping[str, Any]) -> tuple[bool, str]:
    field = str(condition["field"])
    operator = str(condition["operator"])
    expected_values = [str(value) for value in condition["values"]]
    case_sensitive = bool(condition.get("case_sensitive", False))
    actual_raw = get_sigma_field_value(event, field)

    if actual_raw is None:
        return False, f"{field}: field missing"

    actual_values = _actual_values(actual_raw)

    def single_match(actual_value: Any, expected: str, base_operator: str) -> bool:
        actual = _normalize_compare_value(actual_value, case_sensitive=case_sensitive)
        wanted = _normalize_compare_value(expected, case_sensitive=case_sensitive)

        if base_operator == "exact":
            return actual == wanted
        if base_operator == "contains":
            return wanted in actual
        if base_operator == "startswith":
            return actual.startswith(wanted)
        if base_operator == "endswith":
            return actual.endswith(wanted)
        if base_operator == "wildcard":
            return _wildcard_match(
                str(actual_value), expected, case_sensitive=case_sensitive
            )
        if base_operator == "re":
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                return re.search(expected, str(actual_value), flags=flags) is not None
            except re.error as exc:
                raise SigmaUnsupportedError(
                    f"Invalid regular expression on {field}: {exc}"
                ) from exc
        raise SigmaUnsupportedError(f"Unsupported normalized operator: {operator}")

    require_all = operator.endswith("_all")
    base_operator = operator.removesuffix("_all") if require_all else operator

    if require_all:
        matched = all(
            any(single_match(actual, expected, base_operator) for actual in actual_values)
            for expected in expected_values
        )
    else:
        matched = any(
            single_match(actual, expected, base_operator)
            for actual in actual_values
            for expected in expected_values
        )

    return matched, (
        f"{field}: matched {operator}" if matched else f"{field}: no {operator} value matched"
    )


def _selection_matches(group: Mapping[str, Any], event: Mapping[str, Any]) -> tuple[bool, list[str]]:
    if group["type"] == "and":
        trace = []
        results = []
        for condition in group["conditions"]:
            matched, message = _condition_matches(condition, event)
            results.append(matched)
            trace.append(message)
        return all(results), trace

    branch_results = []
    trace = []
    for branch in group["branches"]:
        results = []
        branch_trace = []
        for condition in branch:
            matched, message = _condition_matches(condition, event)
            results.append(matched)
            branch_trace.append(message)
        branch_results.append(all(results))
        trace.append("; ".join(branch_trace))
    return any(branch_results), trace


def _evaluate_ast(
    node: Mapping[str, Any],
    selection_results: Mapping[str, bool],
) -> bool:
    node_type = node["type"]
    if node_type == "selection":
        return bool(selection_results[node["name"]])
    if node_type == "and":
        return all(_evaluate_ast(child, selection_results) for child in node["children"])
    if node_type == "or":
        return any(_evaluate_ast(child, selection_results) for child in node["children"])
    if node_type == "not":
        return not _evaluate_ast(node["child"], selection_results)
    raise SigmaUnsupportedError(f"Unsupported condition AST node: {node_type}")


def evaluate_normalized_sigma(
    normalized_rule: Mapping[str, Any],
    event: Mapping[str, Any],
) -> dict[str, Any]:
    """Evaluate a normalized Sigma rule against a Wazuh or Sigma event."""

    if normalized_rule.get("status") == EVALUATOR_UNSUPPORTED:
        return {
            "status": EVALUATOR_UNSUPPORTED,
            "matched": None,
            "reason": "; ".join(normalized_rule.get("unsupported_reasons", [])),
        }
    if normalized_rule.get("status") == EVALUATOR_INVALID_RULE:
        return {
            "status": EVALUATOR_INVALID_RULE,
            "matched": None,
            "reason": "; ".join(normalized_rule.get("unsupported_reasons", [])),
        }
    if not normalized_rule.get("supported"):
        return {
            "status": EVALUATOR_UNSUPPORTED,
            "matched": None,
            "reason": "Rule is not marked as supported",
        }

    canonical_event = build_canonical_event(event)
    selection_results: dict[str, bool] = {}
    trace: dict[str, list[str]] = {}

    try:
        for name, group in normalized_rule["selection_groups"].items():
            matched, group_trace = _selection_matches(group, event)
            selection_results[name] = matched
            trace[name] = group_trace
        matched = _evaluate_ast(normalized_rule["condition_ast"], selection_results)
    except SigmaUnsupportedError as exc:
        return {
            "status": EVALUATOR_UNSUPPORTED,
            "matched": None,
            "reason": str(exc),
            "selection_results": selection_results,
            "trace": trace,
            "canonical_event": canonical_event,
        }

    return {
        "status": EVALUATOR_MATCH if matched else EVALUATOR_NO_MATCH,
        "matched": matched,
        "selection_results": selection_results,
        "trace": trace,
        "canonical_event": canonical_event,
    }


def evaluate_sigma_rule(
    raw_yaml: str,
    event: Mapping[str, Any] | str,
    *,
    logsource: Any = None,
    rule_logic: Any = None,
    tags: Any = None,
    falsepositives: Any = None,
) -> dict[str, Any]:
    """Normalize and safely evaluate one Sigma rule against one event."""

    if isinstance(event, str):
        try:
            parsed_event = json.loads(event)
        except json.JSONDecodeError as exc:
            return {
                "status": EVALUATOR_INVALID_RULE,
                "matched": None,
                "reason": f"Event is not valid JSON: {exc}",
            }
    elif isinstance(event, Mapping):
        parsed_event = event
    else:
        return {
            "status": EVALUATOR_INVALID_RULE,
            "matched": None,
            "reason": "Event must be a mapping or JSON string",
        }

    normalized = normalize_sigma_rule(
        raw_yaml,
        logsource=logsource,
        rule_logic=rule_logic,
        tags=tags,
        falsepositives=falsepositives,
    )
    result = evaluate_normalized_sigma(normalized, parsed_event)
    result["normalized_rule"] = normalized
    return result


def normalize_sigma_detection(detection: Mapping[str, Any] | str) -> dict[str, Any]:
    """Compatibility adapter for callers that pass a full DB detection row."""

    if isinstance(detection, str):
        return normalize_sigma_rule(detection)
    if not isinstance(detection, Mapping):
        return {
            "status": EVALUATOR_INVALID_RULE,
            "supported": False,
            "unsupported_reasons": [
                "Detection must be a mapping or a raw Sigma YAML string"
            ],
        }
    return normalize_sigma_rule(
        str(detection.get("raw_yaml") or ""),
        logsource=detection.get("logsource"),
        rule_logic=detection.get("rule_logic"),
        tags=detection.get("tags"),
        falsepositives=detection.get("falsepositives"),
    )


# Backward-compatible names for the earlier ABSEGA Step-3 module.
normalize_detection = normalize_sigma_detection
normalize_sigma = normalize_sigma_detection
