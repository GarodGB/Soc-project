from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_text(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(value: Any) -> str:
    return hashlib.sha256(_json_text(value).encode("utf-8")).hexdigest()


def _as_mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _listify(value: Any, *, split_commas: bool = False) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple) or isinstance(value, set):
        return list(value)
    if split_commas and isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return [value]


def _dedupe(values: Iterable[Any]) -> list[Any]:
    output: list[Any] = []
    seen: set[str] = set()
    for value in values:
        marker = _json_text(value)
        if marker not in seen:
            seen.add(marker)
            output.append(value)
    return output


def _int_list(value: Any) -> list[int]:
    result: list[int] = []
    for item in _listify(value, split_commas=True):
        try:
            result.append(int(str(item).strip()))
        except (TypeError, ValueError):
            continue
    return _dedupe(result)


def _string_list(value: Any, *, split_commas: bool = False) -> list[str]:
    return _dedupe(
        str(item).strip()
        for item in _listify(value, split_commas=split_commas)
        if str(item).strip()
    )


def _first_present(rule: Mapping[str, Any], details: Mapping[str, Any], key: str) -> Any:
    if key in details and details.get(key) not in (None, "", [], {}):
        return details.get(key)
    return rule.get(key)


def _extract_mitre(
    rule: Mapping[str, Any],
    details: Mapping[str, Any],
) -> dict[str, list[str]]:
    raw = rule.get("mitre")
    if raw in (None, "", [], {}):
        raw = details.get("mitre")

    if isinstance(raw, Mapping):
        return {
            "id": _string_list(raw.get("id"), split_commas=True),
            "tactic": _string_list(raw.get("tactic"), split_commas=True),
            "technique": _string_list(raw.get("technique"), split_commas=True),
        }

    # Some Wazuh API versions return MITRE IDs directly as a list,
    # for example: ["T1059.001"].
    return {
        "id": _string_list(raw, split_commas=True),
        "tactic": [],
        "technique": [],
    }


def _normalize_field_conditions(
    value: Any,
    source_rule_id: int,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []

    def add(
        name: Any,
        condition_value: Any,
        operator: Any = "match",
        negate: Any = False,
    ) -> None:
        if name in (None, ""):
            return

        values = _listify(condition_value)
        if not values:
            values = [None]

        for item in values:
            output.append(
                {
                    "field": str(name).strip(),
                    "operator": str(operator or "match").strip(),
                    "value": item,
                    "negate": bool(negate),
                    "source_rule_id": source_rule_id,
                }
            )

    if isinstance(value, Mapping):
        single_condition_keys = {
            "name",
            "field",
            "value",
            "pattern",
            "match",
            "regex",
        }

        if any(key in value for key in single_condition_keys):
            name = value.get("name") or value.get("field")
            condition_value = value.get("value")
            operator = value.get("operator") or value.get("type") or "match"

            if condition_value is None:
                if value.get("pattern") is not None:
                    condition_value = value.get("pattern")
                elif value.get("regex") is not None:
                    condition_value = value.get("regex")
                    operator = "regex"
                elif value.get("match") is not None:
                    condition_value = value.get("match")

            add(
                name,
                condition_value,
                operator,
                value.get("negate", False),
            )
        else:
            # Wazuh API shape:
            # "win.eventdata.commandLine": {
            #     "pattern": "...",
            #     "type": "pcre2"
            # }
            for name, specification in value.items():
                if isinstance(specification, Mapping):
                    condition_value = specification.get("value")
                    operator = (
                        specification.get("operator")
                        or specification.get("type")
                        or "match"
                    )

                    if condition_value is None:
                        if specification.get("pattern") is not None:
                            condition_value = specification.get("pattern")
                        elif specification.get("regex") is not None:
                            condition_value = specification.get("regex")
                            operator = "regex"
                        elif specification.get("match") is not None:
                            condition_value = specification.get("match")
                        else:
                            condition_value = dict(specification)

                    add(
                        name,
                        condition_value,
                        operator,
                        specification.get("negate", False),
                    )
                else:
                    add(name, specification)

        return output

    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        for item in value:
            output.extend(
                _normalize_field_conditions(item, source_rule_id)
            )
        return output

    if isinstance(value, str):
        if ":" in value:
            name, condition_value = value.split(":", 1)
            add(name, condition_value)
        else:
            add("_field", value)

    return output


_DETAIL_NON_FIELD_KEYS = {
    "decoded_as",
    "category",
    "program_name",
    "match",
    "regex",
    "field",
    "if_sid",
    "if_group",
    "if_matched_sid",
    "frequency",
    "timeframe",
    "same_source_ip",
    "same_user",
    "options",
    "group",
    "groups",
    "mitre",
}


def _extract_embedded_detail_fields(
    details: Mapping[str, Any],
    source_rule_id: int,
) -> list[dict[str, Any]]:
    embedded: dict[str, Any] = {}

    for name, specification in details.items():
        if name in _DETAIL_NON_FIELD_KEYS:
            continue

        is_field_name = "." in str(name)
        is_condition_mapping = (
            isinstance(specification, Mapping)
            and any(
                key in specification
                for key in ("pattern", "value", "match", "regex")
            )
        )

        if is_field_name or is_condition_mapping:
            embedded[str(name)] = specification

    return _normalize_field_conditions(
        embedded,
        source_rule_id,
    )


def normalize_wazuh_rule(rule: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize one Wazuh /rules item without resolving parents."""
    raw = dict(rule)
    details = _as_mapping(raw.get("details"))

    rule_id_raw = raw.get("id") or raw.get("rule_id")
    if rule_id_raw is None:
        raise ValueError("Wazuh rule is missing id")
    rule_id = int(rule_id_raw)

    groups = _string_list(raw.get("groups") or details.get("group"), split_commas=True)
    mitre = _extract_mitre(raw, details)

    match_values = _string_list(_first_present(raw, details, "match"))
    regex_values = _string_list(_first_present(raw, details, "regex"))
    options = _string_list(_first_present(raw, details, "options"), split_commas=True)
    field_conditions = _dedupe(
        _normalize_field_conditions(
            _first_present(raw, details, "field"),
            rule_id,
        )
        + _extract_embedded_detail_fields(details, rule_id)
    )

    return {
        "rule_id": rule_id,
        "level": raw.get("level"),
        "description": raw.get("description") or "",
        "filename": raw.get("filename") or "",
        "relative_dir": raw.get("relative_dirname") or raw.get("relative_dir") or "",
        "groups": groups,
        "mitre": mitre,
        "decoded_as": _string_list(_first_present(raw, details, "decoded_as")),
        "category": _string_list(_first_present(raw, details, "category")),
        "program_name": _string_list(_first_present(raw, details, "program_name")),
        "match": match_values,
        "regex": regex_values,
        "fields": field_conditions,
        "if_sid": _int_list(_first_present(raw, details, "if_sid")),
        "if_group": _string_list(_first_present(raw, details, "if_group"), split_commas=True),
        "if_matched_sid": _int_list(_first_present(raw, details, "if_matched_sid")),
        "frequency": _first_present(raw, details, "frequency"),
        "timeframe": _first_present(raw, details, "timeframe"),
        "same_source_ip": bool(_first_present(raw, details, "same_source_ip")),
        "same_user": bool(_first_present(raw, details, "same_user")),
        "options": options,
        "details": details,
        "raw_rule": raw,
    }


def build_rule_indexes(rules: Iterable[Mapping[str, Any]]) -> tuple[dict[int, dict[str, Any]], dict[str, list[int]]]:
    by_id: dict[int, dict[str, Any]] = {}
    by_group: dict[str, list[int]] = {}
    for raw_rule in rules:
        normalized = normalize_wazuh_rule(raw_rule)
        by_id[normalized["rule_id"]] = normalized
        for group in normalized["groups"]:
            by_group.setdefault(group.casefold(), []).append(normalized["rule_id"])
    return by_id, by_group


def resolve_effective_logic(
    rule_id: int,
    by_id: Mapping[int, Mapping[str, Any]],
    by_group: Mapping[str, list[int]] | None = None,
    *,
    max_depth: int = 64,
) -> dict[str, Any]:
    """Resolve if_sid/if_matched_sid ancestors recursively and flatten effective logic.

    if_group is recorded as a runtime dependency instead of blindly merging every rule in
    the group, which would be semantically incorrect and could explode the rule tree.
    """
    ordered_layers: list[dict[str, Any]] = []
    visited: set[int] = set()
    active: set[int] = set()
    missing: list[int] = []
    cycles: list[list[int]] = []

    def visit(current_id: int, path: list[int]) -> None:
        if len(path) > max_depth:
            cycles.append(path + [current_id])
            return
        if current_id in active:
            start = path.index(current_id) if current_id in path else 0
            cycles.append(path[start:] + [current_id])
            return
        if current_id in visited:
            return
        current = by_id.get(current_id)
        if current is None:
            missing.append(current_id)
            return

        active.add(current_id)
        parent_ids = _dedupe(list(current.get("if_sid", [])) + list(current.get("if_matched_sid", [])))
        for parent_id in parent_ids:
            visit(int(parent_id), path + [current_id])
        active.remove(current_id)
        visited.add(current_id)
        ordered_layers.append(dict(current))

    visit(int(rule_id), [])
    if rule_id not in by_id:
        raise KeyError(f"Wazuh rule {rule_id} not found")

    conditions: dict[str, Any] = {
        "decoded_as": [],
        "category": [],
        "program_name": [],
        "match": [],
        "regex": [],
        "fields": [],
        "groups": [],
        "mitre": {"id": [], "tactic": [], "technique": []},
        "if_sid": [],
        "if_group": [],
        "if_matched_sid": [],
        "frequency": None,
        "timeframe": None,
        "same_source_ip": False,
        "same_user": False,
        "options": [],
    }

    for layer in ordered_layers:
        for key in ("decoded_as", "category", "program_name", "match", "regex", "fields", "groups", "if_sid", "if_group", "if_matched_sid", "options"):
            conditions[key] = _dedupe(list(conditions[key]) + list(layer.get(key, [])))
        for key in ("id", "tactic", "technique"):
            conditions["mitre"][key] = _dedupe(
                list(conditions["mitre"][key]) + list(layer.get("mitre", {}).get(key, []))
            )
        if layer.get("frequency") not in (None, ""):
            conditions["frequency"] = layer.get("frequency")
        if layer.get("timeframe") not in (None, ""):
            conditions["timeframe"] = layer.get("timeframe")
        conditions["same_source_ip"] = conditions["same_source_ip"] or bool(layer.get("same_source_ip"))
        conditions["same_user"] = conditions["same_user"] or bool(layer.get("same_user"))

    group_dependencies: list[dict[str, Any]] = []
    for group in conditions["if_group"]:
        candidates = []
        if by_group:
            candidates = by_group.get(group.casefold(), [])
        group_dependencies.append(
            {
                "group": group,
                "candidate_rule_ids": candidates,
                "candidate_count": len(candidates),
                "resolution": "runtime_group_dependency",
            }
        )

    parent_rule_ids = [layer["rule_id"] for layer in ordered_layers if layer["rule_id"] != rule_id]
    semantic_logic = {
        "conditions": conditions,
        "group_dependencies": group_dependencies,
        "missing_parent_rule_ids": _dedupe(missing),
        "cycles": cycles,
    }
    status = "resolved"
    if cycles:
        status = "cycle_detected"
    elif missing:
        status = "partially_resolved"

    return {
        "root_rule_id": rule_id,
        "resolution_status": status,
        "parent_rule_ids": parent_rule_ids,
        "ancestor_chain": [layer["rule_id"] for layer in ordered_layers],
        "missing_parent_rule_ids": _dedupe(missing),
        "cycles": cycles,
        "group_dependencies": group_dependencies,
        "conditions": conditions,
        "raw_layers": [
            {
                "rule_id": layer["rule_id"],
                "description": layer.get("description"),
                "filename": layer.get("filename"),
                "details": layer.get("details", {}),
            }
            for layer in ordered_layers
        ],
        "content_hash": _sha256(semantic_logic),
    }


def normalize_wazuh_catalog(rules: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    raw_rules = list(rules)
    by_id, by_group = build_rule_indexes(raw_rules)
    output: list[dict[str, Any]] = []
    for rule_id in sorted(by_id):
        leaf = by_id[rule_id]
        effective = resolve_effective_logic(rule_id, by_id, by_group)
        output.append({**leaf, "effective_logic": effective, "content_hash": effective["content_hash"]})
    return output


def upsert_wazuh_catalog(connection: Any, rules: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    catalog = normalize_wazuh_catalog(rules)
    imported_at = _utc_now()
    for item in catalog:
        connection.execute(
            """
            INSERT INTO wazuh_rule_catalog (
                wazuh_rule_id, level, description, filename, relative_dir,
                groups_json, mitre_json, details_json, effective_logic_json,
                raw_rule_json, content_hash, imported_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(wazuh_rule_id) DO UPDATE SET
                level = excluded.level,
                description = excluded.description,
                filename = excluded.filename,
                relative_dir = excluded.relative_dir,
                groups_json = excluded.groups_json,
                mitre_json = excluded.mitre_json,
                details_json = excluded.details_json,
                effective_logic_json = excluded.effective_logic_json,
                raw_rule_json = excluded.raw_rule_json,
                content_hash = excluded.content_hash,
                imported_at = excluded.imported_at
            """,
            (
                item["rule_id"],
                item.get("level"),
                item.get("description"),
                item.get("filename"),
                item.get("relative_dir"),
                _json_text(item.get("groups", [])),
                _json_text(item.get("mitre", {})),
                _json_text({
                    "decoded_as": item.get("decoded_as", []),
                    "category": item.get("category", []),
                    "program_name": item.get("program_name", []),
                    "match": item.get("match", []),
                    "regex": item.get("regex", []),
                    "fields": item.get("fields", []),
                    "if_sid": item.get("if_sid", []),
                    "if_group": item.get("if_group", []),
                    "if_matched_sid": item.get("if_matched_sid", []),
                    "frequency": item.get("frequency"),
                    "timeframe": item.get("timeframe"),
                    "same_source_ip": item.get("same_source_ip", False),
                    "same_user": item.get("same_user", False),
                    "options": item.get("options", []),
                }),
                _json_text(item["effective_logic"]),
                _json_text(item.get("raw_rule", {})),
                item["content_hash"],
                imported_at,
            ),
        )
    connection.commit()

    status_counts: dict[str, int] = {}
    for item in catalog:
        status = item["effective_logic"]["resolution_status"]
        status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "stored": len(catalog),
        "resolution_status": status_counts,
        "imported_at": imported_at,
    }
