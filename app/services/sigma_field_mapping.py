"""Canonical field mapping for Sigma-on-Wazuh Windows event evaluation.

The module keeps vendor-specific Wazuh paths out of the Sigma evaluator.  All
Windows comparisons are case-insensitive by default unless a Sigma field uses
``|cased``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


SIGMA_FIELD_TO_WAZUH_PATH: dict[str, str] = {
    "EventID": "data.win.system.eventID",
    "Channel": "data.win.system.channel",
    "Provider_Name": "data.win.system.providerName",
    "Computer": "data.win.system.computer",
    "Image": "data.win.eventdata.image",
    "CommandLine": "data.win.eventdata.commandLine",
    "ParentImage": "data.win.eventdata.parentImage",
    "User": "data.win.eventdata.user",
    "SubjectUserName": "data.win.eventdata.subjectUserName",
    "TargetUserName": "data.win.eventdata.targetUserName",
    "IpAddress": "data.win.eventdata.ipAddress",
    "SourceIp": "data.win.eventdata.ipAddress",
    "ServiceName": "data.win.eventdata.serviceName",
    "ObjectName": "data.win.eventdata.objectName",
    "AccessMask": "data.win.eventdata.accessMask",
    "TicketEncryptionType": "data.win.eventdata.ticketEncryptionType",
    "TicketOptions": "data.win.eventdata.ticketOptions",
    "PreAuthType": "data.win.eventdata.preAuthType",
}

SIGMA_FIELD_TO_CANONICAL: dict[str, str] = {
    "EventID": "event_id",
    "Channel": "channel",
    "Provider_Name": "provider_name",
    "Computer": "computer",
    "Image": "image",
    "CommandLine": "command_line",
    "ParentImage": "parent_image",
    "User": "user",
    "SubjectUserName": "subject_user_name",
    "TargetUserName": "target_user_name",
    "IpAddress": "ip_address",
    "SourceIp": "ip_address",
    "ServiceName": "service_name",
    "ObjectName": "object_name",
    "AccessMask": "access_mask",
    "TicketEncryptionType": "ticket_encryption_type",
    "TicketOptions": "ticket_options",
    "PreAuthType": "pre_auth_type",
}

# Direct aliases seen in ABSEGA's existing Wazuh normalizer and test data.
_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "EventID": ("event_id", "eventID", "EventId", "win.system.eventID"),
    "Channel": ("channel", "win.system.channel"),
    "Provider_Name": ("provider", "provider_name", "providerName", "win.system.providerName"),
    "Computer": ("computer", "win.system.computer"),
    "Image": ("image", "win.eventdata.image"),
    "CommandLine": ("command_line", "commandLine", "win.eventdata.commandLine"),
    "ParentImage": ("parent_image", "parentImage", "win.eventdata.parentImage"),
    "User": ("user", "win.eventdata.user"),
    "SubjectUserName": ("subject_user", "subject_user_name", "win.eventdata.subjectUserName"),
    "TargetUserName": ("target_user", "target_user_name", "win.eventdata.targetUserName"),
    "IpAddress": ("source_ip", "ip_address", "ipAddress", "win.eventdata.ipAddress"),
    "SourceIp": ("source_ip", "ip_address", "ipAddress", "win.eventdata.ipAddress"),
    "ServiceName": ("service_name", "serviceName", "win.eventdata.serviceName"),
    "ObjectName": ("object_name", "objectName", "win.eventdata.objectName"),
    "AccessMask": ("access_mask", "accessMask", "win.eventdata.accessMask"),
        "TicketEncryptionType": (
        "ticket_encryption_type",
        "ticketEncryptionType",
        "win.eventdata.ticketEncryptionType",
    ),
    "TicketOptions": (
        "ticket_options",
        "ticketOptions",
        "win.eventdata.ticketOptions",
    ),
    "PreAuthType": ("pre_auth_type", "preAuthType", "win.eventdata.preAuthType"),
}

_CANONICAL_LOOKUP = {
    key.casefold(): value for key, value in SIGMA_FIELD_TO_CANONICAL.items()
}
_CANONICAL_LOOKUP.update(
    {value.casefold(): value for value in SIGMA_FIELD_TO_CANONICAL.values()}
)


def canonical_field_name(field: str) -> str:
    """Return the canonical snake_case name for a Sigma field."""

    return _CANONICAL_LOOKUP.get(str(field).casefold(), str(field))


def get_nested_value(payload: Mapping[str, Any], dotted_path: str) -> Any:
    """Read a dotted path from nested or already-flattened dictionaries."""

    if dotted_path in payload:
        return payload[dotted_path]

    current: Any = payload
    for part in dotted_path.split("."):
        if not isinstance(current, Mapping):
            return None
        if part in current:
            current = current[part]
            continue

        # Wazuh keys are usually exact, but case-insensitive fallback makes the
        # adapter safer for user-created sample events.
        lowered = part.casefold()
        match = next((key for key in current if str(key).casefold() == lowered), None)
        if match is None:
            return None
        current = current[match]
    return current


def _candidate_payloads(event: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    candidates: list[Mapping[str, Any]] = [event]

    normalized = event.get("normalized_event")
    if isinstance(normalized, Mapping):
        candidates.append(normalized)

    sigma_event = event.get("sigma_event")
    if isinstance(sigma_event, Mapping):
        candidates.append(sigma_event)

    fields = event.get("fields")
    if isinstance(fields, Mapping):
        candidates.append(fields)

    nested_data = event.get("data")
    if isinstance(nested_data, Mapping):
        # Keep the full event first because required paths begin with data.*.
        candidates.append(nested_data)

    return candidates


def get_sigma_field_value(event: Mapping[str, Any], sigma_field: str) -> Any:
    """Resolve one Sigma field from direct, canonical, or Wazuh representations."""

    candidates = _candidate_payloads(event)
    direct_names = (
        sigma_field,
        SIGMA_FIELD_TO_CANONICAL.get(sigma_field, sigma_field),
        *_FIELD_ALIASES.get(sigma_field, ()),
    )

    for candidate in candidates:
        for name in direct_names:
            if name in candidate:
                return candidate[name]
            lowered = str(name).casefold()
            match = next(
                (key for key in candidate if str(key).casefold() == lowered),
                None,
            )
            if match is not None:
                return candidate[match]

    wazuh_path = SIGMA_FIELD_TO_WAZUH_PATH.get(sigma_field)
    if wazuh_path:
        for candidate in candidates:
            value = get_nested_value(candidate, wazuh_path)
            if value is not None:
                return value

            # A candidate may already be the object under top-level "data".
            if wazuh_path.startswith("data."):
                value = get_nested_value(candidate, wazuh_path.removeprefix("data."))
                if value is not None:
                    return value

    return None


def build_canonical_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """Convert a Wazuh/raw/sample event to the canonical field layer."""

    canonical: dict[str, Any] = {}
    for sigma_field, canonical_name in SIGMA_FIELD_TO_CANONICAL.items():
        # SourceIp and IpAddress intentionally map to the same canonical key.
        if canonical_name in canonical and canonical[canonical_name] is not None:
            continue
        canonical[canonical_name] = get_sigma_field_value(event, sigma_field)
    return canonical


def build_sigma_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """Return a Sigma-style event dictionary backed by canonical mapping."""

    return {
        sigma_field: get_sigma_field_value(event, sigma_field)
        for sigma_field in SIGMA_FIELD_TO_WAZUH_PATH
    }
