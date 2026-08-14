from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping


def nested_get(obj: Mapping[str, Any], path: str, default: Any = None) -> Any:
    current: Any = obj
    for part in path.split("."):
        if not isinstance(current, Mapping):
            return default
        current = current.get(part)
        if current is None:
            return default
    return current


def _first(event: Mapping[str, Any], *paths: str) -> Any:
    for path in paths:
        value = nested_get(event, path)
        if value not in (None, "", [], {}):
            return value
    return None


def _fingerprint(material: Mapping[str, Any]) -> str:
    raw = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def normalize_wazuh_event(event: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(event, Mapping):
        raise ValueError("Wazuh event must be a JSON object")

    event_id = _first(
        event,
        "data.win.system.eventID",
        "data.win.system.eventId",
        "win.system.eventID",
        "EventID",
        "event_id",
    )
    channel = _first(event, "data.win.system.channel", "win.system.channel", "Channel", "channel")
    provider = _first(
        event,
        "data.win.system.providerName",
        "data.win.system.provider_name",
        "win.system.providerName",
        "Provider_Name",
        "provider",
    )
    image = _first(event, "data.win.eventdata.image", "win.eventdata.image", "Image", "process.executable")
    command_line = _first(
        event,
        "data.win.eventdata.commandLine",
        "data.win.eventdata.commandline",
        "win.eventdata.commandLine",
        "CommandLine",
        "process.command_line",
    )
    parent_image = _first(
        event,
        "data.win.eventdata.parentImage",
        "data.win.eventdata.parentimage",
        "ParentImage",
        "process.parent.executable",
    )
    user = _first(
        event,
        "data.win.eventdata.user",
        "data.win.eventdata.userName",
        "data.win.eventdata.subjectUserName",
        "User",
        "user.name",
    )
    source_ip = _first(
        event,
        "data.win.eventdata.ipAddress",
        "data.srcip",
        "srcip",
        "agent.ip",
        "SourceIp",
        "source.ip",
    )
    target_user = _first(event, "data.win.eventdata.targetUserName", "TargetUserName")
    subject_user = _first(event, "data.win.eventdata.subjectUserName", "SubjectUserName")
    pipe_name = _first(event, "data.win.eventdata.pipeName", "PipeName", "file.name")
    file_name = _first(event, "data.win.eventdata.targetFilename", "TargetFilename", "file.name")

    wazuh_rule_id = _first(event, "rule.id", "rule_id")
    try:
        wazuh_rule_id = int(wazuh_rule_id) if wazuh_rule_id not in (None, "") else None
    except (TypeError, ValueError):
        wazuh_rule_id = None

    normalized_fields = {
        "event_id": str(event_id) if event_id not in (None, "") else None,
        "channel": channel,
        "provider": provider,
        "image": image,
        "command_line": command_line,
        "parent_image": parent_image,
        "user": user,
        "source_ip": source_ip,
        "target_user": target_user,
        "subject_user": subject_user,
        "pipe_name": pipe_name,
        "file_name": file_name,
    }

    sigma_event = {
        "EventID": normalized_fields["event_id"],
        "Channel": channel,
        "Provider_Name": provider,
        "Image": image,
        "CommandLine": command_line,
        "ParentImage": parent_image,
        "User": user,
        "SourceIp": source_ip,
        "TargetUserName": target_user,
        "SubjectUserName": subject_user,
        "PipeName": pipe_name,
        "TargetFilename": file_name,
        "event_id": normalized_fields["event_id"],
        "channel": channel,
        "provider": provider,
        "image": image,
        "command_line": command_line,
        "parent_image": parent_image,
        "user": user,
        "source_ip": source_ip,
        "target_user": target_user,
        "subject_user": subject_user,
        "pipe_name": pipe_name,
        "file_name": file_name,
        "agent": dict(event.get("agent") or {}),
        "rule": dict(event.get("rule") or {}),
        "data": dict(event.get("data") or {}),
    }

    fingerprint_material = {
        "agent": _first(event, "agent.id", "agent.name"),
        "channel": channel,
        "event_id": normalized_fields["event_id"],
        "record_id": _first(event, "data.win.system.eventRecordID"),
        "computer": _first(event, "data.win.system.computer"),
        "system_time": _first(event, "data.win.system.systemTime", "timestamp"),
        "image": image,
        "command_line": command_line,
    }

    return {
        "event_type": "wazuh_alert" if wazuh_rule_id is not None else "wazuh_archive_event",
        "timestamp": event.get("timestamp"),
        "agent_name": _first(event, "agent.name"),
        "agent_ip": _first(event, "agent.ip"),
        "wazuh_rule_id": wazuh_rule_id,
        "wazuh_rule_level": _first(event, "rule.level"),
        "wazuh_rule_description": _first(event, "rule.description"),
        "fields": normalized_fields,
        "sigma_event": sigma_event,
        "event_fingerprint": _fingerprint(fingerprint_material),
        "raw_event": dict(event),
    }
