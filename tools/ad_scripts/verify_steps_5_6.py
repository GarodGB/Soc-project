from __future__ import annotations

import json

from app.services.sigma_field_mapping import build_canonical_event
from app.services.sigma_rule_normalizer import evaluate_sigma_rule, normalize_sigma_rule


RULE = r"""
title: Encoded PowerShell
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    Image|endswith: '\powershell.exe'
  selection_cli:
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc'
  filter_admin:
    User|contains: 'approved-admin'
  condition: all of selection* and not filter*
falsepositives:
  - Administrative scripts
tags:
  - attack.t1059.001
"""

EVENT = {
    "data": {
        "win": {
            "system": {
                "eventID": "1",
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "providerName": "Microsoft-Windows-Sysmon",
                "computer": "WIN11.absega.local",
            },
            "eventdata": {
                "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "commandLine": "powershell.exe -NoProfile -EncodedCommand AAAA",
                "parentImage": r"C:\Windows\explorer.exe",
                "user": r"ABSEGA\Ali",
                "ipAddress": "10.10.10.11",
            },
        }
    }
}

UNSUPPORTED_RULE = r"""
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|base64: powershell
  condition: selection
"""


normalized = normalize_sigma_rule(RULE)
summary = {
    "status": normalized["status"],
    "product": normalized["product"],
    "category": normalized["category"],
    "service": normalized["service"],
    "channels": normalized["channels"],
    "event_ids": normalized["event_ids"],
    "conditions": [
        {
            "field": item["field"],
            "operator": item["operator"],
            "values": item["values"],
        }
        for item in normalized["conditions"]
        if item["field"] in {"Image", "CommandLine"}
    ],
    "mitre": normalized["mitre"],
}

print("=== NORMALIZED RULE ===")
print(json.dumps(summary, indent=2))
print("\n=== CANONICAL EVENT ===")
print(json.dumps(build_canonical_event(EVENT), indent=2))
print("\n=== SUPPORTED EVALUATION ===")
print(json.dumps(evaluate_sigma_rule(RULE, EVENT), indent=2, default=str))
print("\n=== UNSUPPORTED EVALUATION ===")
print(json.dumps(evaluate_sigma_rule(UNSUPPORTED_RULE, EVENT), indent=2, default=str))
