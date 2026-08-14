from __future__ import annotations

import unittest

from app.services.sigma_field_mapping import build_canonical_event
from app.services.sigma_rule_normalizer import (
    EVALUATOR_MATCH,
    EVALUATOR_NO_MATCH,
    EVALUATOR_UNSUPPORTED,
    evaluate_sigma_rule,
    normalize_sigma_rule,
)


POWERSHELL_RULE = r"""
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
  - attack.execution
  - attack.t1059.001
"""


WAZUH_EVENT = {
    "data": {
        "win": {
            "system": {
                "eventID": "1",
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "providerName": "Microsoft-Windows-Sysmon",
                "computer": "WIN11.absega.local",
            },
            "eventdata": {
                "image": (
                    r"C:\Windows\System32\WindowsPowerShell"
                    r"\v1.0\powershell.exe"
                ),
                "commandLine": (
                    r"powershell.exe -NoProfile "
                    r"-EncodedCommand AAAA"
                ),
                "parentImage": r"C:\Windows\explorer.exe",
                "user": r"ABSEGA\Ali",
                "ipAddress": "10.10.10.11",
            },
        }
    }
}


KERBEROS_RC4_RULE = r"""
title: Suspicious Kerberos RC4 Ticket Encryption
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    TicketOptions: '0x40810000'
  reduction:
    ServiceName|endswith: '$'
  condition: selection and not reduction
"""


WAZUH_KERBEROS_EVENT = {
    "data": {
        "win": {
            "system": {
                "eventID": "4769",
                "channel": "Security",
                "providerName": (
                    "Microsoft-Windows-Security-Auditing"
                ),
                "computer": "DC01.absega.local",
            },
            "eventdata": {
                "ticketOptions": "0x40810000",
                "ticketEncryptionType": "0x17",
                "serviceName": "svc_sql",
                "targetUserName": (
                    "Administrator@ABSEGA.LOCAL"
                ),
                "ipAddress": "::ffff:10.10.10.11",
                "status": "0x0",
            },
        }
    }
}


class SigmaNormalizerTests(unittest.TestCase):
    def test_normalized_shape(self) -> None:
        result = normalize_sigma_rule(POWERSHELL_RULE)

        self.assertTrue(result["supported"])
        self.assertEqual(result["product"], "windows")
        self.assertEqual(
            result["category"],
            "process_creation",
        )
        self.assertEqual(
            result["channels"],
            ["Microsoft-Windows-Sysmon/Operational"],
        )
        self.assertEqual(result["event_ids"], ["1"])
        self.assertEqual(result["mitre"], ["T1059.001"])

        operators = {
            item["operator"]
            for item in result["conditions"]
        }

        self.assertIn("endswith", operators)
        self.assertIn("contains", operators)

    def test_field_mapping(self) -> None:
        event = build_canonical_event(WAZUH_EVENT)

        self.assertEqual(event["event_id"], "1")
        self.assertIn(
            "-EncodedCommand",
            event["command_line"],
        )
        self.assertEqual(
            event["ip_address"],
            "10.10.10.11",
        )

    def test_case_insensitive_match(self) -> None:
        event = {
            **WAZUH_EVENT,
            "data": {
                "win": {
                    "system": (
                        WAZUH_EVENT["data"]["win"]["system"]
                    ),
                    "eventdata": {
                        **WAZUH_EVENT[
                            "data"
                        ]["win"]["eventdata"],
                        "commandLine": (
                            "POWERSHELL.EXE -ENC AAAA"
                        ),
                    },
                }
            },
        }

        result = evaluate_sigma_rule(
            POWERSHELL_RULE,
            event,
        )

        self.assertEqual(
            result["status"],
            EVALUATOR_MATCH,
        )
        self.assertTrue(result["matched"])

    def test_not_filter_blocks(self) -> None:
        event = {
            "data": {
                "win": {
                    "system": (
                        WAZUH_EVENT["data"]["win"]["system"]
                    ),
                    "eventdata": {
                        **WAZUH_EVENT[
                            "data"
                        ]["win"]["eventdata"],
                        "user": (
                            "ABSEGA\\approved-admin"
                        ),
                    },
                }
            }
        }

        result = evaluate_sigma_rule(
            POWERSHELL_RULE,
            event,
        )

        self.assertEqual(
            result["status"],
            EVALUATOR_NO_MATCH,
        )
        self.assertFalse(result["matched"])

    def test_contains_all(self) -> None:
        rule = r"""
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - powershell
      - encodedcommand
  condition: selection
"""

        result = evaluate_sigma_rule(
            rule,
            WAZUH_EVENT,
        )

        self.assertEqual(
            result["status"],
            EVALUATOR_MATCH,
        )

    def test_startswith_and_regex(self) -> None:
        rule = r"""
logsource:
  product: windows
  category: process_creation
detection:
  selection_a:
    CommandLine|startswith: powershell.exe
  selection_b:
    CommandLine|re: '(?i)-encodedcommand\s+[A-Z0-9]+'
  condition: all of selection*
"""

        result = evaluate_sigma_rule(
            rule,
            WAZUH_EVENT,
        )

        self.assertEqual(
            result["status"],
            EVALUATOR_MATCH,
        )

    def test_one_of_selection(self) -> None:
        rule = r"""
logsource:
  product: windows
  category: process_creation
detection:
  selection_one:
    Image|endswith: '\cmd.exe'
  selection_two:
    Image|endswith: '\powershell.exe'
  condition: 1 of selection*
"""

        result = evaluate_sigma_rule(
            rule,
            WAZUH_EVENT,
        )

        self.assertEqual(
            result["status"],
            EVALUATOR_MATCH,
        )

    def test_unsupported_is_not_miss(self) -> None:
        rule = r"""
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|base64: powershell
  condition: selection
"""

        result = evaluate_sigma_rule(
            rule,
            WAZUH_EVENT,
        )

        self.assertEqual(
            result["status"],
            EVALUATOR_UNSUPPORTED,
        )
        self.assertIsNone(result["matched"])

    def test_ticket_options_canonical_mapping(
        self,
    ) -> None:
        canonical_event = build_canonical_event(
            WAZUH_KERBEROS_EVENT
        )

        self.assertEqual(
            canonical_event["event_id"],
            "4769",
        )
        self.assertEqual(
            canonical_event["service_name"],
            "svc_sql",
        )
        self.assertEqual(
            canonical_event[
                "ticket_encryption_type"
            ],
            "0x17",
        )
        self.assertEqual(
            canonical_event["ticket_options"],
            "0x40810000",
        )
        self.assertEqual(
            canonical_event["ip_address"],
            "::ffff:10.10.10.11",
        )

    def test_kerberos_rc4_ticket_sigma_match(
        self,
    ) -> None:
        result = evaluate_sigma_rule(
            KERBEROS_RC4_RULE,
            WAZUH_KERBEROS_EVENT,
        )

        self.assertEqual(
            result["status"],
            EVALUATOR_MATCH,
        )
        self.assertTrue(result["matched"])
        self.assertTrue(
            result["selection_results"]["selection"]
        )
        self.assertFalse(
            result["selection_results"]["reduction"]
        )
        self.assertEqual(
            result["canonical_event"][
                "ticket_options"
            ],
            "0x40810000",
        )
        self.assertIn(
            "TicketOptions: matched exact",
            result["trace"]["selection"],
        )
        self.assertIn(
            "ServiceName: no endswith value matched",
            result["trace"]["reduction"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)