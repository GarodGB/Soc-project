import unittest
from unittest.mock import patch

from app.services import rule_content_compare as comparator


class Step7ScoringTests(unittest.TestCase):
    def _compare(
        self,
        similarities,
        *,
        resolution_status="unknown",
    ):
        wazuh_rule = {
            "rule_id": 999999,
            "effective_logic": {
                "resolution_status": resolution_status,
                "conditions": {
                    "mitre": {
                        "id": ["T1059.001"],
                    },
                },
            },
        }

        sigma_rule = {
            "detection_id": 888888,
            "fields": [],
            "values": [],
            "event_ids": [],
            "mitre": ["T1059.001"],
        }

        wazuh_features = {
            "event_ids": set(),
            "fields": set(),
            "values": set(),
        }

        with patch.object(
            comparator,
            "_wazuh_features",
            return_value=wazuh_features,
        ), patch.object(
            comparator,
            "_source_terms_wazuh",
            return_value=set(),
        ), patch.object(
            comparator,
            "_source_terms_sigma",
            return_value=set(),
        ), patch.object(
            comparator,
            "_jaccard",
            side_effect=similarities,
        ):
            return comparator.compare_rule_content(
                wazuh_rule,
                sigma_rule,
            )

    def test_weighted_partial_overlap(self):
        result = self._compare(
            [0.5, 0.5, 0.25, 0.0, 1.0],
            resolution_status="resolved",
        )

        self.assertEqual(
            result["scores"]["total"],
            0.4,
        )
        self.assertEqual(
            result["scores"]["total_percent"],
            40.0,
        )
        self.assertEqual(
            result["verdict"],
            "PARTIAL_OVERLAP",
        )

    def test_mapping_only(self):
        result = self._compare(
            [0.5, 0.0, 0.0, 0.0, 1.0],
        )

        self.assertEqual(
            result["verdict"],
            "MAPPING_ONLY",
        )

    def test_strong_static_overlap_threshold(self):
        result = self._compare(
            [1.0, 1.0, 1.0, 1.0, 1.0],
            resolution_status="resolved",
        )

        self.assertEqual(
            result["scores"]["total"],
            1.0,
        )
        self.assertEqual(
            result["scores"]["total_percent"],
            100.0,
        )
        self.assertEqual(
            result["verdict"],
            "STRONG_STATIC_OVERLAP",
        )

    def test_likely_static_overlap_threshold(self):
        result = self._compare(
            [1.0, 1.0, 1.0, 0.0, 0.0],
        )

        self.assertEqual(
            result["scores"]["total"],
            0.6,
        )
        self.assertEqual(
            result["verdict"],
            "LIKELY_STATIC_OVERLAP",
        )

    def test_no_content_overlap_threshold(self):
        result = self._compare(
            [0.0, 0.0, 0.0, 0.0, 0.0],
        )

        self.assertEqual(
            result["scores"]["total"],
            0.0,
        )
        self.assertEqual(
            result["verdict"],
            "NO_CONTENT_OVERLAP",
        )


if __name__ == "__main__":
    unittest.main()
