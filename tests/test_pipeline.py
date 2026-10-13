import unittest
from pathlib import Path

from src.data_engineering.process_logs import load_cloudtrail, normalize_events, build_activity_features
from src.security.detection_rules import detect_rule_findings

ROOT = Path(__file__).resolve().parents[1]


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        records = load_cloudtrail(ROOT / "data" / "sample_cloudtrail.json")
        cls.events = normalize_events(records)

    def test_sample_records_load(self):
        self.assertGreaterEqual(len(self.events), 1)

    def test_normalized_columns_exist(self):
        self.assertIn("event_name", self.events.columns)
        self.assertIn("identity_arn", self.events.columns)

    def test_features_have_expected_columns(self):
        features = build_activity_features(self.events)
        self.assertIn("api_call_count", features.columns)
        self.assertIn("failed_login_count", features.columns)

    def test_repeated_failed_login_rule_fires(self):
        findings = detect_rule_findings(self.events, failed_login_threshold=3)
        rule_ids = {finding["rule_id"] for finding in findings}
        self.assertIn("REPEATED_FAILED_CONSOLE_LOGIN", rule_ids)


if __name__ == "__main__":
    unittest.main()
