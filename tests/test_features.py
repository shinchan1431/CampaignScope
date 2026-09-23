"""Unit tests for CampaignScope behavioral feature extractor."""

import unittest
import pandas as pd
import numpy as np
from src.features.fingerprint import FeatureExtractor


class TestFeatureExtractor(unittest.TestCase):
    """Tests for behavioral feature calculations and fingerprint representations."""

    def setUp(self):
        self.extractor = FeatureExtractor()

    def test_feature_extraction_columns(self):
        """Verifies that all required metrics and normalized feature columns are present."""
        data = {
            "timestamp": ["2026-09-23 10:00:00", "2026-09-23 10:01:00", "2026-09-23 10:02:00"],
            "ip_address": ["103.21.45.8", "103.21.45.8", "103.21.45.8"],
            "username": ["alice", "bob", "charlie"],
            "endpoint": ["/login", "/login", "/login"],
            "user_agent": ["Chrome-120", "Chrome-120", "Chrome-120"],
            "status_code": [401, 401, 200],
            "country": ["IN", "IN", "IN"],
            "response_time": [150, 180, 200],
            "device_id": ["d1", "d1", "d1"],
        }
        df = pd.DataFrame(data)
        features = self.extractor.extract_features(df)

        expected_cols = [
            "ip_address", "total_requests", "failed_requests", "successful_requests",
            "failure_ratio", "unique_usernames", "username_diversity", "unique_endpoints",
            "endpoint_concentration", "unique_user_agents", "user_agent_concentration",
            "primary_user_agent", "primary_endpoint", "country", "active_duration_seconds",
            "requests_per_minute", "timing_regularity", "target_usernames",
            "feat_failure_ratio", "feat_username_diversity", "feat_endpoint_concentration",
            "feat_ua_concentration", "feat_timing_regularity", "feat_request_frequency"
        ]

        for col in expected_cols:
            self.assertIn(col, features.columns, f"Missing feature column: {col}")

        row = features.iloc[0]
        self.assertEqual(row["total_requests"], 3)
        self.assertEqual(row["failed_requests"], 2)
        self.assertEqual(row["successful_requests"], 1)
        self.assertAlmostEqual(row["failure_ratio"], 2 / 3, places=2)
        self.assertEqual(row["unique_usernames"], 3)
        self.assertAlmostEqual(row["username_diversity"], 1.0, places=2)
        self.assertEqual(row["endpoint_concentration"], 1.0)
        self.assertEqual(row["user_agent_concentration"], 1.0)

    def test_timing_regularity_bot_vs_human(self):
        """Verifies that automated periodic timing achieves high regularity compared to erratic timing."""
        # Bot: exactly 10s between requests (very low CV -> regularity near 1.0)
        bot_timestamps = pd.Series([
            "2026-09-23 10:00:00",
            "2026-09-23 10:00:10",
            "2026-09-23 10:00:20",
            "2026-09-23 10:00:30",
            "2026-09-23 10:00:40",
        ])
        bot_score = FeatureExtractor._compute_timing_regularity(bot_timestamps)
        self.assertGreater(bot_score, 0.90, f"Bot regularity should be near 1.0, got {bot_score}")

        # Human: erratic bursts and long idle intervals (high CV -> low regularity)
        human_timestamps = pd.Series([
            "2026-09-23 10:00:00",
            "2026-09-23 10:00:02",
            "2026-09-23 10:08:45",
            "2026-09-23 10:08:48",
            "2026-09-23 11:22:10",
        ])
        human_score = FeatureExtractor._compute_timing_regularity(human_timestamps)
        self.assertLess(human_score, 0.50, f"Human erratic timing should be < 0.50, got {human_score}")

    def test_corporate_nat_fingerprint(self):
        """Verifies corporate NAT has high diversity (many users) but very low failure ratio."""
        nat_data = {
            "timestamp": [f"2026-09-23 10:0{i}:00" for i in range(10)],
            "ip_address": ["198.51.100.25"] * 10,
            "username": [f"user_{i}" for i in range(10)],
            "endpoint": ["/login"] * 10,
            "user_agent": ["Chrome-122"] * 10,
            "status_code": [200] * 9 + [401],  # 90% success
            "country": ["US"] * 10,
            "response_time": [100] * 10,
            "device_id": [f"dev_{i}" for i in range(10)],
        }
        df = pd.DataFrame(nat_data)
        features = self.extractor.extract_features(df)
        nat_row = features.iloc[0]

        self.assertEqual(nat_row["unique_usernames"], 10)
        self.assertEqual(nat_row["username_diversity"], 1.0)
        self.assertEqual(nat_row["failure_ratio"], 0.1)  # Only 10% failure


if __name__ == "__main__":
    unittest.main()
