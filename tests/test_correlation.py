"""Unit tests for CampaignScope cross-IP correlation engine."""

import unittest
import pandas as pd
from src.correlation.similarity import CrossIPCorrelator, CorrelationWeights


class TestCrossIPCorrelator(unittest.TestCase):
    """Tests for multi-signal correlation and candidate pair evaluation."""

    def setUp(self):
        self.correlator = CrossIPCorrelator(min_composite_score=0.40)

    def test_correlated_bot_pair(self):
        """Verifies that two bot IPs with shared target accounts and matching signatures form a strong edge."""
        features_data = [
            {
                "ip_address": "103.21.45.8",
                "total_requests": 10,
                "failure_ratio": 1.0,
                "feat_failure_ratio": 1.0,
                "primary_user_agent": "Chrome-120",
                "primary_endpoint": "/login",
                "feat_timing_regularity": 0.85,
                "target_usernames": "alice@target.com|bob@target.com|charlie@target.com",
            },
            {
                "ip_address": "103.21.45.9",
                "total_requests": 10,
                "failure_ratio": 0.95,
                "feat_failure_ratio": 0.95,
                "primary_user_agent": "Chrome-120",
                "primary_endpoint": "/login",
                "feat_timing_regularity": 0.88,
                "target_usernames": "alice@target.com|bob@target.com|david@target.com",
            },
        ]
        df = pd.DataFrame(features_data)
        result = self.correlator.compute_correlations(df)

        self.assertEqual(len(result.edges_df), 1)
        edge = result.edges_df.iloc[0]

        # 2 shared targets: alice and bob
        self.assertEqual(edge["shared_targets_count"], 2)
        self.assertEqual(edge["ua_similarity"], 1.0)
        self.assertEqual(edge["endpoint_similarity"], 1.0)
        self.assertGreater(edge["timing_similarity"], 0.90)
        self.assertGreater(edge["composite_score"], 0.70)

    def test_benign_users_no_correlation(self):
        """Verifies that legitimate benign users with distinct accounts do not correlate."""
        features_data = [
            {
                "ip_address": "192.168.1.10",
                "total_requests": 10,
                "failure_ratio": 0.0,
                "feat_failure_ratio": 0.0,
                "primary_user_agent": "Chrome-122",
                "primary_endpoint": "/login",
                "feat_timing_regularity": 0.40,
                "target_usernames": "user_john@company.com",
            },
            {
                "ip_address": "192.168.1.20",
                "total_requests": 10,
                "failure_ratio": 0.0,
                "feat_failure_ratio": 0.0,
                "primary_user_agent": "Safari-17",
                "primary_endpoint": "/login",
                "feat_timing_regularity": 0.35,
                "target_usernames": "user_sarah@company.com",
            },
        ]
        df = pd.DataFrame(features_data)
        result = self.correlator.compute_correlations(df)

        # No shared accounts -> 0 edges
        self.assertEqual(len(result.edges_df), 0)


if __name__ == "__main__":
    unittest.main()
