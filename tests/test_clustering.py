"""Unit tests for CampaignScope campaign clustering engine."""

import unittest
import pandas as pd
from src.clustering.campaign_detector import CampaignClusterer


class TestCampaignClusterer(unittest.TestCase):
    """Tests for DBSCAN and graph-assisted campaign clustering."""

    def setUp(self):
        self.clusterer = CampaignClusterer(min_campaign_members=3, min_failure_ratio=0.70)

    def test_campaign_clustering_and_noise_separation(self):
        """Verifies that coordinated bot groups form clusters while benign IPs are marked as noise."""
        features = [
            # Campaign Alpha IPs (high failure, Chrome-120, shared targets A)
            {
                "ip_address": f"103.21.45.{i}",
                "total_requests": 10,
                "failure_ratio": 0.95,
                "username_diversity": 1.0,
                "endpoint_concentration": 1.0,
                "user_agent_concentration": 1.0,
                "primary_user_agent": "Chrome-120",
                "primary_endpoint": "/login",
                "country": "IN",
                "timing_regularity": 0.85,
                "target_usernames": "alice|bob|charlie",
                "feat_failure_ratio": 0.95,
                "feat_username_diversity": 1.0,
                "feat_endpoint_concentration": 1.0,
                "feat_ua_concentration": 1.0,
                "feat_timing_regularity": 0.85,
            }
            for i in range(1, 6)
        ] + [
            # Benign Noise IPs (low failure, diverse, single user)
            {
                "ip_address": f"192.168.1.{i}",
                "total_requests": 5,
                "failure_ratio": 0.0,
                "username_diversity": 0.2,
                "endpoint_concentration": 1.0,
                "user_agent_concentration": 1.0,
                "primary_user_agent": "Firefox-123",
                "primary_endpoint": "/login",
                "country": "US",
                "timing_regularity": 0.20,
                "target_usernames": f"user_{i}",
                "feat_failure_ratio": 0.0,
                "feat_username_diversity": 0.2,
                "feat_endpoint_concentration": 1.0,
                "feat_ua_concentration": 1.0,
                "feat_timing_regularity": 0.20,
            }
            for i in range(1, 4)
        ]
        df_features = pd.DataFrame(features)

        # Correlation edges linking the 5 Alpha bot IPs together
        edges = []
        for i in range(1, 5):
            edges.append({
                "ip_1": f"103.21.45.{i}",
                "ip_2": f"103.21.45.{i+1}",
                "shared_targets_count": 3,
                "composite_score": 0.90,
            })
        df_edges = pd.DataFrame(edges)

        result = self.clusterer.cluster_campaigns(df_features, df_edges)

        # Check that benign IPs are marked as noise
        benign_rows = result.clustered_ips_df[result.clustered_ips_df["ip_address"].str.startswith("192.168.1.")]
        for _, row in benign_rows.iterrows():
            self.assertEqual(row["cluster_id"], -1)
            self.assertEqual(row["campaign_id"], "BENIGN_NOISE")

        # Check that bot IPs are clustered into a campaign
        bot_rows = result.clustered_ips_df[result.clustered_ips_df["ip_address"].str.startswith("103.21.45.")]
        for _, row in bot_rows.iterrows():
            self.assertNotEqual(row["cluster_id"], -1)
            self.assertTrue(row["campaign_id"].startswith("CAMPAIGN_"))

        # Check summary profiles
        self.assertEqual(len(result.campaign_summaries_df), 1)
        summary = result.campaign_summaries_df.iloc[0]
        self.assertEqual(summary["ip_count"], 5)
        self.assertEqual(summary["unique_target_accounts"], 3)
        self.assertAlmostEqual(summary["mean_failure_ratio"], 0.95, places=2)


if __name__ == "__main__":
    unittest.main()
