"""Unit tests for CampaignScope dashboard data integration."""

import unittest
from src.dashboard.app import load_dashboard_data


class TestDashboardData(unittest.TestCase):
    """Verifies dashboard data sources and structure."""

    def test_load_dashboard_data(self):
        """Verifies that all processed artifacts are loaded and consistent."""
        risk_df, ips_df, graphs_json, logs_df = load_dashboard_data()

        self.assertFalse(risk_df.empty)
        self.assertFalse(ips_df.empty)
        self.assertFalse(logs_df.empty)
        self.assertIsInstance(graphs_json, dict)
        self.assertGreater(len(graphs_json), 0)

        # Check expected columns
        self.assertIn("campaign_id", risk_df.columns)
        self.assertIn("risk_score", risk_df.columns)
        self.assertIn("ip_address", ips_df.columns)
        self.assertIn("campaign_id", ips_df.columns)

        # Check graph payload structure
        first_cid = list(graphs_json.keys())[0]
        self.assertIn("metrics", graphs_json[first_cid])
        self.assertIn("timeline", graphs_json[first_cid])
        self.assertIn("graph", graphs_json[first_cid])
        self.assertIn("nodes", graphs_json[first_cid]["graph"])
        self.assertIn("links", graphs_json[first_cid]["graph"])


if __name__ == "__main__":
    unittest.main()
