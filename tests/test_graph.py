"""Unit tests for CampaignScope investigation graph builder."""

import unittest
import pandas as pd
from src.graph.builder import CampaignGraphBuilder


class TestCampaignGraphBuilder(unittest.TestCase):
    """Tests for graph topology generation and campaign investigation payloads."""

    def setUp(self):
        self.risk_df = pd.DataFrame([{
            "campaign_id": "CAMPAIGN_01",
            "risk_score": 92.5,
            "classification": "CREDENTIAL_STUFFING",
            "ip_count": 5,
            "total_events": 50,
            "unique_target_accounts": 10,
            "avg_attempts_per_ip": 10.0,
            "primary_user_agent": "Chrome-120",
            "primary_endpoint": "/login",
            "top_origin_countries": "IN, US",
        }])

        self.clustered_df = pd.DataFrame([
            {
                "ip_address": f"103.21.45.{i}",
                "campaign_id": "CAMPAIGN_01",
                "cluster_id": 1,
                "total_requests": 10,
                "failure_ratio": 0.95,
                "primary_user_agent": "Chrome-120",
                "primary_endpoint": "/login",
                "country": "IN",
                "target_usernames": "alice@corp.com|bob@corp.com",
            }
            for i in range(1, 6)
        ])

        self.cleaned_logs_df = pd.DataFrame([
            {
                "timestamp": f"2026-09-23 09:{10 + i}:00",
                "ip_address": "103.21.45.1",
                "username": "alice@corp.com",
                "endpoint": "/login",
                "user_agent": "Chrome-120",
                "status_code": 401,
                "country": "IN",
                "response_time": 120,
                "device_id": "d1",
            }
            for i in range(10)
        ])

        self.builder = CampaignGraphBuilder(
            clustered_ips_df=self.clustered_df,
            campaign_risk_df=self.risk_df,
            cleaned_logs_df=self.cleaned_logs_df,
        )

    def test_graph_topology(self):
        """Verifies that heterogeneous nodes and relationships are properly created."""
        G = self.builder.G
        self.assertTrue(G.has_node("CAMPAIGN_01"))
        self.assertTrue(G.has_node("103.21.45.1"))
        self.assertTrue(G.has_node("ep::/login"))
        self.assertTrue(G.has_node("ua::Chrome-120"))

        # Verify edges
        self.assertTrue(G.has_edge("103.21.45.1", "CAMPAIGN_01"))
        self.assertTrue(G.has_edge("CAMPAIGN_01", "ep::/login"))
        self.assertTrue(G.has_edge("CAMPAIGN_01", "ua::Chrome-120"))

    def test_investigation_view_payload(self):
        """Verifies structured payload for interactive UI rendering."""
        view = self.builder.get_campaign_investigation_view("CAMPAIGN_01")

        self.assertEqual(view["campaign_id"], "CAMPAIGN_01")
        self.assertIn("metrics", view)
        self.assertEqual(view["metrics"]["risk_score"], 92.5)

        self.assertIn("timeline", view)
        self.assertIn("started", view["timeline"])
        self.assertIn("duration", view["timeline"])

        self.assertIn("graph", view)
        nodes = view["graph"]["nodes"]
        links = view["graph"]["links"]

        # Central campaign node + 1 endpoint + 1 UA + 5 IPs + 2 accounts = 10 nodes
        self.assertEqual(len(nodes), 10)
        self.assertGreater(len(links), 6)


if __name__ == "__main__":
    unittest.main()
