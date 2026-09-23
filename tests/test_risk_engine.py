"""Unit tests for CampaignScope risk and explainability engine."""

import unittest
import pandas as pd
from src.risk_engine.scorer import CampaignRiskEngine, RiskWeights


class TestCampaignRiskEngine(unittest.TestCase):
    """Tests for risk scoring calculations and reason generation."""

    def setUp(self):
        self.engine = CampaignRiskEngine()

    def test_high_risk_credential_stuffing_assessment(self):
        """Verifies that an attack campaign with high failure, shared targets, and matching UAs is scored as high risk."""
        summary_row = pd.Series({
            "campaign_id": "CAMPAIGN_01",
            "ip_count": 800,
            "total_events": 7979,
            "unique_target_accounts": 400,
            "avg_attempts_per_ip": 9.97,
            "mean_failure_ratio": 0.94,
            "mean_timing_regularity": 0.70,
            "primary_user_agent": "Chrome-120",
            "primary_endpoint": "/api/v1/auth/login",
            "top_origin_countries": "RU, DE, CN",
        })

        ips_df = pd.DataFrame({
            "ip_address": [f"103.21.45.{i}" for i in range(800)],
            "primary_user_agent": ["Chrome-120"] * 800,
            "primary_endpoint": ["/api/v1/auth/login"] * 800,
        })

        assessment = self.engine.assess_campaign(summary_row, ips_df)

        self.assertGreaterEqual(assessment.risk_score, 80.0)
        self.assertEqual(assessment.classification, "CREDENTIAL_STUFFING")
        self.assertEqual(assessment.ua_similarity_pct, 100.0)
        self.assertEqual(assessment.endpoint_similarity_pct, 100.0)
        self.assertEqual(assessment.failure_behavior_pct, 94.0)

        # Check reason generation
        reasons_text = " ".join(assessment.reasons)
        self.assertIn("800", reasons_text)
        self.assertIn("94.0% authentication failure", reasons_text)
        self.assertIn("Chrome-120", reasons_text)
        self.assertIn("/api/v1/auth/login", reasons_text)

    def test_low_risk_campaign(self):
        """Verifies that a low failure activity is classified as LOW_RISK."""
        summary_row = pd.Series({
            "campaign_id": "CAMPAIGN_BENIGN",
            "ip_count": 10,
            "total_events": 20,
            "unique_target_accounts": 20,
            "avg_attempts_per_ip": 2.0,
            "mean_failure_ratio": 0.05,
            "mean_timing_regularity": 0.20,
            "primary_user_agent": "Safari-17",
            "primary_endpoint": "/login",
            "top_origin_countries": "US",
        })

        ips_df = pd.DataFrame({
            "ip_address": [f"192.168.1.{i}" for i in range(10)],
            "primary_user_agent": ["Safari-17"] * 5 + ["Firefox-123"] * 5,
            "primary_endpoint": ["/login"] * 10,
        })

        assessment = self.engine.assess_campaign(summary_row, ips_df)
        self.assertLess(assessment.risk_score, 50.0)
        self.assertEqual(assessment.classification, "LOW_RISK")


if __name__ == "__main__":
    unittest.main()
