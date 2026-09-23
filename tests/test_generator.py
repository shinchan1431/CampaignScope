"""Unit tests for CampaignScope data generator and authentication schema."""

import os
import unittest
import csv
from src.generator.schema import AuthenticationEvent, RAW_COLUMNS, EVALUATION_COLUMNS
from src.generator.generate_logs import LogGenerator, GeneratorConfig


class TestGenerator(unittest.TestCase):
    """Tests for synthetic dataset generation and schema fidelity."""

    @classmethod
    def setUpClass(cls):
        # Generate a lightweight dataset (5,000 events) for fast test execution
        cls.config = GeneratorConfig(
            total_events=5000,
            campaign_alpha_ip_count=100,
            campaign_bravo_ip_count=40,
            corporate_nat_events=200,
            brute_force_events=60,
            random_seed=42,
        )
        cls.generator = LogGenerator(cls.config)
        cls.events, cls.stats = cls.generator.generate()

    def test_schema_columns(self):
        """Verifies column isolation between raw telemetry and evaluation ground truth."""
        event = self.events[0]
        raw_dict = event.to_raw_dict()
        eval_dict = event.to_evaluation_dict()

        self.assertEqual(list(raw_dict.keys()), RAW_COLUMNS)
        self.assertEqual(list(eval_dict.keys()), EVALUATION_COLUMNS)
        self.assertNotIn("is_malicious", raw_dict)
        self.assertNotIn("campaign_id", raw_dict)
        self.assertIn("is_malicious", eval_dict)
        self.assertIn("campaign_id", eval_dict)

    def test_low_and_slow_stealth_threshold(self):
        """Verifies that no coordinated bot IP exceeds 20 requests (evading traditional rate limiters)."""
        alpha_ips = {e.ip_address for e in self.events if e.campaign_id == "campaign_alpha"}
        ip_counts = {}
        for e in self.events:
            if e.ip_address in alpha_ips:
                ip_counts[e.ip_address] = ip_counts.get(e.ip_address, 0) + 1

        self.assertGreater(len(alpha_ips), 50)
        for ip, count in ip_counts.items():
            self.assertLessEqual(
                count, 20, f"Bot IP {ip} exceeded stealth threshold with {count} requests"
            )
            self.assertGreaterEqual(count, 4, f"Bot IP {ip} had too few attempts ({count})")

    def test_campaign_username_overlap(self):
        """Verifies that bot IPs share target accounts from the common breach pool."""
        alpha_ip_users = {}
        for e in self.events:
            if e.campaign_id == "campaign_alpha":
                if e.ip_address not in alpha_ip_users:
                    alpha_ip_users[e.ip_address] = set()
                alpha_ip_users[e.ip_address].add(e.username)

        # Pick pairs of bot IPs and verify intersection
        ips = list(alpha_ip_users.keys())
        shared_pairs = 0
        total_pairs_checked = min(len(ips) - 1, 30)
        for i in range(total_pairs_checked):
            ip1, ip2 = ips[i], ips[i + 1]
            overlap = alpha_ip_users[ip1].intersection(alpha_ip_users[ip2])
            if len(overlap) > 0:
                shared_pairs += 1

        # Across the breach pool, multiple bot IPs will share targets
        all_alpha_targets = [e.username for e in self.events if e.campaign_id == "campaign_alpha"]
        unique_alpha_targets = set(all_alpha_targets)
        # Average attempts per target must be > 1.0 (overlap)
        avg_target_hits = len(all_alpha_targets) / len(unique_alpha_targets)
        self.assertGreater(avg_target_hits, 1.2, "Campaign Alpha must exhibit target account overlap")

    def test_corporate_nat_benign_profile(self):
        """Verifies that corporate NAT exhibits high volume, diverse users, but low failure rate."""
        nat_events = [e for e in self.events if e.ip_address == self.generator.corporate_nat_ip]
        self.assertGreater(len(nat_events), 100)

        # Unique users behind the NAT
        unique_users = {e.username for e in nat_events}
        self.assertGreater(len(unique_users), 20)

        # Success rate must be >= 88%
        successes = sum(1 for e in nat_events if e.status_code == 200)
        success_rate = successes / len(nat_events)
        self.assertGreaterEqual(success_rate, 0.88)

    def test_single_ip_brute_force_profile(self):
        """Verifies single IP brute force exhibits rapid attempts against a single target with high failure."""
        brute_events = [e for e in self.events if e.ip_address == self.generator.brute_force_ip]
        self.assertGreaterEqual(len(brute_events), 50)

        # Single target
        unique_users = {e.username for e in brute_events}
        self.assertEqual(len(unique_users), 1)

        # Failure rate >= 95%
        failures = sum(1 for e in brute_events if e.status_code in (401, 429))
        self.assertGreaterEqual(failures / len(brute_events), 0.95)

    def test_csv_export_isolation(self):
        """Verifies that the generated raw CSV strictly omits ground-truth columns."""
        test_raw_path = "dataset/test_raw.csv"
        test_eval_path = "dataset/test_eval.csv"

        try:
            self.generator.save_to_csv(self.events[:100], test_raw_path, test_eval_path)

            with open(test_raw_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)
                self.assertEqual(header, RAW_COLUMNS)
                self.assertNotIn("is_malicious", header)
                self.assertNotIn("campaign_id", header)

            with open(test_eval_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                eval_header = next(reader)
                self.assertEqual(eval_header, EVALUATION_COLUMNS)
                self.assertIn("is_malicious", eval_header)
                self.assertIn("campaign_id", eval_header)
        finally:
            if os.path.exists(test_raw_path):
                os.remove(test_raw_path)
            if os.path.exists(test_eval_path):
                os.remove(test_eval_path)


if __name__ == "__main__":
    unittest.main()
