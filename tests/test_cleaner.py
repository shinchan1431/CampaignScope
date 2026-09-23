"""Unit tests for CampaignScope data cleaner and normalization logic."""

import unittest
import pandas as pd
from src.ingestion.cleaner import DataCleaner


class TestDataCleaner(unittest.TestCase):
    """Tests for individual normalization rules and dataframe cleaning."""

    def setUp(self):
        self.cleaner = DataCleaner()

    def test_user_agent_normalization(self):
        """Verifies normalization of varied User-Agent strings to canonical tokens."""
        test_cases = [
            ("chrome 120", "Chrome-120"),
            ("Chrome/120.0", "Chrome-120"),
            ("Chrome_120", "Chrome-120"),
            ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36", "Chrome-122"),
            ("FIREFOX_123", "Firefox-123"),
            ("Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0", "Firefox-123"),
            ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 Version/17.2 Safari/605.1.15", "Safari-17"),
            ("safari-mobile", "Safari-Mobile"),
            ("Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/121.0.6167.85 Safari/537.36", "HeadlessChrome-121"),
            ("HeadlessChrome-121", "HeadlessChrome-121"),
            ("curl/8.4.0", "Curl-8"),
            ("python-requests/2.31.0", "Requests-2"),
            ("Hydra/9.5", "Hydra-9"),
            ("", "Unknown"),
            (None, "Unknown"),
        ]

        for raw_ua, expected in test_cases:
            result = self.cleaner.normalize_user_agent(raw_ua)
            self.assertEqual(result, expected, f"Failed for User-Agent: '{raw_ua}' -> got '{result}'")

    def test_endpoint_normalization(self):
        """Verifies endpoint casing and trailing slash removal."""
        self.assertEqual(self.cleaner.normalize_endpoint("/LOGIN/"), "/login")
        self.assertEqual(self.cleaner.normalize_endpoint("/api/v1/auth/login/"), "/api/v1/auth/login")
        self.assertEqual(self.cleaner.normalize_endpoint("  /API/V1/AUTH/LOGIN  "), "/api/v1/auth/login")
        self.assertEqual(self.cleaner.normalize_endpoint(None), "/login")

    def test_username_normalization(self):
        """Verifies username whitespace stripping and lowercasing."""
        self.assertEqual(self.cleaner.normalize_username("  Alice@Example.COM  "), "alice@example.com")
        self.assertEqual(self.cleaner.normalize_username("BOB"), "bob")
        self.assertEqual(self.cleaner.normalize_username(None), "")

    def test_ipv4_validation(self):
        """Verifies valid vs invalid IPv4 strings."""
        self.assertTrue(self.cleaner.is_valid_ipv4("103.21.45.8"))
        self.assertTrue(self.cleaner.is_valid_ipv4("192.168.1.1"))
        self.assertFalse(self.cleaner.is_valid_ipv4("999.999.999.999"))
        self.assertFalse(self.cleaner.is_valid_ipv4("103.21.45"))
        self.assertFalse(self.cleaner.is_valid_ipv4("not_an_ip"))
        self.assertFalse(self.cleaner.is_valid_ipv4(None))

    def test_timestamp_normalization(self):
        """Verifies parsing and standardization of timestamps."""
        self.assertEqual(
            self.cleaner.normalize_timestamp("2026-09-23 10:15:03"),
            "2026-09-23 10:15:03",
        )
        self.assertEqual(
            self.cleaner.normalize_timestamp("2026-09-23T10:15:03Z"),
            "2026-09-23 10:15:03",
        )
        self.assertIsNone(self.cleaner.normalize_timestamp("not_a_time"))

    def test_clean_dataframe_pipeline(self):
        """Tests full DataFrame cleaning including dropped rows and duplicate removal."""
        dirty_data = {
            "timestamp": [
                "2026-09-23 10:15:01",
                "2026-09-23 10:15:02",
                "2026-09-23 10:15:02",  # Duplicate row
                "2026-09-23 10:15:03",  # Missing IP
                "2026-09-23 10:15:04",  # Invalid IP
                "invalid_time",         # Invalid timestamp
            ],
            "ip_address": [
                "103.21.45.8",
                "103.21.45.9",
                "103.21.45.9",
                None,
                "999.999.1.1",
                "103.21.45.10",
            ],
            "username": ["Alice", "Bob", "Bob", "Charlie", "David", "Eve"],
            "endpoint": ["/LOGIN/", "/login", "/login", "/login", "/login", "/login"],
            "user_agent": ["chrome 120", "Chrome_120", "Chrome_120", "Safari", "Safari", "Safari"],
            "status_code": [401, 200, 200, 200, 200, 200],
            "country": ["in", "us", "us", "us", "us", "us"],
            "response_time": [120, 150, 150, 100, 100, 100],
            "device_id": ["d1", "d2", "d2", "d3", "d4", "d5"],
        }

        df = pd.DataFrame(dirty_data)
        clean_df, stats = self.cleaner.clean_dataframe(df)

        # Expected: exactly 2 valid unique rows remaining
        self.assertEqual(len(clean_df), 2)
        self.assertEqual(stats["dropped_missing_critical"], 1)
        self.assertEqual(stats["dropped_invalid_ip"], 1)
        self.assertEqual(stats["dropped_invalid_timestamp"], 1)
        self.assertEqual(stats["dropped_duplicates"], 1)

        # Check normalization
        self.assertEqual(clean_df.iloc[0]["username"], "alice")
        self.assertEqual(clean_df.iloc[0]["endpoint"], "/login")
        self.assertEqual(clean_df.iloc[0]["user_agent"], "Chrome-120")
        self.assertEqual(clean_df.iloc[0]["country"], "IN")


if __name__ == "__main__":
    unittest.main()
