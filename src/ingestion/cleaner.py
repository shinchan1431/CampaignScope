"""Data Cleaning & Normalization Engine for CampaignScope.

Transforms raw, noisy, or unnormalized authentication telemetry into
standardized records suitable for behavioral fingerprinting and correlation.
"""

import re
import ipaddress
from datetime import datetime
from typing import Optional, Tuple, Dict, Any
from dataclasses import dataclass
import pandas as pd


@dataclass
class CleanedEvent:
    """Represents a validated, normalized authentication event."""

    timestamp: str
    ip_address: str
    username: str
    endpoint: str
    user_agent: str
    user_agent_raw: str
    status_code: int
    country: str
    response_time: int
    device_id: str


class DataCleaner:
    """Cleans, validates, and normalizes authentication event streams and DataFrames."""

    # User-Agent Normalization Regexes
    RE_CHROME = re.compile(r"(?:headlesschrome|chrome)[/_\s\-]?(\d+)", re.IGNORECASE)
    RE_FIREFOX = re.compile(r"firefox[/_\s\-]?(\d+)", re.IGNORECASE)
    RE_EDGE = re.compile(r"edge[/_\s\-]?(\d+)", re.IGNORECASE)
    RE_SAFARI_VER = re.compile(r"version[/_\s\-]?(\d+)(?:\.\d+)*\s+safari", re.IGNORECASE)
    RE_SAFARI = re.compile(r"safari", re.IGNORECASE)
    RE_REQUESTS = re.compile(r"python-requests[/_\s\-]?(\d+)", re.IGNORECASE)
    RE_CURL = re.compile(r"curl[/_\s\-]?(\d+)", re.IGNORECASE)
    RE_HYDRA = re.compile(r"hydra[/_\s\-]?(\d+)", re.IGNORECASE)

    @classmethod
    def normalize_user_agent(cls, ua: Optional[str]) -> str:
        """Normalizes noisy User-Agent strings into standardized family-version tokens.

        Examples:
            'Chrome/120.0.0.0' -> 'Chrome-120'
            'chrome 120'       -> 'Chrome-120'
            'Chrome_120'       -> 'Chrome-120'
            'FIREFOX_123'      -> 'Firefox-123'
            'safari-mobile'    -> 'Safari-Mobile'
            'curl/8.4.0'       -> 'Curl-8'
        """
        if not ua or not isinstance(ua, str) or not ua.strip():
            return "Unknown"

        ua_clean = ua.strip()

        # Check for Headless Chrome
        if "headless" in ua_clean.lower():
            m = cls.RE_CHROME.search(ua_clean)
            return f"HeadlessChrome-{m.group(1)}" if m else "HeadlessChrome"

        # Check for Edge
        m = cls.RE_EDGE.search(ua_clean)
        if m:
            return f"Edge-{m.group(1)}"

        # Check for Standard Chrome
        m = cls.RE_CHROME.search(ua_clean)
        if m:
            return f"Chrome-{m.group(1)}"

        # Check for Firefox
        m = cls.RE_FIREFOX.search(ua_clean)
        if m:
            return f"Firefox-{m.group(1)}"

        # Check for Safari
        m = cls.RE_SAFARI_VER.search(ua_clean)
        if m:
            return f"Safari-{m.group(1)}"
        if cls.RE_SAFARI.search(ua_clean):
            if "mobile" in ua_clean.lower():
                return "Safari-Mobile"
            return "Safari"

        # Check for Automation Tools / Scripts
        m = cls.RE_REQUESTS.search(ua_clean)
        if m:
            return f"Requests-{m.group(1)}"

        m = cls.RE_CURL.search(ua_clean)
        if m:
            return f"Curl-{m.group(1)}"

        m = cls.RE_HYDRA.search(ua_clean)
        if m:
            return f"Hydra-{m.group(1)}"

        return "Other"

    @classmethod
    def normalize_endpoint(cls, endpoint: Optional[str]) -> str:
        """Normalizes API and web authentication endpoints."""
        if not endpoint or not isinstance(endpoint, str):
            return "/login"
        ep = endpoint.strip().lower()
        if len(ep) > 1 and ep.endswith("/"):
            ep = ep[:-1]
        return ep

    @classmethod
    def normalize_username(cls, username: Optional[str]) -> str:
        """Standardizes username/email casing and whitespace."""
        if not username or not isinstance(username, str):
            return ""
        return username.strip().lower()

    @classmethod
    def is_valid_ipv4(cls, ip: Optional[str]) -> bool:
        """Validates IPv4 string format."""
        if not ip or not isinstance(ip, str):
            return False
        try:
            addr = ipaddress.IPv4Address(ip.strip())
            return True
        except ValueError:
            return False

    @classmethod
    def normalize_timestamp(cls, ts: Optional[str]) -> Optional[str]:
        """Normalizes various timestamp formats into 'YYYY-MM-DD HH:MM:SS'."""
        if not ts or not isinstance(ts, str):
            return None
        ts = ts.strip()
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y/%m/%d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(ts, fmt)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
        return None

    def clean_dataframe(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Applies comprehensive data cleaning and filtering across a raw DataFrame.

        Returns:
            Tuple of (cleaned_df, cleaning_metrics_dict)
        """
        initial_count = len(df)
        stats = {
            "initial_rows": initial_count,
            "dropped_missing_critical": 0,
            "dropped_invalid_ip": 0,
            "dropped_invalid_timestamp": 0,
            "dropped_duplicates": 0,
            "final_rows": 0,
            "normalized_user_agents": 0,
        }

        # 1. Check critical missing fields (ip, username, timestamp)
        df_clean = df.copy()
        crit_mask = (
            df_clean["ip_address"].notna()
            & df_clean["username"].notna()
            & df_clean["timestamp"].notna()
            & (df_clean["ip_address"].astype(str).str.strip() != "")
            & (df_clean["username"].astype(str).str.strip() != "")
        )
        stats["dropped_missing_critical"] = int((~crit_mask).sum())
        df_clean = df_clean[crit_mask].copy()

        # 2. Validate IP Addresses
        valid_ip_mask = df_clean["ip_address"].apply(self.is_valid_ipv4)
        stats["dropped_invalid_ip"] = int((~valid_ip_mask).sum())
        df_clean = df_clean[valid_ip_mask].copy()

        # 3. Normalize & Validate Timestamps
        norm_ts = df_clean["timestamp"].apply(self.normalize_timestamp)
        valid_ts_mask = norm_ts.notna()
        stats["dropped_invalid_timestamp"] = int((~valid_ts_mask).sum())
        df_clean = df_clean[valid_ts_mask].copy()
        df_clean["timestamp"] = norm_ts[valid_ts_mask]

        # 4. Standardize text fields
        df_clean["username"] = df_clean["username"].apply(self.normalize_username)
        df_clean["endpoint"] = df_clean["endpoint"].apply(self.normalize_endpoint)
        df_clean["user_agent_raw"] = df_clean["user_agent"].astype(str)
        df_clean["user_agent"] = df_clean["user_agent_raw"].apply(self.normalize_user_agent)
        stats["normalized_user_agents"] = int((df_clean["user_agent"] != df_clean["user_agent_raw"]).sum())

        # Ensure numeric status_code & response_time
        df_clean["status_code"] = pd.to_numeric(df_clean["status_code"], errors="coerce").fillna(400).astype(int)
        df_clean["response_time"] = pd.to_numeric(df_clean["response_time"], errors="coerce").fillna(100).astype(int)
        df_clean["country"] = df_clean["country"].fillna("XX").astype(str).str.upper()
        df_clean["device_id"] = df_clean["device_id"].fillna("unknown_device").astype(str)

        # 5. Remove exact duplicates on (timestamp, ip_address, username, endpoint)
        dup_mask = df_clean.duplicated(subset=["timestamp", "ip_address", "username", "endpoint"], keep="first")
        stats["dropped_duplicates"] = int(dup_mask.sum())
        df_clean = df_clean[~dup_mask].copy()

        # Sort chronologically
        df_clean = df_clean.sort_values(by="timestamp").reset_index(drop=True)
        stats["final_rows"] = len(df_clean)

        return df_clean, stats
