"""IP Behavioral Fingerprint Extraction Engine for CampaignScope.

Transforms event-level authentication logs into comprehensive IP-level
behavioral profiles and normalized feature vectors for cross-IP correlation
and unsupervised campaign clustering.
"""

import os
import argparse
from typing import Dict, Any, List, Set, Tuple
from dataclasses import dataclass
import numpy as np
import pandas as pd


@dataclass
class IPFingerprint:
    """Represents the behavioral fingerprint and metrics for an individual IP."""

    ip_address: str
    total_requests: int
    failed_requests: int
    successful_requests: int
    failure_ratio: float
    unique_usernames: int
    username_diversity: float
    unique_endpoints: int
    endpoint_concentration: float
    unique_user_agents: int
    user_agent_concentration: float
    primary_user_agent: str
    primary_endpoint: str
    country: str
    active_duration_seconds: float
    requests_per_minute: float
    timing_regularity: float
    target_usernames: str  # Delimited list of targeted usernames for Phase 4 correlation


class FeatureExtractor:
    """Extracts multidimensional behavioral fingerprints per IP address."""

    def __init__(self, failure_codes: Tuple[int, ...] = (401, 403, 429)):
        self.failure_codes = failure_codes

    @staticmethod
    def _compute_timing_regularity(timestamps: pd.Series) -> float:
        """Calculates inter-arrival timing regularity score in [0.0, 1.0].

        Bots executing automated credential stuffing exhibit consistent sleep/jitter
        intervals (low coefficient of variation), resulting in scores approaching 1.0.
        Human traffic exhibits erratic inter-arrival bursts (high CV), yielding low scores.
        """
        if len(timestamps) < 3:
            return 0.5  # Neutral default for sparse single/dual attempts

        ts_sorted = pd.to_datetime(timestamps).sort_values()
        intervals = (ts_sorted.diff().dropna().dt.total_seconds()).values

        # Filter out 0 second intervals (parallel batch artifacts)
        intervals = intervals[intervals > 0]
        if len(intervals) < 2:
            return 0.5

        mean_val = np.mean(intervals)
        std_val = np.std(intervals)

        if mean_val <= 1e-4:
            return 0.5

        # Coefficient of variation (CV = std / mean)
        cv = std_val / mean_val
        # Map CV into [0, 1] using exponential decay: CV=0 -> 1.0, CV=1 -> 0.37, CV=2 -> 0.13
        regularity = float(np.exp(-cv))
        return min(max(regularity, 0.0), 1.0)

    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Processes a cleaned DataFrame of events into an IP behavioral feature table."""
        if df.empty:
            return pd.DataFrame()

        records: List[Dict[str, Any]] = []

        # Group by IP address
        grouped = df.groupby("ip_address")

        for ip, group in grouped:
            total = len(group)
            failed = int(group["status_code"].isin(self.failure_codes).sum())
            successful = int((group["status_code"] == 200).sum())
            failure_ratio = float(failed / total) if total > 0 else 0.0

            # Username analytics
            usernames = group["username"].dropna().astype(str)
            unique_users = int(usernames.nunique())
            username_diversity = float(unique_users / total) if total > 0 else 0.0
            target_users_str = "|".join(usernames.unique().tolist())

            # Endpoint analytics
            endpoints = group["endpoint"].dropna().astype(str)
            unique_ep = int(endpoints.nunique())
            ep_counts = endpoints.value_counts()
            top_ep = ep_counts.index[0] if len(ep_counts) > 0 else "/login"
            ep_concentration = float(ep_counts.iloc[0] / total) if total > 0 else 1.0

            # User-Agent analytics
            uas = group["user_agent"].dropna().astype(str)
            unique_ua = int(uas.nunique())
            ua_counts = uas.value_counts()
            top_ua = ua_counts.index[0] if len(ua_counts) > 0 else "Unknown"
            ua_concentration = float(ua_counts.iloc[0] / total) if total > 0 else 1.0

            # Country
            countries = group["country"].dropna().astype(str)
            top_country = countries.value_counts().index[0] if len(countries) > 0 else "XX"

            # Temporal analytics
            ts = pd.to_datetime(group["timestamp"])
            min_ts, max_ts = ts.min(), ts.max()
            duration_sec = max(float((max_ts - min_ts).total_seconds()), 1.0)
            rpm = float(total / (duration_sec / 60.0))
            timing_regularity = self._compute_timing_regularity(group["timestamp"])

            records.append({
                "ip_address": ip,
                "total_requests": total,
                "failed_requests": failed,
                "successful_requests": successful,
                "failure_ratio": round(failure_ratio, 4),
                "unique_usernames": unique_users,
                "username_diversity": round(username_diversity, 4),
                "unique_endpoints": unique_ep,
                "endpoint_concentration": round(ep_concentration, 4),
                "unique_user_agents": unique_ua,
                "user_agent_concentration": round(ua_concentration, 4),
                "primary_user_agent": top_ua,
                "primary_endpoint": top_ep,
                "country": top_country,
                "active_duration_seconds": round(duration_sec, 2),
                "requests_per_minute": round(rpm, 4),
                "timing_regularity": round(timing_regularity, 4),
                "target_usernames": target_users_str,
            })

        feature_df = pd.DataFrame(records)

        # Build normalized feature columns [0.0, 1.0] for downstream clustering (DBSCAN / K-Means)
        feature_df["feat_failure_ratio"] = feature_df["failure_ratio"]
        feature_df["feat_username_diversity"] = feature_df["username_diversity"]
        feature_df["feat_endpoint_concentration"] = feature_df["endpoint_concentration"]
        feature_df["feat_ua_concentration"] = feature_df["user_agent_concentration"]
        feature_df["feat_timing_regularity"] = feature_df["timing_regularity"]

        # Log-scale and normalize requests per minute
        rpm_log = np.log1p(feature_df["requests_per_minute"])
        max_rpm = rpm_log.max()
        feature_df["feat_request_frequency"] = (
            (rpm_log / max_rpm).round(4) if max_rpm > 0 else 0.0
        )

        return feature_df


def run_feature_pipeline(
    cleaned_input_path: str, output_dir: str
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Loads cleaned logs, extracts behavioral fingerprints, and saves processed feature tables."""
    print(f"[*] Loading cleaned authentication logs from {cleaned_input_path}...")
    if cleaned_input_path.endswith(".parquet"):
        df_clean = pd.read_parquet(cleaned_input_path)
    else:
        df_clean = pd.read_csv(cleaned_input_path)

    extractor = FeatureExtractor()
    print(f"[*] Extracting behavioral fingerprints for {df_clean['ip_address'].nunique()} distinct IPs...")
    feature_df = extractor.extract_features(df_clean)

    os.makedirs(output_dir, exist_ok=True)
    csv_out = os.path.join(output_dir, "ip_features.csv")
    parquet_out = os.path.join(output_dir, "ip_features.parquet")

    print(f"[*] Saving IP feature table to CSV: {csv_out}")
    feature_df.to_csv(csv_out, index=False)

    print(f"[*] Saving IP feature table to Parquet: {parquet_out}")
    feature_df.to_parquet(parquet_out, index=False)

    stats = {
        "total_unique_ips": len(feature_df),
        "mean_requests_per_ip": round(float(feature_df["total_requests"].mean()), 2),
        "max_requests_per_ip": int(feature_df["total_requests"].max()),
        "mean_failure_ratio": round(float(feature_df["failure_ratio"].mean()), 4),
        "high_failure_ips (>80%)": int((feature_df["failure_ratio"] > 0.8).sum()),
        "high_diversity_ips (>70%)": int((feature_df["username_diversity"] > 0.7).sum()),
        "csv_output": csv_out,
        "parquet_output": parquet_out,
    }
    return feature_df, stats


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CampaignScope Behavioral Feature Extractor")
    parser.add_argument(
        "--input",
        type=str,
        default="dataset/cleaned/cleaned_authentication_logs.csv",
        help="Input cleaned CSV/Parquet",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="dataset/processed",
        help="Output directory for IP feature tables",
    )
    args = parser.parse_args()

    _, summary = run_feature_pipeline(args.input, args.output_dir)
    print("\n[+] Feature Extraction Completed Successfully!")
    print("--------------------------------------------------")
    for k, v in summary.items():
        print(f"  {k:30}: {v}")
    print("--------------------------------------------------")
