"""Cross-IP Correlation Engine for CampaignScope.

Uncovers distributed credential-stuffing campaigns by correlating multi-dimensional
weak signals across distinct IP addresses:
1. Target account overlap (Jaccard similarity on target username pools)
2. Timing cadence similarity (inter-arrival regularity & request frequency)
3. Client signature similarity (User-Agent normalization matching)
4. Endpoint concentration overlap
5. Failure profile alignment
"""

import os
import argparse
from typing import Dict, Any, List, Set, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict
import numpy as np
import pandas as pd


@dataclass
class CorrelationWeights:
    """Configurable weights for composite cross-IP similarity scoring."""

    account_overlap: float = 0.35
    timing: float = 0.20
    user_agent: float = 0.15
    endpoint: float = 0.15
    failure: float = 0.15


@dataclass
class CorrelationResult:
    """Encapsulates correlation output tables and graph-ready edges."""

    edges_df: pd.DataFrame
    ip_correlation_summary_df: pd.DataFrame
    stats: Dict[str, Any]


class CrossIPCorrelator:
    """Computes pairwise behavioral correlations across candidate IPs."""

    def __init__(
        self,
        weights: Optional[CorrelationWeights] = None,
        min_composite_score: float = 0.35,
        min_shared_targets: int = 1,
    ):
        self.weights = weights or CorrelationWeights()
        self.min_composite_score = min_composite_score
        self.min_shared_targets = min_shared_targets

    def _build_inverted_index(self, ip_records: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
        """Constructs an inverted index mapping username -> set of IPs that targeted it."""
        user_to_ips = defaultdict(set)
        for rec in ip_records:
            ip = rec["ip_address"]
            targets_str = rec.get("target_usernames", "")
            if targets_str:
                for u in targets_str.split("|"):
                    if u.strip():
                        user_to_ips[u.strip()].add(ip)
        return user_to_ips

    def compute_correlations(self, features_df: pd.DataFrame) -> CorrelationResult:
        """Finds all correlated IP pairs sharing target accounts and behavioral traits."""
        if features_df.empty:
            empty_edges = pd.DataFrame(columns=[
                "ip_1", "ip_2", "shared_targets_count", "jaccard_overlap",
                "timing_similarity", "ua_similarity", "endpoint_similarity",
                "failure_similarity", "composite_score"
            ])
            return CorrelationResult(empty_edges, pd.DataFrame(), {})

        ip_dict = features_df.set_index("ip_address").to_dict(orient="index")
        ip_records = features_df.to_dict(orient="records")

        # 1. Inverted Index for candidate generation
        user_to_ips = self._build_inverted_index(ip_records)

        # 2. Candidate pair discovery (pairs sharing at least 1 targeted account)
        candidate_pairs: Dict[Tuple[str, str], int] = defaultdict(int)
        for user, ips in user_to_ips.items():
            if len(ips) > 1:
                ip_list = sorted(list(ips))
                # For high-volume benign shared users (e.g. corporate login), limit combinatorial blowup
                sample_ips = ip_list if len(ip_list) <= 150 else list(np.random.choice(ip_list, 150, replace=False))
                for i in range(len(sample_ips)):
                    for j in range(i + 1, len(sample_ips)):
                        pair = (sample_ips[i], sample_ips[j])
                        candidate_pairs[pair] += 1

        # 3. Compute Multi-Signal Similarity for each candidate pair
        edge_rows: List[Dict[str, Any]] = []
        ip_correlations: Dict[str, List[float]] = defaultdict(list)
        ip_partners: Dict[str, Set[str]] = defaultdict(set)

        w = self.weights

        for (ip1, ip2), shared_count in candidate_pairs.items():
            if shared_count < self.min_shared_targets:
                continue

            rec1 = ip_dict.get(ip1)
            rec2 = ip_dict.get(ip2)
            if not rec1 or not rec2:
                continue

            # Targets and Jaccard Overlap
            targets1 = set(rec1.get("target_usernames", "").split("|"))
            targets2 = set(rec2.get("target_usernames", "").split("|"))
            intersection = len(targets1 & targets2)
            union = len(targets1 | targets2)
            jaccard = float(intersection / union) if union > 0 else 0.0

            # Timing similarity (based on regularity & frequency)
            time_reg1 = rec1.get("feat_timing_regularity", 0.5)
            time_reg2 = rec2.get("feat_timing_regularity", 0.5)
            timing_sim = max(0.0, 1.0 - abs(time_reg1 - time_reg2))

            # User-Agent similarity
            ua1 = rec1.get("primary_user_agent", "")
            ua2 = rec2.get("primary_user_agent", "")
            ua_sim = 1.0 if ua1 == ua2 and ua1 != "Unknown" else 0.0

            # Endpoint similarity
            ep1 = rec1.get("primary_endpoint", "")
            ep2 = rec2.get("primary_endpoint", "")
            ep_sim = 1.0 if ep1 == ep2 else 0.0

            # Failure ratio similarity
            fail1 = rec1.get("feat_failure_ratio", 0.0)
            fail2 = rec2.get("feat_failure_ratio", 0.0)
            fail_sim = max(0.0, 1.0 - abs(fail1 - fail2))

            # Composite Correlation Score
            composite = (
                w.account_overlap * min(jaccard * 5.0, 1.0)  # Scale modest Jaccard into strong signal
                + w.timing * timing_sim
                + w.user_agent * ua_sim
                + w.endpoint * ep_sim
                + w.failure * fail_sim
            )

            # Both must have significant failure profile to form a coordinated attack edge
            avg_failure = (fail1 + fail2) / 2.0
            if avg_failure < 0.5:
                # Diminish composite score if both IPs are overwhelmingly benign
                composite *= 0.5

            if composite >= self.min_composite_score:
                edge_rows.append({
                    "ip_1": ip1,
                    "ip_2": ip2,
                    "shared_targets_count": intersection,
                    "jaccard_overlap": round(jaccard, 4),
                    "timing_similarity": round(timing_sim, 4),
                    "ua_similarity": round(ua_sim, 4),
                    "endpoint_similarity": round(ep_sim, 4),
                    "failure_similarity": round(fail_sim, 4),
                    "composite_score": round(composite, 4),
                })
                ip_correlations[ip1].append(composite)
                ip_correlations[ip2].append(composite)
                ip_partners[ip1].add(ip2)
                ip_partners[ip2].add(ip1)

        edges_df = pd.DataFrame(edge_rows)
        if not edges_df.empty:
            edges_df = edges_df.sort_values(by="composite_score", ascending=False).reset_index(drop=True)

        # 4. Generate IP Correlation Summary (Degree & Affinity per IP)
        summary_rows: List[Dict[str, Any]] = []
        for ip, rec in ip_dict.items():
            scores = ip_correlations.get(ip, [])
            partners = ip_partners.get(ip, set())
            summary_rows.append({
                "ip_address": ip,
                "correlated_partners_count": len(partners),
                "mean_correlation_score": round(float(np.mean(scores)), 4) if scores else 0.0,
                "max_correlation_score": round(float(np.max(scores)), 4) if scores else 0.0,
                "is_correlated_attacker": 1 if (len(partners) >= 3 and np.mean(scores or [0]) >= 0.5) else 0,
            })
        summary_df = pd.DataFrame(summary_rows)

        stats = {
            "total_candidate_pairs_checked": len(candidate_pairs),
            "correlated_edges_retained": len(edges_df),
            "ips_with_correlations": len(ip_partners),
            "mean_edge_composite_score": round(float(edges_df["composite_score"].mean()), 4) if not edges_df.empty else 0.0,
            "max_edge_composite_score": round(float(edges_df["composite_score"].max()), 4) if not edges_df.empty else 0.0,
        }

        return CorrelationResult(edges_df, summary_df, stats)


def run_correlation_pipeline(
    features_input_path: str, output_dir: str
) -> CorrelationResult:
    """Loads extracted IP features, runs cross-IP correlation, and exports edge tables."""
    print(f"[*] Loading IP behavioral fingerprints from {features_input_path}...")
    if features_input_path.endswith(".parquet"):
        features_df = pd.read_parquet(features_input_path)
    else:
        features_df = pd.read_csv(features_input_path)

    correlator = CrossIPCorrelator(min_composite_score=0.45)
    print(f"[*] Running multi-signal cross-IP correlation across {len(features_df)} IPs...")
    result = correlator.compute_correlations(features_df)

    os.makedirs(output_dir, exist_ok=True)
    edges_csv = os.path.join(output_dir, "correlation_edges.csv")
    edges_parquet = os.path.join(output_dir, "correlation_edges.parquet")
    summary_csv = os.path.join(output_dir, "ip_correlation_summary.csv")

    print(f"[*] Saving correlation edges to CSV: {edges_csv}")
    result.edges_df.to_csv(edges_csv, index=False)

    print(f"[*] Saving correlation edges to Parquet: {edges_parquet}")
    result.edges_df.to_parquet(edges_parquet, index=False)

    print(f"[*] Saving IP correlation summary to CSV: {summary_csv}")
    result.ip_correlation_summary_df.to_csv(summary_csv, index=False)

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CampaignScope Cross-IP Correlation Engine")
    parser.add_argument(
        "--features-input",
        type=str,
        default="dataset/processed/ip_features.csv",
        help="Input IP features CSV/Parquet",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="dataset/processed",
        help="Output directory for correlation tables",
    )
    args = parser.parse_args()

    res = run_correlation_pipeline(args.features_input, args.output_dir)
    print("\n[+] Cross-IP Correlation Completed Successfully!")
    print("--------------------------------------------------")
    for k, v in res.stats.items():
        print(f"  {k:35}: {v}")
    print("--------------------------------------------------")
