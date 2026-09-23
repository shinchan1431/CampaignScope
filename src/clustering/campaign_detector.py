"""Campaign Clustering Engine for CampaignScope.

Groups correlated and behaviorally similar IPs into distinct attack campaigns
using DBSCAN density clustering and correlation graph community partitioning.
Isolates benign background traffic as unclustered noise (-1).
"""

import os
import argparse
from typing import Dict, Any, List, Set, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict
import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
import networkx as nx


@dataclass
class ClusterResult:
    """Encapsulates clustering output datasets and summary profiles."""

    clustered_ips_df: pd.DataFrame
    campaign_summaries_df: pd.DataFrame
    stats: Dict[str, Any]


class CampaignClusterer:
    """Detects and isolates coordinated attack campaigns from IP fingerprints and correlation edges."""

    def __init__(
        self,
        dbscan_eps: float = 0.22,
        dbscan_min_samples: int = 15,
        min_campaign_members: int = 10,
        min_failure_ratio: float = 0.70,
    ):
        self.dbscan_eps = dbscan_eps
        self.dbscan_min_samples = dbscan_min_samples
        self.min_campaign_members = min_campaign_members
        self.min_failure_ratio = min_failure_ratio

    def cluster_campaigns(
        self,
        features_df: pd.DataFrame,
        edges_df: Optional[pd.DataFrame] = None,
    ) -> ClusterResult:
        """Executes density clustering on behavioral space combined with graph partitioning."""
        if features_df.empty:
            return ClusterResult(pd.DataFrame(), pd.DataFrame(), {})

        df = features_df.copy()

        # 1. Select normalized behavioral feature vector
        feature_cols = [
            "feat_failure_ratio",
            "feat_username_diversity",
            "feat_endpoint_concentration",
            "feat_ua_concentration",
            "feat_timing_regularity",
        ]
        X = df[feature_cols].fillna(0.0).values

        # 2. Run DBSCAN on normalized behavioral feature space
        db = DBSCAN(eps=self.dbscan_eps, min_samples=self.dbscan_min_samples)
        db_labels = db.fit_predict(X)
        df["dbscan_label"] = db_labels

        # 3. Graph Community Refinement using Correlation Edges
        # Build correlation graph for high-affinity edges
        campaign_map: Dict[str, str] = {}  # ip -> campaign_name
        campaign_counter = 1

        if edges_df is not None and not edges_df.empty:
            # Filter edges with strong composite correlation and shared targets
            strong_edges = edges_df[
                (edges_df["composite_score"] >= 0.50)
                & (edges_df["shared_targets_count"] >= 1)
            ]

            G = nx.Graph()
            for _, row in strong_edges.iterrows():
                G.add_edge(row["ip_1"], row["ip_2"], weight=row["composite_score"])

            # Find connected components with sufficient members
            for component in nx.connected_components(G):
                if len(component) >= self.min_campaign_members:
                    # Check that member IPs satisfy minimum failure ratio (filtering benign shared users)
                    comp_ips = list(component)
                    comp_df = df[df["ip_address"].isin(comp_ips)]
                    avg_failure = comp_df["failure_ratio"].mean()

                    if avg_failure >= self.min_failure_ratio:
                        campaign_name = f"CAMPAIGN_{campaign_counter:02d}"
                        for ip in comp_ips:
                            campaign_map[ip] = campaign_name
                        campaign_counter += 1

        # 4. Synthesize final campaign assignments
        assigned_campaigns: List[str] = []
        assigned_cluster_ids: List[int] = []

        for _, row in df.iterrows():
            ip = row["ip_address"]
            if ip in campaign_map:
                assigned_campaigns.append(campaign_map[ip])
                assigned_cluster_ids.append(int(campaign_map[ip].split("_")[1]))
            elif row["dbscan_label"] >= 0 and row["failure_ratio"] >= self.min_failure_ratio:
                # Secondary detection from dense behavioral cluster if edges were sparse
                assigned_campaigns.append(f"CLUSTER_{row['dbscan_label']:02d}")
                assigned_cluster_ids.append(int(row["dbscan_label"]))
            else:
                assigned_campaigns.append("BENIGN_NOISE")
                assigned_cluster_ids.append(-1)

        df["campaign_id"] = assigned_campaigns
        df["cluster_id"] = assigned_cluster_ids
        df["is_campaign_member"] = (df["cluster_id"] != -1).astype(int)

        # 5. Build Comprehensive Campaign Summary Profiles
        summary_rows: List[Dict[str, Any]] = []
        active_campaigns = df[df["cluster_id"] != -1].groupby("campaign_id")

        for camp_id, group in active_campaigns:
            # Aggregate targeted usernames across the entire campaign
            all_targets: Set[str] = set()
            for t_str in group["target_usernames"].dropna():
                if t_str:
                    all_targets.update(t_str.split("|"))

            # Primary signatures
            top_ua = group["primary_user_agent"].value_counts().index[0]
            top_ep = group["primary_endpoint"].value_counts().index[0]
            top_countries = ", ".join(group["country"].value_counts().head(3).index.tolist())

            total_events = int(group["total_requests"].sum())
            ip_count = len(group)
            avg_attempts = round(total_events / ip_count, 2)

            summary_rows.append({
                "campaign_id": camp_id,
                "ip_count": ip_count,
                "total_events": total_events,
                "unique_target_accounts": len(all_targets),
                "avg_attempts_per_ip": avg_attempts,
                "mean_failure_ratio": round(float(group["failure_ratio"].mean()), 4),
                "mean_username_diversity": round(float(group["username_diversity"].mean()), 4),
                "mean_timing_regularity": round(float(group["timing_regularity"].mean()), 4),
                "primary_user_agent": top_ua,
                "primary_endpoint": top_ep,
                "top_origin_countries": top_countries,
            })

        summary_df = pd.DataFrame(summary_rows)
        if not summary_df.empty:
            summary_df = summary_df.sort_values(by="ip_count", ascending=False).reset_index(drop=True)

        stats = {
            "total_ips_analyzed": len(df),
            "campaigns_detected": len(summary_df),
            "total_campaign_ips": int((df["cluster_id"] != -1).sum()),
            "benign_noise_ips": int((df["cluster_id"] == -1).sum()),
            "campaign_breakdown": df["campaign_id"].value_counts().to_dict(),
        }

        return ClusterResult(df, summary_df, stats)


def run_clustering_pipeline(
    features_input_path: str,
    edges_input_path: str,
    output_dir: str,
) -> ClusterResult:
    """Loads feature tables and correlation edges, executes clustering, and exports results."""
    print(f"[*] Loading IP features from {features_input_path}...")
    features_df = pd.read_parquet(features_input_path) if features_input_path.endswith(".parquet") else pd.read_csv(features_input_path)

    print(f"[*] Loading correlation edges from {edges_input_path}...")
    edges_df = pd.read_parquet(edges_input_path) if edges_input_path.endswith(".parquet") else pd.read_csv(edges_input_path)

    clusterer = CampaignClusterer()
    print(f"[*] Clustering {len(features_df)} IPs into coordinated campaigns...")
    result = clusterer.cluster_campaigns(features_df, edges_df)

    os.makedirs(output_dir, exist_ok=True)
    clustered_ips_csv = os.path.join(output_dir, "clustered_ips.csv")
    clustered_ips_parquet = os.path.join(output_dir, "clustered_ips.parquet")
    campaigns_csv = os.path.join(output_dir, "campaign_summaries.csv")

    print(f"[*] Saving clustered IPs to CSV: {clustered_ips_csv}")
    result.clustered_ips_df.to_csv(clustered_ips_csv, index=False)

    print(f"[*] Saving clustered IPs to Parquet: {clustered_ips_parquet}")
    result.clustered_ips_df.to_parquet(clustered_ips_parquet, index=False)

    print(f"[*] Saving campaign summary table to CSV: {campaigns_csv}")
    result.campaign_summaries_df.to_csv(campaigns_csv, index=False)

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CampaignScope Campaign Clustering Engine")
    parser.add_argument(
        "--features-input",
        type=str,
        default="dataset/processed/ip_features.csv",
        help="Input IP features CSV/Parquet",
    )
    parser.add_argument(
        "--edges-input",
        type=str,
        default="dataset/processed/correlation_edges.csv",
        help="Input correlation edges CSV/Parquet",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="dataset/processed",
        help="Output directory for clustering results",
    )
    args = parser.parse_args()

    res = run_clustering_pipeline(args.features_input, args.edges_input, args.output_dir)
    print("\n[+] Campaign Clustering Completed Successfully!")
    print("--------------------------------------------------")
    for k, v in res.stats.items():
        print(f"  {k:30}: {v}")
    print("--------------------------------------------------")
    if not res.campaign_summaries_df.empty:
        print("\n[+] Discovered Campaigns:")
        print(res.campaign_summaries_df.to_string())
