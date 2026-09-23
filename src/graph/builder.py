"""Investigation Graph Builder for CampaignScope.

Constructs multi-layer heterogeneous attack graphs connecting:
IPs -> Attack Campaign -> Target Accounts -> Endpoints -> Client Fingerprints.
Exports graph topologies and timeline progressions optimized for interactive
SOC visualization in Streamlit.
"""

import os
import json
import argparse
from typing import Dict, Any, List, Set, Tuple, Optional
from collections import defaultdict
from datetime import datetime
import pandas as pd
import networkx as nx


class CampaignGraphBuilder:
    """Builds and queries multi-layer attack campaign graphs."""

    def __init__(
        self,
        clustered_ips_df: pd.DataFrame,
        campaign_risk_df: pd.DataFrame,
        correlation_edges_df: Optional[pd.DataFrame] = None,
        cleaned_logs_df: Optional[pd.DataFrame] = None,
    ):
        self.clustered_ips_df = clustered_ips_df.copy()
        self.campaign_risk_df = campaign_risk_df.copy()
        self.correlation_edges_df = correlation_edges_df.copy() if correlation_edges_df is not None else pd.DataFrame()
        self.cleaned_logs_df = cleaned_logs_df.copy() if cleaned_logs_df is not None else pd.DataFrame()

        self.G = nx.Graph()
        self._build_graph()

    def _build_graph(self) -> None:
        """Constructs the heterogeneous network of Campaigns, IPs, Accounts, Endpoints, and UAs."""
        # 1. Add Campaign Nodes
        for _, row in self.campaign_risk_df.iterrows():
            cid = row["campaign_id"]
            self.G.add_node(
                cid,
                node_type="campaign",
                label=f"Campaign {cid}",
                risk_score=row["risk_score"],
                classification=row["classification"],
                ip_count=row["ip_count"],
                total_events=row["total_events"],
                targets_count=row["unique_target_accounts"],
                primary_ua=row.get("primary_user_agent", "Unknown"),
                primary_endpoint=row.get("primary_endpoint", "/login"),
            )

        # 2. Add Endpoint & UA Nodes and attach to Campaigns
        for _, row in self.campaign_risk_df.iterrows():
            cid = row["campaign_id"]
            ep = row.get("primary_endpoint", "/login")
            ua = row.get("primary_user_agent", "Unknown")

            ep_node = f"ep::{ep}"
            if not self.G.has_node(ep_node):
                self.G.add_node(ep_node, node_type="endpoint", label=ep)
            self.G.add_edge(cid, ep_node, relation="accesses", weight=1.0)

            ua_node = f"ua::{ua}"
            if not self.G.has_node(ua_node):
                self.G.add_node(ua_node, node_type="user_agent", label=ua)
            self.G.add_edge(cid, ua_node, relation="uses", weight=1.0)

        # 3. Add IP Nodes and link to Campaign
        active_ips = self.clustered_ips_df[self.clustered_ips_df["campaign_id"].str.startswith("CAMPAIGN_")]
        for _, row in active_ips.iterrows():
            ip = row["ip_address"]
            cid = row["campaign_id"]
            self.G.add_node(
                ip,
                node_type="ip",
                label=ip,
                attempts=row["total_requests"],
                failure_ratio=row["failure_ratio"],
                country=row.get("country", "XX"),
                user_agent=row.get("primary_user_agent", "Unknown"),
            )
            self.G.add_edge(ip, cid, relation="belongs_to", weight=1.0)

        # 4. Add Top Correlated Inter-IP Edges (within same campaign)
        if not self.correlation_edges_df.empty:
            ip_to_camp = dict(zip(active_ips["ip_address"], active_ips["campaign_id"]))
            for _, row in self.correlation_edges_df.head(5000).iterrows():
                ip1, ip2 = row["ip_1"], row["ip_2"]
                if ip1 in ip_to_camp and ip2 in ip_to_camp and ip_to_camp[ip1] == ip_to_camp[ip2]:
                    self.G.add_edge(ip1, ip2, relation="correlated_with", weight=row["composite_score"])

    def get_campaign_investigation_view(
        self,
        campaign_id: str,
        max_display_ips: int = 35,
        max_display_accounts: int = 15,
    ) -> Dict[str, Any]:
        """Extracts a focused, renderable subgraph payload for a selected campaign."""
        camp_row = self.campaign_risk_df[self.campaign_risk_df["campaign_id"] == campaign_id]
        if camp_row.empty:
            return {"error": f"Campaign {campaign_id} not found"}

        camp_info = camp_row.iloc[0].to_dict()
        camp_ips_df = self.clustered_ips_df[self.clustered_ips_df["campaign_id"] == campaign_id]

        # 1. Timeline Analytics
        timeline = self._compute_timeline(campaign_id, camp_ips_df)

        # 2. Extract Top Targeted Accounts
        target_counts: Dict[str, int] = defaultdict(int)
        for t_str in camp_ips_df["target_usernames"].dropna():
            if t_str:
                for u in t_str.split("|"):
                    if u.strip():
                        target_counts[u.strip()] += 1

        top_targets = sorted(target_counts.items(), key=lambda x: x[1], reverse=True)[:max_display_accounts]

        # 3. Build Nodes and Links for Visualization
        nodes: List[Dict[str, Any]] = []
        links: List[Dict[str, Any]] = []

        # Central Campaign Hub Node
        nodes.append({
            "id": campaign_id,
            "label": f"Campaign {campaign_id}",
            "type": "campaign",
            "risk_score": camp_info.get("risk_score", 0),
            "size": 35,
            "color": "#FF4B4B" if camp_info.get("risk_score", 0) >= 75 else "#FFAA00",
        })

        # Endpoint Node
        ep = camp_info.get("primary_endpoint", "/login")
        ep_id = f"ep::{ep}"
        nodes.append({"id": ep_id, "label": ep, "type": "endpoint", "size": 22, "color": "#00CC96"})
        links.append({"source": campaign_id, "target": ep_id, "relation": "accesses"})

        # User-Agent Node
        ua = camp_info.get("primary_user_agent", "Unknown")
        ua_id = f"ua::{ua}"
        nodes.append({"id": ua_id, "label": ua, "type": "user_agent", "size": 22, "color": "#AB63FA"})
        links.append({"source": campaign_id, "target": ua_id, "relation": "uses"})

        # Sample Attacker IPs
        sample_ips = camp_ips_df.sort_values(by="total_requests", ascending=False).head(max_display_ips)
        for _, row in sample_ips.iterrows():
            ip = row["ip_address"]
            nodes.append({
                "id": ip,
                "label": ip,
                "type": "ip",
                "attempts": int(row["total_requests"]),
                "failure_ratio": float(row["failure_ratio"]),
                "country": row.get("country", "XX"),
                "size": 15,
                "color": "#EF553B",
            })
            links.append({"source": ip, "target": campaign_id, "relation": "belongs_to"})

        # Target Account Nodes
        for account, count in top_targets:
            acc_id = f"acc::{account}"
            nodes.append({
                "id": acc_id,
                "label": account,
                "type": "account",
                "hit_count": count,
                "size": 18,
                "color": "#19D3F3",
            })
            links.append({"source": campaign_id, "target": acc_id, "relation": "targets", "hits": count})

        return {
            "campaign_id": campaign_id,
            "metrics": {
                "risk_score": camp_info.get("risk_score", 0),
                "classification": camp_info.get("classification", "UNKNOWN"),
                "ip_count": int(camp_info.get("ip_count", 0)),
                "total_events": int(camp_info.get("total_events", 0)),
                "unique_target_accounts": int(camp_info.get("unique_target_accounts", 0)),
                "avg_attempts_per_ip": float(camp_info.get("avg_attempts_per_ip", 0)),
                "primary_user_agent": ua,
                "primary_endpoint": ep,
                "top_origin_countries": camp_info.get("top_origin_countries", "Unknown"),
            },
            "reasons": (
                [r.strip() for r in str(camp_info.get("reasons_joined")).split("\n") if r.strip()]
                if camp_info.get("reasons_joined") and not pd.isna(camp_info.get("reasons_joined"))
                else camp_info.get("reasons", [])
            ),
            "timeline": timeline,
            "graph": {
                "nodes": nodes,
                "links": links,
            },
        }

    def _compute_timeline(self, campaign_id: str, camp_ips_df: pd.DataFrame) -> Dict[str, Any]:
        """Calculates start time, peak hour, and duration from cleaned events for the campaign."""
        if self.cleaned_logs_df.empty:
            return {"started": "N/A", "peak": "N/A", "duration": "N/A", "hourly_series": []}

        camp_ips = set(camp_ips_df["ip_address"])
        camp_events = self.cleaned_logs_df[self.cleaned_logs_df["ip_address"].isin(camp_ips)].copy()

        if camp_events.empty:
            return {"started": "N/A", "peak": "N/A", "duration": "N/A", "hourly_series": []}

        camp_events["dt"] = pd.to_datetime(camp_events["timestamp"])
        min_dt = camp_events["dt"].min()
        max_dt = camp_events["dt"].max()
        duration_sec = (max_dt - min_dt).total_seconds()
        hours = int(duration_sec // 3600)
        minutes = int((duration_sec % 3600) // 60)

        # 30-minute interval bucketing for timeline chart
        camp_events["time_bin"] = camp_events["dt"].dt.floor("30min").dt.strftime("%H:%M")
        binned = camp_events["time_bin"].value_counts().sort_index()
        peak_bin = binned.idxmax() if not binned.empty else "N/A"

        series = [{"time": k, "attempts": int(v)} for k, v in binned.items()]

        return {
            "started": min_dt.strftime("%H:%M"),
            "peak": peak_bin,
            "duration": f"{hours}h {minutes:02d}m",
            "hourly_series": series,
        }

    def export_all(self, output_dir: str) -> Dict[str, Any]:
        """Exports full graph tables and per-campaign investigation views to JSON and CSV."""
        os.makedirs(output_dir, exist_ok=True)

        # Export per-campaign investigation JSON
        investigation_views = {}
        for _, row in self.campaign_risk_df.iterrows():
            cid = row["campaign_id"]
            if cid.startswith("CAMPAIGN_"):
                investigation_views[cid] = self.get_campaign_investigation_view(cid)

        json_out = os.path.join(output_dir, "investigation_graphs.json")
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(investigation_views, f, indent=2)

        # Export Node Table
        nodes_data = []
        for n, attrs in self.G.nodes(data=True):
            rec = {"node_id": n, **attrs}
            nodes_data.append(rec)
        df_nodes = pd.DataFrame(nodes_data)
        nodes_csv = os.path.join(output_dir, "graph_nodes.csv")
        df_nodes.to_csv(nodes_csv, index=False)

        # Export Edge Table
        edges_data = []
        for u, v, attrs in self.G.edges(data=True):
            edges_data.append({"source": u, "target": v, **attrs})
        df_edges = pd.DataFrame(edges_data)
        edges_csv = os.path.join(output_dir, "graph_edges.csv")
        df_edges.to_csv(edges_csv, index=False)

        print(f"[+] Saved investigation graph JSON: {json_out}")
        print(f"[+] Saved graph nodes CSV ({len(df_nodes)} nodes): {nodes_csv}")
        print(f"[+] Saved graph edges CSV ({len(df_edges)} edges): {edges_csv}")

        return {
            "total_nodes": len(df_nodes),
            "total_edges": len(df_edges),
            "campaign_views_built": len(investigation_views),
            "json_output": json_out,
            "nodes_csv": nodes_csv,
            "edges_csv": edges_csv,
        }


def run_graph_pipeline(
    clustered_ips_path: str,
    risk_scores_path: str,
    correlation_edges_path: str,
    cleaned_logs_path: str,
    output_dir: str,
) -> Dict[str, Any]:
    """Loads all pipeline artifacts and builds complete investigation graphs."""
    print(f"[*] Loading clustered IPs from {clustered_ips_path}...")
    clustered_df = pd.read_csv(clustered_ips_path)

    print(f"[*] Loading risk scores from {risk_scores_path}...")
    risk_df = pd.read_csv(risk_scores_path)

    print(f"[*] Loading correlation edges from {correlation_edges_path}...")
    edges_df = pd.read_csv(correlation_edges_path) if os.path.exists(correlation_edges_path) else None

    print(f"[*] Loading cleaned authentication logs from {cleaned_logs_path}...")
    logs_df = pd.read_parquet(cleaned_logs_path) if cleaned_logs_path.endswith(".parquet") else pd.read_csv(cleaned_logs_path)

    builder = CampaignGraphBuilder(
        clustered_ips_df=clustered_df,
        campaign_risk_df=risk_df,
        correlation_edges_df=edges_df,
        cleaned_logs_df=logs_df,
    )

    return builder.export_all(output_dir)


if __name__ == "__main__":
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description="CampaignScope Investigation Graph Builder")
    parser.add_argument("--clustered-ips", type=str, default="dataset/processed/clustered_ips.csv")
    parser.add_argument("--risk-scores", type=str, default="dataset/processed/campaign_risk_scores.csv")
    parser.add_argument("--correlation-edges", type=str, default="dataset/processed/correlation_edges.csv")
    parser.add_argument("--cleaned-logs", type=str, default="dataset/cleaned/cleaned_authentication_logs.parquet")
    parser.add_argument("--output-dir", type=str, default="dataset/processed")
    args = parser.parse_args()

    stats = run_graph_pipeline(
        args.clustered_ips,
        args.risk_scores,
        args.correlation_edges,
        args.cleaned_logs,
        args.output_dir,
    )
    print("\n[+] Graph Pipeline Completed Successfully!")
    print("--------------------------------------------------")
    for k, v in stats.items():
        print(f"  {k:25}: {v}")
    print("--------------------------------------------------")
