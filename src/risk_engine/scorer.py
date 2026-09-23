"""Campaign Risk & Explainability Engine for CampaignScope.

Calculates transparent, interpretable risk scores (0-100) for discovered campaigns
based on multi-dimensional weak signals and synthesizes plain-language reason codes
for security investigators.
"""

import os
import json
import argparse
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
import pandas as pd


@dataclass
class RiskWeights:
    """Standard weights for explainable campaign risk scoring."""

    account_overlap: float = 0.30
    timing_similarity: float = 0.20
    ua_similarity: float = 0.15
    endpoint_similarity: float = 0.15
    failure_behavior: float = 0.20


@dataclass
class CampaignRiskAssessment:
    """Represents the complete explainable assessment for a campaign."""

    campaign_id: str
    risk_score: float
    classification: str
    ip_count: int
    total_events: int
    unique_target_accounts: int
    avg_attempts_per_ip: float
    account_overlap_pct: float
    timing_similarity_pct: float
    ua_similarity_pct: float
    endpoint_similarity_pct: float
    failure_behavior_pct: float
    reasons: List[str]
    primary_user_agent: str
    primary_endpoint: str
    top_origin_countries: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CampaignRiskEngine:
    """Assesses campaign risk and produces SOC-ready explanations."""

    def __init__(self, weights: Optional[RiskWeights] = None):
        self.weights = weights or RiskWeights()

    def assess_campaign(
        self,
        summary_row: pd.Series,
        campaign_ips_df: pd.DataFrame,
    ) -> CampaignRiskAssessment:
        """Computes multi-signal risk score and explanation for an individual campaign."""
        camp_id = summary_row["campaign_id"]
        ip_count = int(summary_row["ip_count"])
        total_events = int(summary_row["total_events"])
        unique_targets = int(summary_row["unique_target_accounts"])
        avg_attempts = float(summary_row["avg_attempts_per_ip"])

        # 1. Account Overlap (30%)
        # Ratio of total events to unique target accounts (higher reuse = higher overlap score)
        reuse_factor = total_events / max(unique_targets, 1)
        account_overlap_pct = min(100.0, round(reuse_factor * 5.0, 1))

        # 2. Timing Regularity (20%)
        timing_similarity_pct = min(100.0, round(float(summary_row["mean_timing_regularity"]) * 100.0, 1))

        # 3. User-Agent Uniformity (15%)
        top_ua = summary_row["primary_user_agent"]
        ua_match_count = (campaign_ips_df["primary_user_agent"] == top_ua).sum()
        ua_similarity_pct = round((ua_match_count / max(ip_count, 1)) * 100.0, 1)

        # 4. Endpoint Concentration (15%)
        top_ep = summary_row["primary_endpoint"]
        ep_match_count = (campaign_ips_df["primary_endpoint"] == top_ep).sum()
        endpoint_similarity_pct = round((ep_match_count / max(ip_count, 1)) * 100.0, 1)

        # 5. Failure Behavior (20%)
        failure_behavior_pct = round(float(summary_row["mean_failure_ratio"]) * 100.0, 1)

        # Composite Risk Score Calculation
        w = self.weights
        composite_score = (
            w.account_overlap * account_overlap_pct
            + w.timing_similarity * timing_similarity_pct
            + w.ua_similarity * ua_similarity_pct
            + w.endpoint_similarity * endpoint_similarity_pct
            + w.failure_behavior * failure_behavior_pct
        )
        risk_score = round(min(100.0, max(0.0, composite_score)), 1)

        # Classification
        if risk_score >= 75.0:
            classification = "CREDENTIAL_STUFFING"
        elif risk_score >= 50.0:
            classification = "SUSPICIOUS"
        else:
            classification = "LOW_RISK"

        # Plain-language explanation reasons
        reasons = [
            f"✓ {ip_count:,} distributed IPs systematically target {unique_targets:,} accounts ({account_overlap_pct}% target reuse)",
            f"✓ {failure_behavior_pct}% authentication failure rate across {total_events:,} total attempts",
            f"✓ {timing_similarity_pct}% timing regularity indicating automated pacing / bot scheduling",
            f"✓ {ua_similarity_pct}% client signature uniformity using canonical '{top_ua}'",
            f"✓ {endpoint_similarity_pct}% endpoint focus targeting '{top_ep}'",
            f"✓ Low-and-slow profile: average {avg_attempts:.1f} attempts/IP successfully evades standard single-IP threshold alarms",
        ]

        return CampaignRiskAssessment(
            campaign_id=camp_id,
            risk_score=risk_score,
            classification=classification,
            ip_count=ip_count,
            total_events=total_events,
            unique_target_accounts=unique_targets,
            avg_attempts_per_ip=avg_attempts,
            account_overlap_pct=account_overlap_pct,
            timing_similarity_pct=timing_similarity_pct,
            ua_similarity_pct=ua_similarity_pct,
            endpoint_similarity_pct=endpoint_similarity_pct,
            failure_behavior_pct=failure_behavior_pct,
            reasons=reasons,
            primary_user_agent=top_ua,
            primary_endpoint=top_ep,
            top_origin_countries=summary_row.get("top_origin_countries", "Unknown"),
        )

    def assess_all(
        self,
        campaign_summaries_df: pd.DataFrame,
        clustered_ips_df: pd.DataFrame,
    ) -> List[CampaignRiskAssessment]:
        """Assesses risk for all discovered campaigns."""
        assessments: List[CampaignRiskAssessment] = []
        for _, row in campaign_summaries_df.iterrows():
            camp_id = row["campaign_id"]
            camp_ips = clustered_ips_df[clustered_ips_df["campaign_id"] == camp_id]
            assessment = self.assess_campaign(row, camp_ips)
            assessments.append(assessment)
        return assessments


def run_risk_pipeline(
    summaries_input: str,
    clustered_ips_input: str,
    output_dir: str,
) -> List[CampaignRiskAssessment]:
    """Executes the risk scoring pipeline and outputs assessments to CSV and JSON."""
    print(f"[*] Loading campaign summaries from {summaries_input}...")
    summaries_df = pd.read_csv(summaries_input)

    print(f"[*] Loading clustered IPs from {clustered_ips_input}...")
    clustered_ips_df = pd.read_csv(clustered_ips_input)

    engine = CampaignRiskEngine()
    print(f"[*] Evaluating explainable risk scores for {len(summaries_df)} discovered campaigns...")
    assessments = engine.assess_all(summaries_df, clustered_ips_df)

    os.makedirs(output_dir, exist_ok=True)
    csv_out = os.path.join(output_dir, "campaign_risk_scores.csv")
    json_out = os.path.join(output_dir, "campaign_risk_scores.json")

    # Save to CSV
    records = [a.to_dict() for a in assessments]
    for r in records:
        r["reasons_joined"] = " \n".join(r["reasons"])
    df_risk = pd.DataFrame(records).drop(columns=["reasons"])
    df_risk.to_csv(csv_out, index=False)

    # Save to JSON
    with open(json_out, "w", encoding="utf-8") as f:
        json.dump([a.to_dict() for a in assessments], f, indent=2)

    print(f"[+] Saved campaign risk scores to CSV: {csv_out}")
    print(f"[+] Saved campaign risk explanations to JSON: {json_out}")
    return assessments


if __name__ == "__main__":
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="CampaignScope Campaign Risk & Explainability Engine")
    parser.add_argument(
        "--summaries-input",
        type=str,
        default="dataset/processed/campaign_summaries.csv",
        help="Input campaign summaries CSV",
    )
    parser.add_argument(
        "--clustered-ips-input",
        type=str,
        default="dataset/processed/clustered_ips.csv",
        help="Input clustered IPs CSV",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="dataset/processed",
        help="Output directory for risk scores",
    )
    args = parser.parse_args()

    results = run_risk_pipeline(args.summaries_input, args.clustered_ips_input, args.output_dir)
    print("\n[+] Campaign Risk Assessment Summary:")
    print("================================================================================")
    for r in results:
        print(f"Campaign: {r.campaign_id} | Risk: {r.risk_score}/100 | Class: {r.classification}")
        print(f"  Signals -> Overlap: {r.account_overlap_pct}% | Timing: {r.timing_similarity_pct}% | UA: {r.ua_similarity_pct}% | EP: {r.endpoint_similarity_pct}% | Fail: {r.failure_behavior_pct}%")
        print("  WHY FLAGGED:")
        for reason in r.reasons:
            print(f"    {reason}")
        print("--------------------------------------------------------------------------------")
