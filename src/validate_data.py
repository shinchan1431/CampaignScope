"""
CampaignScope Evaluation Engine

Evaluates:
1. Raw campaign clustering
2. Risk-filtered campaign detection

Ground truth:
- credential_stuffing = distributed campaign
- brute_force = single-IP attack
- corporate_nat = legitimate shared-IP traffic
- benign = normal traffic
"""

from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]

GROUND_TRUTH_PATH = (
    ROOT / "dataset" / "evaluation" / "ground_truth_events.csv"
)

CLUSTERED_IPS_PATH = (
    ROOT / "dataset" / "processed" / "clustered_ips.csv"
)

RISK_SCORES_PATH = (
    ROOT / "dataset" / "processed" / "campaign_risk_scores.csv"
)

OUTPUT_DIR = ROOT / "dataset" / "evaluation"

RISK_THRESHOLD = 75.0
TARGET_RISK_CLASS = "CREDENTIAL_STUFFING"


def load_data():
    """Load all evaluation datasets."""

    print("[*] Loading evaluation datasets...")

    ground_truth = pd.read_csv(GROUND_TRUTH_PATH)
    clustered_ips = pd.read_csv(CLUSTERED_IPS_PATH)
    risk_scores = pd.read_csv(RISK_SCORES_PATH)

    print(
        f"[+] Ground-truth events loaded: "
        f"{len(ground_truth):,}"
    )

    print(
        f"[+] Clustered IPs loaded: "
        f"{len(clustered_ips):,}"
    )

    print(
        f"[+] Risk-scored campaigns loaded: "
        f"{len(risk_scores):,}"
    )

    print(
        f"[+] Risk threshold: "
        f"{RISK_THRESHOLD:.1f}"
    )

    print(
        f"[+] Target risk class: "
        f"{TARGET_RISK_CLASS}"
    )

    return ground_truth, clustered_ips, risk_scores


def get_ground_truth_campaign_ips(ground_truth):
    """Return IPs belonging to distributed credential-stuffing attacks."""

    campaign_rows = ground_truth[
        ground_truth["attack_type"]
        .astype(str)
        .str.lower()
        .eq("credential_stuffing")
    ]

    return set(
        campaign_rows["ip_address"]
        .dropna()
        .astype(str)
    )


def get_detected_campaign_ips(clustered_ips):
    """Return all IPs assigned to a discovered cluster/campaign."""

    detected_rows = clustered_ips[
        ~clustered_ips["campaign_id"]
        .astype(str)
        .eq("BENIGN_NOISE")
    ]

    return set(
        detected_rows["ip_address"]
        .dropna()
        .astype(str)
    )


def calculate_metrics(ground_truth_ips, detected_ips):
    """Calculate precision, recall and F1."""

    true_positive = len(
        ground_truth_ips & detected_ips
    )

    false_positive = len(
        detected_ips - ground_truth_ips
    )

    false_negative = len(
        ground_truth_ips - detected_ips
    )

    precision = (
        true_positive
        / (true_positive + false_positive)
        if (true_positive + false_positive)
        else 0.0
    )

    recall = (
        true_positive
        / (true_positive + false_negative)
        if (true_positive + false_negative)
        else 0.0
    )

    f1_score = (
        2 * precision * recall
        / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    return {
        "true_positive_ips": true_positive,
        "false_positive_ips": false_positive,
        "false_negative_ips": false_negative,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
    }


def get_risk_filtered_campaigns(risk_scores):
    """
    Keep campaigns classified as CREDENTIAL_STUFFING.

    The risk engine defines CREDENTIAL_STUFFING as risk >= 75.
    This path uses the explicit class label so that the
    evaluation follows the actual risk-engine decision.
    """

    class_column = None

    for candidate in [
        "risk_class",
        "classification",
        "risk_category",
        "class",
    ]:
        if candidate in risk_scores.columns:
            class_column = candidate
            break

    if class_column is None:
        raise ValueError(
            "Could not find risk class column in "
            f"{RISK_SCORES_PATH}.\n"
            f"Available columns: {list(risk_scores.columns)}"
        )

    filtered = risk_scores[
        risk_scores[class_column]
        .astype(str)
        .str.upper()
        .eq(TARGET_RISK_CLASS)
    ]

    return filtered, class_column


def get_threshold_filtered_campaigns(risk_scores):
    """Keep campaigns whose risk score is at least 75."""

    score_column = None

    for candidate in [
        "risk_score",
        "score",
        "risk",
    ]:
        if candidate in risk_scores.columns:
            score_column = candidate
            break

    if score_column is None:
        raise ValueError(
            "Could not find risk score column in "
            f"{RISK_SCORES_PATH}.\n"
            f"Available columns: {list(risk_scores.columns)}"
        )

    filtered = risk_scores[
        pd.to_numeric(
            risk_scores[score_column],
            errors="coerce",
        ) >= RISK_THRESHOLD
    ]

    return filtered, score_column


def get_campaign_ids_to_ips(
    clustered_ips,
    campaign_ids,
):
    """Convert selected campaign IDs into their IP addresses."""

    selected = clustered_ips[
        clustered_ips["campaign_id"]
        .astype(str)
        .isin(set(map(str, campaign_ids)))
    ]

    return set(
        selected["ip_address"]
        .dropna()
        .astype(str)
    )


def calculate_attack_breakdown(
    ground_truth,
    detected_ips,
):
    """Measure detection across each ground-truth attack type."""

    results = []

    for attack_type in sorted(
        ground_truth["attack_type"]
        .dropna()
        .astype(str)
        .unique()
    ):

        attack_ips = set(
            ground_truth.loc[
                ground_truth["attack_type"].astype(str)
                == attack_type,
                "ip_address",
            ]
            .dropna()
            .astype(str)
        )

        detected_count = len(
            attack_ips & detected_ips
        )

        results.append(
            {
                "attack_type": attack_type,
                "ground_truth_ips": len(attack_ips),
                "detected_as_campaign": detected_count,
                "detection_rate": (
                    detected_count / len(attack_ips)
                    if attack_ips
                    else 0.0
                ),
            }
        )

    return pd.DataFrame(results)


def print_metrics(title, metrics):
    """Print one evaluation result."""

    print()
    print(title)
    print("-" * 72)

    print(
        f"True positives  : "
        f"{metrics['true_positive_ips']:,}"
    )

    print(
        f"False positives : "
        f"{metrics['false_positive_ips']:,}"
    )

    print(
        f"False negatives : "
        f"{metrics['false_negative_ips']:,}"
    )

    print(
        f"Precision       : "
        f"{metrics['precision']:.4f} "
        f"({metrics['precision'] * 100:.2f}%)"
    )

    print(
        f"Recall          : "
        f"{metrics['recall']:.4f} "
        f"({metrics['recall'] * 100:.2f}%)"
    )

    print(
        f"F1 Score        : "
        f"{metrics['f1_score']:.4f} "
        f"({metrics['f1_score'] * 100:.2f}%)"
    )


def main():

    (
        ground_truth,
        clustered_ips,
        risk_scores,
    ) = load_data()

    ground_truth_campaign_ips = (
        get_ground_truth_campaign_ips(ground_truth)
    )

    # ---------------------------------------------------------
    # PATH 1: RAW CLUSTERING
    # ---------------------------------------------------------

    raw_detected_ips = get_detected_campaign_ips(
        clustered_ips
    )

    raw_metrics = calculate_metrics(
        ground_truth_campaign_ips,
        raw_detected_ips,
    )

    # ---------------------------------------------------------
    # PATH 2A: RISK CLASS FILTER
    # ---------------------------------------------------------

    class_filtered, class_column = (
        get_risk_filtered_campaigns(risk_scores)
    )

    if "campaign_id" not in class_filtered.columns:
        raise ValueError(
            "Risk score file must contain 'campaign_id'."
        )

    class_detected_ips = get_campaign_ids_to_ips(
        clustered_ips,
        class_filtered["campaign_id"],
    )

    class_metrics = calculate_metrics(
        ground_truth_campaign_ips,
        class_detected_ips,
    )

    # ---------------------------------------------------------
    # PATH 2B: RISK SCORE THRESHOLD
    # ---------------------------------------------------------

    threshold_filtered, score_column = (
        get_threshold_filtered_campaigns(risk_scores)
    )

    threshold_detected_ips = get_campaign_ids_to_ips(
        clustered_ips,
        threshold_filtered["campaign_id"],
    )

    threshold_metrics = calculate_metrics(
        ground_truth_campaign_ips,
        threshold_detected_ips,
    )

    # ---------------------------------------------------------
    # OUTPUT
    # ---------------------------------------------------------

    print()
    print("=" * 72)
    print("CAMPAIGNSCOPE EVALUATION RESULTS")
    print("=" * 72)

    print(
        f"Ground-truth credential-stuffing IPs : "
        f"{len(ground_truth_campaign_ips):,}"
    )

    print()
    print("PATH 1 — RAW CLUSTERING")
    print_metrics(
        "Raw campaign detection",
        raw_metrics,
    )

    print()
    print("PATH 2A — RISK CLASS FILTER")
    print(
        f"Risk class column: {class_column}"
    )
    print(
        f"Selected class: {TARGET_RISK_CLASS}"
    )
    print(
        f"Selected campaigns: "
        f"{len(class_filtered):,}"
    )

    print_metrics(
        "Risk-class-filtered campaign detection",
        class_metrics,
    )

    print()
    print("PATH 2B — RISK SCORE THRESHOLD")
    print(
        f"Risk score column: {score_column}"
    )
    print(
        f"Threshold: >= {RISK_THRESHOLD:.1f}"
    )
    print(
        f"Selected campaigns: "
        f"{len(threshold_filtered):,}"
    )

    print_metrics(
        "Risk-threshold-filtered campaign detection",
        threshold_metrics,
    )

    # ---------------------------------------------------------
    # FALSE POSITIVE ANALYSIS
    # ---------------------------------------------------------

    class_false_positive_ips = (
        class_detected_ips - ground_truth_campaign_ips
    )

    threshold_false_positive_ips = (
        threshold_detected_ips - ground_truth_campaign_ips
    )

    print()
    print("=" * 72)
    print("REMAINING FALSE POSITIVES")
    print("=" * 72)

    print(
        f"Raw clustering              : "
        f"{len(raw_detected_ips - ground_truth_campaign_ips):,}"
    )

    print(
        f"Risk class filter           : "
        f"{len(class_false_positive_ips):,}"
    )

    print(
        f"Risk threshold filter       : "
        f"{len(threshold_false_positive_ips):,}"
    )

    # ---------------------------------------------------------
    # ATTACK BREAKDOWNS
    # ---------------------------------------------------------

    class_breakdown = calculate_attack_breakdown(
        ground_truth,
        class_detected_ips,
    )

    threshold_breakdown = calculate_attack_breakdown(
        ground_truth,
        threshold_detected_ips,
    )

    print()
    print("RISK CLASS FILTER — ATTACK BREAKDOWN")
    print("-" * 72)
    print(class_breakdown.to_string(index=False))

    print()
    print("RISK THRESHOLD FILTER — ATTACK BREAKDOWN")
    print("-" * 72)
    print(threshold_breakdown.to_string(index=False))

    # ---------------------------------------------------------
    # SAVE RESULTS
    # ---------------------------------------------------------

    comparison = pd.DataFrame(
        [
            {
                "evaluation_path": "raw_clustering",
                **raw_metrics,
            },
            {
                "evaluation_path": "risk_class_CREDENTIAL_STUFFING",
                **class_metrics,
            },
            {
                "evaluation_path": "risk_score_ge_75",
                **threshold_metrics,
            },
        ]
    )

    comparison_path = (
        OUTPUT_DIR / "evaluation_comparison.csv"
    )

    class_breakdown_path = (
        OUTPUT_DIR / "risk_class_attack_breakdown.csv"
    )

    threshold_breakdown_path = (
        OUTPUT_DIR / "risk_threshold_attack_breakdown.csv"
    )

    comparison.to_csv(
        comparison_path,
        index=False,
    )

    class_breakdown.to_csv(
        class_breakdown_path,
        index=False,
    )

    threshold_breakdown.to_csv(
        threshold_breakdown_path,
        index=False,
    )

    print()
    print("=" * 72)
    print("EVALUATION FILES SAVED")
    print("=" * 72)

    print(
        f"[+] Comparison: {comparison_path}"
    )

    print(
        f"[+] Risk-class breakdown: "
        f"{class_breakdown_path}"
    )

    print(
        f"[+] Risk-threshold breakdown: "
        f"{threshold_breakdown_path}"
    )


if __name__ == "__main__":
    main()