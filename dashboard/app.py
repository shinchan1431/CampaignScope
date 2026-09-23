from pathlib import Path

import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[1]

PROCESSED = ROOT / "dataset" / "processed"
EVALUATION = ROOT / "dataset" / "evaluation"


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="CampaignScope",
    page_icon="🛡️",
    layout="wide",
)


# ============================================================
# DATA LOADING
# ============================================================

@st.cache_data
def load_data():

    campaign_summaries = pd.read_csv(
        PROCESSED / "campaign_summaries.csv"
    )

    risk_scores = pd.read_csv(
        PROCESSED / "campaign_risk_scores.csv"
    )

    clustered_ips = pd.read_csv(
        PROCESSED / "clustered_ips.csv"
    )

    correlation_edges = pd.read_csv(
        PROCESSED / "correlation_edges.csv"
    )

    graph_nodes = pd.read_csv(
        PROCESSED / "graph_nodes.csv"
    )

    graph_edges = pd.read_csv(
        PROCESSED / "graph_edges.csv"
    )

    evaluation = pd.read_csv(
        EVALUATION / "evaluation_comparison.csv"
    )

    attack_breakdown = pd.read_csv(
        EVALUATION / "risk_class_attack_breakdown.csv"
    )

    return (
        campaign_summaries,
        risk_scores,
        clustered_ips,
        correlation_edges,
        graph_nodes,
        graph_edges,
        evaluation,
        attack_breakdown,
    )


try:
    (
        campaign_summaries,
        risk_scores,
        clustered_ips,
        correlation_edges,
        graph_nodes,
        graph_edges,
        evaluation,
        attack_breakdown,
    ) = load_data()

except Exception as e:

    st.error(
        "Unable to load CampaignScope processed datasets."
    )

    st.exception(e)

    st.stop()


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ CampaignScope")

st.subheader(
    "Distributed Credential-Stuffing Campaign Detection & Investigation"
)

st.markdown(
    """
CampaignScope correlates authentication behavior across multiple IP
addresses to identify coordinated low-and-slow credential attacks that
may evade traditional single-IP detection.
"""
)


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("CampaignScope")

st.sidebar.markdown(
    """
### Detection Pipeline

Authentication Logs  
↓  
Feature Extraction  
↓  
Cross-IP Correlation  
↓  
Campaign Clustering  
↓  
Risk Assessment  
↓  
Investigation
"""
)

st.sidebar.divider()

selected_campaign = st.sidebar.selectbox(
    "Select Campaign",
    ["All"] + sorted(
        risk_scores["campaign_id"]
        .astype(str)
        .unique()
        .tolist()
    ),
)


# ============================================================
# TOP METRICS
# ============================================================

total_ips = clustered_ips["ip_address"].nunique()

total_candidates = len(
    clustered_ips[
        ~clustered_ips["campaign_id"]
        .astype(str)
        .eq("BENIGN_NOISE")
    ]
)

high_risk = len(
    risk_scores[
        risk_scores["classification"]
        .astype(str)
        .str.upper()
        .eq("CREDENTIAL_STUFFING")
    ]
)

high_risk_ips = 0

for campaign_id in risk_scores.loc[
    risk_scores["classification"]
    .astype(str)
    .str.upper()
    .eq("CREDENTIAL_STUFFING"),
    "campaign_id",
]:

    high_risk_ips += clustered_ips[
        clustered_ips["campaign_id"].astype(str)
        == str(campaign_id)
    ]["ip_address"].nunique()


col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Unique IPs",
    f"{total_ips:,}",
)

col2.metric(
    "Candidate Campaign IPs",
    f"{total_candidates:,}",
)

col3.metric(
    "High-Risk Campaigns",
    f"{high_risk:,}",
)

col4.metric(
    "High-Risk Campaign IPs",
    f"{high_risk_ips:,}",
)


st.divider()


# ============================================================
# CAMPAIGN RISK OVERVIEW
# ============================================================

st.header("Campaign Risk Overview")

risk_display = risk_scores[
    [
        "campaign_id",
        "risk_score",
        "classification",
    ]
].copy()

risk_display = risk_display.sort_values(
    "risk_score",
    ascending=False,
)

st.dataframe(
    risk_display,
    width="stretch",
    hide_index=True,
)


fig_risk = px.bar(
    risk_display,
    x="campaign_id",
    y="risk_score",
    color="classification",
    title="Campaign Risk Scores",
    range_y=[0, 100],
)

fig_risk.add_hline(
    y=75,
    line_dash="dash",
    annotation_text="Credential-Stuffing Threshold",
)

st.plotly_chart(
    fig_risk,
    width="stretch",
)


# ============================================================
# SELECTED CAMPAIGN
# ============================================================

st.header("Campaign Investigation")

if selected_campaign == "All":

    selected_risk = risk_scores.copy()

else:

    selected_risk = risk_scores[
        risk_scores["campaign_id"].astype(str)
        == selected_campaign
    ].copy()


if selected_risk.empty:

    st.warning("No campaign selected.")

else:

    selected_row = selected_risk.iloc[0]

    campaign_id = str(
        selected_row["campaign_id"]
    )

    campaign_cluster = clustered_ips[
        clustered_ips["campaign_id"].astype(str)
        == campaign_id
    ].copy()

    st.subheader(campaign_id)

    m1, m2, m3, m4 = st.columns(4)

    m1.metric(
        "Risk Score",
        f"{float(selected_row['risk_score']):.1f}",
    )

    m2.metric(
        "Classification",
        str(selected_row["classification"]),
    )

    m3.metric(
        "Campaign IPs",
        f"{len(campaign_cluster):,}",
    )

    m4.metric(
        "Total Events",
        f"{campaign_cluster['total_requests'].sum():,.0f}"
        if "total_requests" in campaign_cluster.columns
        else "N/A",
    )


# ============================================================
# RISK SIGNALS
# ============================================================

st.header("Risk Signals")

signal_columns = [
    "account_overlap",
    "timing_similarity",
    "ua_similarity",
    "endpoint_similarity",
    "failure_behavior",
]

available_signals = [
    c for c in signal_columns
    if c in selected_risk.columns
]

if available_signals:

    signal_row = selected_risk.iloc[0]

    signal_data = pd.DataFrame(
        {
            "Signal": [
                c.replace("_", " ").title()
                for c in available_signals
            ],
            "Score": [
                float(signal_row[c])
                for c in available_signals
            ],
        }
    )

    signal_data["Score"] = (
        signal_data["Score"] * 100
    )

    fig_signals = px.bar(
        signal_data,
        x="Score",
        y="Signal",
        orientation="h",
        range_x=[0, 100],
        title="Behavioral Correlation Signals",
    )

    st.plotly_chart(
        fig_signals,
        width="stretch",
    )

else:

    st.info(
        "Risk signal columns were not found in the risk-score dataset."
    )


# ============================================================
# CAMPAIGN SUMMARY
# ============================================================

st.header("Campaign Behavioral Summary")

if selected_campaign == "All":

    summary_display = campaign_summaries.copy()

else:

    summary_display = campaign_summaries[
        campaign_summaries["campaign_id"].astype(str)
        == selected_campaign
    ].copy()


st.dataframe(
    summary_display,
    width="stretch",
    hide_index=True,
)


# ============================================================
# CORRELATION GRAPH
# ============================================================

st.header("Cross-IP Correlation")

st.write(
    f"CampaignScope retained "
    f"**{len(correlation_edges):,} correlation edges** "
    f"between related IP addresses."
)

if not correlation_edges.empty:

    edge_sample = correlation_edges.nlargest(
        min(100, len(correlation_edges)),
        "composite_score",
    )

    fig_edges = px.scatter(
        edge_sample,
        x="ip_1",
        y="ip_2",
        size="composite_score",
        color="composite_score",
        title="Strongest Cross-IP Correlations",
    )

    st.plotly_chart(
        fig_edges,
        width="stretch",
    )


# ============================================================
# INVESTIGATION GRAPH
# ============================================================

st.header("Investigation Graph")

st.write(
    "The graph connects campaigns with participating IPs, "
    "target accounts, endpoints and client signatures."
)

if not graph_nodes.empty and not graph_edges.empty:

    campaign_nodes = graph_nodes[
        graph_nodes["node_type"].astype(str)
        == "campaign"
    ]

    st.write(
        f"Graph contains "
        f"**{len(graph_nodes):,} nodes** and "
        f"**{len(graph_edges):,} edges**."
    )

    st.dataframe(
        campaign_nodes,
        width="stretch",
        hide_index=True,
    )


# ============================================================
# EVALUATION
# ============================================================

st.header("Detection Evaluation")

evaluation_display = evaluation.copy()

for column in [
    "precision",
    "recall",
    "f1_score",
]:

    if column in evaluation_display.columns:

        evaluation_display[column] = (
            evaluation_display[column] * 100
        ).round(2)

st.dataframe(
    evaluation_display,
    width="stretch",
    hide_index=True,
)


fig_evaluation = go.Figure()

fig_evaluation.add_trace(
    go.Bar(
        name="Precision",
        x=evaluation["evaluation_path"],
        y=evaluation["precision"] * 100,
    )
)

fig_evaluation.add_trace(
    go.Bar(
        name="Recall",
        x=evaluation["evaluation_path"],
        y=evaluation["recall"] * 100,
    )
)

fig_evaluation.add_trace(
    go.Bar(
        name="F1",
        x=evaluation["evaluation_path"],
        y=evaluation["f1_score"] * 100,
    )
)

fig_evaluation.update_layout(
    title="Detection Performance Comparison",
    yaxis_title="Score (%)",
    yaxis_range=[0, 105],
    barmode="group",
)

st.plotly_chart(
    fig_evaluation,
    width="stretch",
)


# ============================================================
# ATTACK BREAKDOWN
# ============================================================

st.header("Ground-Truth Attack Breakdown")

st.dataframe(
    attack_breakdown,
    width="stretch",
    hide_index=True,
)


st.divider()

st.caption(
    "CampaignScope — Synthetic security analytics benchmark. "
    "Evaluation metrics are based on the generated ground-truth dataset."
)
