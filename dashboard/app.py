from pathlib import Path
import sys

import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

# Allow dashboard to import CampaignScope pipeline modules
ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ingestion.cleaner import DataCleaner
from src.features.fingerprint import FeatureExtractor
from src.correlation.similarity import CrossIPCorrelator
from src.clustering.campaign_detector import CampaignClusterer
from src.risk_engine.scorer import CampaignRiskEngine
from src.graph.builder import CampaignGraphBuilder


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


# ============================================================
# AUTHENTICATION LOG UPLOAD
# ============================================================

REQUIRED_LOG_COLUMNS = [
    "timestamp",
    "ip_address",
    "username",
    "endpoint",
    "user_agent",
    "status_code",
]


def validate_authentication_log(df):
    """
    Validate whether an uploaded CSV contains the
    minimum authentication-log schema required by CampaignScope.
    """

    missing_columns = [
        column
        for column in REQUIRED_LOG_COLUMNS
        if column not in df.columns
    ]

    if missing_columns:
        return False, missing_columns

    return True, []


# ============================================================
# LIVE UPLOADED LOG ANALYSIS
# ============================================================

def analyze_uploaded_logs(uploaded_df):
    """
    Runs the complete CampaignScope detection pipeline
    directly on an uploaded authentication-log DataFrame.
    """

    df = uploaded_df.copy()

    # --------------------------------------------------------
    # Add optional fields expected by the CampaignScope engine
    # --------------------------------------------------------

    if "country" not in df.columns:
        df["country"] = "XX"

    if "response_time" not in df.columns:
        df["response_time"] = 100

    if "device_id" not in df.columns:
        df["device_id"] = "unknown_device"

    # --------------------------------------------------------
    # Phase 1: Cleaning and normalization
    # --------------------------------------------------------

    cleaner = DataCleaner()

    cleaned_df, cleaning_stats = cleaner.clean_dataframe(df)

    if cleaned_df.empty:
        raise ValueError(
            "No valid authentication events remained after cleaning."
        )

    # --------------------------------------------------------
    # Phase 2: IP behavioral fingerprints
    # --------------------------------------------------------

    extractor = FeatureExtractor()

    feature_df = extractor.extract_features(cleaned_df)

    if feature_df.empty:
        raise ValueError(
            "No IP behavioral fingerprints could be generated."
        )

    # --------------------------------------------------------
    # Phase 3: Cross-IP correlation
    # --------------------------------------------------------

    correlator = CrossIPCorrelator(
        min_composite_score=0.45
    )

    correlation_result = correlator.compute_correlations(
        feature_df
    )

    correlation_edges = correlation_result.edges_df

    # --------------------------------------------------------
    # Phase 4: Campaign clustering
    # --------------------------------------------------------

    clusterer = CampaignClusterer()

    cluster_result = clusterer.cluster_campaigns(
        feature_df,
        correlation_edges,
    )

    clustered_ips = cluster_result.clustered_ips_df
    campaign_summaries = cluster_result.campaign_summaries_df

    # --------------------------------------------------------
    # Phase 5: Risk assessment
    # --------------------------------------------------------

    risk_engine = CampaignRiskEngine()

    assessments = risk_engine.assess_all(
        campaign_summaries,
        clustered_ips,
    )

    risk_records = [
        assessment.to_dict()
        for assessment in assessments
    ]

    risk_scores = pd.DataFrame(risk_records)

    if not risk_scores.empty:
        risk_scores["reasons_joined"] = risk_scores[
            "reasons"
        ].apply(
            lambda reasons: "\n".join(reasons)
            if isinstance(reasons, list)
            else str(reasons)
        )

    # --------------------------------------------------------
    # Phase 6: Investigation graph
    # --------------------------------------------------------

    graph_builder = CampaignGraphBuilder(
        clustered_ips_df=clustered_ips,
        campaign_risk_df=risk_scores,
        correlation_edges_df=correlation_edges,
        cleaned_logs_df=cleaned_df,
    )

    graph_nodes = []

    for node_id, attributes in graph_builder.G.nodes(
        data=True
    ):
        graph_nodes.append(
            {
                "node_id": node_id,
                **attributes,
            }
        )

    graph_nodes_df = pd.DataFrame(graph_nodes)

    graph_edges = []

    for source, target, attributes in graph_builder.G.edges(
        data=True
    ):
        graph_edges.append(
            {
                "source": source,
                "target": target,
                **attributes,
            }
        )

    graph_edges_df = pd.DataFrame(graph_edges)

    # --------------------------------------------------------
    # Return complete live-analysis result
    # --------------------------------------------------------

    return {
        "cleaned_logs": cleaned_df,
        "cleaning_stats": cleaning_stats,
        "features": feature_df,
        "correlation_edges": correlation_edges,
        "correlation_stats": correlation_result.stats,
        "clustered_ips": clustered_ips,
        "campaign_summaries": campaign_summaries,
        "clustering_stats": cluster_result.stats,
        "risk_scores": risk_scores,
        "graph_nodes": graph_nodes_df,
        "graph_edges": graph_edges_df,
    }


# ============================================================
# UPLOAD HANDLER
# ============================================================

st.sidebar.subheader("Analyze Your Logs")

uploaded_file = st.sidebar.file_uploader(
    "Upload authentication logs",
    type=["csv"],
    help=(
        "Upload a CSV containing authentication events. "
        "Required columns: timestamp, ip_address, username, "
        "endpoint, user_agent and status_code."
    ),
)

uploaded_logs = None
live_analysis = None


if uploaded_file is not None:

    try:

        uploaded_logs = pd.read_csv(uploaded_file)

        is_valid, missing_columns = validate_authentication_log(
            uploaded_logs
        )

        if not is_valid:

            st.sidebar.error(
                "Invalid authentication log."
            )

            st.sidebar.write(
                "Missing required columns:"
            )

            for column in missing_columns:
                st.sidebar.write(
                    f"- `{column}`"
                )

            uploaded_logs = None

        else:

            st.sidebar.success(
                "Authentication log accepted."
            )

            with st.spinner(
                "Running CampaignScope analysis..."
            ):

                try:

                    live_analysis = analyze_uploaded_logs(
                        uploaded_logs
                    )

                    st.sidebar.success(
                        "CampaignScope analysis completed."
                    )

                except Exception as e:

                    st.sidebar.error(
                        "CampaignScope analysis failed."
                    )

                    st.exception(e)

                    live_analysis = None

    except Exception as e:

        st.sidebar.error(
            "Unable to read the uploaded CSV."
        )

        st.sidebar.exception(e)

        uploaded_logs = None
        live_analysis = None


# ============================================================
# UPLOADED LOG PREVIEW
# ============================================================

if uploaded_logs is not None:

    st.header("Uploaded Authentication Logs")

    upload_col1, upload_col2, upload_col3 = st.columns(3)

    upload_col1.metric(
        "Log Events",
        f"{len(uploaded_logs):,}",
    )

    upload_col2.metric(
        "Unique IPs",
        f"{uploaded_logs['ip_address'].nunique():,}",
    )

    upload_col3.metric(
        "Target Accounts",
        f"{uploaded_logs['username'].nunique():,}",
    )

    st.subheader("Log Preview")

    st.dataframe(
        uploaded_logs.head(100),
        width="stretch",
        hide_index=True,
    )


# ============================================================
# LIVE ANALYSIS SUMMARY
# ============================================================

if live_analysis is not None:

    cleaning_stats = live_analysis[
        "cleaning_stats"
    ]

    clustering_stats = live_analysis[
        "clustering_stats"
    ]

    correlation_stats = live_analysis[
        "correlation_stats"
    ]

    st.success(
        "CampaignScope analysis completed successfully."
    )

    st.subheader("Live Analysis Summary")

    live_col1, live_col2, live_col3, live_col4 = st.columns(4)

    live_col1.metric(
        "Clean Events",
        f"{cleaning_stats['final_rows']:,}",
    )

    live_col2.metric(
        "Analyzed IPs",
        f"{clustering_stats['total_ips_analyzed']:,}",
    )

    live_col3.metric(
        "Correlation Edges",
        f"{correlation_stats['correlated_edges_retained']:,}",
    )

    live_col4.metric(
        "Campaigns Detected",
        f"{clustering_stats['campaigns_detected']:,}",
    )


# ============================================================
# USE LIVE ANALYSIS WHEN A LOG IS UPLOADED
# ============================================================

if live_analysis is not None:

    campaign_summaries = live_analysis[
        "campaign_summaries"
    ]

    risk_scores = live_analysis[
        "risk_scores"
    ]

    if risk_scores.empty:
        risk_scores = pd.DataFrame(
            columns=[
                "campaign_id",
                "risk_score",
                "classification",
                "ip_count",
                "total_events",
                "unique_target_accounts",
                "avg_attempts_per_ip",
                "account_overlap_pct",
                "timing_similarity_pct",
                "ua_similarity_pct",
                "endpoint_similarity_pct",
                "failure_behavior_pct",
                "primary_user_agent",
                "primary_endpoint",
                "top_origin_countries",
                "reasons_joined",
            ]
        )

    clustered_ips = live_analysis[
        "clustered_ips"
    ]

    correlation_edges = live_analysis[
        "correlation_edges"
    ]

    graph_nodes = live_analysis[
        "graph_nodes"
    ]

    graph_edges = live_analysis[
        "graph_edges"
    ]


# ============================================================
# CAMPAIGN SELECTION
# ============================================================

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
    "account_overlap_pct",
    "timing_similarity_pct",
    "ua_similarity_pct",
    "endpoint_similarity_pct",
    "failure_behavior_pct",
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
