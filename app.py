import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path
import tempfile
import os

from detection.tcp_analyzer import (
    analyze_pcap,
    detect_patterns,
    calculate_metrics
)

from evaluation import evaluate_prediction
from evaluation_dataset import evaluate_dataset


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="TCP Cloud Detection",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ TCP Suspicious Connection Detection")
st.caption(
    "PCAP-Based Network Security Analysis and Detection Engineering"
)


# --------------------------------------------------
# DATASET CONFIGURATION
# --------------------------------------------------

DATASET_DIR = Path("datasets")

datasets = {
    "Legitimate Traffic": "legitimate.pcap",
    "SYN Burst Attack": "syn_burst.pcap",
    "Port Scanning": "port_scan.pcap",
    "Repeated SYN Attempts": "retransmission.pcap"
}


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

st.sidebar.title("PCAP Analysis")

mode = st.sidebar.radio(
    "Select Analysis Mode",
    ["Prepared Dataset", "Upload PCAP"]
)

path = None
temp_path = None
analysis_df = None
analysis_alerts = []
analysis_filename = None

if mode == "Prepared Dataset":

    choice = st.sidebar.selectbox(
        "Choose Dataset",
        list(datasets.keys())
    )

    path = DATASET_DIR / datasets[choice]

else:

    uploaded = st.sidebar.file_uploader(
        "Upload TCP PCAP",
        type=["pcap", "pcapng"]
    )

    if uploaded:

        original_filename = Path(uploaded.name).name
        uploaded_suffix = Path(original_filename).suffix.lower() or ".pcap"

        with tempfile.NamedTemporaryFile(
            suffix=uploaded_suffix,
            delete=False
        ) as tmp:

            tmp.write(uploaded.getvalue())
            temp_path = tmp.name

        path = Path(temp_path)


# --------------------------------------------------
# PCAP ANALYSIS
# --------------------------------------------------

if path is not None:

    if not path.exists():

        st.error("Selected PCAP file does not exist.")

    else:

        try:

            # Extract TCP packets
            df = analyze_pcap(str(path))

            if df.empty:

                st.warning("No IPv4 TCP packets found.")

            else:

                # Detection engine
                alerts = detect_patterns(df)

                # Keep the exact current PCAP analysis for evaluation below.
                analysis_df = df
                analysis_alerts = alerts
                analysis_filename = (
                    original_filename
                    if mode == "Upload PCAP" and uploaded
                    else path.name
                )

                # TCP metrics
                metrics = calculate_metrics(df)

                st.success(f"Analyzed: {analysis_filename}")

                # ----------------------------------
                # NETWORK OVERVIEW
                # ----------------------------------

                st.header("Network Traffic Overview")

                c1, c2, c3, c4 = st.columns(4)

                c1.metric("Total Packets", metrics["total_packets"])
                c2.metric("TCP Packets", metrics["tcp_packets"])
                c3.metric("UDP Packets", metrics["udp_packets"])
                c4.metric("Unique Sources", df["src_ip"].nunique())

                c5, c6, c7, c8 = st.columns(4)

                c5.metric("IPv4 Packets", metrics["ipv4_packets"])
                c6.metric("IPv6 Packets", metrics["ipv6_packets"])
                c7.metric("Initial SYN", metrics["initial_syn"])
                c8.metric("Detection Alerts", len(alerts))

                # ----------------------------------
                # PROTOCOL AND IP VERSION DISTRIBUTION
                # ----------------------------------

                st.header("Protocol and IP Version Distribution")

                protocol_counts = (
                    df["protocol"]
                    .value_counts()
                    .rename_axis("Protocol")
                    .reset_index(name="Packets")
                )

                ip_version_counts = (
                    df["ip_version"]
                    .map({4: "IPv4", 6: "IPv6"})
                    .fillna("Other")
                    .value_counts()
                    .rename_axis("IP Version")
                    .reset_index(name="Packets")
                )

                chart1, chart2 = st.columns(2)

                with chart1:
                    st.subheader("Protocol Distribution")

                    protocol_fig = px.pie(
                        protocol_counts,
                        names="Protocol",
                        values="Packets",
                        hole=0.45,
                        title="TCP vs UDP"
                    )

                    st.plotly_chart(
                        protocol_fig,
                        use_container_width=True
                    )

                with chart2:
                    st.subheader("IP Version Distribution")

                    ip_fig = px.pie(
                        ip_version_counts,
                        names="IP Version",
                        values="Packets",
                        hole=0.45,
                        title="IPv4 vs IPv6"
                    )

                    st.plotly_chart(
                        ip_fig,
                        use_container_width=True
                    )

                # ----------------------------------
                # HANDSHAKE ANALYTICS
                # ----------------------------------

                st.header("TCP Handshake Analytics")

                m1, m2, m3, m4 = st.columns(4)

                m1.metric(
                    "Initial SYN",
                    metrics["initial_syn"]
                )

                m2.metric(
                    "SYN-ACK",
                    metrics["syn_ack"]
                )

                m3.metric(
                    "Completed Handshakes",
                    metrics["completed_handshakes"]
                )

                m4.metric(
                    "Completion Rate",
                    f'{metrics["handshake_completion_rate"]}%'
                )

                st.subheader("Handshake Status")

                m5, m6, m7, m8 = st.columns(4)

                m5.metric(
                    "Unanswered SYN",
                    metrics["unanswered_syn"]
                )

                m6.metric(
                    "SYN-ACK Without Final ACK",
                    metrics["synack_without_final_ack"]
                )

                m7.metric(
                    "Pending Handshakes",
                    metrics["pending_handshakes"]
                )

                m8.metric(
                    "Incomplete Handshakes",
                    metrics["incomplete_handshakes"]
                )

                m9, m10 = st.columns(2)

                m9.metric(
                    "Incomplete Rate",
                    f'{metrics["incomplete_handshake_rate"]}%'
                )

                m10.metric(
                    "Retransmission Candidates",
                    metrics["retransmission_candidates"]
                )

                st.caption(
                    "Handshake timeout: 30 seconds. Pending sessions "
                    "are excluded from completion and incomplete rates."
                )

                # ----------------------------------
                # SOURCE IP TRAFFIC
                # ----------------------------------

                st.header("Traffic by Source IP")

                traffic = (
                    df["src_ip"]
                    .value_counts()
                    .reset_index()
                )

                traffic.columns = ["Source IP", "Packets"]

                fig = px.bar(
                    traffic,
                    x="Source IP",
                    y="Packets",
                    title="TCP Packets by Source IP"
                )

                st.plotly_chart(
                    fig,
                    use_container_width=True
                )

                # ----------------------------------
                # TCP FLAG DISTRIBUTION
                # ----------------------------------

                st.header("TCP Flag Distribution")

                flag_data = pd.DataFrame({
                    "Flag": [
                        "SYN",
                        "SYN-ACK",
                        "ACK",
                        "RST",
                        "FIN"
                    ],

                    "Count": [
                        int((df["syn"] & ~df["ack_flag"]).sum()),
                        int((df["syn"] & df["ack_flag"]).sum()),
                        int((~df["syn"] & df["ack_flag"]).sum()),
                        int(df["rst"].sum()),
                        int(df["fin"].sum())
                    ]
                })

                fig2 = px.bar(
                    flag_data,
                    x="Flag",
                    y="Count",
                    title="TCP Flag Analysis"
                )

                st.plotly_chart(
                    fig2,
                    use_container_width=True
                )

                # ----------------------------------
                # SECURITY ALERT ANALYSIS
                # ----------------------------------

                st.header("Security Alert Analysis")

                if alerts:

                    alert_df = pd.DataFrame(alerts)

                    # Alert summary
                    total_alerts = len(alert_df)
                    severity_counts = (
                        alert_df["severity"]
                        .fillna("Unknown")
                        .value_counts()
                    )

                    high_alerts = int(severity_counts.get("HIGH", 0))
                    medium_alerts = int(severity_counts.get("MEDIUM", 0))
                    low_alerts = int(severity_counts.get("LOW", 0))

                    a1, a2, a3, a4 = st.columns(4)

                    a1.metric("Total Alerts", total_alerts)
                    a2.metric("High Severity", high_alerts)
                    a3.metric("Medium Severity", medium_alerts)
                    a4.metric("Low Severity", low_alerts)

                    # Alert type distribution
                    st.subheader("Alerts by Detection Rule")

                    type_counts = (
                        alert_df["type"]
                        .fillna("Unknown")
                        .value_counts()
                        .rename_axis("Detection Rule")
                        .reset_index(name="Alert Count")
                    )

                    type_fig = px.bar(
                        type_counts,
                        x="Detection Rule",
                        y="Alert Count",
                        color="Detection Rule",
                        title="Detection Alerts by Rule"
                    )

                    st.plotly_chart(
                        type_fig,
                        use_container_width=True
                    )

                    # Detailed alert investigation table
                    st.subheader("Alert Investigation Details")

                    display_columns = [
                        column for column in [
                            "type",
                            "source",
                            "severity",
                            "confidence",
                            "evidence"
                        ]
                        if column in alert_df.columns
                    ]

                    st.dataframe(
                        alert_df[display_columns],
                        use_container_width=True,
                        hide_index=True
                    )

                    # Download original complete alert records
                    st.download_button(
                        "Download Alerts CSV",
                        alert_df.to_csv(index=False),
                        "tcp_alerts.csv",
                        "text/csv"
                    )

                    st.caption(
                        "Alerts are detection indicators. They require "
                        "investigation and are not automatically confirmed attacks."
                    )

                else:

                    st.success(
                        "No configured detection rules triggered."
                    )

                # ----------------------------------
                # PACKET DETAILS
                # ----------------------------------

                with st.expander("View TCP Packet Details"):

                    st.dataframe(
                        df,
                        use_container_width=True
                    )

                st.download_button(
                    "Download Packet Analysis CSV",
                    df.to_csv(index=False),
                    "tcp_analysis.csv",
                    "text/csv"
                )

        except Exception as error:

            st.error(f"PCAP analysis failed: {error}")

        finally:

            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)


# --------------------------------------------------
# DETECTION PERFORMANCE EVALUATION - CURRENT PCAP ONLY
# --------------------------------------------------

st.divider()
st.header("Detection Performance Evaluation")

if analysis_df is None:
    st.info("Select a prepared dataset or upload a PCAP file to analyse it. The evaluation below will use that same file.")
else:
    st.write(f"Evaluation source: **{analysis_filename}**")
    st.write(f"The prediction is generated from the detection alerts for this exact PCAP. Provide its expected class (ground truth) to compare the prediction.")

    expected_class = st.radio(
        "What is the expected class of this PCAP? (Ground truth)",
        ["Benign", "Malicious / Suspicious"],
        horizontal=True,
        key=f"ground_truth_{analysis_filename}"
    )

    ground_truth = 1 if expected_class == "Malicious / Suspicious" else 0

    if st.button("Evaluate This PCAP", type="primary"):
        try:
            results, evaluation = evaluate_prediction(
                analysis_filename,
                analysis_alerts,
                ground_truth
            )

            st.subheader("Performance Metrics — Current Uploaded/Selected PCAP")
            e1, e2, e3, e4 = st.columns(4)
            e1.metric("File-level Agreement", f'{evaluation["accuracy"] * 100:.2f}%')
            e2.metric("Precision", f'{evaluation["precision"]:.2f}')
            e3.metric("Recall", f'{evaluation["recall"]:.2f}')
            e4.metric("F1 Score", f'{evaluation["f1"]:.2f}')

            st.subheader("Confusion Matrix — This PCAP")
            matrix = pd.DataFrame(
                [[evaluation["tn"], evaluation["fp"]],
                 [evaluation["fn"], evaluation["tp"]]],
                index=["Actual Benign", "Actual Suspicious"],
                columns=["Predicted Benign", "Predicted Suspicious"]
            )
            st.dataframe(matrix, use_container_width=True)
            st.metric("False Positive Rate", f'{evaluation["fpr"] * 100:.2f}%')

            st.subheader("Evaluation Result for This PCAP")
            st.dataframe(results, use_container_width=True)
            st.download_button(
                "Download This PCAP Evaluation CSV",
                results.to_csv(index=False),
                file_name=f"{Path(analysis_filename).stem}_evaluation.csv",
                mime="text/csv"
            )

            if evaluation["prediction"] == evaluation["ground_truth"]:
                st.success("The detection result matches the ground-truth label you provided.")
            else:
                st.warning("The detection result does not match the ground-truth label you provided.")

            st.warning(
                "Important: this evaluation contains only one labelled PCAP file. "
                "The metrics describe this single file-level comparison and are not a reliable estimate "
                "of general detection accuracy. For robust precision, recall and F1-score, evaluate a "
                "larger collection of independently labelled PCAP files."
            )
        except Exception as error:
            st.error(f"Evaluation failed: {error}")



# --------------------------------------------------
# MULTI-PCAP DATASET EVALUATION
# --------------------------------------------------

st.divider()
st.header("Multi-PCAP Dataset Evaluation")

st.write(
    "Evaluate all labelled PCAP files in the prepared dataset using "
    "the ground-truth labels in datasets/labels.csv."
)

st.caption(
    "Prediction policy: a PCAP is classified as Suspicious if at least "
    "one detection alert is generated; otherwise it is classified as Benign."
)

if st.button("Run Multi-PCAP Evaluation", type="primary"):
    try:
        results_df, dataset_metrics = evaluate_dataset()

        st.subheader("Dataset-Level Performance Metrics")

        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("PCAP Files", dataset_metrics["total_pcaps"])
        m2.metric("Accuracy", f'{dataset_metrics["accuracy"] * 100:.2f}%')
        m3.metric("Precision", f'{dataset_metrics["precision"] * 100:.2f}%')
        m4.metric("Recall", f'{dataset_metrics["recall"] * 100:.2f}%')
        m5.metric("F1 Score", f'{dataset_metrics["f1"] * 100:.2f}%')

        st.metric(
            "False Positive Rate",
            f'{dataset_metrics["fpr"] * 100:.2f}%'
        )

        st.subheader("Dataset Confusion Matrix")

        matrix = pd.DataFrame(
            [
                [dataset_metrics["tn"], dataset_metrics["fp"]],
                [dataset_metrics["fn"], dataset_metrics["tp"]]
            ],
            index=["Actual Benign", "Actual Suspicious"],
            columns=["Predicted Benign", "Predicted Suspicious"]
        )

        st.dataframe(matrix, use_container_width=True)

        st.subheader("Individual PCAP Evaluation Results")
        st.dataframe(results_df, use_container_width=True)

        st.download_button(
            "Download Multi-PCAP Evaluation CSV",
            results_df.to_csv(index=False),
            file_name="multi_pcap_evaluation.csv",
            mime="text/csv",
            key="download_multi_pcap_evaluation"
        )

        st.success(
            f"Evaluation completed for {dataset_metrics['total_pcaps']} PCAP files."
        )

        st.warning(
            "Research limitation: these results use a small synthetic dataset "
            "with analyst-provided labels. They demonstrate controlled "
            "scenario detection, not generalised real-world detection accuracy. "
            "Repeated SYN packets may also occur in legitimate network traffic."
        )

    except Exception as error:
        st.error(f"Multi-PCAP evaluation failed: {error}")


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "TCP Cloud Detection | Python | Scapy | Streamlit | "
    "Detection Engineering Prototype"
)

