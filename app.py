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

from detection.evaluator import evaluate_datasets


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

        with tempfile.NamedTemporaryFile(
            suffix=".pcap",
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

                # TCP metrics
                metrics = calculate_metrics(df)

                st.success(f"Analyzed: {path.name}")

                # ----------------------------------
                # NETWORK OVERVIEW
                # ----------------------------------

                st.header("Network Traffic Overview")

                c1, c2, c3, c4 = st.columns(4)

                c1.metric("TCP Packets", len(df))

                c2.metric(
                    "Unique Sources",
                    df["src_ip"].nunique()
                )

                c3.metric(
                    "Initial SYN",
                    metrics["initial_syn"]
                )

                c4.metric(
                    "Detection Alerts",
                    len(alerts)
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

                m5, m6, m7 = st.columns(3)

                m5.metric(
                    "Incomplete Handshakes",
                    metrics["incomplete_handshakes"]
                )

                m6.metric(
                    "Incomplete Rate",
                    f'{metrics["incomplete_handshake_rate"]}%'
                )

                m7.metric(
                    "Retransmission Candidates",
                    metrics["retransmission_candidates"]
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
                # SECURITY ALERTS
                # ----------------------------------

                st.header("Security Detection Alerts")

                if alerts:

                    alert_df = pd.DataFrame(alerts)

                    st.dataframe(
                        alert_df,
                        use_container_width=True
                    )

                    st.download_button(
                        "Download Alerts CSV",
                        alert_df.to_csv(index=False),
                        "tcp_alerts.csv",
                        "text/csv"
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
# DETECTION PERFORMANCE EVALUATION
# --------------------------------------------------

st.divider()

st.header("Detection Performance Evaluation")

st.write(
    "Evaluate the detection engine against the four "
    "prepared and labelled synthetic PCAP datasets."
)

if st.button("Run Dataset Evaluation"):

    try:

        results, evaluation = evaluate_datasets()

        st.subheader("Performance Metrics")

        e1, e2, e3, e4 = st.columns(4)

        e1.metric(
            "Accuracy",
            f'{evaluation["accuracy"] * 100:.2f}%'
        )

        e2.metric(
            "Precision",
            f'{evaluation["precision"]:.2f}'
        )

        e3.metric(
            "Recall",
            f'{evaluation["recall"]:.2f}'
        )

        e4.metric(
            "F1 Score",
            f'{evaluation["f1"]:.2f}'
        )

        # ----------------------------------
        # CONFUSION MATRIX
        # ----------------------------------

        st.subheader("Confusion Matrix")

        matrix = pd.DataFrame(
            [
                [evaluation["tn"], evaluation["fp"]],
                [evaluation["fn"], evaluation["tp"]]
            ],

            index=[
                "Actual Benign",
                "Actual Suspicious"
            ],

            columns=[
                "Predicted Benign",
                "Predicted Suspicious"
            ]
        )

        st.dataframe(
            matrix,
            use_container_width=True
        )

        # ----------------------------------
        # FALSE POSITIVE RATE
        # ----------------------------------

        st.metric(
            "False Positive Rate",
            f'{evaluation["fpr"] * 100:.2f}%'
        )

        # ----------------------------------
        # DATASET RESULTS
        # ----------------------------------

        st.subheader("Dataset Evaluation Results")

        st.dataframe(
            results,
            use_container_width=True
        )

        st.download_button(
            "Download Evaluation CSV",
            results.to_csv(index=False),
            "detection_evaluation.csv",
            "text/csv"
        )

        st.success("Evaluation completed successfully.")

        st.caption(
            "Results represent the current synthetic test dataset, "
            "not validated production detection accuracy."
        )

    except Exception as error:

        st.error(f"Evaluation failed: {error}")


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "TCP Cloud Detection | Python | Scapy | Streamlit | "
    "Detection Engineering Prototype"
)

