from pathlib import Path

from detection.tcp_analyzer import (
    analyze_pcap,
    detect_patterns,
    calculate_metrics
)


DATASETS = Path("datasets")


def get_alert_types(filename):
    df = analyze_pcap(str(DATASETS / filename))
    return df, {
        alert["type"] for alert in detect_patterns(df)
    }


def test_legitimate_traffic():
    df, alerts = get_alert_types("legitimate.pcap")

    assert len(df) == 45
    assert "SYN Burst" not in alerts
    assert "Port Scanning" not in alerts


def test_syn_burst():
    df, alerts = get_alert_types("syn_burst.pcap")

    assert len(df) == 150
    assert "SYN Burst" in alerts


def test_port_scan():
    df, alerts = get_alert_types("port_scan.pcap")

    assert len(df) == 80
    assert "Port Scanning" in alerts


def test_repeated_syn():
    df, alerts = get_alert_types("retransmission.pcap")

    assert len(df) == 5
    assert "Retransmission Candidate" in alerts


def test_handshake_metrics():
    df = analyze_pcap(str(DATASETS / "legitimate.pcap"))
    metrics = calculate_metrics(df)

    assert metrics["completed_handshakes"] == 15
    assert metrics["handshake_completion_rate"] == 100.0
    assert metrics["incomplete_handshakes"] == 0
