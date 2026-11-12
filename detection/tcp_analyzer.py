from collections import defaultdict
from scapy.all import rdpcap, IP, TCP
import pandas as pd


# Configurable detection thresholds
SYN_THRESHOLD = 100
PORT_SCAN_THRESHOLD = 20
RETRANSMISSION_THRESHOLD = 3
WINDOW_SECONDS = 10
HANDSHAKE_TIMEOUT = 30


def analyze_pcap(file_path):
    packets = rdpcap(file_path)
    records = []

    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue

        ip = pkt[IP]
        tcp = pkt[TCP]
        flags = int(tcp.flags)

        records.append({
            "timestamp": float(pkt.time),
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "src_port": int(tcp.sport),
            "dst_port": int(tcp.dport),
            "flags": flags,
            "seq": int(tcp.seq),
            "ack": int(tcp.ack),
            "syn": bool(flags & 0x02),
            "ack_flag": bool(flags & 0x10),
            "rst": bool(flags & 0x04),
            "fin": bool(flags & 0x01),
        })

    return pd.DataFrame(records).sort_values(
        "timestamp"
    ).reset_index(drop=True)


def detect_patterns(df):
    alerts = []

    if df.empty:
        return alerts

    # Only initial SYN packets, not SYN-ACK
    syns = df[df["syn"] & ~df["ack_flag"]].copy()

    # 1. SYN burst detection using a sliding window
    for src, group in syns.groupby("src_ip"):
        times = sorted(group["timestamp"].tolist())
        left = 0

        for right, current in enumerate(times):
            while current - times[left] > WINDOW_SECONDS:
                left += 1

            count = right - left + 1

            if count > SYN_THRESHOLD:
                alerts.append({
                    "source": src,
                    "type": "SYN Burst",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "evidence": (
                        f"{count} initial SYN attempts "
                        f"within {WINDOW_SECONDS} seconds"
                    )
                })
                break

    # 2. Port scanning detection within a time window
    for src, group in syns.groupby("src_ip"):
        group = group.sort_values("timestamp")
        rows = group.to_dict("records")
        left = 0

        for right, row in enumerate(rows):
            while (
                row["timestamp"] - rows[left]["timestamp"]
                > WINDOW_SECONDS
            ):
                left += 1

            window = rows[left:right + 1]
            unique_ports = len({
                item["dst_port"] for item in window
            })

            if unique_ports >= PORT_SCAN_THRESHOLD:
                alerts.append({
                    "source": src,
                    "type": "Port Scanning",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "evidence": (
                        f"{unique_ports} destination ports "
                        f"contacted within {WINDOW_SECONDS} seconds"
                    )
                })
                break

    # 3. TCP three-way handshake correlation
    flows = {}

    for row in df.to_dict("records"):
        key = (
            row["src_ip"], row["dst_ip"],
            row["src_port"], row["dst_port"]
        )

        reverse = (
            row["dst_ip"], row["src_ip"],
            row["dst_port"], row["src_port"]
        )

        if row["syn"] and not row["ack_flag"]:
            flows.setdefault(key, {
                "syn_time": row["timestamp"],
                "syn_seq": row["seq"],
                "synack_time": None,
                "synack_seq": None,
                "completed": False,
            })

        elif row["syn"] and row["ack_flag"]:
            flow = flows.get(reverse)

            if (
                flow
                and row["ack"] == flow["syn_seq"] + 1
                and flow["synack_time"] is None
            ):
                flow["synack_time"] = row["timestamp"]
                flow["synack_seq"] = row["seq"]

        elif row["ack_flag"] and not row["syn"]:
            flow = flows.get(key)

            if (
                flow
                and flow["synack_time"] is not None
                and row["timestamp"] >= flow["synack_time"]
                and row["seq"] == flow["syn_seq"] + 1
                and row["ack"] == flow["synack_seq"] + 1
            ):
                flow["completed"] = True

    completed = sum(
        1 for flow in flows.values() if flow["completed"]
    )

    total = len(flows)
    incomplete = total - completed

    for key, flow in flows.items():
        if flow["completed"]:
            continue

        elapsed = (
            df["timestamp"].max() - flow["syn_time"]
        )

        # Only flag when capture has enough observation time
        if elapsed >= HANDSHAKE_TIMEOUT:
            alerts.append({
                "source": key[0],
                "type": "Incomplete Handshake",
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
                "evidence": (
                    f"No complete handshake observed for "
                    f"{key[1]}:{key[3]}"
                )
            })

    # 4. Repeated SYN / retransmission candidates
    syn_groups = syns.groupby([
        "src_ip", "dst_ip", "src_port",
        "dst_port", "seq"
    ])

    for key, group in syn_groups:
        group = group.sort_values("timestamp")
        times = group["timestamp"].tolist()

        if len(times) >= RETRANSMISSION_THRESHOLD:
            if times[-1] - times[0] <= WINDOW_SECONDS:
                alerts.append({
                    "source": key[0],
                    "type": "Retransmission Candidate",
                    "severity": "LOW",
                    "confidence": "MEDIUM",
                    "evidence": (
                        f"{len(times)} SYN packets with identical "
                        f"flow and sequence number"
                    )
                })

    return alerts


def calculate_metrics(df):
    if df.empty:
        return {
            "total_packets": 0,
            "initial_syn": 0,
            "syn_ack": 0,
            "completed_handshakes": 0,
            "incomplete_handshakes": 0,
            "handshake_completion_rate": 0.0,
            "incomplete_handshake_rate": 0.0,
            "retransmission_candidates": 0,
        }

    syns = df[df["syn"] & ~df["ack_flag"]]
    synacks = df[df["syn"] & df["ack_flag"]]

    # Unique initial SYN flow count
    unique_flows = syns.drop_duplicates([
        "src_ip", "dst_ip", "src_port",
        "dst_port", "seq"
    ])

    # Reuse detection output logic for handshake correlation
    flows = {}

    for row in df.to_dict("records"):
        key = (
            row["src_ip"], row["dst_ip"],
            row["src_port"], row["dst_port"]
        )
        reverse = (
            row["dst_ip"], row["src_ip"],
            row["dst_port"], row["src_port"]
        )

        if row["syn"] and not row["ack_flag"]:
            flows.setdefault(key, {
                "syn_seq": row["seq"],
                "synack_seq": None,
                "synack": False,
                "complete": False,
            })

        elif row["syn"] and row["ack_flag"]:
            flow = flows.get(reverse)
            if flow and row["ack"] == flow["syn_seq"] + 1:
                flow["synack"] = True
                flow["synack_seq"] = row["seq"]

        elif row["ack_flag"] and not row["syn"]:
            flow = flows.get(key)
            if (
                flow and flow["synack"]
                and row["seq"] == flow["syn_seq"] + 1
                and row["ack"] == flow["synack_seq"] + 1
            ):
                flow["complete"] = True

    completed = sum(
        1 for f in flows.values() if f["complete"]
    )
    total = len(flows)
    incomplete = max(0, total - completed)

    completion_rate = (
        completed / total * 100 if total else 0
    )

    incomplete_rate = (
        incomplete / total * 100 if total else 0
    )

    repeated = syns.duplicated(
        subset=[
            "src_ip", "dst_ip", "src_port",
            "dst_port", "seq"
        ],
        keep="first"
    ).sum()

    return {
        "total_packets": len(df),
        "initial_syn": len(syns),
        "syn_ack": len(synacks),
        "completed_handshakes": completed,
        "incomplete_handshakes": incomplete,
        "handshake_completion_rate": round(
            completion_rate, 2
        ),
        "incomplete_handshake_rate": round(
            incomplete_rate, 2
        ),
        "retransmission_candidates": int(repeated),
    }
