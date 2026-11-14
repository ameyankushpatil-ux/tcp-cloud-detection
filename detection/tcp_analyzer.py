from scapy.all import PcapReader, IP, IPv6, TCP, UDP
import pandas as pd


# Configurable detection thresholds
SYN_THRESHOLD = 100
PORT_SCAN_THRESHOLD = 20
RETRANSMISSION_THRESHOLD = 3
WINDOW_SECONDS = 10
HANDSHAKE_TIMEOUT = 30


def analyze_pcap(file_path):
    """
    Stream a PCAP/PCAPNG file and extract IPv4/IPv6 TCP and UDP traffic.
    TCP records retain the fields required by the detection engine.
    """

    records = []

    try:
        with PcapReader(str(file_path)) as packets:
            for pkt in packets:

                if IP in pkt:
                    ip = pkt[IP]
                    src_ip = ip.src
                    dst_ip = ip.dst
                    ip_version = 4

                elif IPv6 in pkt:
                    ip = pkt[IPv6]
                    src_ip = ip.src
                    dst_ip = ip.dst
                    ip_version = 6

                else:
                    continue

                timestamp = float(pkt.time)

                if TCP in pkt:
                    transport = pkt[TCP]
                    protocol = "TCP"
                    flags = int(transport.flags)

                    records.append({
                        "timestamp": timestamp,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": int(transport.sport),
                        "dst_port": int(transport.dport),
                        "protocol": protocol,
                        "ip_version": ip_version,
                        "flags": flags,
                        "seq": int(transport.seq),
                        "ack": int(transport.ack),
                        "syn": bool(flags & 0x02),
                        "ack_flag": bool(flags & 0x10),
                        "rst": bool(flags & 0x04),
                        "fin": bool(flags & 0x01),
                    })

                elif UDP in pkt:
                    transport = pkt[UDP]

                    records.append({
                        "timestamp": timestamp,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": int(transport.sport),
                        "dst_port": int(transport.dport),
                        "protocol": "UDP",
                        "ip_version": ip_version,
                        "flags": 0,
                        "seq": 0,
                        "ack": 0,
                        "syn": False,
                        "ack_flag": False,
                        "rst": False,
                        "fin": False,
                    })

    except Exception as exc:
        raise ValueError(
            f"Unable to read PCAP/PCAPNG file: {exc}"
        ) from exc

    columns = [
        "timestamp", "src_ip", "dst_ip",
        "src_port", "dst_port", "protocol",
        "ip_version", "flags", "seq", "ack",
        "syn", "ack_flag", "rst", "fin"
    ]

    return pd.DataFrame(records, columns=columns).sort_values(
        "timestamp"
    ).reset_index(drop=True)


def _tcp_only(df):
    """Return TCP rows while supporting legacy test DataFrames."""
    if "protocol" in df.columns:
        return df[df["protocol"] == "TCP"].copy()
    return df.copy()


def _analyze_handshakes(df):
    """Correlate TCP SYN, SYN-ACK and final ACK packets."""

    sessions = {}

    df = _tcp_only(df)

    if df.empty:
        return sessions

    for row in df.sort_values("timestamp").to_dict("records"):
        key = (
            row["src_ip"], row["dst_ip"],
            row["src_port"], row["dst_port"]
        )

        reverse = (
            row["dst_ip"], row["src_ip"],
            row["dst_port"], row["src_port"]
        )

        # Initial SYN, including SYN packets with ECN flags
        if row["syn"] and not row["ack_flag"]:
            session_key = (key, row["seq"])

            if session_key not in sessions:
                sessions[session_key] = {
                    "syn_time": row["timestamp"],
                    "last_syn_time": row["timestamp"],
                    "syn_seq": row["seq"],
                    "synack_time": None,
                    "synack_seq": None,
                    "completed": False,
                }
            else:
                # Retransmission: update observation time,
                # but do not create another connection.
                sessions[session_key]["last_syn_time"] = max(
                    sessions[session_key]["last_syn_time"],
                    row["timestamp"]
                )

        # SYN-ACK: reverse tuple and matching acknowledgement
        elif row["syn"] and row["ack_flag"]:
            original_syn_seq = row["ack"] - 1
            session_key = (reverse, original_syn_seq)
            flow = sessions.get(session_key)

            if (
                flow
                and row["timestamp"] >= flow["syn_time"]
                and flow["synack_time"] is None
            ):
                flow["synack_time"] = row["timestamp"]
                flow["synack_seq"] = row["seq"]

        # Final ACK: match original tuple and both sequence numbers
        elif row["ack_flag"] and not row["syn"]:
            original_syn_seq = row["seq"] - 1
            session_key = (key, original_syn_seq)
            flow = sessions.get(session_key)

            if (
                flow
                and flow["synack_time"] is not None
                and row["timestamp"] >= flow["synack_time"]
                and row["ack"] == flow["synack_seq"] + 1
            ):
                flow["completed"] = True

    return sessions


def detect_patterns(df):
    alerts = []
    df = _tcp_only(df)

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

    # 3. TCP handshake analysis
    sessions = _analyze_handshakes(df)
    capture_end = df["timestamp"].max()

    for (key, syn_seq), flow in sessions.items():
        if flow["completed"]:
            continue

        # Wait until sufficient time has elapsed since
        # the most recently observed SYN.
        elapsed = capture_end - flow["last_syn_time"]

        if elapsed < HANDSHAKE_TIMEOUT:
            continue

        if flow["synack_time"] is None:
            alert_type = "Unanswered SYN"
            evidence = (
                f"No matching SYN-ACK observed for "
                f"{key[1]}:{key[3]} (SYN sequence {syn_seq})"
            )
        else:
            alert_type = "Incomplete Handshake"
            evidence = (
                f"SYN-ACK observed, but final ACK not observed for "
                f"{key[1]}:{key[3]} (SYN sequence {syn_seq})"
            )

        alerts.append({
            "source": key[0],
            "type": alert_type,
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "evidence": evidence
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
    """Calculate network-wide statistics and TCP-only handshake metrics."""

    total_packets = len(df)

    # Network-wide protocol and IP version statistics.
    if "protocol" in df.columns:
        tcp_df = _tcp_only(df)
        tcp_packets = len(tcp_df)
        udp_packets = int((df["protocol"] == "UDP").sum())
    else:
        # Backward compatibility with older test DataFrames.
        tcp_df = df.copy()
        tcp_packets = total_packets
        udp_packets = 0

    if "ip_version" in df.columns:
        ipv4_packets = int((df["ip_version"] == 4).sum())
        ipv6_packets = int((df["ip_version"] == 6).sum())
    else:
        ipv4_packets = 0
        ipv6_packets = 0

    network_metrics = {
        "total_packets": total_packets,
        "tcp_packets": tcp_packets,
        "udp_packets": udp_packets,
        "ipv4_packets": ipv4_packets,
        "ipv6_packets": ipv6_packets,
    }

    tcp_metric_defaults = {
        "initial_syn": 0,
        "unique_initial_syn": 0,
        "syn_ack": 0,
        "completed_handshakes": 0,
        "incomplete_handshakes": 0,
        "unanswered_syn": 0,
        "synack_without_final_ack": 0,
        "pending_handshakes": 0,
        "handshake_completion_rate": 0.0,
        "incomplete_handshake_rate": 0.0,
        "retransmission_candidates": 0,
    }

    if tcp_df.empty:
        return {**network_metrics, **tcp_metric_defaults}

    syns = tcp_df[tcp_df["syn"] & ~tcp_df["ack_flag"]]
    synacks = tcp_df[tcp_df["syn"] & tcp_df["ack_flag"]]

    sessions = _analyze_handshakes(tcp_df)
    capture_end = tcp_df["timestamp"].max()

    completed = 0
    unanswered = 0
    synack_without_final_ack = 0
    pending = 0

    for flow in sessions.values():
        if flow["completed"]:
            completed += 1
            continue

        elapsed = capture_end - flow["last_syn_time"]

        if elapsed < HANDSHAKE_TIMEOUT:
            pending += 1
        elif flow["synack_time"] is None:
            unanswered += 1
        else:
            synack_without_final_ack += 1

    incomplete = unanswered + synack_without_final_ack
    classified = completed + incomplete

    completion_rate = (
        completed / classified * 100 if classified else 0.0
    )
    incomplete_rate = (
        incomplete / classified * 100 if classified else 0.0
    )

    repeated = syns.duplicated(
        subset=[
            "src_ip", "dst_ip", "src_port",
            "dst_port", "seq"
        ],
        keep="first"
    ).sum()

    tcp_metrics = {
        "initial_syn": len(syns),
        "unique_initial_syn": len(sessions),
        "syn_ack": len(synacks),
        "completed_handshakes": completed,
        "incomplete_handshakes": incomplete,
        "unanswered_syn": unanswered,
        "synack_without_final_ack": synack_without_final_ack,
        "pending_handshakes": pending,
        "handshake_completion_rate": round(completion_rate, 2),
        "incomplete_handshake_rate": round(incomplete_rate, 2),
        "retransmission_candidates": int(repeated),
    }

    return {**network_metrics, **tcp_metrics}
