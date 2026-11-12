from detection.tcp_analyzer import analyze_pcap, detect_patterns

datasets = [
    "legitimate.pcap",
    "syn_burst.pcap",
    "port_scan.pcap",
    "retransmission.pcap"
]

for filename in datasets:
    path = f"datasets/{filename}"

    df = analyze_pcap(path)
    alerts = detect_patterns(df)

    print("\n" + "=" * 55)
    print(f"DATASET: {filename}")
    print("=" * 55)

    print(f"Total TCP packets: {len(df)}")
    print(f"Unique source IPs: {df['src_ip'].nunique()}")
    print(f"SYN packets: {df['syn'].sum()}")
    print(f"Alerts generated: {len(alerts)}")

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['type']} | "
            f"{alert['source']} | "
            f"{alert['evidence']}"
        )
