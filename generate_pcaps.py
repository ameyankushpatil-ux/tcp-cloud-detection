from scapy.all import IP, TCP, wrpcap
from datetime import datetime, timedelta
import os

os.makedirs("datasets", exist_ok=True)

BASE_TIME = datetime(2026, 11, 12, 12, 0, 0)

def packet(src, dst, sport, dport, flags, seq=1000, ack=0):
    return IP(src=src, dst=dst) / TCP(
        sport=sport,
        dport=dport,
        flags=flags,
        seq=seq,
        ack=ack
    )

# 1. Legitimate TCP traffic
legitimate = []

for i in range(15):
    sport = 40000 + i
    dport = 443
    seq = 1000 + i * 100

    legitimate.extend([
        packet("10.0.0.10", "10.0.0.20", sport, dport, "S", seq),
        packet("10.0.0.20", "10.0.0.10", dport, sport, "SA", 2000+i, seq+1),
        packet("10.0.0.10", "10.0.0.20", sport, dport, "A", seq+1, 2001+i)
    ])

wrpcap("datasets/legitimate.pcap", legitimate)

# 2. SYN burst
syn_burst = []

for i in range(150):
    syn_burst.append(
        packet(
            "192.168.1.100",
            "10.0.0.20",
            30000+i,
            443,
            "S",
            10000+i
        )
    )

wrpcap("datasets/syn_burst.pcap", syn_burst)

# 3. Port scanning
port_scan = []

for port in range(1, 81):
    port_scan.append(
        packet(
            "192.168.1.150",
            "10.0.0.20",
            45000+port,
            port,
            "S",
            20000+port
        )
    )

wrpcap("datasets/port_scan.pcap", port_scan)

# 4. Repeated SYN packets
retransmission = []

for i in range(5):
    retransmission.append(
        packet(
            "192.168.1.200",
            "10.0.0.20",
            50000,
            443,
            "S",
            30000
        )
    )

wrpcap("datasets/retransmission.pcap", retransmission)

print("Successfully generated four PCAP datasets.")

for name in os.listdir("datasets"):
    print(f"Created: {name}")
