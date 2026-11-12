# Project Methodology

## 1. Data Collection

The prototype uses controlled synthetic PCAP datasets
generated using Scapy.

## 2. Packet Parsing

Scapy extracts IPv4 and TCP packet information,
including source and destination addresses, ports,
TCP flags, sequence numbers and timestamps.

## 3. Feature Extraction

The framework extracts:

- Initial SYN packets
- SYN-ACK responses
- ACK packets
- RST and FIN flags
- TCP connection tuples
- TCP sequence numbers
- Packet timestamps

## 4. Detection Techniques

### SYN Burst

Detects high volumes of initial SYN attempts
within a configurable time window.

### Port Scanning

Identifies sources contacting multiple
destination ports within a time window.

### Handshake Analysis

Correlates SYN, SYN-ACK and final ACK packets
to evaluate connection completion.

### Retransmission Candidates

Identifies repeated SYN packets sharing
the same connection tuple and sequence number.

## 5. Evaluation

The initial evaluation uses labelled synthetic
PCAP files and calculates accuracy, precision,
recall, F1-score and false-positive rate.

## 6. Limitations

Results are preliminary and limited to controlled
synthetic traffic. Additional datasets and
independent validation are required.
