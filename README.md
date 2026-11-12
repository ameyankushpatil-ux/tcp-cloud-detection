# Detection of Suspicious TCP Connection Patterns in Cloud Networks

## 1. Project Overview

This project implements a Python-based TCP network traffic
analysis and detection framework using PCAP files.

It analyzes TCP connection patterns to identify potentially
suspicious network behavior, including:

- TCP SYN burst patterns
- Incomplete TCP handshakes
- TCP port scanning
- Repeated SYN / retransmission candidates

The project provides a Streamlit dashboard for packet
analysis, visualization, security alerts and evaluation.

## 2. Objectives

1. Analyze TCP packet patterns from PCAP files.
2. Identify suspicious TCP connection behavior.
3. Analyze TCP three-way handshake completion.
4. Generate alerts for configured detection rules.
5. Evaluate detection performance using labelled datasets.

## 3. Technologies

- Python 3.12
- Scapy
- Pandas
- Streamlit
- Plotly
- Scikit-learn
- Pytest

## 4. Architecture

PCAP Files
    |
    v
Scapy Packet Parser
    |
    v
TCP Feature Extraction
    |
    v
Detection Engine
    |
    +---- SYN Burst Detection
    +---- Port Scan Detection
    +---- Handshake Analysis
    +---- Repeated SYN Detection
    |
    v
Streamlit Dashboard
    |
    v
Performance Evaluation

## 5. Project Structure

tcp-cloud-detection/
|
|-- app.py
|-- evaluation.py
|-- generate_pcaps.py
|-- validate.py
|-- requirements.txt
|-- README.md
|
|-- detection/
|   |-- tcp_analyzer.py
|   |-- evaluator.py
|
|-- datasets/
|   |-- legitimate.pcap
|   |-- syn_burst.pcap
|   |-- port_scan.pcap
|   |-- retransmission.pcap
|
|-- tests/
|   |-- test_detection.py
|
|-- docs/
|-- screenshots/
|-- output/

## 6. Installation

Clone the repository:

    git clone YOUR_GITHUB_REPOSITORY_URL
    cd tcp-cloud-detection

Create virtual environment:

    python3 -m venv .venv
    source .venv/bin/activate

Install dependencies:

    pip install -r requirements.txt

## 7. Generate Test Datasets

    python generate_pcaps.py

## 8. Run Automated Tests

    pytest -v

## 9. Run Evaluation

    python evaluation.py

## 10. Launch Dashboard

    streamlit run app.py --server.address 0.0.0.0 --server.port 8505

Open:

    http://localhost:8505

## 11. Initial Experimental Results

The initial evaluation uses four controlled synthetic PCAP files.

Observed results:

- Accuracy: 100%
- Precision: 1.00
- Recall: 1.00
- F1-score: 1.00
- False Positive Rate: 0.00

Confusion matrix:

                 Predicted
                 Benign  Suspicious

Actual Benign       1        0
Actual Suspicious   0        3

These results are limited to the four synthetic test
datasets and do not establish real-world detection accuracy.

## 12. Limitations

- Evaluation dataset is small and synthetic.
- Repeated SYN packets are treated as retransmission candidates.
- Thresholds require validation against diverse traffic.
- The prototype does not establish cloud-provider attribution.
- Production deployment requires additional validation.

## 13. Future Scope

- Larger independently labelled PCAP datasets.
- Improved TCP retransmission analysis.
- Detection latency measurement.
- Advanced false-positive analysis.
- Cloud network telemetry integration.
- Expanded detection and evaluation rules.

## 14. Disclaimer

This project is intended for academic research and
authorized network security analysis.
