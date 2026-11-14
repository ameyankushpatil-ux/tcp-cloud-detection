"""Evaluation helpers for the TCP PCAP detection prototype.

The uploaded PCAP is evaluated directly. A ground-truth label must be
provided by the analyst because a PCAP file does not contain its own label.
"""

import pandas as pd
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score


def evaluate_prediction(filename, alerts, ground_truth):
    """Evaluate one analysed PCAP against its analyst-provided ground truth.

    Args:
        filename: Name of the PCAP file analysed by the dashboard.
        alerts: Alerts returned by detection.tcp_analyzer.detect_patterns.
        ground_truth: 0 for Benign, 1 for Malicious/Suspicious.

    Returns:
        (results_dataframe, metrics_dict)
    """
    prediction = int(len(alerts) > 0)
    y_true = [int(ground_truth)]
    y_pred = [prediction]

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    accuracy = (tp + tn) / (tp + tn + fp + fn)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    metrics = {
        "accuracy": accuracy,
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "fpr": fpr,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "prediction": prediction,
        "ground_truth": int(ground_truth),
    }

    results = pd.DataFrame([{
        "PCAP File": filename,
        "Ground Truth": "Malicious/Suspicious" if ground_truth else "Benign",
        "Predicted Class": "Malicious/Suspicious" if prediction else "Benign",
        "Detection Alerts": len(alerts),
        "Verdict": "Correct" if prediction == ground_truth else "Incorrect",
    }])

    return results, metrics


if __name__ == "__main__":
    print(
        "This module is used by app.py to evaluate the currently uploaded PCAP. "
        "Run the Streamlit application and upload a PCAP to evaluate it."
    )
