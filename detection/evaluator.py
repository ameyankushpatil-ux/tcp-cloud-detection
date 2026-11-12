import pandas as pd

from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    accuracy_score
)

from detection.tcp_analyzer import (
    analyze_pcap,
    detect_patterns
)


DATASETS = {
    "legitimate.pcap": 0,
    "syn_burst.pcap": 1,
    "port_scan.pcap": 1,
    "retransmission.pcap": 1
}


def evaluate_datasets(dataset_dir="datasets"):
    y_true = []
    y_pred = []
    rows = []

    for filename, label in DATASETS.items():
        df = analyze_pcap(f"{dataset_dir}/{filename}")
        alerts = detect_patterns(df)

        prediction = int(len(alerts) > 0)

        y_true.append(label)
        y_pred.append(prediction)

        rows.append({
            "Dataset": filename,
            "Actual": "Suspicious" if label else "Benign",
            "Predicted": "Suspicious" if prediction else "Benign",
            "Alerts": len(alerts),
            "Result": "Correct" if label == prediction else "Incorrect"
        })

    tn, fp, fn, tp = confusion_matrix(
        y_true, y_pred, labels=[0, 1]
    ).ravel()

    metrics = {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "fpr": fp / (fp + tn) if (fp + tn) else 0,
        "tp": int(tp),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn)
    }

    return pd.DataFrame(rows), metrics
