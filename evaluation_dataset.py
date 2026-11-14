"""Multi-PCAP evaluation using analyst-provided ground-truth labels."""

from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)

from detection.tcp_analyzer import analyze_pcap, detect_patterns


def evaluate_dataset(
    labels_file="datasets/labels.csv",
    dataset_dir="datasets",
    output_file="output/multi_pcap_evaluation.csv",
):
    labels_path = Path(labels_file)
    dataset_path = Path(dataset_dir)
    output_path = Path(output_file)

    if not labels_path.exists():
        raise FileNotFoundError(f"Labels file not found: {labels_path}")

    labels = pd.read_csv(labels_path)

    required_columns = {"filename", "ground_truth", "scenario"}
    if not required_columns.issubset(labels.columns):
        raise ValueError(
            f"Labels CSV must contain: {sorted(required_columns)}"
        )

    if labels.empty:
        raise ValueError("Labels CSV contains no PCAP records.")

    if labels["filename"].duplicated().any():
        raise ValueError("Duplicate PCAP filenames found in labels CSV.")

    if not labels["ground_truth"].isin([0, 1]).all():
        raise ValueError("Ground truth must contain only 0 (Benign) or 1 (Suspicious).")

    results = []

    for _, row in labels.iterrows():
        filename = str(row["filename"])

        # Only allow filenames within the configured dataset directory.
        if Path(filename).name != filename:
            raise ValueError(f"Invalid dataset filename: {filename}")

        pcap_path = dataset_path / filename

        if not pcap_path.is_file():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        df = analyze_pcap(str(pcap_path))
        alerts = detect_patterns(df)

        ground_truth = int(row["ground_truth"])
        prediction = int(len(alerts) > 0)

        results.append({
            "PCAP File": filename,
            "Scenario": str(row["scenario"]),
            "Packets": len(df),
            "Alert Count": len(alerts),
            "Alert Types": "; ".join(
                sorted({str(alert["type"]) for alert in alerts})
            ),
            "Ground Truth": ground_truth,
            "Prediction": prediction,
            "Ground Truth Label": (
                "Suspicious" if ground_truth else "Benign"
            ),
            "Predicted Label": (
                "Suspicious" if prediction else "Benign"
            ),
            "Verdict": (
                "Correct" if prediction == ground_truth else "Incorrect"
            ),
        })

    results_df = pd.DataFrame(results)

    y_true = results_df["Ground Truth"]
    y_pred = results_df["Prediction"]

    tn, fp, fn, tp = confusion_matrix(
        y_true, y_pred, labels=[0, 1]
    ).ravel()

    metrics = {
        "total_pcaps": len(results_df),
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    results_df.to_csv(output_path, index=False)

    return results_df, metrics


if __name__ == "__main__":
    results, metrics = evaluate_dataset()

    print("\nMULTI-PCAP EVALUATION RESULTS")
    print("=" * 65)
    print(results.to_string(index=False))

    print("\nDATASET-LEVEL PERFORMANCE")
    print("=" * 65)

    for key, value in metrics.items():
        if key in {"accuracy", "precision", "recall", "f1", "fpr"}:
            print(f"{key}: {value:.4f} ({value * 100:.2f}%)")
        else:
            print(f"{key}: {value}")

    print("\nResults saved to output/multi_pcap_evaluation.csv")
