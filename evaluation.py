import pandas as pd
from sklearn.metrics import (
    confusion_matrix,
    classification_report,
    precision_score,
    recall_score,
    f1_score
)

from detection.tcp_analyzer import (
    analyze_pcap,
    detect_patterns
)

datasets = {
    "legitimate.pcap": 0,
    "syn_burst.pcap": 1,
    "port_scan.pcap": 1,
    "retransmission.pcap": 1
}

y_true = []
y_pred = []

results = []

for filename, label in datasets.items():

    df = analyze_pcap(f"datasets/{filename}")
    alerts = detect_patterns(df)

    prediction = int(len(alerts) > 0)

    y_true.append(label)
    y_pred.append(prediction)

    results.append({
        "Dataset": filename,
        "Ground Truth": "Malicious" if label else "Benign",
        "Prediction": "Malicious" if prediction else "Benign",
        "Alerts": len(alerts),
        "Result": "Correct" if label == prediction else "Incorrect"
    })

print("\nDETECTION EVALUATION RESULTS")
print("=" * 60)

print(pd.DataFrame(results).to_string(index=False))

print("\nCONFUSION MATRIX")
print(confusion_matrix(y_true, y_pred, labels=[0, 1]))

print("\nPERFORMANCE METRICS")
print("Precision:", precision_score(y_true, y_pred, zero_division=0))
print("Recall:", recall_score(y_true, y_pred, zero_division=0))
print("F1 Score:", f1_score(y_true, y_pred, zero_division=0))

tn, fp, fn, tp = confusion_matrix(
    y_true, y_pred, labels=[0, 1]
).ravel()

fpr = fp / (fp + tn) if (fp + tn) else 0

print("False Positive Rate:", fpr)

print("\nCLASSIFICATION REPORT")
print(classification_report(
    y_true,
    y_pred,
    target_names=["Benign", "Malicious"],
    zero_division=0
))
