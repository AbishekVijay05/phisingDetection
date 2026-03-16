from typing import Any, Dict

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_proba: np.ndarray) -> Dict[str, Any]:
    acc = float(accuracy_score(y_true, y_pred))
    pr, rc, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    cm = confusion_matrix(y_true, y_pred).tolist()
    try:
        auc = float(roc_auc_score(y_true, y_proba))
    except Exception:
        auc = float("nan")

    return {
        "accuracy": acc,
        "precision": float(pr),
        "recall": float(rc),
        "f1": float(f1),
        "roc_auc": auc,
        "confusion_matrix": cm,
        "classification_report": classification_report(y_true, y_pred, zero_division=0),
    }

