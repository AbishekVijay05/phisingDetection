import argparse
import os
import sys

import numpy as np
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from evaluation.metrics import compute_metrics
from model.naive_bayes_model import (
    load_naive_bayes,
    predict_proba_phishing,
    save_naive_bayes,
    train_naive_bayes,
)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--data_csv", required=True)
    p.add_argument("--output_dir", required=True)
    p.add_argument("--max_features", type=int, default=50000)
    p.add_argument("--min_df", type=int, default=2)
    p.add_argument("--ngram_min", type=int, default=1)
    p.add_argument("--ngram_max", type=int, default=2)
    args = p.parse_args()

    df = pd.read_csv(args.data_csv)
    if "text" not in df.columns or "label" not in df.columns:
        raise ValueError("CSV must contain columns: text, label")

    # Use precomputed splits if present
    base = os.path.splitext(args.data_csv)[0]
    train_path = base + "_train.csv"
    val_path = base + "_val.csv"
    if os.path.exists(train_path) and os.path.exists(val_path):
        train_df = pd.read_csv(train_path)
        val_df = pd.read_csv(val_path)
    else:
        train_df = df.sample(frac=0.7, random_state=42)
        val_df = df.drop(train_df.index)

    art = train_naive_bayes(
        train_df["text"].astype(str).tolist(),
        train_df["label"].astype(int).tolist(),
        max_features=args.max_features,
        ngram_range=(args.ngram_min, args.ngram_max),
        min_df=args.min_df,
    )
    save_naive_bayes(art, args.output_dir)

    # quick validation metrics
    art2 = load_naive_bayes(args.output_dir)
    y_true = val_df["label"].astype(int).to_numpy()
    y_proba = predict_proba_phishing(art2, val_df["text"].astype(str).tolist())
    y_pred = (y_proba >= 0.5).astype(int)
    metrics = compute_metrics(y_true=y_true, y_pred=y_pred, y_proba=y_proba)

    print("Naive Bayes validation metrics:")
    for k in ["accuracy", "precision", "recall", "f1", "roc_auc"]:
        print(f"- {k}: {metrics[k]}")
    print("Confusion matrix:", metrics["confusion_matrix"])


if __name__ == "__main__":
    main()

