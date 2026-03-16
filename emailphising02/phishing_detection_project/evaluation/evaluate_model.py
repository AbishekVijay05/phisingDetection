import argparse
import json
import os
import sys
from typing import Dict

import numpy as np
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from ensemble.hybrid_model import HybridEnsemble
from evaluation.metrics import compute_metrics
from model.naive_bayes_model import load_naive_bayes, predict_proba_phishing
from model.roberta_model import load_roberta, predict_proba_phishing_roberta


def _load_split(data_csv: str, split: str) -> pd.DataFrame:
    base = os.path.splitext(data_csv)[0]
    path = f"{base}_{split}.csv"
    if os.path.exists(path):
        return pd.read_csv(path)
    return pd.read_csv(data_csv)


def eval_one(y_true: np.ndarray, proba: np.ndarray, threshold: float = 0.5) -> Dict:
    y_pred = (proba >= threshold).astype(int)
    return compute_metrics(y_true=y_true, y_pred=y_pred, y_proba=proba)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--data_csv", required=True)
    p.add_argument("--nb_dir", required=True)
    p.add_argument("--roberta_dir", required=True)
    p.add_argument("--split", choices=["train", "val", "test"], default="test")
    p.add_argument("--ensemble_mode", choices=["soft", "weighted"], default="weighted")
    p.add_argument("--hybrid_weights", nargs=2, type=float, default=[0.7, 0.3])
    p.add_argument("--threshold", type=float, default=0.5)
    p.add_argument("--out_json", default=None)
    args = p.parse_args()

    df = _load_split(args.data_csv, args.split)
    if "text" not in df.columns or "label" not in df.columns:
        raise ValueError("Expected columns: text,label. Run preprocessing to normalize.")

    y_true = df["label"].astype(int).to_numpy()
    texts = df["text"].astype(str).tolist()

    nb = load_naive_bayes(args.nb_dir)
    ro = load_roberta(args.roberta_dir)

    nb_p = predict_proba_phishing(nb, texts)
    ro_p = predict_proba_phishing_roberta(ro, texts)

    ens = HybridEnsemble(
        mode=args.ensemble_mode,
        roberta_weight=float(args.hybrid_weights[0]),
        nb_weight=float(args.hybrid_weights[1]),
    )
    hy_p = ens.combine(ro_p, nb_p)

    out = {
        "split": args.split,
        "naive_bayes": eval_one(y_true, nb_p, threshold=args.threshold),
        "roberta": eval_one(y_true, ro_p, threshold=args.threshold),
        "hybrid": eval_one(y_true, hy_p, threshold=args.threshold),
    }

    print(f"Evaluation split={args.split}")
    for name in ["naive_bayes", "roberta", "hybrid"]:
        m = out[name]
        print(f"\n{name.upper()}:")
        for k in ["accuracy", "precision", "recall", "f1", "roc_auc"]:
            print(f"- {k}: {m[k]}")
        print("Confusion matrix:", m["confusion_matrix"])

    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        print(f"\nWrote metrics JSON: {args.out_json}")


if __name__ == "__main__":
    main()

