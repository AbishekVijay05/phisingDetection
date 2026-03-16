import argparse
import os
import re
import sys
from typing import List, Tuple

import numpy as np
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from inference.eml_parser import load_eml_file


def _clean_ws(s: str) -> str:
    s = re.sub(r"\s+", " ", s or "")
    return s.strip()


def _collect_eml_paths(root_dir: str) -> List[str]:
    out: List[str] = []
    for root, _, files in os.walk(root_dir):
        for f in files:
            if f.lower().endswith(".eml"):
                out.append(os.path.join(root, f))
    out.sort()
    return out


def _split_df(df: pd.DataFrame, seed: int = 42) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    n = len(df)
    n_train = int(0.70 * n)
    n_val = int(0.15 * n)
    train = df.iloc[:n_train].copy()
    val = df.iloc[n_train : n_train + n_val].copy()
    test = df.iloc[n_train + n_val :].copy()
    return train, val, test


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--phishing_dir", required=True, help="Directory containing phishing .eml files")
    p.add_argument("--safe_dir", required=True, help="Directory containing safe/legitimate .eml files")
    p.add_argument("--out_csv", required=True, help="Output CSV path (text,label)")
    p.add_argument("--max_per_class", type=int, default=None, help="Optional cap per class")
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()

    phish_paths = _collect_eml_paths(args.phishing_dir)
    safe_paths = _collect_eml_paths(args.safe_dir)
    if not phish_paths:
        raise SystemExit(f"No .eml files found in phishing_dir: {args.phishing_dir}")
    if not safe_paths:
        raise SystemExit(f"No .eml files found in safe_dir: {args.safe_dir}")

    rng = np.random.RandomState(args.seed)

    if args.max_per_class is not None:
        if len(phish_paths) > args.max_per_class:
            phish_paths = list(rng.choice(phish_paths, size=args.max_per_class, replace=False))
        if len(safe_paths) > args.max_per_class:
            safe_paths = list(rng.choice(safe_paths, size=args.max_per_class, replace=False))
        phish_paths.sort()
        safe_paths.sort()

    rows = []
    for path in safe_paths:
        text = _clean_ws(load_eml_file(path))
        if text:
            rows.append({"text": text, "label": 0, "path": path})
    for path in phish_paths:
        text = _clean_ws(load_eml_file(path))
        if text:
            rows.append({"text": text, "label": 1, "path": path})

    df = pd.DataFrame(rows)
    df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)
    if df.empty:
        raise SystemExit("No usable email text extracted from .eml files.")

    out_dir = os.path.dirname(args.out_csv)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    # Save canonical training CSV (only text,label)
    df[["text", "label"]].to_csv(args.out_csv, index=False)

    # Save splits (and keep path for debugging)
    base = os.path.splitext(args.out_csv)[0]
    tr, va, te = _split_df(df, seed=args.seed)
    tr[["text", "label"]].to_csv(base + "_train.csv", index=False)
    va[["text", "label"]].to_csv(base + "_val.csv", index=False)
    te[["text", "label"]].to_csv(base + "_test.csv", index=False)

    print(f"Wrote: {args.out_csv} (rows={len(df)})")
    print(f"Wrote splits: {base}_train.csv / _val.csv / _test.csv")
    print(df["label"].value_counts().to_dict())


if __name__ == "__main__":
    main()

