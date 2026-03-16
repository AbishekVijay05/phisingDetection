import argparse
import os
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd
from bs4 import BeautifulSoup


def _clean_text(text: str) -> str:
    if text is None or (isinstance(text, float) and np.isnan(text)):
        return ""
    text = str(text)

    # Remove HTML
    if "<" in text and ">" in text:
        try:
            text = BeautifulSoup(text, "lxml").get_text(separator=" ")
        except Exception:
            text = BeautifulSoup(text, "html.parser").get_text(separator=" ")

    # Normalize
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"[^a-z0-9\s\.\,\!\?\-\_\:\;\/\@\#\$\%\&\*\(\)\[\]\{\}\'\"]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _try_download_kagglehub(slug: str) -> Optional[str]:
    try:
        import kagglehub  # type: ignore
    except Exception:
        return None

    try:
        path = kagglehub.dataset_download(slug)
        return path
    except Exception:
        return None


def _read_any_csv_from_dir(dir_path: str) -> pd.DataFrame:
    csv_files = []
    for root, _, files in os.walk(dir_path):
        for f in files:
            if f.lower().endswith(".csv"):
                csv_files.append(os.path.join(root, f))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found under: {dir_path}")

    # Prefer files with obvious names
    csv_files_sorted = sorted(
        csv_files,
        key=lambda p: (
            0
            if any(k in os.path.basename(p).lower() for k in ["phish", "spam", "email", "enron"])
            else 1,
            os.path.getsize(p),
        ),
    )
    return pd.read_csv(csv_files_sorted[0])


def _normalize_columns(df: pd.DataFrame, text_col: Optional[str], label_col: Optional[str]) -> pd.DataFrame:
    cols = {c.lower(): c for c in df.columns}

    if text_col is None:
        for candidate in ["text", "email", "body", "content", "message", "mail", "EmailText".lower()]:
            if candidate in cols:
                text_col = cols[candidate]
                break
    if text_col is None:
        # fallback: first object-like column
        obj_cols = [c for c in df.columns if df[c].dtype == "object"]
        if not obj_cols:
            raise ValueError("Could not infer text column; please pass --text_col.")
        text_col = obj_cols[0]

    if label_col is None:
        for candidate in ["label", "labels", "class", "target", "is_phishing", "phishing", "spam"]:
            if candidate in cols:
                label_col = cols[candidate]
                break

    out = pd.DataFrame()
    out["text"] = df[text_col].astype(str)

    if label_col is not None:
        out["label"] = df[label_col]
    return out


def _coerce_label(series: pd.Series) -> pd.Series:
    # Accept 0/1, true/false, phishing/legit strings, etc.
    s = series.copy()
    if s.dtype == bool:
        return s.astype(int)
    if pd.api.types.is_numeric_dtype(s):
        return (s.astype(float) > 0.5).astype(int)

    s = s.astype(str).str.lower().str.strip()
    phishing_values = {"1", "phishing", "phish", "spam", "malicious", "fraud", "scam", "yes", "true"}
    legit_values = {"0", "legitimate", "legit", "ham", "safe", "no", "false"}

    def map_one(x: str) -> int:
        if x in phishing_values:
            return 1
        if x in legit_values:
            return 0
        # try to parse numeric strings
        try:
            return 1 if float(x) > 0.5 else 0
        except Exception:
            # default unknown -> legitimate (conservative for training hygiene)
            return 0

    return s.map(map_one).astype(int)


@dataclass
class SplitData:
    train: pd.DataFrame
    val: pd.DataFrame
    test: pd.DataFrame


def split_df(df: pd.DataFrame, seed: int = 42) -> SplitData:
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    n = len(df)
    n_train = int(0.70 * n)
    n_val = int(0.15 * n)
    train = df.iloc[:n_train].copy()
    val = df.iloc[n_train : n_train + n_val].copy()
    test = df.iloc[n_train + n_val :].copy()
    return SplitData(train=train, val=val, test=test)


def build_dataset(
    input_csv: Optional[str],
    text_col: Optional[str],
    label_col: Optional[str],
    label_missing_default: Optional[int],
    extra_csvs: Optional[List[str]],
    extra_text_cols: Optional[List[Optional[str]]],
    extra_label_cols: Optional[List[Optional[str]]],
    extra_label_missing_defaults: Optional[List[Optional[int]]],
    enron_slug: str,
    phishing_slug: str,
    max_per_class: Optional[int],
    seed: int,
) -> pd.DataFrame:
    if input_csv:
        df_raw = pd.read_csv(input_csv)
        df = _normalize_columns(df_raw, text_col=text_col, label_col=label_col)
        if "label" not in df.columns:
            if label_missing_default is None:
                raise ValueError(
                    "Input CSV has no label column. Pass --label_col, or set --label_missing_default 0|1."
                )
            df["label"] = int(label_missing_default)
        else:
            df["label"] = _coerce_label(df["label"])

        if extra_csvs:
            text_cols = extra_text_cols or []
            label_cols = extra_label_cols or []
            label_defaults = extra_label_missing_defaults or []

            def _get(lst, i, default=None):
                return lst[i] if i < len(lst) else default

            for i, extra_csv in enumerate(extra_csvs):
                df2_raw = pd.read_csv(extra_csv)
                df2 = _normalize_columns(
                    df2_raw,
                    text_col=_get(text_cols, i, None),
                    label_col=_get(label_cols, i, None),
                )
                if "label" not in df2.columns:
                    dflt = _get(label_defaults, i, None)
                    if dflt is None:
                        raise ValueError(
                            f"Extra CSV has no label column: {extra_csv}. "
                            "Pass --extra_label_col (repeatable), or set --extra_label_missing_default (repeatable) to 0|1."
                        )
                    df2["label"] = int(dflt)
                else:
                    df2["label"] = _coerce_label(df2["label"])
                df = pd.concat([df[["text", "label"]], df2[["text", "label"]]], ignore_index=True)
    else:
        enron_path = _try_download_kagglehub(enron_slug)
        phishing_path = _try_download_kagglehub(phishing_slug)

        if not enron_path or not phishing_path:
            raise RuntimeError(
                "KaggleHub download failed. Either configure Kaggle credentials, or pass --input_csv.\n"
                f"Attempted enron_slug={enron_slug}, phishing_slug={phishing_slug}"
            )

        enron_df_raw = _read_any_csv_from_dir(enron_path)
        phishing_df_raw = _read_any_csv_from_dir(phishing_path)

        enron_df = _normalize_columns(enron_df_raw, text_col=None, label_col=None)
        phishing_df = _normalize_columns(phishing_df_raw, text_col=None, label_col=None)

        # Enron is treated as legitimate by default (common in hybrid builds); phishing dataset provides positives.
        enron_df["label"] = 0
        if "label" not in phishing_df.columns:
            # If the phishing dataset has no label column, treat it as all-phishing
            phishing_df["label"] = 1
        phishing_df["label"] = _coerce_label(phishing_df["label"])

        df = pd.concat([enron_df[["text", "label"]], phishing_df[["text", "label"]]], ignore_index=True)

    # Clean
    df["text"] = df["text"].map(_clean_text)
    df = df[df["text"].str.len() > 0]
    df = df.dropna(subset=["text", "label"])

    # Dedupe
    df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)

    # Balance / cap (optional)
    if max_per_class is not None:
        parts = []
        for y in [0, 1]:
            part = df[df["label"] == y]
            part = part.sample(n=min(len(part), max_per_class), random_state=seed)
            parts.append(part)
        df = pd.concat(parts).sample(frac=1.0, random_state=seed).reset_index(drop=True)

    return df[["text", "label"]]


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--out_csv", default=os.path.join("dataset", "phishing_emails.csv"))
    p.add_argument("--input_csv", default=None)
    p.add_argument("--text_col", default=None)
    p.add_argument("--label_col", default=None)
    p.add_argument("--label_missing_default", type=int, default=None)
    p.add_argument("--extra_csv", action="append", default=None)
    p.add_argument("--extra_text_col", action="append", default=None)
    p.add_argument("--extra_label_col", action="append", default=None)
    p.add_argument("--extra_label_missing_default", action="append", type=int, default=None)
    p.add_argument("--enron_slug", default="wcukierski/enron-email-dataset")
    p.add_argument("--phishing_slug", default="phishing-email-dataset")  # override if needed
    p.add_argument("--max_per_class", type=int, default=30000)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()

    df = build_dataset(
        input_csv=args.input_csv,
        text_col=args.text_col,
        label_col=args.label_col,
        label_missing_default=args.label_missing_default,
        extra_csvs=args.extra_csv,
        extra_text_cols=args.extra_text_col,
        extra_label_cols=args.extra_label_col,
        extra_label_missing_defaults=args.extra_label_missing_default,
        enron_slug=args.enron_slug,
        phishing_slug=args.phishing_slug,
        max_per_class=args.max_per_class,
        seed=args.seed,
    )

    # Save unified dataset
    out_csv = args.out_csv
    out_dir = os.path.dirname(out_csv)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    df.to_csv(out_csv, index=False)

    splits = split_df(df, seed=args.seed)
    # also persist splits for convenience
    base = os.path.splitext(out_csv)[0]
    splits.train.to_csv(base + "_train.csv", index=False)
    splits.val.to_csv(base + "_val.csv", index=False)
    splits.test.to_csv(base + "_test.csv", index=False)

    print(f"Wrote: {out_csv} (rows={len(df)})")
    print(f"Wrote splits: {base}_train.csv / _val.csv / _test.csv")
    print(df["label"].value_counts().to_dict())


if __name__ == "__main__":
    main()

