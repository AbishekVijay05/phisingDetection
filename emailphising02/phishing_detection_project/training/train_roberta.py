import argparse
import os
import sys
from dataclasses import dataclass
from typing import Dict, List

import numpy as np
import pandas as pd
import torch
from sklearn.model_selection import train_test_split
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
)

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from evaluation.metrics import compute_metrics
from model.roberta_model import load_roberta, predict_proba_phishing_roberta


@dataclass
class TextDataset(torch.utils.data.Dataset):
    encodings: Dict[str, torch.Tensor]
    labels: torch.Tensor

    def __len__(self) -> int:
        return int(self.labels.shape[0])

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        item = {k: v[idx] for k, v in self.encodings.items()}
        item["labels"] = self.labels[idx]
        return item


def _load_splits(data_csv: str) -> tuple[pd.DataFrame, pd.DataFrame]:
    base = os.path.splitext(data_csv)[0]
    train_path = base + "_train.csv"
    val_path = base + "_val.csv"
    if os.path.exists(train_path) and os.path.exists(val_path):
        return pd.read_csv(train_path), pd.read_csv(val_path)

    df = pd.read_csv(data_csv)
    train_df, val_df = train_test_split(df, test_size=0.3, random_state=42, stratify=df["label"])
    return train_df, val_df


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--data_csv", required=True)
    p.add_argument("--output_dir", required=True)
    p.add_argument("--model_name", default="roberta-base")
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--batch_size", type=int, default=16)
    p.add_argument("--lr", type=float, default=2e-5)
    p.add_argument("--max_length", type=int, default=512)
    p.add_argument("--warmup_ratio", type=float, default=0.06)
    p.add_argument("--weight_decay", type=float, default=0.01)
    p.add_argument("--max_steps", type=int, default=-1)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()

    train_df, val_df = _load_splits(args.data_csv)
    for col in ["text", "label"]:
        if col not in train_df.columns or col not in val_df.columns:
            raise ValueError("CSV must contain columns: text, label (run preprocessing first).")

    tokenizer = AutoTokenizer.from_pretrained(args.model_name)
    model = AutoModelForSequenceClassification.from_pretrained(args.model_name, num_labels=2)

    train_enc = tokenizer(
        train_df["text"].astype(str).tolist(),
        truncation=True,
        max_length=args.max_length,
        padding="max_length",
    )
    val_enc = tokenizer(
        val_df["text"].astype(str).tolist(),
        truncation=True,
        max_length=args.max_length,
        padding="max_length",
    )

    train_ds = TextDataset(
        encodings={k: torch.tensor(v) for k, v in train_enc.items()},
        labels=torch.tensor(train_df["label"].astype(int).to_numpy()),
    )
    val_ds = TextDataset(
        encodings={k: torch.tensor(v) for k, v in val_enc.items()},
        labels=torch.tensor(val_df["label"].astype(int).to_numpy()),
    )

    data_collator = DataCollatorWithPadding(tokenizer=tokenizer, padding="longest", return_tensors="pt")

    # HuggingFace expects a metrics fn on logits/preds; we'll compute on the fly.
    def hf_metrics(eval_pred):
        logits, labels = eval_pred
        probs = torch.softmax(torch.tensor(logits), dim=-1)[:, 1].numpy()
        y_pred = (probs >= 0.5).astype(int)
        return {
            "accuracy": float((y_pred == labels).mean()),
        }

    training_args = TrainingArguments(
        output_dir=args.output_dir,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        learning_rate=args.lr,
        warmup_ratio=args.warmup_ratio,
        weight_decay=args.weight_decay,
        eval_strategy="epoch",
        save_strategy="epoch",
        logging_strategy="steps",
        logging_steps=50,
        max_steps=args.max_steps,
        load_best_model_at_end=False,  # Can't easily use best model when limiting max steps, just save what we have
        seed=args.seed,
        fp16=torch.cuda.is_available(),
        report_to=[],
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        processing_class=tokenizer,
        data_collator=data_collator,
        compute_metrics=hf_metrics,
    )

    trainer.train()
    trainer.save_model(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)

    # Detailed validation metrics using our shared evaluator
    art = load_roberta(args.output_dir)
    y_true = val_df["label"].astype(int).to_numpy()
    y_proba = predict_proba_phishing_roberta(art, val_df["text"].astype(str).tolist(), batch_size=args.batch_size)
    y_pred = (y_proba >= 0.5).astype(int)
    m = compute_metrics(y_true=y_true, y_pred=y_pred, y_proba=y_proba)
    print("RoBERTa validation metrics:")
    for k in ["accuracy", "precision", "recall", "f1", "roc_auc"]:
        print(f"- {k}: {m[k]}")
    print("Confusion matrix:", m["confusion_matrix"])


if __name__ == "__main__":
    main()

