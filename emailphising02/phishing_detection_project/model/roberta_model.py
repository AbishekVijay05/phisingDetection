import os
from dataclasses import dataclass
from typing import List, Optional

import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer


@dataclass
class RobertaArtifacts:
    tokenizer: any
    model: any
    device: torch.device


def load_roberta(model_dir: str, device: Optional[str] = None) -> RobertaArtifacts:
    tok = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir)
    if device is None:
        device = "cuda" if torch.cuda.is_available() else "cpu"
    dev = torch.device(device)
    model.to(dev)
    model.eval()
    return RobertaArtifacts(tokenizer=tok, model=model, device=dev)


@torch.no_grad()
def predict_proba_phishing_roberta(
    art: RobertaArtifacts,
    texts: List[str],
    *,
    max_length: int = 512,
    batch_size: int = 16,
) -> np.ndarray:
    probs: List[float] = []
    for i in range(0, len(texts), batch_size):
        batch = texts[i : i + batch_size]
        enc = art.tokenizer(
            batch,
            padding=True,
            truncation=True,
            max_length=max_length,
            return_tensors="pt",
        )
        enc = {k: v.to(art.device) for k, v in enc.items()}
        out = art.model(**enc)
        logits = out.logits
        p = torch.softmax(logits, dim=-1)[:, 1].detach().cpu().numpy()
        probs.extend(p.tolist())
    return np.asarray(probs, dtype=np.float32)


@torch.no_grad()
def attention_token_scores(
    art: RobertaArtifacts,
    text: str,
    *,
    max_length: int = 256,
    top_k: int = 15,
) -> List[tuple]:
    """
    Lightweight "attention visualization":
    average last-layer attention from <s> token to other tokens.
    Returns (token, score) sorted descending (excluding special tokens).
    """
    enc = art.tokenizer(
        text,
        padding=False,
        truncation=True,
        max_length=max_length,
        return_tensors="pt",
        return_attention_mask=True,
    )
    enc = {k: v.to(art.device) for k, v in enc.items()}
    out = art.model(**enc, output_attentions=True)
    att = out.attentions[-1]  # [batch=1, heads, seq, seq]
    att = att.mean(dim=1)[0]  # [seq, seq]
    cls_to_all = att[0]  # attention from first token (<s>)

    input_ids = enc["input_ids"][0].detach().cpu().tolist()
    tokens = art.tokenizer.convert_ids_to_tokens(input_ids)

    special = set([art.tokenizer.cls_token, art.tokenizer.sep_token, art.tokenizer.pad_token, "<s>", "</s>"])
    pairs = []
    for tok, score in zip(tokens, cls_to_all.detach().cpu().tolist()):
        if tok in special:
            continue
        if tok.startswith("Ġ"):
            tok_disp = tok[1:]
        else:
            tok_disp = tok
        if tok_disp.strip() == "":
            continue
        pairs.append((tok_disp, float(score)))

    pairs.sort(key=lambda x: x[1], reverse=True)
    return pairs[:top_k]


def save_roberta_pretrained(model, tokenizer, output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)

