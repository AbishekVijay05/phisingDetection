import json
import os
from dataclasses import dataclass
from typing import Dict, List, Tuple

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB


@dataclass
class NaiveBayesArtifacts:
    vectorizer: TfidfVectorizer
    model: MultinomialNB


def train_naive_bayes(
    texts: List[str],
    labels: List[int],
    *,
    max_features: int = 50000,
    ngram_range: Tuple[int, int] = (1, 2),
    min_df: int = 2,
) -> NaiveBayesArtifacts:
    vectorizer = TfidfVectorizer(
        lowercase=True,
        stop_words="english",
        max_features=max_features,
        ngram_range=ngram_range,
        min_df=min_df,
        strip_accents="unicode",
    )
    X = vectorizer.fit_transform(texts)
    clf = MultinomialNB()
    clf.fit(X, labels)
    return NaiveBayesArtifacts(vectorizer=vectorizer, model=clf)


def predict_proba_phishing(art: NaiveBayesArtifacts, texts: List[str]) -> np.ndarray:
    X = art.vectorizer.transform(texts)
    proba = art.model.predict_proba(X)
    # class index for phishing (1)
    if hasattr(art.model, "classes_"):
        classes = list(art.model.classes_)
        idx = classes.index(1) if 1 in classes else int(np.argmax(classes))
    else:
        idx = 1
    return proba[:, idx]


def top_terms(art: NaiveBayesArtifacts, top_k: int = 20) -> Dict[str, List[Tuple[str, float]]]:
    """
    Return indicative tokens by class using log probability differences.
    """
    feature_names = np.array(art.vectorizer.get_feature_names_out())
    logp = art.model.feature_log_prob_  # shape: [n_classes, n_features]
    classes = list(art.model.classes_)
    if 0 in classes and 1 in classes:
        i0 = classes.index(0)
        i1 = classes.index(1)
        diff = logp[i1] - logp[i0]
        phishing_idx = np.argsort(-diff)[:top_k]
        legit_idx = np.argsort(diff)[:top_k]
        return {
            "phishing": [(feature_names[i], float(diff[i])) for i in phishing_idx],
            "legitimate": [(feature_names[i], float(-diff[i])) for i in legit_idx],
        }
    # fallback: just list top tokens per class
    out: Dict[str, List[Tuple[str, float]]] = {}
    for ci, c in enumerate(classes):
        idx = np.argsort(-logp[ci])[:top_k]
        out[str(c)] = [(feature_names[i], float(logp[ci, i])) for i in idx]
    return out


def save_naive_bayes(art: NaiveBayesArtifacts, output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    joblib.dump(art.vectorizer, os.path.join(output_dir, "tfidf.joblib"))
    joblib.dump(art.model, os.path.join(output_dir, "multinomial_nb.joblib"))
    meta = {
        "type": "tfidf_multinomial_nb",
        "stop_words": "english",
    }
    with open(os.path.join(output_dir, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


def load_naive_bayes(output_dir: str) -> NaiveBayesArtifacts:
    vectorizer = joblib.load(os.path.join(output_dir, "tfidf.joblib"))
    model = joblib.load(os.path.join(output_dir, "multinomial_nb.joblib"))
    return NaiveBayesArtifacts(vectorizer=vectorizer, model=model)

