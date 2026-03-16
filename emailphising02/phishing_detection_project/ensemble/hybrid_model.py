from dataclasses import dataclass
from typing import List, Literal

import numpy as np


EnsembleMode = Literal["soft", "weighted"]


@dataclass
class HybridEnsemble:
    mode: EnsembleMode = "weighted"
    roberta_weight: float = 0.7
    nb_weight: float = 0.3

    def combine(self, roberta_proba: np.ndarray, nb_proba: np.ndarray) -> np.ndarray:
        roberta_proba = np.asarray(roberta_proba, dtype=np.float32)
        nb_proba = np.asarray(nb_proba, dtype=np.float32)
        if roberta_proba.shape != nb_proba.shape:
            raise ValueError(f"Shape mismatch: roberta={roberta_proba.shape} nb={nb_proba.shape}")

        if self.mode == "soft":
            return (roberta_proba + nb_proba) / 2.0

        w_sum = float(self.roberta_weight + self.nb_weight)
        if w_sum <= 0:
            raise ValueError("Weights must sum to a positive value.")
        wr = float(self.roberta_weight) / w_sum
        wn = float(self.nb_weight) / w_sum
        return wr * roberta_proba + wn * nb_proba

    @staticmethod
    def classify_binary(proba: float) -> str:
        """
        0.00 - 0.61 -> Legitimate
        0.62 - 1.00 -> Phishing
        """
        return "Phishing" if float(proba) >= 0.61 else "Legitimate"

    @staticmethod
    def classify_batch_binary(probas: np.ndarray) -> List[str]:
        return [HybridEnsemble.classify_binary(p) for p in probas]

    @staticmethod
    def label_from_proba(proba: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        proba = np.asarray(proba, dtype=np.float32)
        return (proba >= float(threshold)).astype(int)

