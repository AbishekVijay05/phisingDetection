import os
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel

from ensemble.hybrid_model import HybridEnsemble
from inference.eml_parser import eml_to_text
from model.naive_bayes_model import load_naive_bayes, predict_proba_phishing
from model.roberta_model import load_roberta, predict_proba_phishing_roberta


class PredictRequest(BaseModel):
    email_text: Optional[str] = None
    eml_base64: Optional[str] = None
    ensemble_mode: Optional[str] = "weighted"  # soft | weighted
    roberta_weight: Optional[float] = 0.7
    nb_weight: Optional[float] = 0.3
    threshold: Optional[float] = 0.5


class PredictResponse(BaseModel):
    prediction: str
    confidence: float
    roberta_probability: float
    naive_bayes_probability: float
    final_probability: float


NB_DIR = os.environ.get("NB_DIR", os.path.join("artifacts", "nb"))
ROBERTA_DIR = os.environ.get("ROBERTA_DIR", os.path.join("artifacts", "roberta"))

app = FastAPI(title="Hybrid Phishing Detector", version="1.0")

_nb = None
_ro = None


@app.on_event("startup")
def _load_models():
    global _nb, _ro
    _nb = load_naive_bayes(NB_DIR)
    _ro = load_roberta(ROBERTA_DIR)


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    ensemble = HybridEnsemble(
        mode="soft" if req.ensemble_mode == "soft" else "weighted",
        roberta_weight=float(req.roberta_weight or 0.7),
        nb_weight=float(req.nb_weight or 0.3),
    )
    if req.email_text:
        text = req.email_text
    elif req.eml_base64:
        import base64

        b64_str: str = req.eml_base64 or ""
        raw = base64.b64decode(b64_str.encode("utf-8"))
        text = eml_to_text(raw)
    else:
        raise ValueError("Provide either email_text or eml_base64.")
    nb_p = float(predict_proba_phishing(_nb, [text])[0])
    ro_p = float(predict_proba_phishing_roberta(_ro, [text])[0])
    final_p = float(ensemble.combine([ro_p], [nb_p])[0])
    pred = HybridEnsemble.classify_binary(final_p)
    return PredictResponse(
        prediction=pred,
        confidence=final_p,
        roberta_probability=ro_p,
        naive_bayes_probability=nb_p,
        final_probability=final_p,
    )

