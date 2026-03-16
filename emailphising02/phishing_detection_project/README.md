# 🛡️ Hybrid RoBERTa + MultinomialNB Email Phishing Detection

A **production-grade hybrid phishing detector** that ensembles two complementary ML models for robust email classification:

- **RoBERTa (`roberta-base`)** — Deep contextual understanding of email semantics
- **TF-IDF + Multinomial Naive Bayes** — Fast keyword/statistical signal detection

## 🎯 Features

- **Hybrid ensemble** with configurable soft and weighted voting strategies
- **Multiple input modes**: raw text, `.eml` files, CSV batch scanning
- **Explainability**: LIME, NB top terms, RoBERTa attention visualization
- **FastAPI deployment** with REST endpoint
- **Docker support** for containerized deployment
- **Comprehensive test suite** with pytest

## 📊 Output

For each email analyzed, the system provides:

| Output | Description |
|--------|-------------|
| RoBERTa probability | Contextual semantic phishing score |
| Naive Bayes probability | Keyword-based phishing score |
| Final ensemble probability | Combined score (soft or weighted voting) |
| Prediction label | **Phishing** or **Safe** |

---

## 🗂️ Project Structure

```
phishing_detection_project/
├── model/                    # Model definitions & utilities
│   ├── naive_bayes_model.py  # TF-IDF + MultinomialNB
│   └── roberta_model.py      # RoBERTa fine-tuned classifier
├── ensemble/
│   └── hybrid_model.py       # Soft & weighted ensemble combiner
├── preprocessing/
│   ├── preprocess.py          # Dataset download, cleaning, splitting
│   └── build_eml_dataset.py   # Build dataset from .eml files
├── training/
│   ├── train_model.py         # Unified training entry point
│   ├── train_naive_bayes.py   # NB training pipeline
│   └── train_roberta.py       # RoBERTa fine-tuning pipeline
├── evaluation/
│   ├── evaluate_model.py      # Full model evaluation
│   └── metrics.py             # Accuracy, F1, AUC, confusion matrix
├── inference/
│   ├── predict_email.py       # CLI prediction (text, .eml, batch)
│   └── eml_parser.py          # RFC-2822 .eml file parser
├── deployment/
│   └── api.py                 # FastAPI REST API server
├── tests/                     # Unit test suite
│   ├── test_ensemble.py
│   ├── test_metrics.py
│   ├── test_naive_bayes.py
│   ├── test_eml_parser.py
│   └── test_preprocessing.py
├── artifacts/                 # Trained model weights (generated)
│   ├── nb/                    # TF-IDF vectorizer + NB classifier
│   └── roberta/               # Fine-tuned RoBERTa checkpoint
├── dataset/                   # Training/validation/test data (generated)
├── requirements.txt
├── pyproject.toml
├── Dockerfile
├── LICENSE
└── README.md
```

---

## ⚡ Quick Start

### 1. Setup

```bash
cd phishing_detection_project
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS
pip install -r requirements.txt
```

### 2. Build Dataset

Download datasets via KaggleHub (requires Kaggle credentials) and produce a unified CSV:

```bash
python preprocessing\preprocess.py --out_csv dataset\phishing_emails.csv
```

Or use your own labeled CSV:

```bash
python preprocessing\preprocess.py --input_csv path\to\your.csv --text_col text --label_col label --out_csv dataset\phishing_emails.csv
```

Or build from `.eml` files:

```bash
python preprocessing\build_eml_dataset.py --phishing_dir path\to\emls\phishing --safe_dir path\to\emls\safe --out_csv dataset\phishing_emails.csv
```

### 3. Train Naive Bayes

```bash
python training\train_model.py --model naive_bayes --data_csv dataset\phishing_emails.csv --output_dir artifacts\nb
```

### 4. Fine-tune RoBERTa

```bash
python training\train_model.py --model roberta --data_csv dataset\phishing_emails.csv --output_dir artifacts\roberta --epochs 3 --batch_size 16 --lr 2e-5
```

### 5. Evaluate (NB, RoBERTa, Hybrid)

```bash
python evaluation\evaluate_model.py --data_csv dataset\phishing_emails.csv --nb_dir artifacts\nb --roberta_dir artifacts\roberta --hybrid_weights 0.7 0.3
```

### 6. Predict

**Single email text:**
```bash
python inference\predict_email.py --nb_dir artifacts\nb --roberta_dir artifacts\roberta --text "Your account has been suspended. Click here to verify immediately."
```

**Scan an `.eml` file:**
```bash
python inference\predict_email.py --nb_dir artifacts\nb --roberta_dir artifacts\roberta --eml_path path\to\email.eml --explain
```

**Batch scan a directory of `.eml` files:**
```bash
python inference\predict_email.py --nb_dir artifacts\nb --roberta_dir artifacts\roberta --eml_dir path\to\emls --out_csv artifacts\eml_scan_report.csv
```

### 7. Explainability (LIME + NB Terms + RoBERTa Attention)

```bash
python inference\predict_email.py --nb_dir artifacts\nb --roberta_dir artifacts\roberta --text "Verify your password urgently" --explain
```

---

## 🌐 API Deployment

### Local (FastAPI)

```bash
uvicorn deployment.api:app --reload --port 8000
```

**Example request:**
```bash
curl -X POST http://127.0.0.1:8000/predict -H "Content-Type: application/json" -d "{\"email_text\":\"Verify your account immediately\"}"
```

**Example response:**
```json
{
  "prediction": "Phishing",
  "confidence": 0.82,
  "roberta_probability": 0.89,
  "naive_bayes_probability": 0.65,
  "final_probability": 0.82
}
```

### Docker

```bash
docker build -t phishing-detector .
docker run -p 8000:8000 phishing-detector
```

---

## 🧪 Testing

```bash
pip install pytest pytest-cov
pytest tests/ -v
pytest tests/ --cov=model --cov=ensemble --cov=evaluation --cov=inference --cov=preprocessing -v
```

---

## ⚙️ Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--ensemble_mode` | `weighted` | `soft` (equal avg) or `weighted` |
| `--weights` | `0.7 0.3` | RoBERTa weight, NB weight |
| `--threshold` | `0.5` | Classification threshold |
| `--explain` | off | Enable LIME + attention explainability |

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.
