"""Unit tests for Naive Bayes model training and inference."""

import os
import sys
import tempfile

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from model.naive_bayes_model import (
    NaiveBayesArtifacts,
    load_naive_bayes,
    predict_proba_phishing,
    save_naive_bayes,
    top_terms,
    train_naive_bayes,
)


@pytest.fixture
def sample_data():
    texts = [
        "Click here to verify your account immediately",
        "Your password has expired reset now",
        "Urgent action required verify your identity",
        "Meeting tomorrow at 3pm conference room",
        "Project update quarterly results attached",
        "Lunch plans for Friday with the team",
        "Win a free prize claim now limited time",
        "Suspicious login attempt verify your account",
        "Weekly newsletter from community group",
        "Invitation to annual company retreat",
    ]
    labels = [1, 1, 1, 0, 0, 0, 1, 1, 0, 0]
    return texts, labels


@pytest.fixture
def trained_model(sample_data):
    texts, labels = sample_data
    return train_naive_bayes(texts, labels, max_features=1000, ngram_range=(1, 1), min_df=1)


class TestTraining:

    def test_train_returns_artifacts(self, trained_model):
        assert isinstance(trained_model, NaiveBayesArtifacts)
        assert trained_model.vectorizer is not None
        assert trained_model.model is not None

    def test_predict_returns_probabilities(self, trained_model):
        probs = predict_proba_phishing(trained_model, ["verify your account now"])
        assert len(probs) == 1
        assert 0.0 <= probs[0] <= 1.0

    def test_predict_batch(self, trained_model):
        texts = ["verify account", "meeting at 3pm", "click here now"]
        probs = predict_proba_phishing(trained_model, texts)
        assert len(probs) == 3
        assert all(0.0 <= p <= 1.0 for p in probs)


class TestSaveLoad:

    def test_save_and_load(self, trained_model):
        with tempfile.TemporaryDirectory() as tmp:
            save_naive_bayes(trained_model, tmp)
            loaded = load_naive_bayes(tmp)
            assert isinstance(loaded, NaiveBayesArtifacts)

            # Predictions should match
            test_texts = ["verify your password"]
            orig_probs = predict_proba_phishing(trained_model, test_texts)
            loaded_probs = predict_proba_phishing(loaded, test_texts)
            np.testing.assert_allclose(orig_probs, loaded_probs)

    def test_save_creates_files(self, trained_model):
        with tempfile.TemporaryDirectory() as tmp:
            save_naive_bayes(trained_model, tmp)
            assert os.path.exists(os.path.join(tmp, "tfidf.joblib"))
            assert os.path.exists(os.path.join(tmp, "multinomial_nb.joblib"))
            assert os.path.exists(os.path.join(tmp, "meta.json"))


class TestTopTerms:

    def test_top_terms_returns_dict(self, trained_model):
        terms = top_terms(trained_model, top_k=5)
        assert isinstance(terms, dict)
        assert "phishing" in terms or len(terms) > 0

    def test_top_terms_count(self, trained_model):
        terms = top_terms(trained_model, top_k=3)
        for key, val in terms.items():
            assert len(val) <= 3
