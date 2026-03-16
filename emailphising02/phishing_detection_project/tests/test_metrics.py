"""Unit tests for evaluation metrics."""

import numpy as np
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from evaluation.metrics import compute_metrics


class TestComputeMetrics:

    def test_perfect_predictions(self):
        y_true = np.array([0, 0, 1, 1])
        y_pred = np.array([0, 0, 1, 1])
        y_proba = np.array([0.1, 0.2, 0.9, 0.8])
        m = compute_metrics(y_true, y_pred, y_proba)
        assert m["accuracy"] == 1.0
        assert m["precision"] == 1.0
        assert m["recall"] == 1.0
        assert m["f1"] == 1.0
        assert m["roc_auc"] == 1.0

    def test_all_wrong(self):
        y_true = np.array([0, 0, 1, 1])
        y_pred = np.array([1, 1, 0, 0])
        y_proba = np.array([0.9, 0.8, 0.1, 0.2])
        m = compute_metrics(y_true, y_pred, y_proba)
        assert m["accuracy"] == 0.0
        assert m["recall"] == 0.0

    def test_confusion_matrix_shape(self):
        y_true = np.array([0, 1, 0, 1])
        y_pred = np.array([0, 1, 1, 0])
        y_proba = np.array([0.2, 0.8, 0.6, 0.4])
        m = compute_metrics(y_true, y_pred, y_proba)
        cm = m["confusion_matrix"]
        assert len(cm) == 2
        assert len(cm[0]) == 2

    def test_classification_report_is_string(self):
        y_true = np.array([0, 1])
        y_pred = np.array([0, 1])
        y_proba = np.array([0.1, 0.9])
        m = compute_metrics(y_true, y_pred, y_proba)
        assert isinstance(m["classification_report"], str)
