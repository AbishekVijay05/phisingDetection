"""Unit tests for the HybridEnsemble model."""

import numpy as np
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ensemble.hybrid_model import HybridEnsemble


class TestHybridEnsemble:
    """Tests for HybridEnsemble.combine and label_from_proba."""

    def test_soft_voting_averages(self):
        ens = HybridEnsemble(mode="soft")
        ro = np.array([0.8, 0.2, 0.5])
        nb = np.array([0.6, 0.4, 0.5])
        result = ens.combine(ro, nb)
        expected = (ro + nb) / 2.0
        np.testing.assert_allclose(result, expected)

    def test_weighted_voting_default(self):
        ens = HybridEnsemble(mode="weighted", roberta_weight=0.7, nb_weight=0.3)
        ro = np.array([1.0, 0.0])
        nb = np.array([0.0, 1.0])
        result = ens.combine(ro, nb)
        expected = np.array([0.7, 0.3])
        np.testing.assert_allclose(result, expected)

    def test_weighted_voting_custom(self):
        ens = HybridEnsemble(mode="weighted", roberta_weight=0.5, nb_weight=0.5)
        ro = np.array([0.8])
        nb = np.array([0.4])
        result = ens.combine(ro, nb)
        np.testing.assert_allclose(result, np.array([0.6]))

    def test_shape_mismatch_raises(self):
        ens = HybridEnsemble()
        with pytest.raises(ValueError, match="Shape mismatch"):
            ens.combine(np.array([0.5, 0.5]), np.array([0.5]))

    def test_label_from_proba_threshold(self):
        proba = np.array([0.3, 0.5, 0.7, 0.49, 0.51])
        labels = HybridEnsemble.label_from_proba(proba, threshold=0.5)
        expected = np.array([0, 1, 1, 0, 1])
        np.testing.assert_array_equal(labels, expected)

    def test_label_from_proba_custom_threshold(self):
        proba = np.array([0.3, 0.5, 0.7])
        labels = HybridEnsemble.label_from_proba(proba, threshold=0.6)
        expected = np.array([0, 0, 1])
        np.testing.assert_array_equal(labels, expected)

    def test_combine_all_zeros(self):
        ens = HybridEnsemble(mode="weighted")
        ro = np.array([0.0, 0.0])
        nb = np.array([0.0, 0.0])
        result = ens.combine(ro, nb)
        np.testing.assert_allclose(result, np.array([0.0, 0.0]))

    def test_combine_all_ones(self):
        ens = HybridEnsemble(mode="weighted")
        ro = np.array([1.0, 1.0])
        nb = np.array([1.0, 1.0])
        result = ens.combine(ro, nb)
        np.testing.assert_allclose(result, np.array([1.0, 1.0]))

    def test_zero_weights_raises(self):
        ens = HybridEnsemble(mode="weighted", roberta_weight=0.0, nb_weight=0.0)
        with pytest.raises(ValueError, match="positive"):
            ens.combine(np.array([0.5]), np.array([0.5]))

    def test_classify_binary(self):
        assert HybridEnsemble.classify_binary(0.2) == "Legitimate"
        assert HybridEnsemble.classify_binary(0.5) == "Legitimate"
        assert HybridEnsemble.classify_binary(0.6) == "Legitimate"
        assert HybridEnsemble.classify_binary(0.61) == "Phishing"
        assert HybridEnsemble.classify_binary(0.9) == "Phishing"

    def test_classify_batch_binary(self):
        probas = np.array([0.2, 0.5, 0.8])
        results = HybridEnsemble.classify_batch_binary(probas)
        assert results == ["Legitimate", "Legitimate", "Phishing"]
