"""Unit tests for preprocessing utilities."""

import sys
import os

import pandas as pd
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from preprocessing.preprocess import _clean_text, _coerce_label, split_df


class TestCleanText:

    def test_removes_html(self):
        html = "<html><body><p>Hello <b>world</b></p></body></html>"
        result = _clean_text(html)
        assert "<" not in result
        assert "hello" in result
        assert "world" in result

    def test_normalizes_whitespace(self):
        text = "  hello    world   "
        result = _clean_text(text)
        assert result == "hello world"

    def test_lowercases(self):
        result = _clean_text("HELLO World")
        assert result == "hello world"

    def test_handles_none(self):
        result = _clean_text(None)
        assert result == ""

    def test_handles_nan(self):
        result = _clean_text(float("nan"))
        assert result == ""


class TestCoerceLabel:

    def test_numeric_binary(self):
        s = pd.Series([0, 1, 0, 1])
        result = _coerce_label(s)
        assert list(result) == [0, 1, 0, 1]

    def test_string_phishing_legit(self):
        s = pd.Series(["phishing", "legitimate", "Phishing", "Legit"])
        result = _coerce_label(s)
        assert list(result) == [1, 0, 1, 0]

    def test_boolean(self):
        s = pd.Series([True, False, True])
        result = _coerce_label(s)
        assert list(result) == [1, 0, 1]

    def test_spam_ham(self):
        s = pd.Series(["spam", "ham", "SPAM", "HAM"])
        result = _coerce_label(s)
        assert list(result) == [1, 0, 1, 0]


class TestSplitDf:

    def test_split_proportions(self):
        df = pd.DataFrame({"text": [f"text_{i}" for i in range(100)], "label": [0, 1] * 50})
        splits = split_df(df, seed=42)
        assert len(splits.train) == 70
        assert len(splits.val) == 15
        assert len(splits.test) == 15

    def test_no_overlap(self):
        df = pd.DataFrame({"text": [f"text_{i}" for i in range(100)], "label": [0, 1] * 50})
        splits = split_df(df, seed=42)
        train_idx = set(splits.train.index)
        val_idx = set(splits.val.index)
        test_idx = set(splits.test.index)
        assert len(train_idx & val_idx) == 0
        assert len(train_idx & test_idx) == 0
        assert len(val_idx & test_idx) == 0
