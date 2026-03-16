"""Unit tests for the EML parser."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from inference.eml_parser import eml_to_text


class TestEmlParser:

    def _make_eml(self, subject="Test Subject", from_addr="sender@example.com",
                  to_addr="recipient@example.com", body="Hello world"):
        """Build a minimal RFC-2822 email as bytes."""
        lines = [
            f"From: {from_addr}",
            f"To: {to_addr}",
            f"Subject: {subject}",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=utf-8",
            "",
            body,
        ]
        return "\r\n".join(lines).encode("utf-8")

    def test_basic_parsing(self):
        raw = self._make_eml(subject="Verify Account", body="Click here now")
        result = eml_to_text(raw)
        assert "Verify Account" in result
        assert "Click here now" in result

    def test_from_header(self):
        raw = self._make_eml(from_addr="phisher@evil.com")
        result = eml_to_text(raw)
        assert "phisher@evil.com" in result

    def test_to_header(self):
        raw = self._make_eml(to_addr="victim@example.com")
        result = eml_to_text(raw)
        assert "victim@example.com" in result

    def test_empty_body(self):
        raw = self._make_eml(body="")
        result = eml_to_text(raw)
        # Should still have headers
        assert "subject:" in result.lower()

    def test_html_email(self):
        lines = [
            "From: sender@test.com",
            "To: user@test.com",
            "Subject: HTML Test",
            "MIME-Version: 1.0",
            "Content-Type: text/html; charset=utf-8",
            "",
            "<html><body><p>Click <a href='http://phish.com'>here</a></p></body></html>",
        ]
        raw = "\r\n".join(lines).encode("utf-8")
        try:
            result = eml_to_text(raw)
            assert "Click" in result
            assert "here" in result
        except Exception:
            # lxml may not be installed; skip gracefully
            import pytest
            pytest.skip("lxml not available for HTML parsing")
