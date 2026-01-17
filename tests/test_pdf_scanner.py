# Copyright (c) Liam Suorsa
import json
import logging
import subprocess
from types import SimpleNamespace

import pytest

from services import pdf_scanner


def _fake_run(stdout_text: str, returncode: int = 0):
    def _runner(*_args, **_kwargs):
        return SimpleNamespace(
            returncode=returncode, stdout=stdout_text, stderr=""
        )

    return _runner


def test_scan_pdf_allows_clean_pdf(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run(json.dumps({"objects": []})))
    verdict = pdf_scanner.scan_pdf_bytes(b"%PDF-1.4 clean")
    assert verdict.decision == "ALLOW"
    assert verdict.findings == []


def test_scan_pdf_rejects_suspicious_features(monkeypatch):
    suspicious = json.dumps({"objects": [{"has": "JavaScript"}, {"type": "OpenAction"}]})
    monkeypatch.setattr(subprocess, "run", _fake_run(suspicious))
    verdict = pdf_scanner.scan_pdf_bytes(b"%PDF-1.4 suspicious")
    assert verdict.decision == "REJECT"
    assert "JavaScript" in verdict.findings
    assert "OpenAction" in verdict.findings


def test_scan_pdf_handles_timeout(monkeypatch):
    def _timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["quicksand"], timeout=1)

    monkeypatch.setattr(subprocess, "run", _timeout)
    with pytest.raises(ValueError):
        pdf_scanner.scan_pdf_bytes(b"%PDF-1.4 slow", logging.getLogger(__name__))
