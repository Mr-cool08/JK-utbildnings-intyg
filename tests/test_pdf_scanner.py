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


def test_scan_pdf_allows_benign_openaction_only(monkeypatch):
    benign = json.dumps({"catalog": {"OpenAction": ["GoTo", "/Fit"]}})
    monkeypatch.setattr(subprocess, "run", _fake_run(benign))
    verdict = pdf_scanner.scan_pdf_bytes(b"%PDF-1.4 benign openaction")
    assert verdict.decision == "ALLOW"
    assert verdict.findings == ["GoTo", "OpenAction", "ViewDestination"]


def test_scan_pdf_rejects_openaction_with_javascript(monkeypatch):
    suspicious = json.dumps(
        {"catalog": {"OpenAction": ["JavaScript", "app.alert('Hej')"]}}
    )
    monkeypatch.setattr(subprocess, "run", _fake_run(suspicious))
    verdict = pdf_scanner.scan_pdf_bytes(b"%PDF-1.4 dangerous openaction")
    assert verdict.decision == "REJECT"
    assert "JavaScript" in verdict.findings


def test_scan_pdf_rejects_embedded_file(monkeypatch):
    suspicious = json.dumps({"names": {"EmbeddedFiles": ["payload.bin"]}})
    monkeypatch.setattr(subprocess, "run", _fake_run(suspicious))
    verdict = pdf_scanner.scan_pdf_bytes(b"%PDF-1.4 embedded")
    assert verdict.decision == "REJECT"
    assert "EmbeddedFile" in verdict.findings


def test_scan_pdf_nonzero_unknown_output_raises(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run("scanner internal error", returncode=2))
    with pytest.raises(ValueError):
        pdf_scanner.scan_pdf_bytes(b"%PDF-1.4 unknown failure")


def test_scan_pdf_nonzero_exitcode_with_benign_output_allows(monkeypatch):
    benign = json.dumps({"catalog": {"OpenAction": ["GoTo", "/XYZ"]}})
    monkeypatch.setattr(subprocess, "run", _fake_run(benign, returncode=1))
    verdict = pdf_scanner.scan_pdf_bytes(b"%PDF-1.4 benign despite nonzero")
    assert verdict.decision == "ALLOW"
    assert verdict.findings == ["GoTo", "OpenAction", "ViewDestination"]


def test_scan_pdf_handles_timeout(monkeypatch):
    def _timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["quicksand"], timeout=1)

    monkeypatch.setattr(subprocess, "run", _timeout)
    with pytest.raises(ValueError):
        pdf_scanner.scan_pdf_bytes(b"%PDF-1.4 slow", logging.getLogger(__name__))
