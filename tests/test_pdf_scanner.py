# Copyright (c) Liam Suorsa
import json
import logging
import subprocess
from types import SimpleNamespace

import pytest

from services import pdf_scanner


def _fake_run(stdout_text: str, returncode: int = 0, stderr_text: str = ""):
    def _runner(*_args, **_kwargs):
        return SimpleNamespace(
            returncode=returncode, stdout=stdout_text, stderr=stderr_text
        )

    return _runner


def test_scan_pdf_allows_clean_pdf(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run(json.dumps({"objects": []})))
    verdict = pdf_scanner.scan_pdf_bytes(b"%PDF-1.4 clean")
    assert verdict.decision == "ALLOW"
    assert verdict.findings == []


def test_scan_pdf_allows_only_benign_openaction(monkeypatch):
    benign = json.dumps({"objects": [{"type": "OpenAction", "dest": "/Fit"}]})
    monkeypatch.setattr(subprocess, "run", _fake_run(benign))
    verdict = pdf_scanner.scan_pdf_bytes(b"%PDF-1.4 benign-openaction")
    assert verdict.decision == "ALLOW"
    assert "OpenAction" in verdict.findings


def test_scan_pdf_rejects_openaction_with_javascript(monkeypatch):
    suspicious = json.dumps(
        {"objects": [{"type": "OpenAction", "dest": "/Fit"}, {"has": "JavaScript"}]}
    )
    monkeypatch.setattr(subprocess, "run", _fake_run(suspicious))
    verdict = pdf_scanner.scan_pdf_bytes(b"%PDF-1.4 suspicious")
    assert verdict.decision == "REJECT"
    assert "JavaScript" in verdict.findings


def test_scan_pdf_rejects_embeddedfile(monkeypatch):
    suspicious = json.dumps({"objects": [{"type": "EmbeddedFile"}]})
    monkeypatch.setattr(subprocess, "run", _fake_run(suspicious))
    verdict = pdf_scanner.scan_pdf_bytes(b"%PDF-1.4 embedded")
    assert verdict.decision == "REJECT"
    assert "EmbeddedFile" in verdict.findings


def test_scan_pdf_nonzero_unknown_output_raises_value_error(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_run("scanner panic and undecodable payload", returncode=3, stderr_text="err"),
    )
    with pytest.raises(ValueError):
        pdf_scanner.scan_pdf_bytes(b"%PDF-1.4 unknown")


def test_scan_pdf_nonzero_benign_only_allows(monkeypatch):
    benign = json.dumps({"objects": [{"type": "OpenAction", "dest": "/XYZ"}]})
    monkeypatch.setattr(subprocess, "run", _fake_run(benign, returncode=1))
    verdict = pdf_scanner.scan_pdf_bytes(b"%PDF-1.4 benign-nonzero")
    assert verdict.decision == "ALLOW"
    assert "OpenAction" in verdict.findings


def test_scan_pdf_nonzero_with_dangerous_findings_rejects(monkeypatch):
    suspicious = json.dumps({"objects": [{"has": "JavaScript"}]})
    monkeypatch.setattr(subprocess, "run", _fake_run(suspicious, returncode=2))
    verdict = pdf_scanner.scan_pdf_bytes(b"%PDF-1.4 dangerous-nonzero")
    assert verdict.decision == "REJECT"
    assert "JavaScript" in verdict.findings


def test_scan_pdf_nonzero_benign_string_fallback_raises_value_error(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_run("OpenAction /Fit", returncode=2, stderr_text="warn"),
    )
    with pytest.raises(ValueError):
        pdf_scanner.scan_pdf_bytes(b"%PDF-1.4 benign-text-nonzero")


def test_scan_pdf_handles_timeout(monkeypatch):
    def _timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["quicksand"], timeout=1)

    monkeypatch.setattr(subprocess, "run", _timeout)
    with pytest.raises(ValueError):
        pdf_scanner.scan_pdf_bytes(b"%PDF-1.4 slow", logging.getLogger(__name__))
