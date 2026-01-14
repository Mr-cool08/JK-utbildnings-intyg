"""Tester för e-postmallar."""

from __future__ import annotations

from functions.emails import service as email_service


def _capture_send_email(monkeypatch):
    captured = {}

    def _fake_send_email(recipient, subject, body, attachments=None):
        captured["recipient"] = recipient
        captured["subject"] = subject
        captured["body"] = body
        captured["attachments"] = attachments

    monkeypatch.setattr(email_service, "send_email", _fake_send_email)
    return captured


def test_send_application_approval_email_standard_without_company(monkeypatch):
    captured = _capture_send_email(monkeypatch)

    email_service.send_application_approval_email(
        "test@example.com", "standardkonto", ""
    )

    normalized_body = " ".join(captured["body"].split())

    assert captured["subject"] == "Ansökan om standardkonto godkänd"
    assert (
        "Din ansökan om ett standardkonto har blivit godkänd." in normalized_body
    )
    assert "kopplat till" not in normalized_body


def test_send_application_approval_email_standard_with_company(monkeypatch):
    captured = _capture_send_email(monkeypatch)

    email_service.send_application_approval_email(
        "test@example.com", "standardkonto", "AB & Co"
    )

    normalized_body = " ".join(captured["body"].split())

    assert (
        captured["subject"]
        == "Ansökan om standardkonto godkänd för AB & Co"
    )
    assert "kopplat till AB &amp; Co" in normalized_body
    assert "AB & Co" not in normalized_body  # HTML ska vara escapad


def test_send_application_approval_email_corporate_defaults_company(monkeypatch):
    captured = _capture_send_email(monkeypatch)

    email_service.send_application_approval_email(
        "test@example.com", "foretagskonto", ""
    )

    normalized_body = " ".join(captured["body"].split())

    assert captured["subject"] == "Ansökan godkänd för företaget"
    assert "kopplat till företaget" in normalized_body
    assert "företaget" in normalized_body
    assert captured["attachments"] is None
