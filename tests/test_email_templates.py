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


def test_send_application_rejection_email_uses_branded_support_email(monkeypatch):
    captured = _capture_send_email(monkeypatch)

    email_service.send_application_rejection_email(
        "test@example.com", "AT&T AB", "Saknar underlag"
    )

    normalized_body = " ".join(captured["body"].split())

    assert captured["subject"] == "Ansökan avslogs för AT&T AB"
    assert "AT&amp;T AB" in normalized_body
    assert "support@utbildningsintyg.se" in normalized_body


def test_send_organization_link_approved_email(monkeypatch):
    captured = _capture_send_email(monkeypatch)

    email_service.send_organization_link_approved_email(
        "test@example.com",
        "AT&T AB",
    )

    assert captured["recipient"] == "test@example.com"
    assert "AT&T AB" in captured["subject"]
    assert "AT&amp;T AB" in captured["body"]
    assert "godkänd" in captured["body"]


def test_send_organization_link_rejected_email(monkeypatch):
    captured = _capture_send_email(monkeypatch)

    email_service.send_organization_link_rejected_email(
        "test@example.com",
        "AT&T AB",
    )

    assert captured["recipient"] == "test@example.com"
    assert "avslogs" in captured["subject"]
    assert "AT&T AB" in captured["subject"]
    assert "AT&amp;T AB" in captured["body"]


def test_send_certificate_expiry_summary_email(monkeypatch):
    captured = _capture_send_email(monkeypatch)
    monkeypatch.setenv("BASE_URL", "https://staging.utbildningsintyg.se")

    email_service.send_certificate_expiry_summary_email(
        "test@example.com",
        "Anna",
        [
            {
                "display_name": "Truckkort",
                "expires_on": "2026-08-10",
            },
            {
                "display_name": "HLR",
                "expires_on": "2026-09-15",
            },
        ],
        months=6,
    )

    normalized_body = " ".join(captured["body"].split())

    assert captured["recipient"] == "test@example.com"
    assert captured["subject"] == "Intyg som snart går ut"
    assert "Hej Anna" in normalized_body
    assert "Truckkort" in normalized_body
    assert "2026-08-10" in normalized_body
    assert "https://staging.utbildningsintyg.se/dashboard" in normalized_body


def test_send_supervisor_expiry_summary_email(monkeypatch):
    captured = _capture_send_email(monkeypatch)
    monkeypatch.setenv("BASE_URL", "https://staging.utbildningsintyg.se")

    email_service.send_supervisor_expiry_summary_email(
        "foretag@example.com",
        "AT&T AB",
        [
            {
                "user_name": "Anna Andersson",
                "certificates": [
                    {
                        "display_name": "Truckkort",
                        "expires_on": "2026-08-10",
                    }
                ],
            }
        ],
        months=6,
    )

    normalized_body = " ".join(captured["body"].split())

    assert captured["recipient"] == "foretag@example.com"
    assert captured["subject"] == "Intyg för anslutna konton som snart går ut"
    assert "AT&amp;T AB" in normalized_body
    assert "Anna Andersson" in normalized_body
    assert "Truckkort" in normalized_body
    assert "https://staging.utbildningsintyg.se/foretagskonto" in normalized_body


def test_send_email_skips_when_disable_emails_enabled(monkeypatch):
    monkeypatch.setenv("DISABLE_EMAILS", "true")

    called = {"load_settings": False, "send_message": False}

    def _fake_load_settings():
        called["load_settings"] = True
        raise AssertionError("SMTP-inställningar ska inte laddas när e-post är avstängt")

    def _fake_send_message(*_args, **_kwargs):
        called["send_message"] = True
        raise AssertionError("E-post ska inte skickas när e-post är avstängt")

    monkeypatch.setattr(email_service, "load_smtp_settings", _fake_load_settings)
    monkeypatch.setattr(email_service, "send_email_message", _fake_send_message)

    email_service.send_email("test@example.com", "Ämne", "<p>Hej</p>")

    assert called["load_settings"] is False
    assert called["send_message"] is False


def test_should_disable_email_sending_is_false_without_flag(monkeypatch):
    monkeypatch.delenv("DISABLE_EMAILS", raising=False)

    assert email_service.should_disable_email_sending() is False


# Copyright (c) Liam Suorsa and Mika Suorsa
