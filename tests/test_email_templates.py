# Copyright (c) Liam Suorsa and Mika Suorsa
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
        "test@example.com", "ACME AB", "Saknar underlag"
    )

    normalized_body = " ".join(captured["body"].split())

    assert captured["subject"] == "Ansökan avslogs för ACME AB"
    assert "support@utbildningsintyg.se" in normalized_body



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
