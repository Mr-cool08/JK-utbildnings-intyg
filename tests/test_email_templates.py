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

