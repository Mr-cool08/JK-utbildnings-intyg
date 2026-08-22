# Copyright (c) Liam Suorsa and Mika Suorsa
import re
from html import escape

import app
import functions
import pytest

from course_categories import COURSE_CATEGORIES
from functions.emails import service as email_service


@pytest.fixture(autouse=True)
def _enable_email_sending(monkeypatch):
    monkeypatch.setenv("DISABLE_EMAILS", "false")


def _login_default_user(client):
    with client.session_transaction() as sess:
        sess["csrf_token"] = "test-token"
    return client.post(
        "/login",
        data={
            "personnummer": "9001011234",
            "password": "secret",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )


def _store_sample_pdf(
    filename: str = "delningstest.pdf",
    categories: list[str] | None = None,
) -> int:
    personnummer_hash = functions.hash_value("9001011234")
    return functions.store_pdf_blob(
        personnummer_hash,
        filename,
        b"%PDF-1.4 sample",
        [COURSE_CATEGORIES[0][0]] if categories is None else categories,
    )


def _set_mail_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("smtp_server", "smtp.example.com")
    monkeypatch.setenv("smtp_port", "587")
    monkeypatch.setenv("smtp_user", "info@example.com")
    monkeypatch.setenv("smtp_password", "hemligt")
    monkeypatch.setenv("smtp_timeout", "10")


def _assert_attachment_link(html_content, attachment, expected_heading: str) -> None:
    content_id = attachment["Content-ID"]
    filename = attachment.get_filename()
    assert content_id is not None
    assert filename is not None
    cid_reference = re.escape(content_id.strip("<>"))
    safe_filename = re.escape(escape(filename))
    safe_heading = re.escape(escape(expected_heading))
    section_pattern = (
        rf"<h2\b[^>]*>\s*{safe_heading}\s*</h2>\s*"
        rf"<p\b[^>]*>\s*<a\b[^>]*href=['\"]cid:{cid_reference}['\"][^>]*>"
        rf"\s*{safe_filename}\s*</a>"
    )
    assert re.search(section_pattern, html_content)


def test_share_pdf_requires_login(user_db):
    pdf_id = _store_sample_pdf()

    with app.app.test_client() as client:
        response = client.post(
            "/share_pdf",
            json={"pdf_id": pdf_id, "recipient_email": "mottagare@example.com"},
        )

    assert response.status_code == 401


def test_share_pdf_sends_email(monkeypatch, user_db):
    _set_mail_env(monkeypatch)
    pdf_id = _store_sample_pdf()

    sent = {}

    def fake_sender(message, recipient, settings):
        sent["message"] = message
        sent["recipient"] = recipient
        sent["settings"] = settings

    monkeypatch.setattr(email_service, "send_email_message", fake_sender)

    with app.app.test_client() as client:
        _login_default_user(client)
        with client.session_transaction() as sess:
            sess["username"] = "Anna & Bo"
        response = client.post(
            "/share_pdf",
            json={
                "pdf_ids": [pdf_id],
                "recipient_email": "mottagare@example.com",
            },
        )

    assert response.status_code == 200
    data = response.get_json()
    assert data["meddelande"] == "Intyget har skickats via e-post."

    assert sent["recipient"] == "mottagare@example.com"
    assert sent["settings"].user == "info@example.com"

    message = sent["message"]
    assert message["To"] == "mottagare@example.com"
    assert message["From"] == "info@example.com"
    assert "från Anna & Bo" in message["Subject"]
    assert "&amp;" not in message["Subject"]
    html_part = message.get_body(preferencelist=("html", "plain"))
    assert html_part is not None
    html_content = html_part.get_content()
    assert "delat ett intyg" in html_content
    assert "<strong>Anna &amp; Bo</strong>" in html_content

    attachments = list(message.iter_attachments())
    assert len(attachments) == 1
    attachment = attachments[0]
    assert attachment.get_filename() == "delningstest.pdf"
    assert attachment.get_content_type() == "application/pdf"
    _assert_attachment_link(html_content, attachment, COURSE_CATEGORIES[0][1])


def test_share_pdf_rejects_invalid_email(monkeypatch, user_db):
    _set_mail_env(monkeypatch)
    pdf_id = _store_sample_pdf()

    monkeypatch.setattr(email_service, "send_email_message", lambda *args, **kwargs: None)

    with app.app.test_client() as client:
        _login_default_user(client)
        response = client.post(
            "/share_pdf",
            json={"pdf_ids": [pdf_id], "recipient_email": "fel-adress"},
        )

    assert response.status_code == 400
    data = response.get_json()
    assert "Ogiltig e-postadress" in data["fel"]


def test_share_pdf_missing_document(monkeypatch, user_db):
    _set_mail_env(monkeypatch)
    monkeypatch.setattr(email_service, "send_email_message", lambda *args, **kwargs: None)

    with app.app.test_client() as client:
        _login_default_user(client)
        response = client.post(
            "/share_pdf",
            json={"pdf_ids": [9999], "recipient_email": "mottagare@example.com"},
        )

    assert response.status_code == 404
    data = response.get_json()
    assert "kunde inte hittas" in data["fel"]


def test_share_pdf_uses_uncategorized_heading_and_escapes_filename(
    monkeypatch,
    user_db,
):
    _set_mail_env(monkeypatch)
    filename = "arbetsmiljö & <test>.pdf"
    pdf_id = _store_sample_pdf(filename, [])
    sent = {}

    def fake_sender(message, recipient, settings):
        sent["message"] = message

    monkeypatch.setattr(email_service, "send_email_message", fake_sender)

    with app.app.test_client() as client:
        _login_default_user(client)
        response = client.post(
            "/share_pdf",
            json={
                "pdf_ids": [pdf_id],
                "recipient_email": "mottagare@example.com",
            },
        )

    assert response.status_code == 200
    message = sent["message"]
    html_part = message.get_body(preferencelist=("html", "plain"))
    assert html_part is not None
    html_content = html_part.get_content()
    assert ">Okategoriserade intyg</h2>" in html_content
    assert escape(filename) in html_content
    assert "<test>" not in html_content

    attachments = list(message.iter_attachments())
    assert len(attachments) == 1
    assert attachments[0].get_filename() == filename
    _assert_attachment_link(html_content, attachments[0], "Okategoriserade intyg")


def test_share_multiple_pdfs(monkeypatch, user_db):
    _set_mail_env(monkeypatch)
    first_pdf = _store_sample_pdf("delningstest.pdf")
    second_pdf = _store_sample_pdf(
        "extra-intyg.pdf",
        [COURSE_CATEGORIES[1][0], COURSE_CATEGORIES[2][0]],
    )

    sent = {}

    def fake_sender(message, recipient, settings):
        sent["message"] = message
        sent["recipient"] = recipient
        sent["settings"] = settings

    monkeypatch.setattr(email_service, "send_email_message", fake_sender)

    with app.app.test_client() as client:
        _login_default_user(client)
        response = client.post(
            "/share_pdf",
            json={
                "pdf_ids": [first_pdf, second_pdf],
                "recipient_email": "mottagare@example.com",
            },
        )

    assert response.status_code == 200
    data = response.get_json()
    assert data["meddelande"] == "Intygen har skickats via e-post."

    assert sent["recipient"] == "mottagare@example.com"
    message = sent["message"]
    assert message["Subject"].startswith("Delade intyg")

    html_part = message.get_body(preferencelist=("html", "plain"))
    assert html_part is not None
    html_content = html_part.get_content()
    assert "flera intyg" in html_content
    assert "delningstest.pdf" in html_content
    assert "extra-intyg.pdf" in html_content

    attachments = list(message.iter_attachments())
    assert len(attachments) == 2
    filenames = {attachment.get_filename() for attachment in attachments}
    assert filenames == {"delningstest.pdf", "extra-intyg.pdf"}
    content_ids = {attachment["Content-ID"] for attachment in attachments}
    assert None not in content_ids
    assert len(content_ids) == 2
    expected_headings = {
        "delningstest.pdf": COURSE_CATEGORIES[0][1],
        "extra-intyg.pdf": (
            f"{COURSE_CATEGORIES[1][1]} · {COURSE_CATEGORIES[2][1]}"
        ),
    }
    assert len(re.findall(r"<h2\b", html_content)) == len(attachments)
    for attachment in attachments:
        filename = attachment.get_filename()
        assert filename is not None
        _assert_attachment_link(
            html_content,
            attachment,
            expected_headings[filename],
        )
