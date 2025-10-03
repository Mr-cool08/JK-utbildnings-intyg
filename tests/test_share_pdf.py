import app
import functions
import pytest

from course_categories import COURSE_CATEGORIES
from services import email as email_service


def _login_default_user(client):
    return client.post(
        "/login",
        data={"personnummer": "9001011234", "password": "secret"},
        follow_redirects=False,
    )


def _store_sample_pdf(filename: str = "delningstest.pdf") -> int:
    personnummer_hash = functions.hash_value("9001011234")
    return functions.store_pdf_blob(
        personnummer_hash,
        filename,
        b"%PDF-1.4 sample",
        [COURSE_CATEGORIES[0][0]],
    )


def _set_mail_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("smtp_server", "smtp.example.com")
    monkeypatch.setenv("smtp_port", "587")
    monkeypatch.setenv("smtp_user", "info@example.com")
    monkeypatch.setenv("smtp_password", "hemligt")
    monkeypatch.setenv("smtp_timeout", "10")


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

    html_part = message.get_body(preferencelist=("html", "plain"))
    assert html_part is not None
    assert "delat ett intyg" in html_part.get_content()

    attachments = list(message.iter_attachments())
    assert len(attachments) == 1
    attachment = attachments[0]
    assert attachment.get_filename() == "delningstest.pdf"
    assert attachment.get_content_type() == "application/pdf"


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


def test_share_multiple_pdfs(monkeypatch, user_db):
    _set_mail_env(monkeypatch)
    first_pdf = _store_sample_pdf("delningstest.pdf")
    second_pdf = _store_sample_pdf("extra-intyg.pdf")

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
    filenames = {attachment.get_filename() for attachment in attachments}
    assert filenames == {"delningstest.pdf", "extra-intyg.pdf"}
