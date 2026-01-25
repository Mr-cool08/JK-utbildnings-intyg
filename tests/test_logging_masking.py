# Copyright (c) Liam Suorsa
import io
import logging
import os
import sys

import pytest
import werkzeug

if not hasattr(werkzeug, "__version__"):
    werkzeug.__version__ = "3.0.0"

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import app  # noqa: E402
import functions  # noqa: E402
from app import save_pdf_for_user  # noqa: E402
from course_categories import COURSE_CATEGORIES  # noqa: E402
from werkzeug.datastructures import FileStorage  # noqa: E402


def _file_storage(data: bytes, filename: str) -> FileStorage:
    return FileStorage(stream=io.BytesIO(data), filename=filename, content_type="application/pdf")


def _admin_client():
    client = app.app.test_client()
    with client.session_transaction() as sess:
        sess["admin_logged_in"] = True
    return client


@pytest.mark.usefixtures("empty_db")
def test_save_pdf_logging_masks_personnummer(caplog):
    pdf = _file_storage(b"%PDF-1.4 masked", "199001011234_certificate.pdf")
    category = COURSE_CATEGORIES[0][0]
    normalized = functions.normalize_personnummer("19900101-1234")
    hashed = functions.hash_value(normalized)

    caplog.set_level(logging.DEBUG, logger="functions")
    with caplog.at_level(logging.DEBUG, logger="app"):
        save_pdf_for_user("19900101-1234", pdf, [category])

    log_text = caplog.text
    assert "19900101-1234" not in log_text
    assert normalized not in log_text
    assert hashed not in log_text


def test_login_logging_masks_personnummer(user_db, caplog):
    client = app.app.test_client()
    normalized = functions.normalize_personnummer("9001011234")
    hashed = functions.hash_value(normalized)
    with client.session_transaction() as sess:
        sess["csrf_token"] = "test-token"

    caplog.set_level(logging.DEBUG, logger="functions")
    with caplog.at_level(logging.DEBUG, logger="app"):
        response = client.post(
            "/login",
            data={
                "personnummer": "9001011234",
                "password": "secret",
                "csrf_token": "test-token",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    log_text = caplog.text
    assert "9001011234" not in log_text
    assert normalized not in log_text
    assert hashed not in log_text


def test_admin_upload_logging_masks_sensitive_data(empty_db, caplog):
    pdf_bytes = b"%PDF-1.4 admin"
    data = {
        "email": "new.user@example.com",
        "username": "Ny Anvandare",
        "personnummer": "19900101-1234",
        "pdf": (io.BytesIO(pdf_bytes), "upload.pdf"),
        "categories": COURSE_CATEGORIES[0][0],
    }

    normalized_pnr = functions.normalize_personnummer(data["personnummer"])
    hashed_pnr = functions.hash_value(normalized_pnr)
    normalized_email = functions.normalize_email(data["email"])
    hashed_email = functions.hash_value(normalized_email)

    with empty_db.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username=data["username"],
                email=hashed_email,
                password=functions.hash_password("hemligt"),
                personnummer=hashed_pnr,
            )
        )

    caplog.set_level(logging.DEBUG, logger="functions")
    with caplog.at_level(logging.DEBUG, logger="app"):
        with _admin_client() as client:
            response = client.post("/admin", data=data, content_type="multipart/form-data")

    assert response.status_code == 200
    log_text = caplog.text
    assert data["personnummer"] not in log_text
    assert normalized_pnr not in log_text
    assert hashed_pnr not in log_text
    assert data["email"] not in log_text
    assert normalized_email not in log_text
    assert hashed_email not in log_text
