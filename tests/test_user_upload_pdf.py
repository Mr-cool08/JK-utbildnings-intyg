# Copyright (c) Liam Suorsa and Mika Suorsa
from datetime import date
import io

import app
import functions
from course_categories import COURSE_CATEGORIES


def _login_user_and_get_csrf(client):
    with client.session_transaction() as session_data:
        session_data["csrf_token"] = "test-token"
    client.post(
        "/login",
        data={
            "personnummer": "9001011234",
            "password": "secret",
            "csrf_token": "test-token",
        },
    )

    client.get("/dashboard")

    with client.session_transaction() as session_data:
        return session_data.get("csrf_token")


def test_user_can_upload_pdf_from_dashboard(user_db):
    pdf_bytes = b"%PDF-1.4 via upload"

    with app.app.test_client() as client:
        with client.session_transaction() as session_data:
            session_data["csrf_token"] = "test-token"
        client.post(
            "/login",
            data={
                "personnummer": "9001011234",
                "password": "secret",
                "csrf_token": "test-token",
            },
        )

        client.get("/dashboard")

        with client.session_transaction() as session_data:
            csrf_token = session_data.get("csrf_token")

        response = client.post(
            "/dashboard/ladda-upp",
            data={
                "category": COURSE_CATEGORIES[1][0],
                "certificate": (io.BytesIO(pdf_bytes), "intyg.pdf"),
                "csrf_token": csrf_token,
                "note": "Min anteckning",
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    assert response.status_code == 200

    personnummer_hash = functions.hash_value("9001011234")
    with functions.get_engine().connect() as conn:
        row = conn.execute(
            functions.user_pdfs_table.select().where(
                functions.user_pdfs_table.c.personnummer == personnummer_hash
            )
        ).first()

    assert row is not None
    assert row.filename.endswith(".pdf")
    assert row.note == "Min anteckning"
    assert row.expires_on is None

    filename, stored_content = functions.get_pdf_content(personnummer_hash, row.id)
    assert filename == row.filename
    assert stored_content == pdf_bytes


def test_user_can_upload_pdf_with_exact_expiry_date(user_db):
    pdf_bytes = b"%PDF-1.4 via upload"

    with app.app.test_client() as client:
        with client.session_transaction() as session_data:
            session_data["csrf_token"] = "test-token"
        client.post(
            "/login",
            data={
                "personnummer": "9001011234",
                "password": "secret",
                "csrf_token": "test-token",
            },
        )

        client.get("/dashboard")

        with client.session_transaction() as session_data:
            csrf_token = session_data.get("csrf_token")

        response = client.post(
            "/dashboard/ladda-upp",
            data={
                "category": COURSE_CATEGORIES[1][0],
                "certificate": (io.BytesIO(pdf_bytes), "intyg.pdf"),
                "csrf_token": csrf_token,
                "expiry_mode": "date",
                "expiry_date": "2027-05-27",
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    assert response.status_code == 200

    personnummer_hash = functions.hash_value("9001011234")
    with functions.get_engine().connect() as conn:
        row = conn.execute(
            functions.user_pdfs_table.select().where(
                functions.user_pdfs_table.c.personnummer == personnummer_hash
            )
        ).first()

    assert row is not None
    assert row.expires_on == date(2027, 5, 27)


def test_user_upload_rejects_too_long_note(user_db):
    pdf_bytes = b"%PDF-1.4 via upload"

    with app.app.test_client() as client:
        with client.session_transaction() as session_data:
            session_data["csrf_token"] = "test-token"
        client.post(
            "/login",
            data={
                "personnummer": "9001011234",
                "password": "secret",
                "csrf_token": "test-token",
            },
        )

        client.get("/dashboard")

        with client.session_transaction() as session_data:
            csrf_token = session_data.get("csrf_token")

        response = client.post(
            "/dashboard/ladda-upp",
            data={
                "category": COURSE_CATEGORIES[1][0],
                "certificate": (io.BytesIO(pdf_bytes), "intyg.pdf"),
                "note": "a" * 301,
                "csrf_token": csrf_token,
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    assert response.status_code == 200
    assert "Anteckningen får vara högst 300 tecken.".encode("utf-8") in response.data


def test_resolve_certificate_expiry_supports_combined_duration_inputs():
    today = date(2026, 1, 31)

    assert app._resolve_certificate_expiry("none", "", "", "", today=today) is None
    assert app._resolve_certificate_expiry("duration", "", "1", "0", today=today) == date(
        2026,
        2,
        28,
    )
    assert app._resolve_certificate_expiry("duration", "", "6", "2", today=today) == date(
        2028,
        7,
        31,
    )


def test_user_upload_rejects_past_expiry_date(user_db):
    pdf_bytes = b"%PDF-1.4 via upload"

    with app.app.test_client() as client:
        with client.session_transaction() as session_data:
            session_data["csrf_token"] = "test-token"
        client.post(
            "/login",
            data={
                "personnummer": "9001011234",
                "password": "secret",
                "csrf_token": "test-token",
            },
        )

        client.get("/dashboard")

        with client.session_transaction() as session_data:
            csrf_token = session_data.get("csrf_token")

        response = client.post(
            "/dashboard/ladda-upp",
            data={
                "category": COURSE_CATEGORIES[1][0],
                "certificate": (io.BytesIO(pdf_bytes), "intyg.pdf"),
                "csrf_token": csrf_token,
                "expiry_mode": "date",
                "expiry_date": "2020-01-01",
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    assert response.status_code == 200
    assert "Utgångsdatum kan inte vara tidigare än idag.".encode("utf-8") in response.data


def test_user_upload_rejects_request_over_global_limit(user_db, monkeypatch):
    pdf_bytes = b"%PDF-1.4 via upload"

    with app.app.test_client() as client:
        with client.session_transaction() as session_data:
            session_data["csrf_token"] = "test-token"
        client.post(
            "/login",
            data={
                "personnummer": "9001011234",
                "password": "secret",
                "csrf_token": "test-token",
            },
        )

        client.get("/dashboard")

        with client.session_transaction() as session_data:
            csrf_token = session_data.get("csrf_token")

        monkeypatch.setitem(app.app.config, "MAX_CONTENT_LENGTH", 1)
        response = client.post(
            "/dashboard/ladda-upp",
            data={
                "category": COURSE_CATEGORIES[1][0],
                "certificate": (io.BytesIO(pdf_bytes), "intyg.pdf"),
                "csrf_token": csrf_token,
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    assert response.status_code == 200
    assert "Uppladdningen är för stor. Max 50 MB tillåts.".encode("utf-8") in response.data


def test_user_can_update_pdf_metadata_from_dashboard(user_db):
    personnummer_hash = functions.hash_value("9001011234")
    pdf_content = b"%PDF-1.4 redigera"
    pdf_id = functions.store_pdf_blob(
        personnummer_hash,
        "1717171717_gammalt_intyg.pdf",
        pdf_content,
        [COURSE_CATEGORIES[0][0]],
    )

    with app.app.test_client() as client:
        csrf_token = _login_user_and_get_csrf(client)

        response = client.post(
            f"/dashboard/intyg/{pdf_id}/uppdatera",
            json={
                "csrf_token": csrf_token,
                "filename": "Nytt intyg.pdf",
                "note": "Uppdaterad anteckning",
                "expiry_mode": "date",
                "expiry_date": "2027-05-27",
                "expiry_years": "",
                "expiry_months": "",
            },
        )

        download_response = client.get(f"/my_pdfs/{pdf_id}")

    assert response.status_code == 200
    data = response.get_json()
    assert data["meddelande"] == "Intyget har uppdaterats."
    assert data["data"]["filename"] == "Nytt_intyg.pdf"
    assert data["data"]["note"] == "Uppdaterad anteckning"
    assert data["data"]["expires_on"] == "2027-05-27"

    with functions.get_engine().connect() as conn:
        row = conn.execute(
            functions.user_pdfs_table.select().where(functions.user_pdfs_table.c.id == pdf_id)
        ).first()

    assert row is not None
    assert row.filename == "Nytt_intyg.pdf"
    assert row.note == "Uppdaterad anteckning"
    assert row.expires_on == date(2027, 5, 27)

    filename, stored_content = functions.get_pdf_content(personnummer_hash, pdf_id)
    assert filename == "Nytt_intyg.pdf"
    assert stored_content == pdf_content
    assert download_response.headers["Content-Disposition"] == 'attachment; filename="Nytt_intyg.pdf"'


def test_user_can_clear_pdf_expiry_date_from_dashboard(user_db):
    personnummer_hash = functions.hash_value("9001011234")
    pdf_id = functions.store_pdf_blob(
        personnummer_hash,
        "expires.pdf",
        b"%PDF-1.4 expires",
        [COURSE_CATEGORIES[0][0]],
        note="Behåll anteckning",
        expires_on=date(2027, 5, 27),
    )

    with app.app.test_client() as client:
        csrf_token = _login_user_and_get_csrf(client)

        response = client.post(
            f"/dashboard/intyg/{pdf_id}/uppdatera",
            json={
                "csrf_token": csrf_token,
                "filename": "expires.pdf",
                "note": "Behåll anteckning",
                "expiry_mode": "none",
                "expiry_date": "",
                "expiry_years": "",
                "expiry_months": "",
            },
        )

    assert response.status_code == 200
    data = response.get_json()
    assert data["data"]["expires_on"] is None

    with functions.get_engine().connect() as conn:
        row = conn.execute(
            functions.user_pdfs_table.select().where(functions.user_pdfs_table.c.id == pdf_id)
        ).first()

    assert row is not None
    assert row.expires_on is None


def test_user_update_pdf_rejects_invalid_filename(user_db):
    personnummer_hash = functions.hash_value("9001011234")
    pdf_id = functions.store_pdf_blob(
        personnummer_hash,
        "gammalt.pdf",
        b"%PDF-1.4 invalid-name",
        [COURSE_CATEGORIES[0][0]],
    )

    with app.app.test_client() as client:
        csrf_token = _login_user_and_get_csrf(client)

        response = client.post(
            f"/dashboard/intyg/{pdf_id}/uppdatera",
            json={
                "csrf_token": csrf_token,
                "filename": "!!!",
                "note": "",
                "expiry_mode": "none",
                "expiry_date": "",
                "expiry_years": "",
                "expiry_months": "",
            },
        )

    assert response.status_code == 400
    assert response.get_json()["fel"] == "Intygsnamnet innehåller inga tillåtna tecken."


def test_user_update_pdf_rejects_too_long_note(user_db):
    personnummer_hash = functions.hash_value("9001011234")
    pdf_id = functions.store_pdf_blob(
        personnummer_hash,
        "gammalt.pdf",
        b"%PDF-1.4 long-note",
        [COURSE_CATEGORIES[0][0]],
    )

    with app.app.test_client() as client:
        csrf_token = _login_user_and_get_csrf(client)

        response = client.post(
            f"/dashboard/intyg/{pdf_id}/uppdatera",
            json={
                "csrf_token": csrf_token,
                "filename": "gammalt",
                "note": "a" * 301,
                "expiry_mode": "none",
                "expiry_date": "",
                "expiry_years": "",
                "expiry_months": "",
            },
        )

    assert response.status_code == 400
    assert response.get_json()["fel"] == "Anteckningen får vara högst 300 tecken."


def test_user_update_pdf_rejects_past_expiry_date(user_db):
    personnummer_hash = functions.hash_value("9001011234")
    pdf_id = functions.store_pdf_blob(
        personnummer_hash,
        "gammalt.pdf",
        b"%PDF-1.4 past-expiry",
        [COURSE_CATEGORIES[0][0]],
    )

    with app.app.test_client() as client:
        csrf_token = _login_user_and_get_csrf(client)

        response = client.post(
            f"/dashboard/intyg/{pdf_id}/uppdatera",
            json={
                "csrf_token": csrf_token,
                "filename": "gammalt",
                "note": "",
                "expiry_mode": "date",
                "expiry_date": "2020-01-01",
                "expiry_years": "",
                "expiry_months": "",
            },
        )

    assert response.status_code == 400
    assert response.get_json()["fel"] == "Utgångsdatum kan inte vara tidigare än idag."


def test_user_update_pdf_requires_valid_csrf(user_db):
    personnummer_hash = functions.hash_value("9001011234")
    pdf_id = functions.store_pdf_blob(
        personnummer_hash,
        "gammalt.pdf",
        b"%PDF-1.4 csrf",
        [COURSE_CATEGORIES[0][0]],
    )

    with app.app.test_client() as client:
        _login_user_and_get_csrf(client)

        response = client.post(
            f"/dashboard/intyg/{pdf_id}/uppdatera",
            json={
                "csrf_token": "fel-token",
                "filename": "gammalt",
                "note": "",
                "expiry_mode": "none",
                "expiry_date": "",
                "expiry_years": "",
                "expiry_months": "",
            },
        )

    assert response.status_code == 400
    assert response.get_json()["fel"] == app.CSRF_EXPIRED_MESSAGE


def test_user_update_pdf_requires_login(user_db):
    personnummer_hash = functions.hash_value("9001011234")
    pdf_id = functions.store_pdf_blob(
        personnummer_hash,
        "gammalt.pdf",
        b"%PDF-1.4 auth",
        [COURSE_CATEGORIES[0][0]],
    )

    with app.app.test_client() as client:
        response = client.post(
            f"/dashboard/intyg/{pdf_id}/uppdatera",
            json={
                "csrf_token": "saknas",
                "filename": "gammalt",
                "note": "",
                "expiry_mode": "none",
                "expiry_date": "",
                "expiry_years": "",
                "expiry_months": "",
            },
        )

    assert response.status_code == 401
    assert response.get_json()["fel"] == "Du måste vara inloggad för att uppdatera intyg."


def test_user_cannot_update_another_users_pdf(user_db):
    other_hash = functions.hash_value("0001011234")
    pdf_id = functions.store_pdf_blob(
        other_hash,
        "annans-intyg.pdf",
        b"%PDF-1.4 foreign",
        [COURSE_CATEGORIES[0][0]],
    )

    with app.app.test_client() as client:
        csrf_token = _login_user_and_get_csrf(client)

        response = client.post(
            f"/dashboard/intyg/{pdf_id}/uppdatera",
            json={
                "csrf_token": csrf_token,
                "filename": "mitt-intyg",
                "note": "Test",
                "expiry_mode": "none",
                "expiry_date": "",
                "expiry_years": "",
                "expiry_months": "",
            },
        )

    assert response.status_code == 404
    assert response.get_json()["fel"] == "Intyget kunde inte hittas."
