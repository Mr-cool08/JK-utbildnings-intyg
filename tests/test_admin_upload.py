import io

import app
import functions


def _admin_client():
    client = app.app.test_client()
    with client.session_transaction() as sess:
        sess["admin_logged_in"] = True
    return client


def test_admin_upload_existing_user_only_saves_pdf(empty_db):
    engine = empty_db
    with engine.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Existing",
                email=functions.hash_value("exist@example.com"),
                password=functions.hash_password("secret"),
                personnummer=functions.hash_value("9001011234"),
            )
        )

    pdf_bytes = b"%PDF-1.4 test"
    data = {
        "email": "exist@example.com",
        "username": "Existing",
        "personnummer": "19900101-1234",
        "category": "Intyg",
        "pdf": (io.BytesIO(pdf_bytes), "doc.pdf"),
    }

    with _admin_client() as client:
        response = client.post("/admin", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    assert response.get_json()["status"] == "success"

    pnr_hash = functions.hash_value("9001011234")
    with engine.connect() as conn:
        rows = list(
            conn.execute(
                functions.user_pdfs_table.select().where(
                    functions.user_pdfs_table.c.personnummer == pnr_hash
                )
            )
        )
    assert len(rows) == 1
    assert rows[0].content == pdf_bytes
    assert rows[0].category == "Intyg"


def test_admin_upload_existing_email(empty_db):
    engine = empty_db
    with engine.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Existing",
                email=functions.hash_value("exist@example.com"),
                password=functions.hash_password("secret"),
                personnummer=functions.hash_value("9001011234"),
            )
        )

    pdf_bytes = b"%PDF-1.4 test"
    data = {
        "email": "exist@example.com",
        "username": "Existing",
        "personnummer": "20000101-9999",
        "category": "Kurs",
        "pdf": (io.BytesIO(pdf_bytes), "doc.pdf"),
    }

    with _admin_client() as client:
        response = client.post("/admin", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    assert response.get_json()["status"] == "success"

    new_hash = functions.hash_value(functions.normalize_personnummer("20000101-9999"))
    with engine.connect() as conn:
        rows = list(
            conn.execute(
                functions.user_pdfs_table.select().where(
                    functions.user_pdfs_table.c.personnummer == new_hash
                )
            )
        )
    assert len(rows) == 1
    assert rows[0].content == pdf_bytes
    assert rows[0].category == "Kurs"


def test_admin_upload_pending_user(empty_db):
    engine = empty_db
    email = "pending@example.com"
    username = "Pending"
    personnummer = "19900101-1234"

    assert functions.admin_create_user(email, username, personnummer)

    pdf_bytes = b"%PDF-1.4 pending"
    data = {
        "email": email,
        "username": username,
        "personnummer": personnummer,
        "category": "Rapport",
        "pdf": (io.BytesIO(pdf_bytes), "doc.pdf"),
    }

    with _admin_client() as client:
        response = client.post("/admin", data=data, content_type="multipart/form-data")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "success"
    assert (
        payload["message"]
        == "Användaren väntar redan på aktivering. PDF:er uppladdade."
    )

    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    with engine.connect() as conn:
        rows = list(
            conn.execute(
                functions.user_pdfs_table.select().where(
                    functions.user_pdfs_table.c.personnummer == pnr_hash
                )
            )
        )
    assert len(rows) == 1
    assert rows[0].content == pdf_bytes
    assert rows[0].category == "Rapport"
