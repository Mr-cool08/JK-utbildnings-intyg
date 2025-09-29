import io

import app
import functions
from course_categories import COURSE_CATEGORIES
from werkzeug.datastructures import MultiDict


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
        "pdf": (io.BytesIO(pdf_bytes), "doc.pdf"),
        # FIX: only slug, not tuple
        "categories": COURSE_CATEGORIES[0][0],
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
    assert rows[0].categories == COURSE_CATEGORIES[0][0]


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
        "pdf": (io.BytesIO(pdf_bytes), "doc.pdf"),
        "categories": COURSE_CATEGORIES[1][0],
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
    assert rows[0].categories == COURSE_CATEGORIES[1][0]


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
        "pdf": (io.BytesIO(pdf_bytes), "doc.pdf"),
        "categories": COURSE_CATEGORIES[0][0],
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
    assert rows[0].categories == COURSE_CATEGORIES[0][0]


def test_admin_upload_multiple_pdfs_with_individual_categories(empty_db):
    engine = empty_db
    email = "multi@example.com"
    username = "Multi"
    personnummer = "19991231-0000"

    assert functions.admin_create_user(email, username, personnummer)

    pdf_first = b"%PDF-1.4 first"
    pdf_second = b"%PDF-1.4 second"

    data = MultiDict(
        (
            ("email", email),
            ("username", username),
            ("personnummer", personnummer),
        )
    )
    data.add("pdf", (io.BytesIO(pdf_first), "first.pdf"))
    data.add("pdf", (io.BytesIO(pdf_second), "second.pdf"))
    data.add("categories", COURSE_CATEGORIES[0][0])
    data.add("categories", COURSE_CATEGORIES[1][0])

    with _admin_client() as client:
        response = client.post("/admin", data=data, content_type="multipart/form-data")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "success"

    personnummer_hash = functions.hash_value(
        functions.normalize_personnummer(personnummer)
    )
    with engine.connect() as conn:
        rows = list(
            conn.execute(
                functions.user_pdfs_table.select().where(
                    functions.user_pdfs_table.c.personnummer == personnummer_hash
                )
            )
        )

    assert len(rows) == 2
    stored = {(row.categories, row.content) for row in rows}
    assert stored == {
        (COURSE_CATEGORIES[0][0], pdf_first),
        (COURSE_CATEGORIES[1][0], pdf_second),
    }


def test_admin_upload_requires_category(empty_db):
    pdf_bytes = b"%PDF-1.4 test"
    data = {
        "email": "new@example.com",
        "username": "Ny",
        "personnummer": "19900101-5678",
        "pdf": (io.BytesIO(pdf_bytes), "doc.pdf"),
    }

    with _admin_client() as client:
        response = client.post("/admin", data=data, content_type="multipart/form-data")

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["status"] == "error"
    assert payload["message"] == "Välj kategori för varje PDF."



