import io
import sqlite3
import app
import functions


def test_admin_upload_existing_user_only_saves_pdf(empty_db, tmp_path, monkeypatch):
    monkeypatch.setitem(app.app.config, "UPLOAD_ROOT", tmp_path)

    conn = sqlite3.connect(empty_db)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, password, personnummer) VALUES (?, ?, ?, ?)",
        (
            "Existing",
            functions.hash_value("exist@example.com"),
            functions.hash_password("secret"),
            functions.hash_value("199001011234"),
        ),
    )
    conn.commit()
    conn.close()

    pdf_bytes = b"%PDF-1.4 test"
    data = {
        "email": "exist@example.com",
        "username": "Existing",
        "personnummer": "19900101-1234",
        "pdf": (io.BytesIO(pdf_bytes), "doc.pdf"),
    }

    with app.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["admin_logged_in"] = True
        response = client.post("/admin", data=data, content_type="multipart/form-data")
        assert response.status_code == 200
        assert response.get_json()["status"] == "success"


def test_admin_upload_existing_email(tmp_path, empty_db, monkeypatch):
    monkeypatch.setitem(app.app.config, "UPLOAD_ROOT", tmp_path)

    conn = sqlite3.connect(empty_db)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, password, personnummer) VALUES (?, ?, ?, ?)",
        (
            "Existing",
            functions.hash_value("exist@example.com"),
            functions.hash_password("secret"),
            functions.hash_value("199001011234"),
        ),
    )
    conn.commit()
    conn.close()

    pdf_bytes = b"%PDF-1.4 test"
    data = {
        "email": "exist@example.com",
        "username": "Existing",
        "personnummer": "20000101-9999",
        "pdf": (io.BytesIO(pdf_bytes), "doc.pdf"),
    }

    with app.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["admin_logged_in"] = True
        response = client.post("/admin", data=data, content_type="multipart/form-data")
        assert response.status_code == 200
        assert response.get_json()["status"] == "success"

    pnr_hash = functions.hash_value(functions.normalize_personnummer("20000101-9999"))
    saved_dir = tmp_path / pnr_hash
    assert saved_dir.exists()
    assert any(p.suffix == ".pdf" for p in saved_dir.iterdir())
