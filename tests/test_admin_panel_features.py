import json

import app
import functions
from course_categories import COURSE_CATEGORIES


def _admin_client():
    client = app.app.test_client()
    with client.session_transaction() as sess:
        sess["admin_logged_in"] = True
        sess["admin_username"] = "testadmin"
    return client


def test_admin_delete_pdf_removes_record(empty_db):
    engine = empty_db
    personnummer = "19900101-1234"
    pnr_norm = functions.normalize_personnummer(personnummer)
    pnr_hash = functions.hash_value(pnr_norm)
    first_slug = COURSE_CATEGORIES[0][0]
    pdf_id = functions.store_pdf_blob(pnr_hash, "test.pdf", b"%PDF", [first_slug])
    with _admin_client() as client:
        response = client.post(
            "/admin/api/radera-pdf",
            json={"personnummer": personnummer, "pdf_id": pdf_id},
        )
    assert response.status_code == 200

    with engine.connect() as conn:
        result = conn.execute(
            functions.user_pdfs_table.select().where(
                functions.user_pdfs_table.c.id == pdf_id
            )
        ).first()
        assert result is None
        log_entry = conn.execute(
            functions.admin_audit_log_table.select()
        ).first()
        assert log_entry is not None
        assert log_entry.admin == "testadmin"


def test_admin_update_pdf_categories(empty_db):
    engine = empty_db
    personnummer = "19900101-1234"
    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    slugs = [slug for slug, _ in COURSE_CATEGORIES[:2]]
    pdf_id = functions.store_pdf_blob(pnr_hash, "test.pdf", b"%PDF", [slugs[0]])

    with _admin_client() as client:
        response = client.post(
            "/admin/api/uppdatera-pdf",
            json={
                "personnummer": personnummer,
                "pdf_id": pdf_id,
                "categories": slugs,
            },
        )
    assert response.status_code == 200

    with engine.connect() as conn:
        result = conn.execute(
            functions.user_pdfs_table.select().where(
                functions.user_pdfs_table.c.id == pdf_id
            )
        ).first()
        assert result is not None
        assert set(result.categories.split(",")) == set(slugs)


def test_password_reset_flow(empty_db, monkeypatch):
    personnummer = "19900101-1234"
    email = "user@example.com"
    assert functions.admin_create_user(email, "Användare", personnummer)
    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user("GamlaLosen123", pnr_hash)

    captured = {}

    def _fake_send(to_email, link):
        captured["email"] = to_email
        captured["link"] = link

    monkeypatch.setattr(app.email_service, "send_password_reset_email", _fake_send)

    with _admin_client() as client:
        response = client.post(
            "/admin/api/skicka-aterstallning",
            json={"personnummer": personnummer, "email": email},
        )
    assert response.status_code == 200
    data = response.get_json()
    assert "link" in data
    assert captured["link"] == data["link"]

    token = data["link"].rstrip("/").split("/")[-1]

    client = app.app.test_client()
    reset_response = client.post(
        f"/aterstall-losenord/{token}",
        data={"password": "NyLosenord123", "confirm": "NyLosenord123"},
        follow_redirects=False,
    )
    assert reset_response.status_code == 302
    assert functions.check_personnummer_password(personnummer, "NyLosenord123")


def test_admin_advanced_crud(empty_db):
    engine = empty_db
    with _admin_client() as client:
        schema_resp = client.get("/admin/advanced/api/schema/pending_users")
        assert schema_resp.status_code == 200

        create_payload = {
            "username": "Avancerad",
            "email": functions.hash_value("advanced@example.com"),
            "personnummer": functions.hash_value("199001019999"),
        }
        create_resp = client.post(
            "/admin/advanced/api/rows/pending_users",
            data=json.dumps(create_payload),
            content_type="application/json",
        )
        assert create_resp.status_code == 201
        new_id = create_resp.get_json()["row"]["id"]

        update_resp = client.put(
            f"/admin/advanced/api/rows/pending_users/{new_id}",
            data=json.dumps({"username": "Uppdaterad"}),
            content_type="application/json",
        )
        assert update_resp.status_code == 200

        rows_resp = client.get("/admin/advanced/api/rows/pending_users")
        assert rows_resp.status_code == 200
        rows = rows_resp.get_json()["rows"]
        assert any(row["id"] == new_id for row in rows)

        delete_resp = client.delete(
            f"/admin/advanced/api/rows/pending_users/{new_id}"
        )
        assert delete_resp.status_code == 200

    with engine.connect() as conn:
        log_rows = list(conn.execute(functions.admin_audit_log_table.select()))
        assert len(log_rows) >= 3
