# Copyright (c) Liam Suorsa
import json
from datetime import datetime, timedelta, timezone

import app
import functions
import pytest
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


def test_admin_delete_account_removes_records(empty_db):
    engine = empty_db
    personnummer = "19900101-1234"
    email = "radera@example.com"
    assert functions.admin_create_user(email, "Radera", personnummer)
    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user("StartLosen1!", pnr_hash)
    functions.store_pdf_blob(pnr_hash, "test.pdf", b"%PDF", [COURSE_CATEGORIES[0][0]])
    functions.create_password_reset_token(personnummer, email)

    with engine.begin() as conn:
        application_id = conn.execute(
            functions.application_requests_table.insert().values(
                account_type="standard",
                name="Radera Användare",
                email=email,
                orgnr_normalized="",
                company_name="Radera AB",
                personnummer_hash=pnr_hash,
                status="approved",
            )
        ).inserted_primary_key[0]
        conn.execute(
            functions.company_users_table.insert().values(
                company_id=None,
                role="standard",
                name="Radera Användare",
                email=functions.normalize_email(email),
                created_via_application_id=application_id,
            )
        )
        supervisor_hash = functions.hash_value("handledare@example.com")
        conn.execute(
            functions.supervisor_connections_table.insert().values(
                supervisor_email=supervisor_hash,
                user_personnummer=pnr_hash,
            )
        )
        conn.execute(
            functions.supervisor_link_requests_table.insert().values(
                supervisor_email=supervisor_hash,
                user_personnummer=pnr_hash,
            )
        )

    with _admin_client() as client:
        response = client.post(
            "/admin/api/radera-konto",
            json={"personnummer": personnummer},
        )
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"

    with engine.connect() as conn:
        assert conn.execute(
            functions.users_table.select().where(
                functions.users_table.c.personnummer == pnr_hash
            )
        ).first() is None
        assert conn.execute(
            functions.user_pdfs_table.select().where(
                functions.user_pdfs_table.c.personnummer == pnr_hash
            )
        ).first() is None
        assert conn.execute(
            functions.password_resets_table.select().where(
                functions.password_resets_table.c.personnummer == pnr_hash
            )
        ).first() is None
        assert conn.execute(
            functions.supervisor_connections_table.select().where(
                functions.supervisor_connections_table.c.user_personnummer == pnr_hash
            )
        ).first() is None
        assert conn.execute(
            functions.supervisor_link_requests_table.select().where(
                functions.supervisor_link_requests_table.c.user_personnummer == pnr_hash
            )
        ).first() is None
        assert conn.execute(
            functions.company_users_table.select().where(
                functions.company_users_table.c.created_via_application_id
                == application_id
            )
        ).first() is None
        assert conn.execute(
            functions.application_requests_table.select().where(
                functions.application_requests_table.c.id == application_id
            )
        ).first() is None
        log_entry = conn.execute(
            functions.admin_audit_log_table.select()
        ).first()
        assert log_entry is not None


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


def test_password_reset_for_pending_user(_empty_db):
    personnummer = "19900101-4321"
    email = "pending@example.com"
    assert functions.admin_create_user(email, "Väntande", personnummer)

    with _admin_client() as client:
        response = client.post(
            "/admin/api/skicka-aterstallning",
            json={"personnummer": personnummer, "email": email},
        )
    assert response.status_code == 409
    data = response.get_json()
    assert data["message"] == "Kontot är inte aktiverat ännu."


def test_supervisor_password_reset_flow(empty_db, monkeypatch):
    email = "foretagskonto@example.com"
    assert functions.admin_create_supervisor(email, "Företagskonto")
    email_hash = functions.get_supervisor_email_hash(email)
    assert functions.supervisor_activate_account(email_hash, "StartLosen1!")

    captured = {}

    def _fake_send(to_email, link):
        captured["email"] = to_email
        captured["link"] = link

    monkeypatch.setattr(app.email_service, "send_password_reset_email", _fake_send)

    with _admin_client() as client:
        response = client.post(
            "/admin/api/skicka-aterstallning",
            json={"email": email, "account_type": "foretagskonto"},
        )
    assert response.status_code == 200
    data = response.get_json()
    assert "link" in data
    assert "/foretagskonto/aterstall-losenord/" in data["link"]
    assert captured["link"] == data["link"]

    token = data["link"].rstrip("/").split("/")[-1]
    client = app.app.test_client()
    reset_response = client.post(
        f"/foretagskonto/aterstall-losenord/{token}",
        data={"password": "NyttLosenord123", "confirm": "NyttLosenord123"},
        follow_redirects=False,
    )
    assert reset_response.status_code == 302
    assert functions.verify_supervisor_credentials(email, "NyttLosenord123")


def test_password_reset_token_lifecycle(empty_db):
    personnummer = "19900101-1234"
    email = "token@example.com"
    assert functions.admin_create_user(email, "Token", personnummer)
    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user("StartLosen1!", pnr_hash)

    token = functions.create_password_reset_token(personnummer, email)
    info = functions.get_password_reset(token)
    assert info is not None
    assert info["personnummer"] == pnr_hash
    assert info["email"] == functions.hash_value(
        functions.normalize_email(email)
    )
    assert info["used_at"] is None

    assert functions.reset_password_with_token(token, "NyttLosen1!") is True
    assert functions.check_personnummer_password(personnummer, "NyttLosen1!")
    assert functions.reset_password_with_token(token, "AndraLosen1!") is False


def test_password_reset_token_expires(empty_db):
    personnummer = "19850505-4321"
    email = "expired@example.com"
    assert functions.admin_create_user(email, "Utgången", personnummer)
    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user("StartLosen1!", pnr_hash)

    token = functions.create_password_reset_token(personnummer, email)
    token_hash = functions.hash_value(token)
    expired_time = datetime.now(timezone.utc) - timedelta(days=3)

    with functions.get_engine().begin() as conn:
        conn.execute(
            functions.password_resets_table.update()
            .where(functions.password_resets_table.c.token_hash == token_hash)
            .values(created_at=expired_time)
        )

    assert functions.reset_password_with_token(token, "NyttLosen1!") is False


def test_password_reset_token_requires_matching_user(empty_db):
    personnummer = "19700101-9999"
    email = "missing@example.com"

    assert functions.admin_create_user(email, "Missing", personnummer)
    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user("StartLosen1!", pnr_hash)

    with pytest.raises(ValueError):
        functions.create_password_reset_token(personnummer, "other@example.com")


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
