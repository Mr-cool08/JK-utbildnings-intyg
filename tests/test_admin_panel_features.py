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
        sess["csrf_token"] = "test-token"
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


def test_admin_delete_account_removes_records(empty_db, monkeypatch):
    engine = empty_db
    personnummer = "19900101-1234"
    email = "radera@example.com"
    assert functions.admin_create_user(email, "Radera", personnummer)
    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user("StartLosen1!", pnr_hash)
    functions.store_pdf_blob(pnr_hash, "test.pdf", b"%PDF", [COURSE_CATEGORIES[0][0]])
    functions.create_password_reset_token(personnummer, email)

    with engine.connect() as conn:
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
        conn.commit()

    def _fake_send_account_deletion_email(to_email, _username=None):
        assert to_email == email

    monkeypatch.setattr(
        app.email_service,
        "send_account_deletion_email",
        _fake_send_account_deletion_email,
    )

    with _admin_client() as client:
        response = client.post(
            "/admin/api/radera-konto",
            json={
                "personnummer": personnummer,
                "email": email,
                "csrf_token": "test-token",
            },
            headers={"X-CSRF-Token": "test-token"},
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


def test_admin_delete_account_without_email(empty_db, monkeypatch):
    personnummer = "19910101-1111"
    email = "utan-notis@example.com"
    assert functions.admin_create_user(email, "Utan Notis", personnummer)
    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user("StartLosen1!", pnr_hash)

    called = {"sent": False}

    def _fake_send_account_deletion_email(_to_email, _username=None):
        called["sent"] = True

    monkeypatch.setattr(
        app.email_service,
        "send_account_deletion_email",
        _fake_send_account_deletion_email,
    )

    with _admin_client() as client:
        response = client.post(
            "/admin/api/radera-konto",
            json={
                "personnummer": personnummer,
                "csrf_token": "test-token",
            },
            headers={"X-CSRF-Token": "test-token"},
        )
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert called["sent"] is False

    with empty_db.connect() as conn:
        assert conn.execute(
            functions.users_table.select().where(
                functions.users_table.c.personnummer == pnr_hash
            )
        ).first() is None


def test_admin_guide_renders_markdown():
    with _admin_client() as client:
        response = client.get("/admin/guide")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "<h1>Hur man administrerar systemet</h1>" in body


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


def test_admin_list_accounts_returns_active_and_pending(empty_db):
    _ = empty_db
    personnummer_active = "19900101-1234"
    email_active = "aktiv@example.com"
    assert functions.admin_create_user(email_active, "Aktiv", personnummer_active)
    pnr_active_hash = functions.hash_value(
        functions.normalize_personnummer(personnummer_active)
    )
    assert functions.user_create_user("StartLosen1!", pnr_active_hash)

    personnummer_pending = "19900202-2345"
    email_pending = "vantande@example.com"
    assert functions.admin_create_user(email_pending, "Väntande", personnummer_pending)
    pnr_pending_hash = functions.hash_value(
        functions.normalize_personnummer(personnummer_pending)
    )

    with _admin_client() as client:
        response = client.get("/admin/api/konton/lista")
    assert response.status_code == 200
    data = response.get_json()
    hashes = {entry["personnummer_hash"]: entry["status"] for entry in data["data"]}
    assert hashes[pnr_active_hash] == "active"
    assert hashes[pnr_pending_hash] == "pending"


def test_admin_update_account_updates_record(empty_db):
    personnummer = "19900303-3456"
    email = "uppdatera@example.com"
    assert functions.admin_create_user(email, "Uppdatera", personnummer)
    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user("StartLosen1!", pnr_hash)

    new_email = "ny@example.com"
    new_name = "Nytt Namn"
    with _admin_client() as client:
        response = client.post(
            "/admin/api/konton/uppdatera",
            json={
                "personnummer": personnummer,
                "email": new_email,
                "username": new_name,
                "csrf_token": "test-token",
            },
            headers={"X-CSRF-Token": "test-token"},
        )
    assert response.status_code == 200

    with empty_db.connect() as conn:
        row = conn.execute(
            functions.users_table.select().where(
                functions.users_table.c.personnummer == pnr_hash
            )
        ).first()
        assert row is not None
        assert row.username == new_name
        assert row.email == functions.hash_value(functions.normalize_email(new_email))


def test_admin_remove_supervisor_connection(empty_db):
    personnummer = "19900404-4567"
    email = "konto@example.com"
    assert functions.admin_create_user(email, "Konto", personnummer)
    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user("StartLosen1!", pnr_hash)

    supervisor_email = "foretag@example.com"
    supervisor_hash = functions.hash_value(functions.normalize_email(supervisor_email))
    orgnr = "556966-8337"
    with empty_db.begin() as conn:
        company_id = conn.execute(
            functions.companies_table.insert().values(
                name="Testbolag AB",
                orgnr=functions.validate_orgnr(orgnr),
            )
        ).inserted_primary_key[0]
        conn.execute(
            functions.company_users_table.insert().values(
                company_id=company_id,
                role="foretagskonto",
                name="Testbolag AB",
                email=functions.normalize_email(supervisor_email),
            )
        )
        conn.execute(
            functions.supervisors_table.insert().values(
                email=supervisor_hash,
                name="Testbolag AB",
                password=functions.hash_password("Losen123!"),
            )
        )
        conn.execute(
            functions.supervisor_connections_table.insert().values(
                supervisor_email=supervisor_hash,
                user_personnummer=pnr_hash,
            )
        )

    with _admin_client() as client:
        response = client.post(
            "/admin/api/foretagskonto/ta-bort",
            json={"orgnr": orgnr, "personnummer": personnummer},
        )
    assert response.status_code == 403

    with _admin_client() as client:
        response = client.post(
            "/admin/api/foretagskonto/ta-bort",
            json={
                "orgnr": orgnr,
                "personnummer": personnummer,
                "csrf_token": "test-token",
            },
            headers={"X-CSRF-Token": "test-token"},
        )
    assert response.status_code == 200

    with empty_db.connect() as conn:
        assert conn.execute(
            functions.supervisor_connections_table.select().where(
                functions.supervisor_connections_table.c.user_personnummer == pnr_hash
            )
        ).first() is None


def test_admin_change_supervisor_connection(empty_db):
    personnummer = "19900505-5678"
    email = "flytta@example.com"
    assert functions.admin_create_user(email, "Flytta", personnummer)
    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user("StartLosen1!", pnr_hash)

    orgnr_old = "556966-8337"
    orgnr_new = "556677-8899"
    supervisor_old_email = "old@example.com"
    supervisor_new_email = "new@example.com"
    supervisor_old_hash = functions.hash_value(
        functions.normalize_email(supervisor_old_email)
    )
    supervisor_new_hash = functions.hash_value(
        functions.normalize_email(supervisor_new_email)
    )

    with empty_db.begin() as conn:
        old_company_id = conn.execute(
            functions.companies_table.insert().values(
                name="Gammalt AB",
                orgnr=functions.validate_orgnr(orgnr_old),
            )
        ).inserted_primary_key[0]
        new_company_id = conn.execute(
            functions.companies_table.insert().values(
                name="Nytt AB",
                orgnr=functions.validate_orgnr(orgnr_new),
            )
        ).inserted_primary_key[0]
        conn.execute(
            functions.company_users_table.insert().values(
                company_id=old_company_id,
                role="foretagskonto",
                name="Gammalt AB",
                email=functions.normalize_email(supervisor_old_email),
            )
        )
        conn.execute(
            functions.company_users_table.insert().values(
                company_id=new_company_id,
                role="foretagskonto",
                name="Nytt AB",
                email=functions.normalize_email(supervisor_new_email),
            )
        )
        conn.execute(
            functions.supervisors_table.insert().values(
                email=supervisor_old_hash,
                name="Gammalt AB",
                password=functions.hash_password("Losen123!"),
            )
        )
        conn.execute(
            functions.supervisors_table.insert().values(
                email=supervisor_new_hash,
                name="Nytt AB",
                password=functions.hash_password("Losen123!"),
            )
        )
        conn.execute(
            functions.supervisor_connections_table.insert().values(
                supervisor_email=supervisor_old_hash,
                user_personnummer=pnr_hash,
            )
        )

    with _admin_client() as client:
        response = client.post(
            "/admin/api/foretagskonto/uppdatera-koppling",
            json={
                "from_orgnr": orgnr_old,
                "to_orgnr": orgnr_new,
                "personnummer": personnummer,
            },
        )
    assert response.status_code == 403

    with _admin_client() as client:
        response = client.post(
            "/admin/api/foretagskonto/uppdatera-koppling",
            json={
                "from_orgnr": orgnr_old,
                "to_orgnr": orgnr_new,
                "personnummer": personnummer,
                "csrf_token": "test-token",
            },
            headers={"X-CSRF-Token": "test-token"},
        )
    assert response.status_code == 200

    with empty_db.connect() as conn:
        old_link = conn.execute(
            functions.supervisor_connections_table.select().where(
                functions.supervisor_connections_table.c.supervisor_email
                == supervisor_old_hash
            )
        ).first()
        new_link = conn.execute(
            functions.supervisor_connections_table.select().where(
                functions.supervisor_connections_table.c.supervisor_email
                == supervisor_new_hash
            )
        ).first()
        assert old_link is None
        assert new_link is not None


def test_admin_remove_supervisor_connection_by_hash(empty_db):
    personnummer = "19910606-6789"
    email = "hashkonto@example.com"
    assert functions.admin_create_user(email, "Hashkonto", personnummer)
    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user("StartLosen1!", pnr_hash)

    supervisor_email = "kopplad@example.com"
    supervisor_hash = functions.hash_value(functions.normalize_email(supervisor_email))
    orgnr = "556123-4567"
    with empty_db.begin() as conn:
        company_id = conn.execute(
            functions.companies_table.insert().values(
                name="Hashbolag AB",
                orgnr=functions.validate_orgnr(orgnr),
            )
        ).inserted_primary_key[0]
        conn.execute(
            functions.company_users_table.insert().values(
                company_id=company_id,
                role="foretagskonto",
                name="Hashbolag AB",
                email=functions.normalize_email(supervisor_email),
            )
        )
        conn.execute(
            functions.supervisors_table.insert().values(
                email=supervisor_hash,
                name="Hashbolag AB",
                password=functions.hash_password("Losen123!"),
            )
        )
        conn.execute(
            functions.supervisor_connections_table.insert().values(
                supervisor_email=supervisor_hash,
                user_personnummer=pnr_hash,
            )
        )

    with _admin_client() as client:
        response = client.post(
            "/admin/api/foretagskonto/ta-bort",
            json={
                "orgnr": orgnr,
                "personnummer_hash": pnr_hash,
                "csrf_token": "test-token",
            },
            headers={"X-CSRF-Token": "test-token"},
        )
    assert response.status_code == 200

    with empty_db.connect() as conn:
        assert conn.execute(
            functions.supervisor_connections_table.select().where(
                functions.supervisor_connections_table.c.user_personnummer == pnr_hash
            )
        ).first() is None


def test_admin_delete_supervisor_account(empty_db):
    orgnr = "556966-8337"
    supervisor_email = "radera-foretag@example.com"
    supervisor_hash = functions.hash_value(functions.normalize_email(supervisor_email))
    personnummer = "19920202-2222"
    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))

    with empty_db.begin() as conn:
        company_id = conn.execute(
            functions.companies_table.insert().values(
                name="Radera AB",
                orgnr=functions.validate_orgnr(orgnr),
            )
        ).inserted_primary_key[0]
        conn.execute(
            functions.company_users_table.insert().values(
                company_id=company_id,
                role="foretagskonto",
                name="Radera AB",
                email=functions.normalize_email(supervisor_email),
            )
        )
        conn.execute(
            functions.supervisors_table.insert().values(
                email=supervisor_hash,
                name="Radera AB",
                password=functions.hash_password("Losen123!"),
            )
        )
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
        conn.execute(
            functions.supervisor_password_resets_table.insert().values(
                email=supervisor_hash,
                token_hash=functions.hash_value("reset-token"),
            )
        )

    with _admin_client() as client:
        response = client.post(
            "/admin/api/foretagskonto/radera",
            json={"orgnr": orgnr, "csrf_token": "test-token"},
            headers={"X-CSRF-Token": "test-token"},
        )
    assert response.status_code == 200

    with empty_db.connect() as conn:
        assert conn.execute(
            functions.company_users_table.select().where(
                functions.company_users_table.c.company_id == company_id,
                functions.company_users_table.c.role == "foretagskonto",
            )
        ).first() is None
        assert conn.execute(
            functions.supervisors_table.select().where(
                functions.supervisors_table.c.email == supervisor_hash
            )
        ).first() is None
        assert conn.execute(
            functions.supervisor_connections_table.select().where(
                functions.supervisor_connections_table.c.supervisor_email
                == supervisor_hash
            )
        ).first() is None
        assert conn.execute(
            functions.supervisor_link_requests_table.select().where(
                functions.supervisor_link_requests_table.c.supervisor_email
                == supervisor_hash
            )
        ).first() is None
        assert conn.execute(
            functions.supervisor_password_resets_table.select().where(
                functions.supervisor_password_resets_table.c.email
                == supervisor_hash
            )
        ).first() is None
        assert conn.execute(
            functions.companies_table.select().where(
                functions.companies_table.c.id == company_id
            )
        ).first() is None


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


_ADMIN_PROTECTED_ENDPOINTS = [
    ("get", "/admin/guide", 302),
    ("get", "/admin/konton", 302),
    ("get", "/admin/intyg", 302),
    ("get", "/admin/foretagskonto", 302),
    ("get", "/admin/ansokningar", 302),
    ("post", "/admin/ansokningar", 302),
    ("get", "/admin/fakturering", 302),
    ("get", "/admin/api/ansokningar", 403),
    ("get", "/admin/api/ansokningar/1", 403),
    ("get", "/admin/api/ansokningar/2", 403),
    ("post", "/admin/api/ansokningar/1/godkann", 403),
    ("post", "/admin/api/ansokningar/2/godkann", 403),
    ("post", "/admin/api/ansokningar/1/avslag", 403),
    ("post", "/admin/api/ansokningar/2/avslag", 403),
    ("post", "/admin/api/oversikt", 403),
    ("post", "/admin/api/klientlogg", 403),
    ("post", "/admin/api/radera-pdf", 403),
    ("post", "/admin/api/radera-konto", 403),
    ("get", "/admin/api/konton/lista", 403),
    ("post", "/admin/api/konton/uppdatera", 403),
    ("post", "/admin/api/konton/losenord-status", 403),
    ("post", "/admin/api/konton/skapa-losenordslank", 403),
    ("post", "/admin/api/uppdatera-pdf", 403),
    ("post", "/admin/api/skicka-aterstallning", 403),
    ("post", "/admin/api/foretagskonto/skapa", 403),
    ("post", "/admin/api/foretagskonto/koppla", 403),
    ("post", "/admin/api/foretagskonto/oversikt", 403),
    ("post", "/admin/api/foretagskonto/ta-bort", 403),
    ("post", "/admin/api/foretagskonto/uppdatera-koppling", 403),
    ("post", "/admin/api/foretagskonto/radera", 403),
    ("get", "/admin/avancerat", 302),
    ("get", "/admin/advanced/api/schema/pending_users", 403),
    ("get", "/admin/advanced/api/schema/users", 403),
    ("get", "/admin/advanced/api/rows/pending_users", 403),
    ("get", "/admin/advanced/api/rows/users", 403),
    ("post", "/admin/advanced/api/rows/pending_users", 403),
    ("post", "/admin/advanced/api/rows/users", 403),
    ("put", "/admin/advanced/api/rows/pending_users/1", 403),
    ("put", "/admin/advanced/api/rows/users/1", 403),
    ("delete", "/admin/advanced/api/rows/pending_users/1", 403),
    ("delete", "/admin/advanced/api/rows/users/1", 403),
    ("get", "/admin/api/ansokningar/99", 403),
    ("post", "/admin/api/ansokningar/99/godkann", 403),
    ("post", "/admin/api/ansokningar/99/avslag", 403),
    ("put", "/admin/advanced/api/rows/pending_users/99", 403),
    ("delete", "/admin/advanced/api/rows/pending_users/99", 403),
    ("put", "/admin/advanced/api/rows/users/99", 403),
    ("delete", "/admin/advanced/api/rows/users/99", 403),
    ("get", "/admin/api/ansokningar/12345", 403),
    ("post", "/admin/api/ansokningar/12345/godkann", 403),
    ("post", "/admin/api/ansokningar/12345/avslag", 403),
    ("get", "/admin/advanced/api/schema/company_users", 403),
]


def _call_with_method(client, method, path):
    request_method = getattr(client, method)
    return request_method(path)


def test_admin_protected_endpoints_count():
    assert len(_ADMIN_PROTECTED_ENDPOINTS) == 52


@pytest.mark.parametrize("method,path,expected_status", _ADMIN_PROTECTED_ENDPOINTS)
def test_admin_routes_require_login(method, path, expected_status):
    client = app.app.test_client()
    response = _call_with_method(client, method, path)
    assert response.status_code == expected_status


def test_admin_password_status_pending_account(empty_db):
    personnummer = "19900101-9999"
    email = "pending@example.com"
    assert functions.admin_create_user(email, "Väntande", personnummer)

    with _admin_client() as client:
        response = client.post(
            "/admin/api/konton/losenord-status",
            json={
                "personnummer": personnummer,
                "email": email,
                "csrf_token": "test-token",
            },
            headers={"X-CSRF-Token": "test-token"},
        )

    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert data["data"]["password_created"] is False
    assert data["data"]["status"] == "pending"


def test_admin_send_create_password_link(empty_db, monkeypatch):
    personnummer = "19900202-2222"
    email = "NyttKonto@Example.COM"
    assert functions.admin_create_user(email, "Nytt Konto", personnummer)

    sent = {}

    def _fake_send_creation_email(to_email, link):
        sent["to_email"] = to_email
        sent["link"] = link

    monkeypatch.setattr(app.email_service, "send_creation_email", _fake_send_creation_email)

    with _admin_client() as client:
        response = client.post(
            "/admin/api/konton/skapa-losenordslank",
            json={
                "personnummer": personnummer,
                "email": email,
                "csrf_token": "test-token",
            },
            headers={"X-CSRF-Token": "test-token"},
        )

    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert "create_user" in data["link"]
    assert sent["to_email"] == functions.normalize_email(email)
    assert sent["link"] == data["link"]


def test_admin_password_status_active_account(empty_db):
    personnummer = "19900606-6666"
    email = "active@example.com"
    assert functions.admin_create_user(email, "Aktiv Användare", personnummer)
    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user("AktivtLosen1!", pnr_hash)

    with _admin_client() as client:
        response = client.post(
            "/admin/api/konton/losenord-status",
            json={
                "personnummer": personnummer,
                "email": email,
                "csrf_token": "test-token",
            },
            headers={"X-CSRF-Token": "test-token"},
        )

    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert data["data"]["password_created"] is True
    assert data["data"]["status"] == "active"


def test_admin_send_create_password_link_rejects_active_account(empty_db, monkeypatch):
    personnummer = "19900303-3333"
    email = "redanaktiv@example.com"
    assert functions.admin_create_user(email, "Redan Aktiv", personnummer)
    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user("AktivtLosen1!", pnr_hash)

    called = {"sent": False}

    def _fake_send_creation_email(_to_email, _link):
        called["sent"] = True

    monkeypatch.setattr(app.email_service, "send_creation_email", _fake_send_creation_email)

    with _admin_client() as client:
        response = client.post(
            "/admin/api/konton/skapa-losenordslank",
            json={
                "personnummer": personnummer,
                "email": email,
                "csrf_token": "test-token",
            },
            headers={"X-CSRF-Token": "test-token"},
        )

    assert response.status_code == 404
    assert called["sent"] is False


def test_admin_password_status_requires_csrf(empty_db):
    personnummer = "19900404-4444"
    email = "csrf-status@example.com"
    assert functions.admin_create_user(email, "CSRF Status", personnummer)

    with _admin_client() as client:
        response = client.post(
            "/admin/api/konton/losenord-status",
            json={"personnummer": personnummer, "email": email},
        )

    assert response.status_code == 400
    data = response.get_json()
    assert data["status"] == "error"
    assert data["message"] == "Ogiltig CSRF-token."


def test_admin_send_create_password_link_requires_csrf(empty_db):
    personnummer = "19900505-5555"
    email = "csrf-link@example.com"
    assert functions.admin_create_user(email, "CSRF Länk", personnummer)

    with _admin_client() as client:
        response = client.post(
            "/admin/api/konton/skapa-losenordslank",
            json={"personnummer": personnummer, "email": email},
        )

    assert response.status_code == 400
    data = response.get_json()
    assert data["status"] == "error"
    assert data["message"] == "Ogiltig CSRF-token."
