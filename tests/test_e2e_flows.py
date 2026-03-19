import io
from urllib.parse import urlparse

import app
import functions
from course_categories import COURSE_CATEGORIES


def _csrf_token(client) -> str:
    with client.session_transaction() as session_data:
        return str(session_data["csrf_token"])


def _admin_login(client) -> None:
    response = client.post(
        "/login_admin",
        data={"username": "test_admin", "password": "test_password_123"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers.get("Location", "").endswith("/admin")


def _user_login(client, personnummer: str, password: str) -> None:
    get_response = client.get("/login")
    assert get_response.status_code == 200
    csrf_token = _csrf_token(client)
    response = client.post(
        "/login",
        data={
            "personnummer": personnummer,
            "password": password,
            "csrf_token": csrf_token,
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers.get("Location", "").endswith("/dashboard")


def _supervisor_login(client, orgnr: str, password: str) -> None:
    get_response = client.get("/foretagskonto/login")
    assert get_response.status_code == 200
    csrf_token = _csrf_token(client)
    response = client.post(
        "/foretagskonto/login",
        data={"orgnr": orgnr, "password": password, "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers.get("Location", "").endswith("/foretagskonto")


def test_e2e_standardkonto_flow_application_to_upload_and_share(empty_db, monkeypatch):
    public_client = app.app.test_client()
    apply_get = public_client.get("/ansok/standardkonto")
    assert apply_get.status_code == 200
    csrf_token = _csrf_token(public_client)

    apply_response = public_client.post(
        "/ansok/standardkonto",
        data={
            "csrf_token": csrf_token,
            "name": "E2E Standard",
            "email": "e2e.standard@example.com",
            "personnummer": "9001011234",
            "comment": "E2E testflöde för standardkonto.",
            "terms_confirmed": "1",
        },
        follow_redirects=True,
    )
    assert apply_response.status_code == 200
    apply_body = apply_response.get_data(as_text=True)
    assert "Vi har tagit emot din ansökan om privatkonto." in apply_body
    assert "Du får ett första svar via e-post inom 2 arbetsdagar." in apply_body
    assert "privatkonto" in apply_body

    with empty_db.connect() as conn:
        application = conn.execute(
            functions.application_requests_table.select().where(
                functions.application_requests_table.c.email == "e2e.standard@example.com"
            )
        ).first()

    assert application is not None
    assert application.status == "pending"
    application_id = application.id

    admin_client = app.app.test_client()
    _admin_login(admin_client)
    admin_get = admin_client.get("/admin/ansokningar")
    assert admin_get.status_code == 200
    admin_csrf = _csrf_token(admin_client)

    approve_response = admin_client.post(
        f"/admin/api/ansokningar/{application_id}/godkann",
        json={"csrf_token": admin_csrf},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert approve_response.status_code == 200
    approve_payload = approve_response.get_json()
    assert approve_payload is not None
    assert approve_payload["status"] == "success"
    assert approve_payload["data"]["account_type"] == "standard"
    creation_link = approve_payload["creation_link"]
    activation_path = urlparse(creation_link).path

    activation_client = app.app.test_client()
    activation_get = activation_client.get(activation_path)
    assert activation_get.status_code == 200
    activation_post = activation_client.post(
        activation_path,
        data={"password": "NyttLosenord123", "confirm": "NyttLosenord123"},
        follow_redirects=False,
    )
    assert activation_post.status_code == 302
    assert activation_post.headers.get("Location", "").endswith("/login")

    user_client = app.app.test_client()
    _user_login(user_client, "9001011234", "NyttLosenord123")

    dashboard_get = user_client.get("/dashboard")
    assert dashboard_get.status_code == 200
    assert "Här är dina intyg." in dashboard_get.get_data(as_text=True)

    upload_csrf = _csrf_token(user_client)
    upload_response = user_client.post(
        "/dashboard/ladda-upp",
        data={
            "csrf_token": upload_csrf,
            "category": COURSE_CATEGORIES[0][0],
            "note": "E2E-uppladdning",
            "certificate": (io.BytesIO(b"%PDF-1.4 e2e"), "e2e-intyg.pdf"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert upload_response.status_code == 200
    assert "Intyget har laddats upp och sparats som PDF." in upload_response.get_data(as_text=True)

    personnummer_hash = functions.hash_value("9001011234")
    with empty_db.connect() as conn:
        uploaded = conn.execute(
            functions.user_pdfs_table.select().where(
                functions.user_pdfs_table.c.personnummer == personnummer_hash
            )
        ).first()

    assert uploaded is not None
    assert uploaded.note == "E2E-uppladdning"

    shared = {}

    def _fake_share(recipient, attachments, sender_name, owner_name=None):
        shared["recipient"] = recipient
        shared["attachments"] = attachments
        shared["sender"] = sender_name
        shared["owner"] = owner_name

    monkeypatch.setattr(app.email_service, "send_pdf_share_email", _fake_share)

    share_response = user_client.post(
        "/share_pdf",
        json={"pdf_id": uploaded.id, "recipient_email": "mottagare@example.com"},
    )
    assert share_response.status_code == 200
    share_payload = share_response.get_json()
    assert share_payload is not None
    assert share_payload["meddelande"] == "Intyget har skickats via e-post."
    assert shared["recipient"] == "mottagare@example.com"
    assert shared["attachments"][0][0] == uploaded.filename


def test_e2e_foretagskonto_flow_application_to_link_request_and_acceptance(empty_db):
    personnummer = "9112121234"
    personnummer_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.admin_create_user("e2e.user@example.com", "E2E User", personnummer)
    assert functions.user_create_user("UserStart123", personnummer_hash)

    public_client = app.app.test_client()
    apply_get = public_client.get("/ansok/foretagskonto")
    assert apply_get.status_code == 200
    csrf_token = _csrf_token(public_client)

    apply_response = public_client.post(
        "/ansok/foretagskonto",
        data={
            "csrf_token": csrf_token,
            "name": "E2E Företagskonto",
            "email": "e2e.foretag@example.com",
            "company_name": "E2E Bolaget AB",
            "orgnr": "5569668337",
            "invoice_address": "E2E-gatan 1",
            "invoice_contact": "E2E Kontakt",
            "invoice_reference": "E2E-REF",
            "comment": "E2E testflöde för företagskonto.",
            "terms_confirmed": "1",
        },
        follow_redirects=True,
    )
    assert apply_response.status_code == 200
    apply_body = apply_response.get_data(as_text=True)
    assert "Vi har tagit emot din ansökan om företagskonto." in apply_body
    assert "Du får ett första svar via e-post inom 2 arbetsdagar." in apply_body
    assert "företagskonto" in apply_body

    with empty_db.connect() as conn:
        application = conn.execute(
            functions.application_requests_table.select().where(
                functions.application_requests_table.c.email == "e2e.foretag@example.com"
            )
        ).first()

    assert application is not None
    application_id = application.id

    admin_client = app.app.test_client()
    _admin_login(admin_client)
    admin_get = admin_client.get("/admin/ansokningar")
    assert admin_get.status_code == 200
    admin_csrf = _csrf_token(admin_client)

    approve_response = admin_client.post(
        f"/admin/api/ansokningar/{application_id}/godkann",
        json={"csrf_token": admin_csrf},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert approve_response.status_code == 200
    approve_payload = approve_response.get_json()
    assert approve_payload is not None
    assert approve_payload["status"] == "success"
    assert approve_payload["data"]["account_type"] == "foretagskonto"
    supervisor_hash = approve_payload["data"]["supervisor_email_hash"]
    creation_link = approve_payload["creation_link"]
    activation_path = urlparse(creation_link).path

    supervisor_activation_client = app.app.test_client()
    activation_get = supervisor_activation_client.get(activation_path)
    assert activation_get.status_code == 200
    activation_post = supervisor_activation_client.post(
        activation_path,
        data={"password": "Supervisor123", "confirm": "Supervisor123"},
        follow_redirects=False,
    )
    assert activation_post.status_code == 302
    assert activation_post.headers.get("Location", "").endswith("/foretagskonto/login")

    supervisor_client = app.app.test_client()
    _supervisor_login(supervisor_client, "5569668337", "Supervisor123")
    supervisor_dashboard = supervisor_client.get("/foretagskonto")
    assert supervisor_dashboard.status_code == 200
    assert "Företagskontopanel" in supervisor_dashboard.get_data(as_text=True)

    supervisor_csrf = _csrf_token(supervisor_client)
    request_link = supervisor_client.post(
        "/foretagskonto/kopplingsforfragan",
        data={"personnummer": personnummer, "csrf_token": supervisor_csrf},
        follow_redirects=True,
    )
    assert request_link.status_code == 200
    assert "Kopplingsförfrågan har skickats." in request_link.get_data(as_text=True)

    user_client = app.app.test_client()
    _user_login(user_client, personnummer, "UserStart123")
    dashboard = user_client.get("/dashboard")
    assert dashboard.status_code == 200
    assert "Väntande kopplingsförfrågningar" in dashboard.get_data(as_text=True)

    user_csrf = _csrf_token(user_client)
    accept_response = user_client.post(
        f"/dashboard/kopplingsforfragan/{supervisor_hash}/godkann",
        data={"csrf_token": user_csrf},
        follow_redirects=True,
    )
    assert accept_response.status_code == 200
    assert "Kopplingen är nu aktiv." in accept_response.get_data(as_text=True)

    with empty_db.connect() as conn:
        connection = conn.execute(
            functions.supervisor_connections_table.select().where(
                functions.supervisor_connections_table.c.supervisor_email == supervisor_hash,
                functions.supervisor_connections_table.c.user_personnummer == personnummer_hash,
            )
        ).first()

    assert connection is not None


# Copyright (c) Liam Suorsa and Mika Suorsa
