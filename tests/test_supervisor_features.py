import os
import sys

import pytest

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import app  # noqa: E402
import functions  # noqa: E402


def _admin_client():
    client = app.app.test_client()
    with client.session_transaction() as sess:
        sess["admin_logged_in"] = True
        sess["admin_username"] = "admin"
    return client


@pytest.fixture
def supervisor_setup(empty_db):
    email = "chef@example.com"
    name = "Chef Test"
    user_email = "user@example.com"
    user_name = "Test Användare"
    personnummer = "19900101-1234"
    orgnr = "556016-0680"
    normalized_orgnr = functions.validate_orgnr(orgnr)

    assert functions.admin_create_user(user_email, user_name, personnummer)
    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user("Hemligt123", pnr_hash)
    functions.store_pdf_blob(pnr_hash, "intyg.pdf", b"%PDF-1.4", [])

    application_id = functions.create_application_request(
        "foretagskonto",
        name,
        email,
        orgnr,
        "Testbolaget AB",
        "",  # kommentar
        "Fakturavägen 1",
        "Ekonomi Test",
        "REF-123",
    )
    approval = functions.approve_application_request(application_id, "admin")
    email_hash = approval["supervisor_email_hash"]
    assert functions.check_pending_supervisor_hash(email_hash)
    assert functions.supervisor_activate_account(email_hash, "StarktLosen123")

    success, reason = functions.admin_link_supervisor_to_user(email, personnummer)
    assert success and reason == "created"

    return {
        "email": email,
        "name": name,
        "email_hash": email_hash,
        "personnummer": personnummer,
        "personnummer_hash": pnr_hash,
        "user_name": user_name,
        "orgnr": normalized_orgnr,
    }


def _supervisor_client(email_hash, name):
    client = app.app.test_client()
    with client.session_transaction() as sess:
        sess["supervisor_logged_in"] = True
        sess["supervisor_email_hash"] = email_hash
        sess["supervisor_name"] = name
    return client


def test_supervisor_activation_flow(empty_db):
    email = "foretagskonto@example.com"
    name = "Företagskonto"
    assert functions.admin_create_supervisor(email, name)
    email_hash = functions.get_supervisor_email_hash(email)
    assert functions.check_pending_supervisor_hash(email_hash)
    with pytest.raises(ValueError):
        functions.supervisor_activate_account(email_hash, "kort")
    assert functions.supervisor_activate_account(email_hash, "LångtLösen123")
    assert not functions.check_pending_supervisor_hash(email_hash)
    assert functions.supervisor_exists(email)


def test_get_supervisor_login_details_for_orgnr(supervisor_setup):
    details = functions.get_supervisor_login_details_for_orgnr(supervisor_setup["orgnr"])
    assert details is not None
    assert details["email_hash"] == supervisor_setup["email_hash"]


def test_supervisor_dashboard_lists_users(supervisor_setup):
    client = _supervisor_client(
        supervisor_setup["email_hash"], supervisor_setup["name"]
    )
    response = client.get("/foretagskonto")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert supervisor_setup["user_name"] in body
    assert "intyg.pdf" in body


def test_supervisor_share_pdf(monkeypatch, supervisor_setup):
    captured = {}

    def fake_send(recipient, attachments, sender, owner_name=None):
        captured["recipient"] = recipient
        captured["attachments"] = attachments
        captured["sender"] = sender
        captured["owner"] = owner_name

    monkeypatch.setattr(app.email_service, "send_pdf_share_email", fake_send)

    client = _supervisor_client(
        supervisor_setup["email_hash"], supervisor_setup["name"]
    )
    pdfs = functions.get_user_pdfs(supervisor_setup["personnummer_hash"])
    pdf_id = pdfs[0]["id"]
    response = client.post(
        f"/foretagskonto/dela/{supervisor_setup['personnummer_hash']}/{pdf_id}",
        data={"recipient_email": "mottagare@example.com", "anchor": "user-anchor"},
    )
    assert response.status_code == 302
    assert captured["recipient"] == "mottagare@example.com"
    assert captured["sender"] == supervisor_setup["name"]
    assert captured["owner"] == supervisor_setup["user_name"]
    assert captured["attachments"][0][0] == "intyg.pdf"


def test_supervisor_remove_connection(supervisor_setup):
    client = _supervisor_client(
        supervisor_setup["email_hash"], supervisor_setup["name"]
    )
    response = client.post(
        f"/foretagskonto/kopplingar/{supervisor_setup['personnummer_hash']}/ta-bort",
        data={"anchor": "user-anchor"},
    )
    assert response.status_code == 302
    assert not functions.supervisor_has_access(
        supervisor_setup["email_hash"], supervisor_setup["personnummer_hash"]
    )


def test_admin_create_supervisor_api(empty_db, monkeypatch):
    sent = {}

    def fake_send(email, link):
        sent["email"] = email
        sent["link"] = link

    monkeypatch.setattr(app.email_service, "send_creation_email", fake_send)

    client = _admin_client()
    response = client.post(
        "/admin/api/foretagskonto/skapa",
        json={"name": "Chef", "email": "chef@example.com"},
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert "link" in data
    assert sent["email"] == "chef@example.com"


def test_admin_link_supervisor_api(supervisor_setup):
    functions.supervisor_remove_connection(
        supervisor_setup["email_hash"], supervisor_setup["personnummer_hash"]
    )
    client = _admin_client()
    response = client.post(
        "/admin/api/foretagskonto/koppla",
        json={
            "email": supervisor_setup["email"],
            "personnummer": supervisor_setup["personnummer"],
        },
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "success"
    assert functions.supervisor_has_access(
        supervisor_setup["email_hash"], supervisor_setup["personnummer_hash"]
    )


def test_admin_supervisor_overview_api(supervisor_setup):
    client = _admin_client()
    response = client.post(
        "/admin/api/foretagskonto/oversikt",
        json={"email": supervisor_setup["email"]},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "success"
    data = payload["data"]
    assert data["name"] == supervisor_setup["name"]
    assert data["connections"]
