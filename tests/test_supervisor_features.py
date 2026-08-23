# Copyright (c) Liam Suorsa and Mika Suorsa
import os
import sys

import pytest
from sqlalchemy import text

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import app  # noqa: E402
import functions  # noqa: E402
from course_categories import COURSE_CATEGORIES  # noqa: E402


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
    orgnr = "556966-8337"
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

    success, reason, _ = functions.admin_link_supervisor_to_user(orgnr, personnummer)
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


@pytest.fixture
def second_connected_user(supervisor_setup):
    email = "andra.anvandaren@example.com"
    name = "Andra Användaren"
    personnummer = "19850505-4321"
    assert functions.admin_create_user(email, name, personnummer)
    person_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user("Hemligt456", person_hash)
    pdf_id = functions.store_pdf_blob(
        person_hash,
        "andra-intyget.pdf",
        b"%PDF-1.4 second owner",
        [COURSE_CATEGORIES[1][0]],
    )
    success, reason, _ = functions.admin_link_supervisor_to_user(
        supervisor_setup["orgnr"],
        personnummer,
    )
    assert success and reason == "created"
    return {
        "name": name,
        "personnummer_hash": person_hash,
        "pdf_id": pdf_id,
    }


def _supervisor_client(email_hash, name, orgnr=None, csrf_token=None):
    client = app.app.test_client()
    with client.session_transaction() as sess:
        sess["supervisor_logged_in"] = True
        sess["supervisor_email_hash"] = email_hash
        sess["supervisor_name"] = name
        if orgnr:
            sess["supervisor_orgnr"] = orgnr
        if csrf_token:
            sess["csrf_token"] = csrf_token
    return client


def _user_client(personnummer_hash, username):
    client = app.app.test_client()
    with client.session_transaction() as sess:
        sess["user_logged_in"] = True
        sess["personnummer"] = personnummer_hash
        sess["username"] = username
    return client


def test_supervisor_activation_flow(empty_db):
    email = "foretagskonto@example.com"
    name = "Företagskonto"
    assert functions.admin_create_supervisor(email, name)
    email_hash = functions.get_supervisor_email_hash(email)
    normalized_email = functions.normalize_email(email)
    activation_token = functions.ensure_pending_supervisor_activation_token(email)
    with empty_db.connect() as conn:
        pending_supervisor = conn.execute(
            functions.pending_supervisors_table.select().where(
                functions.pending_supervisors_table.c.email == normalized_email
            )
        ).first()
    assert pending_supervisor is not None
    assert pending_supervisor.email == normalized_email
    assert pending_supervisor.activation_token == activation_token
    assert "@" not in activation_token
    assert functions.get_pending_supervisor_email_by_token(activation_token) == normalized_email
    assert functions.check_pending_supervisor_hash(email_hash)
    with pytest.raises(ValueError):
        functions.supervisor_activate_account(email_hash, "kort")
    assert functions.supervisor_activate_account(email_hash, "LångtLösen123")
    assert not functions.check_pending_supervisor_hash(email_hash)
    assert functions.get_pending_supervisor_email_by_token(activation_token) is None
    assert functions.supervisor_exists(email)


def test_supervisor_activation_handles_legacy_supervisors_table_without_defaults(
    empty_db,
):
    email = "legacy-supervisor@example.com"
    name = "Legacy Chef"
    normalized_email = functions.normalize_email(email)

    with empty_db.begin() as conn:
        conn.execute(text("DROP TABLE supervisors"))
        conn.execute(
            text(
                """
                CREATE TABLE supervisors (
                    id INTEGER PRIMARY KEY,
                    name VARCHAR NOT NULL,
                    email VARCHAR NOT NULL UNIQUE,
                    password VARCHAR NOT NULL,
                    created_at DATETIME NOT NULL
                )
                """
            )
        )

    assert functions.admin_create_supervisor(email, name)
    activation_token = functions.ensure_pending_supervisor_activation_token(email)

    assert activation_token
    assert functions.get_pending_supervisor_email_by_token(activation_token) == normalized_email
    assert functions.supervisor_activate_account(email, "LångtLösen123")

    with empty_db.connect() as conn:
        supervisor = conn.execute(
            functions.supervisors_table.select().where(
                functions.supervisors_table.c.email == normalized_email
            )
        ).first()

    assert supervisor is not None
    assert supervisor.created_at is not None


def test_pending_supervisor_activation_token_backfills_missing_value(empty_db):
    normalized_email = functions.normalize_email("legacy@example.com")
    with empty_db.begin() as conn:
        conn.execute(
            functions.pending_supervisors_table.insert().values(
                email=normalized_email,
                name="Legacy",
                activation_token=None,
            )
        )

    activation_token = functions.ensure_pending_supervisor_activation_token(normalized_email)

    assert activation_token
    assert "@" not in activation_token
    assert functions.get_pending_supervisor_email_by_token(activation_token) == normalized_email


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


def test_supervisor_dashboard_exposes_total_pdf_count(
    monkeypatch,
    supervisor_setup,
):
    captured = {}

    def fake_render(template_name, **context):
        captured["template_name"] = template_name
        captured["context"] = context
        return "Företagsportal"

    monkeypatch.setattr(app, "render_template", fake_render)
    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
    )

    response = client.get("/foretagskonto")

    assert response.status_code == 200
    assert captured["template_name"] == "supervisor_dashboard.html"
    assert captured["context"]["total_pdf_count"] == 1


@pytest.mark.parametrize(
    ("target_table", "fetcher"),
    [
        (
            functions.supervisor_connections_table,
            functions.list_user_supervisor_connections,
        ),
        (
            functions.supervisor_link_requests_table,
            functions.list_user_link_requests,
        ),
    ],
)
def test_supervisor_company_name_lookup_supports_legacy_hashes(
    empty_db,
    target_table,
    fetcher,
):
    personnummer_hash = functions.hash_value(
        functions.normalize_personnummer("19900101-1234")
    )
    supervisor_hash = functions.hash_value(
        functions.normalize_email("legacy-chef@example.com")
    )

    with empty_db.begin() as conn:
        company_id = conn.execute(
            functions.companies_table.insert().values(
                name="Legacy Bolag AB",
                orgnr=functions.validate_orgnr("556966-8337"),
            )
        ).inserted_primary_key[0]
        conn.execute(
            functions.company_users_table.insert().values(
                company_id=company_id,
                role="foretagskonto",
                name="Legacy Bolag AB",
                email=supervisor_hash,
            )
        )
        conn.execute(
            functions.supervisors_table.insert().values(
                email=supervisor_hash,
                name="Kontaktperson",
                password=functions.hash_password("Losen123!"),
            )
        )
        conn.execute(
            target_table.insert().values(
                supervisor_email=supervisor_hash,
                user_personnummer=personnummer_hash,
            )
        )

    rows = fetcher(personnummer_hash)

    assert len(rows) == 1
    assert rows[0]["supervisor_email"] == supervisor_hash
    assert rows[0]["supervisor_name"] == "Legacy Bolag AB"


def test_supervisor_dashboard_has_user_list_and_search(supervisor_setup):
    client = _supervisor_client(
        supervisor_setup["email_hash"], supervisor_setup["name"]
    )
    response = client.get("/foretagskonto")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'data-user-search' in body
    assert 'data-user-search-status' in body
    assert 'class="supervisor-user-list"' in body
    assert 'data-user-toggle' in body
    assert 'data-user-panel' in body
    assert 'data-supervisor-share-select' in body
    assert 'data-supervisor-select-all' in body
    assert 'data-supervisor-global-selection' in body
    assert 'data-supervisor-global-share' in body
    assert 'id="supervisorShareModal"' in body
    assert 'id="supervisorShareRecipientEmail"' in body
    assert "dashboard.css" in body
    assert "dashboard.js" in body
    assert "Sök på namn, filnamn eller kategori" in body


def test_supervisor_dashboard_search_indexes_certificate_metadata(supervisor_setup):
    client = _supervisor_client(
        supervisor_setup["email_hash"], supervisor_setup["name"]
    )
    response = client.get("/foretagskonto")
    assert response.status_code == 200
    body = response.get_data(as_text=True)

    assert 'data-user-search-text="' in body
    assert "intyg.pdf" in body
    assert "Visa intyg" in body


def test_supervisor_dashboard_lists_pending_organization_requests(supervisor_setup):
    functions.register_standard_account(
        "Ny Person",
        "ny.person@example.com",
        "19850505-1234",
        supervisor_setup["orgnr"],
    )

    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
        orgnr=supervisor_setup["orgnr"],
    )
    response = client.get("/foretagskonto")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Väntande förfrågningar" in body
    assert "Ny Person" in body
    assert "Inväntar lösenord" in body


def test_supervisor_dashboard_handles_missing_public_org_overview(
    supervisor_setup, monkeypatch
):
    def _missing_overview(_orgnr):
        raise ValueError("saknas")

    monkeypatch.setattr(app.functions, "get_public_organization_overview", _missing_overview)

    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
        orgnr=supervisor_setup["orgnr"],
    )
    response = client.get("/foretagskonto")
    assert response.status_code == 200
    assert supervisor_setup["user_name"] in response.get_data(as_text=True)


def test_supervisor_can_approve_organization_request(supervisor_setup, monkeypatch, empty_db):
    captured = {}
    csrf_token = "approve-token"
    registration = functions.register_standard_account(
        "Ny Person",
        "ny.person@example.com",
        "19850505-1234",
        supervisor_setup["orgnr"],
    )

    def _fake_send(email, company_name):
        captured["email"] = email
        captured["company_name"] = company_name

    monkeypatch.setattr(
        app.email_service,
        "send_organization_link_approved_email",
        _fake_send,
    )

    with empty_db.connect() as conn:
        request_row = conn.execute(
            functions.organization_link_requests_table.select().where(
                functions.organization_link_requests_table.c.user_personnummer
                == registration["personnummer_hash"]
            )
        ).first()

    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
        orgnr=supervisor_setup["orgnr"],
        csrf_token=csrf_token,
    )
    response = client.post(
        f"/foretagskonto/organisationskopplingar/{request_row.id}/godkann",
        data={"csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 302

    with empty_db.connect() as conn:
        request_row = conn.execute(
            functions.organization_link_requests_table.select().where(
                functions.organization_link_requests_table.c.id == request_row.id
            )
        ).first()
        connection = conn.execute(
            functions.supervisor_connections_table.select().where(
                functions.supervisor_connections_table.c.supervisor_email
                == supervisor_setup["email_hash"],
                functions.supervisor_connections_table.c.user_personnummer
                == registration["personnummer_hash"],
            )
        ).first()

    assert request_row.status == "approved"
    assert connection is not None
    assert captured["email"] == "ny.person@example.com"
    assert captured["company_name"] == "Testbolaget AB"


def test_supervisor_can_reject_organization_request(supervisor_setup, monkeypatch, empty_db):
    captured = {}
    csrf_token = "reject-token"
    registration = functions.register_standard_account(
        "Ny Person",
        "ny.person@example.com",
        "19850505-1234",
        supervisor_setup["orgnr"],
    )

    def _fake_send(email, company_name):
        captured["email"] = email
        captured["company_name"] = company_name

    monkeypatch.setattr(
        app.email_service,
        "send_organization_link_rejected_email",
        _fake_send,
    )

    with empty_db.connect() as conn:
        request_row = conn.execute(
            functions.organization_link_requests_table.select().where(
                functions.organization_link_requests_table.c.user_personnummer
                == registration["personnummer_hash"]
            )
        ).first()

    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
        orgnr=supervisor_setup["orgnr"],
        csrf_token=csrf_token,
    )
    response = client.post(
        f"/foretagskonto/organisationskopplingar/{request_row.id}/avsla",
        data={"csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 302

    with empty_db.connect() as conn:
        request_row = conn.execute(
            functions.organization_link_requests_table.select().where(
                functions.organization_link_requests_table.c.id == request_row.id
            )
        ).first()
        connection = conn.execute(
            functions.supervisor_connections_table.select().where(
                functions.supervisor_connections_table.c.supervisor_email
                == supervisor_setup["email_hash"],
                functions.supervisor_connections_table.c.user_personnummer
                == registration["personnummer_hash"],
            )
        ).first()

    assert request_row.status == "rejected"
    assert connection is None
    assert captured["email"] == "ny.person@example.com"
    assert captured["company_name"] == "Testbolaget AB"


@pytest.mark.parametrize(
    ("action", "email_attr"),
    [
        ("godkann", "send_organization_link_approved_email"),
        ("avsla", "send_organization_link_rejected_email"),
    ],
)
def test_supervisor_org_request_decision_uses_orgnr_fallback_when_overview_missing(
    supervisor_setup,
    monkeypatch,
    empty_db,
    action,
    email_attr,
):
    captured = {}
    csrf_token = f"{action}-token"
    registration = functions.register_standard_account(
        "Ny Person",
        "ny.person@example.com",
        "19850505-1234",
        supervisor_setup["orgnr"],
    )

    def _missing_overview(_orgnr):
        raise ValueError("saknas")

    monkeypatch.setattr(app.functions, "get_public_organization_overview", _missing_overview)
    monkeypatch.setattr(
        app.email_service,
        email_attr,
        lambda email, company_name: captured.update(email=email, company_name=company_name),
    )

    with empty_db.connect() as conn:
        request_row = conn.execute(
            functions.organization_link_requests_table.select().where(
                functions.organization_link_requests_table.c.user_personnummer
                == registration["personnummer_hash"]
            )
        ).first()

    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
        orgnr=supervisor_setup["orgnr"],
        csrf_token=csrf_token,
    )
    response = client.post(
        f"/foretagskonto/organisationskopplingar/{request_row.id}/{action}",
        data={"csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert captured["email"] == "ny.person@example.com"
    assert captured["company_name"] == f"organisationsnummer {supervisor_setup['orgnr']}"


@pytest.mark.parametrize("action", ["godkann", "avsla"])
def test_supervisor_org_request_decision_requires_csrf(
    supervisor_setup,
    empty_db,
    action,
):
    registration = functions.register_standard_account(
        "Ny Person",
        "ny.person@example.com",
        "19850505-1234",
        supervisor_setup["orgnr"],
    )

    with empty_db.connect() as conn:
        request_row = conn.execute(
            functions.organization_link_requests_table.select().where(
                functions.organization_link_requests_table.c.user_personnummer
                == registration["personnummer_hash"]
            )
        ).first()

    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
        orgnr=supervisor_setup["orgnr"],
        csrf_token="required-token",
    )
    response = client.post(
        f"/foretagskonto/organisationskopplingar/{request_row.id}/{action}",
        data={},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert app.CSRF_EXPIRED_MESSAGE in response.get_data(as_text=True)

    with empty_db.connect() as conn:
        updated_request = conn.execute(
            functions.organization_link_requests_table.select().where(
                functions.organization_link_requests_table.c.id == request_row.id
            )
        ).first()
        connection = conn.execute(
            functions.supervisor_connections_table.select().where(
                functions.supervisor_connections_table.c.supervisor_email
                == supervisor_setup["email_hash"],
                functions.supervisor_connections_table.c.user_personnummer
                == registration["personnummer_hash"],
            )
        ).first()

    assert updated_request is not None
    assert updated_request.status == "pending"
    assert connection is None


def test_org_request_becomes_visible_after_company_account_is_created(empty_db):
    registration = functions.register_standard_account(
        "Ny Person",
        "ny.person@example.com",
        "19850505-1234",
        "5569668337",
    )

    application_id = functions.create_application_request(
        "foretagskonto",
        "Chef Test",
        "chef@example.com",
        "5569668337",
        "Testbolaget AB",
        "",
        "Fakturavägen 1",
        "Ekonomi Test",
        "REF-123",
    )
    approval = functions.approve_application_request(application_id, "admin")
    email_hash = approval["supervisor_email_hash"]
    assert functions.supervisor_activate_account(email_hash, "StarktLosen123")

    client = _supervisor_client(
        email_hash,
        "Chef Test",
        orgnr="5569668337",
    )
    response = client.get("/foretagskonto")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Ny Person" in body
    assert "Väntande förfrågningar" in body

    with empty_db.connect() as conn:
        request_row = conn.execute(
            functions.organization_link_requests_table.select().where(
                functions.organization_link_requests_table.c.user_personnummer
                == registration["personnummer_hash"]
            )
        ).first()
    assert request_row is not None
    assert request_row.status == "pending"


def test_supervisor_share_pdf(monkeypatch, supervisor_setup):
    captured = {}

    def fake_send(
        recipient,
        attachments,
        sender,
        owner_name=None,
        category_labels=None,
    ):
        captured["recipient"] = recipient
        captured["attachments"] = attachments
        captured["sender"] = sender
        captured["owner"] = owner_name
        captured["category_labels"] = category_labels

    monkeypatch.setattr(app.email_service, "send_pdf_share_email", fake_send)

    client = _supervisor_client(
        supervisor_setup["email_hash"], supervisor_setup["name"]
    )
    pdfs = functions.get_user_pdfs(supervisor_setup["personnummer_hash"])
    pdf_id = pdfs[0]["id"]
    assert functions.update_pdf_categories(
        supervisor_setup["personnummer"],
        pdf_id,
        [COURSE_CATEGORIES[0][0]],
    )
    response = client.post(
        f"/foretagskonto/dela/{supervisor_setup['personnummer_hash']}/{pdf_id}",
        data={"recipient_email": "mottagare@example.com", "anchor": "user-anchor"},
    )
    assert response.status_code == 302
    assert captured["recipient"] == "mottagare@example.com"
    assert captured["sender"] == supervisor_setup["name"]
    assert captured["owner"] == supervisor_setup["user_name"]
    assert captured["attachments"][0][0] == "intyg.pdf"
    assert captured["category_labels"] == [[COURSE_CATEGORIES[0][1]]]


def test_supervisor_share_multiple_pdfs_deduplicates_ids(
    monkeypatch,
    supervisor_setup,
):
    first_pdf_id = functions.get_user_pdfs(supervisor_setup["personnummer_hash"])[0]["id"]
    second_pdf_id = functions.store_pdf_blob(
        supervisor_setup["personnummer_hash"],
        "andra-intyget.pdf",
        b"%PDF-1.4 second",
        [COURSE_CATEGORIES[1][0]],
    )
    captured = {}

    def fake_send(
        recipient,
        attachments,
        sender,
        owner_name=None,
        category_labels=None,
    ):
        captured["recipient"] = recipient
        captured["attachments"] = attachments
        captured["sender"] = sender
        captured["owner"] = owner_name
        captured["category_labels"] = category_labels

    monkeypatch.setattr(app.email_service, "send_pdf_share_email", fake_send)
    csrf_token = "batch-share-token"
    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
        csrf_token=csrf_token,
    )

    response = client.post(
        f"/foretagskonto/dela/{supervisor_setup['personnummer_hash']}",
        json={
            "pdf_ids": [first_pdf_id, second_pdf_id, first_pdf_id],
            "recipient_email": " mottagare@example.com ",
            "csrf_token": csrf_token,
        },
    )

    assert response.status_code == 200
    assert response.get_json() == {"meddelande": "Intygen har skickats via e-post."}
    assert captured["recipient"] == "mottagare@example.com"
    assert captured["sender"] == supervisor_setup["name"]
    assert captured["owner"] == supervisor_setup["user_name"]
    assert [filename for filename, _ in captured["attachments"]] == [
        "intyg.pdf",
        "andra-intyget.pdf",
    ]
    assert captured["category_labels"] == [
        [],
        [COURSE_CATEGORIES[1][1]],
    ]


def test_supervisor_share_multiple_pdfs_requires_csrf(
    monkeypatch,
    supervisor_setup,
):
    sent = []
    monkeypatch.setattr(
        app.email_service,
        "send_pdf_share_email",
        lambda *args, **kwargs: sent.append((args, kwargs)),
    )
    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
        csrf_token="expected-token",
    )
    pdf_id = functions.get_user_pdfs(supervisor_setup["personnummer_hash"])[0]["id"]

    response = client.post(
        f"/foretagskonto/dela/{supervisor_setup['personnummer_hash']}",
        json={
            "pdf_ids": [pdf_id],
            "recipient_email": "mottagare@example.com",
            "csrf_token": "wrong-token",
        },
    )

    assert response.status_code == 400
    assert response.get_json() == {"fel": app.CSRF_EXPIRED_MESSAGE}
    assert sent == []


def test_supervisor_share_multiple_pdfs_requires_selection(
    monkeypatch,
    supervisor_setup,
):
    sent = []
    monkeypatch.setattr(
        app.email_service,
        "send_pdf_share_email",
        lambda *args, **kwargs: sent.append((args, kwargs)),
    )
    csrf_token = "batch-share-token"
    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
        csrf_token=csrf_token,
    )

    response = client.post(
        f"/foretagskonto/dela/{supervisor_setup['personnummer_hash']}",
        json={
            "pdf_ids": [],
            "recipient_email": "mottagare@example.com",
            "csrf_token": csrf_token,
        },
    )

    assert response.status_code == 400
    assert response.get_json() == {"fel": "Välj minst ett intyg."}
    assert sent == []


def test_supervisor_share_multiple_pdfs_is_all_or_nothing(
    monkeypatch,
    supervisor_setup,
):
    sent = []
    monkeypatch.setattr(
        app.email_service,
        "send_pdf_share_email",
        lambda *args, **kwargs: sent.append((args, kwargs)),
    )
    csrf_token = "batch-share-token"
    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
        csrf_token=csrf_token,
    )
    owned_pdf_id = functions.get_user_pdfs(supervisor_setup["personnummer_hash"])[0]["id"]

    response = client.post(
        f"/foretagskonto/dela/{supervisor_setup['personnummer_hash']}",
        json={
            "pdf_ids": [owned_pdf_id, owned_pdf_id + 9999],
            "recipient_email": "mottagare@example.com",
            "csrf_token": csrf_token,
        },
    )

    assert response.status_code == 404
    assert response.get_json() == {
        "fel": "Ett eller flera intyg kunde inte hittas."
    }
    assert sent == []


def test_supervisor_share_multiple_pdfs_denies_unconnected_user(
    monkeypatch,
    supervisor_setup,
):
    foreign_person_hash = functions.hash_value(
        functions.normalize_personnummer("19850505-4321")
    )
    foreign_pdf_id = functions.store_pdf_blob(
        foreign_person_hash,
        "främmande-intyg.pdf",
        b"%PDF-1.4 foreign",
        [],
    )
    sent = []
    monkeypatch.setattr(
        app.email_service,
        "send_pdf_share_email",
        lambda *args, **kwargs: sent.append((args, kwargs)),
    )
    csrf_token = "batch-share-token"
    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
        csrf_token=csrf_token,
    )

    response = client.post(
        f"/foretagskonto/dela/{foreign_person_hash}",
        json={
            "pdf_ids": [foreign_pdf_id],
            "recipient_email": "mottagare@example.com",
            "csrf_token": csrf_token,
        },
    )

    assert response.status_code == 404
    assert response.get_json() == {"fel": "Åtgärden kunde inte utföras."}
    assert sent == []


def test_supervisor_share_selection_across_users(
    monkeypatch,
    supervisor_setup,
    second_connected_user,
):
    first_pdf_id = functions.get_user_pdfs(supervisor_setup["personnummer_hash"])[0]["id"]
    captured = {}

    def fake_send(
        recipient,
        attachments,
        sender,
        owner_name=None,
        category_labels=None,
    ):
        captured["recipient"] = recipient
        captured["attachments"] = attachments
        captured["sender"] = sender
        captured["owner"] = owner_name
        captured["category_labels"] = category_labels

    monkeypatch.setattr(app.email_service, "send_pdf_share_email", fake_send)
    csrf_token = "selection-token"
    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
        csrf_token=csrf_token,
    )

    response = client.post(
        "/foretagskonto/dela",
        json={
            "items": [
                {
                    "person_hash": supervisor_setup["personnummer_hash"],
                    "pdf_id": first_pdf_id,
                },
                {
                    "person_hash": second_connected_user["personnummer_hash"],
                    "pdf_id": second_connected_user["pdf_id"],
                },
            ],
            "recipient_email": " mottagare@example.com ",
            "csrf_token": csrf_token,
        },
    )

    assert response.status_code == 200
    assert response.get_json() == {"meddelande": "Intygen har skickats via e-post."}
    assert captured["recipient"] == "mottagare@example.com"
    assert captured["sender"] == supervisor_setup["name"]
    assert captured["owner"] is None
    assert [filename for filename, _ in captured["attachments"]] == [
        "intyg.pdf",
        "andra-intyget.pdf",
    ]
    assert captured["category_labels"] == [
        [f"Ägare: {supervisor_setup['user_name']}"],
        [
            f"Ägare: {second_connected_user['name']}",
            COURSE_CATEGORIES[1][1],
        ],
    ]


def test_supervisor_share_selection_deduplicates_items(
    monkeypatch,
    supervisor_setup,
):
    pdf_id = functions.get_user_pdfs(supervisor_setup["personnummer_hash"])[0]["id"]
    captured = {}

    def fake_send(
        recipient,
        attachments,
        sender,
        owner_name=None,
        category_labels=None,
    ):
        captured["attachments"] = attachments
        captured["owner"] = owner_name
        captured["category_labels"] = category_labels

    monkeypatch.setattr(app.email_service, "send_pdf_share_email", fake_send)
    csrf_token = "selection-token"
    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
        csrf_token=csrf_token,
    )
    item = {
        "person_hash": supervisor_setup["personnummer_hash"],
        "pdf_id": pdf_id,
    }

    response = client.post(
        "/foretagskonto/dela",
        json={
            "items": [item, item],
            "recipient_email": "mottagare@example.com",
            "csrf_token": csrf_token,
        },
    )

    assert response.status_code == 200
    assert response.get_json() == {"meddelande": "Intyget har skickats via e-post."}
    assert len(captured["attachments"]) == 1
    assert captured["owner"] == supervisor_setup["user_name"]
    assert captured["category_labels"] == [[]]


def test_supervisor_share_selection_requires_strict_csrf(
    monkeypatch,
    supervisor_setup,
):
    sent = []
    monkeypatch.setattr(
        app.email_service,
        "send_pdf_share_email",
        lambda *args, **kwargs: sent.append((args, kwargs)),
    )
    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
    )
    pdf_id = functions.get_user_pdfs(supervisor_setup["personnummer_hash"])[0]["id"]

    response = client.post(
        "/foretagskonto/dela",
        json={
            "items": [
                {
                    "person_hash": supervisor_setup["personnummer_hash"],
                    "pdf_id": pdf_id,
                }
            ],
            "recipient_email": "mottagare@example.com",
        },
    )

    assert response.status_code == 400
    assert response.get_json() == {"fel": app.CSRF_EXPIRED_MESSAGE}
    assert sent == []


def test_supervisor_share_selection_rejects_invalid_items(
    monkeypatch,
    supervisor_setup,
):
    sent = []
    monkeypatch.setattr(
        app.email_service,
        "send_pdf_share_email",
        lambda *args, **kwargs: sent.append((args, kwargs)),
    )
    csrf_token = "selection-token"
    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
        csrf_token=csrf_token,
    )
    valid_hash = supervisor_setup["personnummer_hash"]
    invalid_items = [
        {"person_hash": "inte-en-hash", "pdf_id": 1},
        {"person_hash": valid_hash, "pdf_id": 0},
        {"person_hash": valid_hash, "pdf_id": True},
        {"person_hash": valid_hash, "pdf_id": "1"},
    ]

    for item in invalid_items:
        response = client.post(
            "/foretagskonto/dela",
            json={
                "items": [item],
                "recipient_email": "mottagare@example.com",
                "csrf_token": csrf_token,
            },
        )
        assert response.status_code == 400
        assert response.get_json() == {"fel": "Ogiltiga intyg angivna."}

    assert sent == []


def test_supervisor_share_selection_denies_all_before_fetching(
    monkeypatch,
    supervisor_setup,
):
    authorized_pdf_id = functions.get_user_pdfs(supervisor_setup["personnummer_hash"])[0]["id"]
    foreign_person_hash = functions.hash_value(functions.normalize_personnummer("19770707-7777"))
    foreign_pdf_id = functions.store_pdf_blob(
        foreign_person_hash,
        "obehorig.pdf",
        b"%PDF-1.4 foreign",
        [],
    )
    fetched = []
    sent = []
    original_get_pdf_content = app.functions.get_pdf_content

    def tracked_get_pdf_content(person_hash, pdf_id):
        fetched.append((person_hash, pdf_id))
        return original_get_pdf_content(person_hash, pdf_id)

    monkeypatch.setattr(app.functions, "get_pdf_content", tracked_get_pdf_content)
    monkeypatch.setattr(
        app.email_service,
        "send_pdf_share_email",
        lambda *args, **kwargs: sent.append((args, kwargs)),
    )
    csrf_token = "selection-token"
    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
        csrf_token=csrf_token,
    )

    response = client.post(
        "/foretagskonto/dela",
        json={
            "items": [
                {
                    "person_hash": supervisor_setup["personnummer_hash"],
                    "pdf_id": authorized_pdf_id,
                },
                {
                    "person_hash": foreign_person_hash,
                    "pdf_id": foreign_pdf_id,
                },
            ],
            "recipient_email": "mottagare@example.com",
            "csrf_token": csrf_token,
        },
    )

    assert response.status_code == 404
    assert response.get_json() == {"fel": "Åtgärden kunde inte utföras."}
    assert fetched == []
    assert sent == []


def test_supervisor_share_selection_rechecks_access_before_sending(
    monkeypatch,
    supervisor_setup,
):
    pdf_id = functions.get_user_pdfs(supervisor_setup["personnummer_hash"])[0]["id"]
    access_results = iter([True, False])
    sent = []
    monkeypatch.setattr(
        app.functions,
        "supervisor_has_access",
        lambda *_args: next(access_results),
    )
    monkeypatch.setattr(
        app.email_service,
        "send_pdf_share_email",
        lambda *args, **kwargs: sent.append((args, kwargs)),
    )
    csrf_token = "selection-token"
    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
        csrf_token=csrf_token,
    )

    response = client.post(
        "/foretagskonto/dela",
        json={
            "items": [
                {
                    "person_hash": supervisor_setup["personnummer_hash"],
                    "pdf_id": pdf_id,
                }
            ],
            "recipient_email": "mottagare@example.com",
            "csrf_token": csrf_token,
        },
    )

    assert response.status_code == 404
    assert response.get_json() == {"fel": "Åtgärden kunde inte utföras."}
    assert sent == []


def test_supervisor_share_selection_enforces_certificate_limit(
    monkeypatch,
    supervisor_setup,
):
    monkeypatch.setattr(
        app.functions,
        "get_pdf_content",
        lambda *_args: pytest.fail("Intyg ska inte hämtas när gränsen överskrids"),
    )
    csrf_token = "selection-token"
    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
        csrf_token=csrf_token,
    )
    items = [
        {
            "person_hash": supervisor_setup["personnummer_hash"],
            "pdf_id": pdf_id,
        }
        for pdf_id in range(1, app.SUPERVISOR_SHARE_MAX_CERTIFICATES + 2)
    ]

    response = client.post(
        "/foretagskonto/dela",
        json={
            "items": items,
            "recipient_email": "mottagare@example.com",
            "csrf_token": csrf_token,
        },
    )

    assert response.status_code == 400
    assert response.get_json() == {"fel": app.SUPERVISOR_SHARE_TOO_MANY_MESSAGE}


def test_supervisor_share_selection_enforces_total_size_limit(
    monkeypatch,
    supervisor_setup,
):
    first_pdf_id = functions.get_user_pdfs(supervisor_setup["personnummer_hash"])[0]["id"]
    second_pdf_id = functions.store_pdf_blob(
        supervisor_setup["personnummer_hash"],
        "stor-bilaga.pdf",
        b"%PDF-1.4 more bytes",
        [],
    )
    sent = []
    monkeypatch.setattr(app, "SUPERVISOR_SHARE_MAX_TOTAL_BYTES", 10)
    monkeypatch.setattr(
        app.email_service,
        "send_pdf_share_email",
        lambda *args, **kwargs: sent.append((args, kwargs)),
    )
    csrf_token = "selection-token"
    client = _supervisor_client(
        supervisor_setup["email_hash"],
        supervisor_setup["name"],
        csrf_token=csrf_token,
    )

    response = client.post(
        "/foretagskonto/dela",
        json={
            "items": [
                {
                    "person_hash": supervisor_setup["personnummer_hash"],
                    "pdf_id": first_pdf_id,
                },
                {
                    "person_hash": supervisor_setup["personnummer_hash"],
                    "pdf_id": second_pdf_id,
                },
            ],
            "recipient_email": "mottagare@example.com",
            "csrf_token": csrf_token,
        },
    )

    assert response.status_code == 413
    assert response.get_json() == {"fel": app.SUPERVISOR_SHARE_TOO_LARGE_MESSAGE}
    assert sent == []


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


def test_supervisor_link_request_and_user_accept(supervisor_setup):
    functions.supervisor_remove_connection(
        supervisor_setup["email_hash"], supervisor_setup["personnummer_hash"]
    )
    supervisor_client = _supervisor_client(
        supervisor_setup["email_hash"], supervisor_setup["name"]
    )
    response = supervisor_client.post(
        "/foretagskonto/kopplingsforfragan",
        data={"personnummer": supervisor_setup["personnummer"]},
    )
    assert response.status_code == 302
    pending = functions.list_user_link_requests(
        supervisor_setup["personnummer_hash"]
    )
    assert any(
        entry["supervisor_email"] == supervisor_setup["email_hash"]
        for entry in pending
    )

    user_client = _user_client(
        supervisor_setup["personnummer_hash"], supervisor_setup["user_name"]
    )
    response = user_client.post(
        f"/dashboard/kopplingsforfragan/{supervisor_setup['email_hash']}/godkann"
    )
    assert response.status_code == 302
    assert functions.supervisor_has_access(
        supervisor_setup["email_hash"], supervisor_setup["personnummer_hash"]
    )


def test_user_remove_supervisor_connection(supervisor_setup):
    user_client = _user_client(
        supervisor_setup["personnummer_hash"], supervisor_setup["user_name"]
    )
    response = user_client.post(
        f"/dashboard/kopplingar/{supervisor_setup['email_hash']}/ta-bort"
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
    assert sent["link"] == data["link"]
    assert "/foretagskonto/skapa/" in sent["link"]
    assert "chef@example.com" not in sent["link"]
    activation_token = sent["link"].rstrip("/").split("/")[-1]
    assert functions.get_pending_supervisor_email_by_token(activation_token) == "chef@example.com"


def test_admin_link_supervisor_api(supervisor_setup):
    functions.supervisor_remove_connection(
        supervisor_setup["email_hash"], supervisor_setup["personnummer_hash"]
    )
    client = _admin_client()
    response = client.post(
        "/admin/api/foretagskonto/koppla",
        json={
            "orgnr": supervisor_setup["orgnr"],
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
        json={"orgnr": supervisor_setup["orgnr"]},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "success"
    data = payload["data"]
    assert data["name"] == supervisor_setup["name"]
    assert data["connections"]
