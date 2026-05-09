import pytest

import app
import functions


def _client():
    return app.app.test_client()


def test_apply_landing_has_links(empty_db):
    with _client() as client:
        response = client.get("/ansok")
        assert response.status_code == 200
        body = response.data.decode("utf-8")
        assert "/ansok/standardkonto" in body
        assert "/ansok/foretagskonto" in body
        assert "Privatkonto är alltid gratis." in body
        assert "Skapa privatkonto" in body


@pytest.mark.allow_public_rate_limited
def test_user_account_registration_creates_pending_user_and_org_request(
    empty_db, monkeypatch
):
    sent = {}

    def _fake_send_creation_email(to_email, link):
        sent["email"] = to_email
        sent["link"] = link

    monkeypatch.setattr(app.email_service, "send_creation_email", _fake_send_creation_email)

    with _client() as client:
        with client.session_transaction() as session:
            session["csrf_token"] = "test-token"
        response = client.post(
            "/ansok/standardkonto",
            data={
                "csrf_token": "test-token",
                "name": "Anna Användare",
                "email": "anna@example.com",
                "personnummer": "9001011234",
                "orgnr": "556966-8337",
                "terms_confirmed": "1",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200
        body = response.data.decode("utf-8")
        assert "Kontot är skapat." in body
        assert "skapa ditt lösenord innan du loggar in" in body
        assert "Privatinloggning" in body

    with empty_db.connect() as conn:
        pending_users = conn.execute(functions.pending_users_table.select()).fetchall()
        assert len(pending_users) == 1
        pending_user = pending_users[0]
        assert pending_user.username == "Anna Användare"
        assert pending_user.orgnr_normalized == "5569668337"

        org_requests = conn.execute(functions.organization_link_requests_table.select()).fetchall()
        assert len(org_requests) == 1
        org_request = org_requests[0]
        assert org_request.orgnr_normalized == "5569668337"
        assert org_request.user_name == "Anna Användare"
        assert org_request.user_email == "anna@example.com"
        assert org_request.status == "pending"

        applications = conn.execute(functions.application_requests_table.select()).fetchall()
        assert applications == []

    assert sent["email"] == "anna@example.com"
    assert "/create_user/" in sent["link"]


@pytest.mark.allow_public_rate_limited
def test_user_account_registration_without_orgnr_only_creates_pending_user(
    empty_db, monkeypatch
):
    monkeypatch.setattr(app.email_service, "send_creation_email", lambda *_args: None)

    with _client() as client:
        with client.session_transaction() as session:
            session["csrf_token"] = "test-token"
        response = client.post(
            "/ansok/standardkonto",
            data={
                "csrf_token": "test-token",
                "name": "Anna Användare",
                "email": "anna@example.com",
                "personnummer": "9001011234",
                "terms_confirmed": "1",
            },
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/login")

    with empty_db.connect() as conn:
        pending_user = conn.execute(functions.pending_users_table.select()).first()
        assert pending_user is not None
        assert pending_user.orgnr_normalized == ""
        org_requests = conn.execute(functions.organization_link_requests_table.select()).fetchall()
        assert org_requests == []


@pytest.mark.allow_public_rate_limited
def test_foretagskonto_application_submission(empty_db):
    with _client() as client:
        with client.session_transaction() as session:
            session["csrf_token"] = "test-token"
        response = client.post(
            "/ansok/foretagskonto",
            data={
                "csrf_token": "test-token",
                "name": "Helena Företagskonto",
                "email": "helena@example.com",
                "company_name": "Handledarbolaget AB",
                "invoice_address": "Fakturagatan 1",
                "invoice_contact": "Helena Företagskonto",
                "invoice_reference": "Märkning 123",
                "orgnr": "5569668337",
                "comment": "Vi vill administrera våra kursdeltagare.",
                "terms_confirmed": "1",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200
        text = response.data.decode("utf-8")
        assert "Tack! Vi hör av oss så snart vi granskat ansökan." in text

    with empty_db.connect() as conn:
        stored = conn.execute(functions.application_requests_table.select()).fetchall()
        assert len(stored) == 1
        row = stored[0]
        assert row.account_type == "foretagskonto"
        assert row.invoice_address == "Fakturagatan 1"
        assert row.invoice_contact == "Helena Företagskonto"
        assert row.invoice_reference == "Märkning 123"


@pytest.mark.allow_public_rate_limited
def test_user_account_registration_requires_terms_confirmation(empty_db):
    with _client() as client:
        with client.session_transaction() as session:
            session["csrf_token"] = "test-token"
        response = client.post(
            "/ansok/standardkonto",
            data={
                "csrf_token": "test-token",
                "name": "Anna Användare",
                "email": "anna@example.com",
                "personnummer": "9001011234",
            },
            follow_redirects=True,
        )
        body = response.data.decode("utf-8")
        assert response.status_code == 200
        assert "innan du skapar kontot" in body

    with empty_db.connect() as conn:
        pending_users = conn.execute(functions.pending_users_table.select()).fetchall()
        assert pending_users == []


def test_public_organization_search_shows_active_user_count_and_company_name(empty_db):
    personnummer_hash = functions.hash_value(functions.normalize_personnummer("19900101-1234"))
    with empty_db.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Aktiv Person",
                email=functions.hash_value(functions.normalize_email("aktiv@example.com")),
                password="hashed-password",
                personnummer=personnummer_hash,
                orgnr_normalized="5569668337",
            )
        )
        company_result = conn.execute(
            functions.companies_table.insert().values(
                orgnr="5569668337",
                name="Handledarbolaget AB",
                invoice_address="Adress",
                invoice_contact="Kontakt",
                invoice_reference="Ref",
            )
        )
        company_id = company_result.inserted_primary_key[0]
        conn.execute(
            functions.company_users_table.insert().values(
                company_id=company_id,
                role="foretagskonto",
                name="Chef",
                email="chef@example.com",
            )
        )

    with _client() as client:
        response = client.get("/organisationer?orgnr=556966-8337")
        assert response.status_code == 200
        body = response.data.decode("utf-8")
        assert "5569668337" in body
        assert "Handledarbolaget AB" in body
        assert "Registrerade privatkonton" in body
        assert ">1<" in body or " 1" in body


def test_public_organization_search_rejects_invalid_orgnr(empty_db):
    with _client() as client:
        response = client.get("/organisationer?orgnr=123")
        assert response.status_code == 200
        body = response.data.decode("utf-8")
        assert "Kontrollera organisationsnumret" in body


# Copyright (c) Liam Suorsa and Mika Suorsa
