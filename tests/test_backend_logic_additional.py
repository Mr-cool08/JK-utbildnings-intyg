import base64
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

import functions


def test_get_table_schema_describes_known_columns(empty_db):
    _ = empty_db

    schema = {
        column["name"]: column
        for column in functions.get_table_schema("pending_users")
    }

    assert schema["id"]["primary_key"] is True
    assert schema["username"]["type"] == "String"
    assert schema["personnummer"]["nullable"] is False

    with pytest.raises(ValueError):
        functions.get_table_schema("finns_inte")


def test_table_admin_binary_round_trip_and_literal_search(empty_db):
    _ = empty_db
    personnummer_hash = functions.hash_value("199001019999")
    encoded_content = base64.b64encode(b"%PDF-1.4 test").decode("ascii")

    first_row = functions.create_table_row(
        "user_pdfs",
        {
            "personnummer": personnummer_hash,
            "filename": "100%_plan.pdf",
            "content": encoded_content,
            "categories": "kursintyg",
        },
    )
    second_row = functions.create_table_row(
        "user_pdfs",
        {
            "personnummer": personnummer_hash,
            "filename": "tom.pdf",
            "content": "",
            "categories": "",
        },
    )
    functions.create_table_row(
        "user_pdfs",
        {
            "personnummer": personnummer_hash,
            "filename": "100abcxplan.pdf",
            "content": encoded_content,
            "categories": "annat",
        },
    )

    matching_rows = functions.fetch_table_rows("user_pdfs", search="100%_plan")
    empty_content_rows = functions.fetch_table_rows("user_pdfs", search="tom.pdf")

    assert first_row["content"] == encoded_content
    assert second_row["content"] == ""
    assert [row["filename"] for row in matching_rows] == ["100%_plan.pdf"]
    assert empty_content_rows[0]["content"] == ""


def test_table_admin_update_delete_and_validation_errors(empty_db):
    _ = empty_db
    row = functions.create_table_row(
        "pending_users",
        {
            "username": "Tabellrad",
            "email": "tabellrad@example.com",
            "personnummer": functions.hash_value("200001019999"),
            "orgnr_normalized": "",
        },
    )

    assert functions.update_table_row(
        "pending_users", row["id"], {"username": "Uppdaterad"}
    )
    assert functions.update_table_row(
        "pending_users", 999999, {"username": "Finns inte"}
    ) is False
    assert functions.delete_table_row("pending_users", row["id"]) is True
    assert functions.delete_table_row("pending_users", row["id"]) is False
    assert functions.fetch_table_rows("pending_users", search="Uppdaterad") == []

    with pytest.raises(ValueError):
        functions.create_table_row("pending_users", {"id": row["id"]})

    with pytest.raises(ValueError):
        functions.update_table_row("pending_users", row["id"], {"id": row["id"]})

    with pytest.raises(ValueError):
        functions.create_table_row(
            "user_pdfs",
            {
                "personnummer": functions.hash_value("200101019999"),
                "filename": "ogiltig.pdf",
                "content": 123,
            },
        )


def test_get_public_organization_overview_counts_users_and_company(empty_db):
    normalized_orgnr = functions.validate_orgnr("556966-8337")

    with functions.get_engine().begin() as conn:
        conn.execute(
            functions.users_table.insert(),
            [
                {
                    "username": "Anvandare Ett",
                    "email": "ett@example.com",
                    "password": functions.hash_password("StartLosen1!"),
                    "personnummer": functions.hash_value("199001011111"),
                    "orgnr_normalized": normalized_orgnr,
                },
                {
                    "username": "Anvandare Tva",
                    "email": "tva@example.com",
                    "password": functions.hash_password("StartLosen1!"),
                    "personnummer": functions.hash_value("199002022222"),
                    "orgnr_normalized": normalized_orgnr,
                },
            ],
        )
        company_result = conn.execute(
            functions.companies_table.insert().values(
                name="Testbolaget AB",
                orgnr=normalized_orgnr,
            )
        )
        company_id = company_result.inserted_primary_key[0]
        conn.execute(
            functions.company_users_table.insert().values(
                company_id=company_id,
                role="foretagskonto",
                name="Kontaktperson",
                email="kontakt@example.com",
            )
        )

    overview = functions.get_public_organization_overview("556966-8337")

    assert overview == {
        "orgnr": normalized_orgnr,
        "user_count": 2,
        "company_name": "Testbolaget AB",
    }


def test_list_pending_organization_link_requests_reports_account_statuses(empty_db):
    normalized_orgnr = functions.validate_orgnr("556966-8337")
    active_personnummer_hash = functions.hash_value("198001011111")
    missing_personnummer_hash = functions.hash_value("198303033333")
    pending_registration = functions.register_standard_account(
        "Vantande Person",
        "vantande@example.com",
        "19820202-2222",
        normalized_orgnr,
    )

    with functions.get_engine().begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Aktiv Person",
                email="aktiv@example.com",
                password=functions.hash_password("StartLosen1!"),
                personnummer=active_personnummer_hash,
                orgnr_normalized=normalized_orgnr,
            )
        )
        conn.execute(
            functions.organization_link_requests_table.insert(),
            [
                {
                    "orgnr_normalized": normalized_orgnr,
                    "user_personnummer": active_personnummer_hash,
                    "user_name": "Aktiv Person",
                    "user_email": "aktiv@example.com",
                    "status": "pending",
                },
                {
                    "orgnr_normalized": normalized_orgnr,
                    "user_personnummer": missing_personnummer_hash,
                    "user_name": "Saknad Person",
                    "user_email": "saknad@example.com",
                    "status": "pending",
                },
                {
                    "orgnr_normalized": normalized_orgnr,
                    "user_personnummer": functions.hash_value("198404044444"),
                    "user_name": "Avvisad Person",
                    "user_email": "avvisad@example.com",
                    "status": "rejected",
                },
            ],
        )

    requests = functions.list_pending_organization_link_requests("556966-8337")
    statuses = {row["user_name"]: row["account_status"] for row in requests}

    assert statuses == {
        "Aktiv Person": "active",
        "Vantande Person": "pending",
        "Saknad Person": "missing",
    }
    assert all(row["user_name"] != "Avvisad Person" for row in requests)
    assert any(
        row["user_personnummer"] == pending_registration["personnummer_hash"]
        for row in requests
    )


def test_approve_organization_link_request_reuses_existing_connection(empty_db):
    normalized_orgnr = functions.validate_orgnr("556966-8337")
    supervisor_email = "chef@example.com"
    assert functions.admin_create_supervisor(supervisor_email, "Chef")
    supervisor_hash = functions.get_supervisor_email_hash(supervisor_email)
    registration = functions.register_standard_account(
        "Godkand Person",
        "godkand@example.com",
        "19850505-1234",
        normalized_orgnr,
    )

    with functions.get_engine().begin() as conn:
        request_row = conn.execute(
            select(functions.organization_link_requests_table).where(
                functions.organization_link_requests_table.c.user_personnummer
                == registration["personnummer_hash"]
            )
        ).first()
        conn.execute(
            functions.supervisor_connections_table.insert().values(
                supervisor_email=supervisor_hash,
                user_personnummer=registration["personnummer_hash"],
            )
        )

    success, payload, result = functions.approve_organization_link_request(
        request_row.id,
        supervisor_hash,
        normalized_orgnr,
    )

    with functions.get_engine().connect() as conn:
        connections = conn.execute(
            select(functions.supervisor_connections_table).where(
                functions.supervisor_connections_table.c.supervisor_email
                == supervisor_hash,
                functions.supervisor_connections_table.c.user_personnummer
                == registration["personnummer_hash"],
            )
        ).fetchall()

    assert success is True
    assert result == "approved"
    assert payload["user_personnummer"] == registration["personnummer_hash"]
    assert len(connections) == 1
    assert functions.approve_organization_link_request(
        request_row.id,
        supervisor_hash,
        normalized_orgnr,
    ) == (False, None, "handled_request")


def test_organization_link_actions_handle_invalid_inputs_and_missing_user(empty_db):
    normalized_orgnr = functions.validate_orgnr("556966-8337")
    supervisor_hash = functions.hash_value("chef@example.com")

    with functions.get_engine().begin() as conn:
        request_result = conn.execute(
            functions.organization_link_requests_table.insert().values(
                orgnr_normalized=normalized_orgnr,
                user_personnummer=functions.hash_value("198606066666"),
                user_name="Saknad Person",
                user_email="saknad@example.com",
                status="pending",
            )
        )
        request_id = request_result.inserted_primary_key[0]

    assert functions.approve_organization_link_request(
        request_id,
        "inte-en-adress",
        normalized_orgnr,
    ) == (False, None, "invalid_supervisor")
    assert functions.approve_organization_link_request(
        request_id,
        supervisor_hash,
        normalized_orgnr,
    ) == (False, None, "missing_user")
    assert functions.reject_organization_link_request(
        request_id,
        "inte-en-adress",
        normalized_orgnr,
    ) == (False, None, "invalid_supervisor")

    success, payload, result = functions.reject_organization_link_request(
        request_id,
        supervisor_hash,
        normalized_orgnr,
    )

    assert success is True
    assert result == "rejected"
    assert payload["id"] == str(request_id)
    assert functions.reject_organization_link_request(
        request_id,
        supervisor_hash,
        normalized_orgnr,
    ) == (False, None, "handled_request")


def test_organization_link_contact_updates_delete_and_orgnr_lookup(empty_db):
    _ = empty_db
    normalized_orgnr = functions.validate_orgnr("556966-8337")
    registration = functions.register_standard_account(
        "Kontakt Person",
        "kontakt@example.com",
        "19910101-1234",
        normalized_orgnr,
    )

    updated = functions.update_organization_request_contact_details(
        registration["personnummer_hash"],
        "Nytt Namn",
        "NYTT@EXAMPLE.COM",
    )

    with functions.get_engine().connect() as conn:
        request_row = conn.execute(
            select(functions.organization_link_requests_table).where(
                functions.organization_link_requests_table.c.user_personnummer
                == registration["personnummer_hash"]
            )
        ).first()

    assert updated == 1
    assert request_row.user_name == "Nytt Namn"
    assert request_row.user_email == "nytt@example.com"
    assert functions.get_account_orgnr(registration["personnummer_hash"]) == normalized_orgnr
    assert functions.delete_organization_link_requests_for_user("ogiltig-hash") == 0
    assert (
        functions.delete_organization_link_requests_for_user(
            registration["personnummer_hash"]
        )
        == 1
    )
    assert functions.list_pending_organization_link_requests(normalized_orgnr) == []


def test_supervisor_password_reset_token_lifecycle(empty_db):
    _ = empty_db
    email = "foretagskonto@example.com"
    assert functions.admin_create_supervisor(email, "Foretagskonto")
    email_hash = functions.get_supervisor_email_hash(email)
    assert functions.supervisor_activate_account(email_hash, "StartLosen1!")

    token = functions.create_supervisor_password_reset_token(email.upper())
    info = functions.get_supervisor_password_reset(token)

    assert info is not None
    assert info["email"] == functions.normalize_email(email)
    assert info["used_at"] is None
    assert functions.reset_supervisor_password_with_token(token, "NyttLosen1!")
    assert functions.verify_supervisor_credentials(email, "NyttLosen1!")
    assert (
        functions.reset_supervisor_password_with_token(token, "AndraLosen1!")
        is False
    )
    assert functions.get_supervisor_password_reset("saknas") is None


def test_supervisor_password_reset_token_expires_and_requires_account(empty_db):
    _ = empty_db

    with pytest.raises(ValueError):
        functions.create_supervisor_password_reset_token("saknas@example.com")

    email = "utgangen@example.com"
    assert functions.admin_create_supervisor(email, "Utgangen")
    email_hash = functions.get_supervisor_email_hash(email)
    assert functions.supervisor_activate_account(email_hash, "StartLosen1!")

    token = functions.create_supervisor_password_reset_token(email)
    token_hash = functions.hash_value(token)
    expired_time = datetime.now().replace(tzinfo=None) - timedelta(days=3)

    with functions.get_engine().begin() as conn:
        conn.execute(
            functions.supervisor_password_resets_table.update()
            .where(functions.supervisor_password_resets_table.c.token_hash == token_hash)
            .values(created_at=expired_time)
        )

    assert functions.reset_supervisor_password_with_token(token, "NyttLosen1!") is False
    assert functions.verify_supervisor_credentials(email, "StartLosen1!")


# Copyright (c) Liam Suorsa and Mika Suorsa
