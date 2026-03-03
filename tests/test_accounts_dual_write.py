# Copyright (c) Liam Suorsa and Mika Suorsa
from sqlalchemy import select

import functions
import functions.database as database_module


def test_dual_write_flag_off_keeps_legacy_only(empty_db, monkeypatch):
    monkeypatch.setenv("USE_ACCOUNTS_DUAL_WRITE", "false")

    created = functions.admin_create_user(
        email="test@example.com",
        username="Test",
        personnummer="9001011234",
    )

    assert created is True
    with empty_db.begin() as conn:
        pending = conn.execute(select(functions.pending_users_table.c.id)).fetchall()
        accounts = conn.execute(select(functions.accounts_table.c.id)).fetchall()

    assert len(pending) == 1
    assert accounts == []


def test_dual_write_flag_on_mirrors_standard_activation(empty_db, monkeypatch):
    monkeypatch.setenv("USE_ACCOUNTS_DUAL_WRITE", "true")

    created = functions.admin_create_user(
        email="person@example.com",
        username="Person",
        personnummer="9001011234",
    )
    assert created is True

    pnr_hash = functions.hash_value(functions.normalize_personnummer("9001011234"))
    activated = functions.user_create_user("hemligt123", pnr_hash)
    assert activated is True

    with empty_db.begin() as conn:
        pending = conn.execute(
            select(functions.pending_users_table.c.id).where(
                functions.pending_users_table.c.personnummer == pnr_hash
            )
        ).first()
        active = conn.execute(
            select(functions.users_table.c.id).where(
                functions.users_table.c.personnummer == pnr_hash
            )
        ).first()
        account_rows = conn.execute(
            select(
                functions.accounts_table.c.account_type,
                functions.accounts_table.c.status,
                functions.accounts_table.c.personnummer,
                functions.accounts_table.c.source_table,
            ).where(functions.accounts_table.c.personnummer == pnr_hash)
        ).fetchall()

    assert pending is None
    assert active is not None
    assert len(account_rows) == 1
    assert account_rows[0].account_type == "standard"
    assert account_rows[0].status == "active"
    assert account_rows[0].source_table == "users"


def test_dual_write_flag_on_mirrors_supervisor_activation(empty_db, monkeypatch):
    monkeypatch.setenv("USE_ACCOUNTS_DUAL_WRITE", "true")

    created = functions.admin_create_supervisor("chef@example.com", "Chef")
    assert created is True

    email_hash = functions.hash_value(functions.normalize_email("chef@example.com"))
    activated = functions.supervisor_activate_account(email_hash, "hemligt123")
    assert activated is True

    with empty_db.begin() as conn:
        account_rows = conn.execute(
            select(
                functions.accounts_table.c.account_type,
                functions.accounts_table.c.status,
                functions.accounts_table.c.email,
                functions.accounts_table.c.source_table,
            ).where(functions.accounts_table.c.email == email_hash)
        ).fetchall()

    assert len(account_rows) == 1
    assert account_rows[0].account_type == "foretagskonto"
    assert account_rows[0].status == "active"
    assert account_rows[0].source_table == "supervisors"


def test_reconcile_accounts_integrity_counts(empty_db, monkeypatch):
    monkeypatch.setenv("USE_ACCOUNTS_DUAL_WRITE", "true")

    functions.admin_create_user("u@example.com", "U", "9001011234")
    functions.admin_create_supervisor("s@example.com", "S")

    with empty_db.begin() as conn:
        summary = database_module.reconcile_accounts_integrity(conn)

    assert summary["legacy_standard_pending"] == 1
    assert summary["legacy_supervisor_pending"] == 1
    assert summary["accounts_standard_pending"] == 1
    assert summary["accounts_supervisor_pending"] == 1


# <!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
