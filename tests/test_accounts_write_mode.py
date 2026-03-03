# Copyright (c) Liam Suorsa and Mika Suorsa
import functions
import functions.database as database_module


def test_accounts_only_write_for_admin_create_and_activate_user(empty_db, monkeypatch):
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("ACCOUNTS_WRITE_MODE", "accounts_only")

    created = functions.admin_create_user("a@example.com", "A", "9001011234")
    assert created is True

    pnr_hash = functions.hash_value(functions.normalize_personnummer("9001011234"))
    activated = functions.user_create_user("hemligt123", pnr_hash)
    assert activated is True

    with empty_db.begin() as conn:
        legacy_pending = conn.execute(functions.pending_users_table.select()).fetchall()
        legacy_users = conn.execute(functions.users_table.select()).fetchall()
        account_active = conn.execute(
            functions.accounts_table.select().where(
                functions.accounts_table.c.account_type == "standard",
                functions.accounts_table.c.personnummer == pnr_hash,
            )
        ).first()

    assert legacy_pending == []
    assert legacy_users == []
    assert account_active is not None
    assert account_active.status == "active"


def test_accounts_only_write_for_supervisor_activation(empty_db, monkeypatch):
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("ACCOUNTS_WRITE_MODE", "accounts_only")

    created = functions.admin_create_supervisor("chef@example.com", "Chef")
    assert created is True

    email_hash = functions.hash_value(functions.normalize_email("chef@example.com"))
    activated = functions.supervisor_activate_account(email_hash, "hemligt123")
    assert activated is True

    with empty_db.begin() as conn:
        legacy_pending = conn.execute(functions.pending_supervisors_table.select()).fetchall()
        legacy_active = conn.execute(functions.supervisors_table.select()).fetchall()
        account_active = conn.execute(
            functions.accounts_table.select().where(
                functions.accounts_table.c.account_type == "foretagskonto",
                functions.accounts_table.c.email == email_hash,
            )
        ).first()

    assert legacy_pending == []
    assert legacy_active == []
    assert account_active is not None
    assert account_active.status == "active"


def test_accounts_only_write_blocks_are_observable(empty_db, monkeypatch):
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("ACCOUNTS_WRITE_MODE", "accounts_only")

    functions.admin_create_user("obs@example.com", "Obs", "7601011234")

    metrics = database_module.get_legacy_write_block_metrics()
    assert metrics.get("admin_create_user", 0) >= 1


def test_credential_reads_work_with_accounts_only_data(empty_db, monkeypatch):
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("ACCOUNTS_WRITE_MODE", "accounts_only")

    functions.admin_create_user("login@example.com", "Login", "7801011234")
    pnr_hash = functions.hash_value(functions.normalize_personnummer("7801011234"))
    functions.user_create_user("hemligt123", pnr_hash)

    assert functions.check_password_user("login@example.com", "hemligt123") is True
    assert functions.check_personnummer_password("7801011234", "hemligt123") is True


# <!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
