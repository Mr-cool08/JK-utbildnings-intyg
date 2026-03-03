# Copyright (c) Liam Suorsa and Mika Suorsa
from sqlalchemy import select

import functions
import functions.users as users_module


def test_accounts_read_mode_off_uses_legacy(empty_db, monkeypatch):
    monkeypatch.setenv("DEV_MODE", "false")
    monkeypatch.setenv("ACCOUNTS_READ_MODE", "accounts_first")

    email_hash = functions.hash_value(functions.normalize_email("legacy@example.com"))
    pnr_hash = functions.hash_value(functions.normalize_personnummer("9001011234"))

    with empty_db.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Legacy",
                email=email_hash,
                password=functions.hash_password("hemligt123"),
                personnummer=pnr_hash,
            )
        )

    assert functions.check_user_exists("legacy@example.com") is True
    assert functions.get_username("legacy@example.com") == "Legacy"


def test_accounts_first_reads_prefer_accounts_when_enabled(empty_db, monkeypatch):
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("ACCOUNTS_READ_MODE", "accounts_first")

    email_hash = functions.hash_value(functions.normalize_email("konto@example.com"))
    pnr_hash = functions.hash_value(functions.normalize_personnummer("9001011234"))

    with empty_db.begin() as conn:
        conn.execute(
            functions.accounts_table.insert().values(
                account_type="standard",
                status="active",
                name="FrånAccounts",
                email=email_hash,
                personnummer=pnr_hash,
            )
        )

    assert functions.check_user_exists("konto@example.com") is True
    assert functions.get_username("konto@example.com") == "FrånAccounts"
    assert functions.get_username_by_personnummer_hash(pnr_hash) == "FrånAccounts"


def test_hybrid_mode_falls_back_to_legacy_when_accounts_missing(empty_db, monkeypatch):
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("ACCOUNTS_READ_MODE", "hybrid")

    email_hash = functions.hash_value(functions.normalize_email("fallback@example.com"))
    pnr_hash = functions.hash_value(functions.normalize_personnummer("8501011234"))

    with empty_db.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="LegacyFallback",
                email=email_hash,
                password=functions.hash_password("hemligt123"),
                personnummer=pnr_hash,
            )
        )

    assert functions.check_user_exists("fallback@example.com") is True
    assert functions.get_username("fallback@example.com") == "LegacyFallback"


def test_hybrid_mode_logs_mismatch_and_returns_legacy_name(empty_db, monkeypatch):
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("ACCOUNTS_READ_MODE", "hybrid")

    email_hash = functions.hash_value(functions.normalize_email("mismatch@example.com"))
    pnr_hash = functions.hash_value(functions.normalize_personnummer("7701011234"))

    with empty_db.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="LegacyNamn",
                email=email_hash,
                password=functions.hash_password("hemligt123"),
                personnummer=pnr_hash,
            )
        )
        conn.execute(
            functions.accounts_table.insert().values(
                account_type="standard",
                status="active",
                name="AccountsNamn",
                email=email_hash,
                personnummer=pnr_hash,
            )
        )

    calls = []

    def _capture(context, key, accounts_value, legacy_value):
        calls.append((context, key, accounts_value, legacy_value))

    monkeypatch.setattr(users_module, "_log_accounts_read_mismatch", _capture)

    assert functions.get_username("mismatch@example.com") == "LegacyNamn"
    assert calls
    assert calls[0][0] == "get_username"


def test_supervisor_accounts_first_with_fallback_and_pending(empty_db, monkeypatch):
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("ACCOUNTS_READ_MODE", "accounts_first")

    email_hash = functions.hash_value(functions.normalize_email("chef@example.com"))

    with empty_db.begin() as conn:
        conn.execute(
            functions.accounts_table.insert().values(
                account_type="foretagskonto",
                status="active",
                name="Chef Accounts",
                email=email_hash,
                personnummer=None,
            )
        )
        conn.execute(
            functions.accounts_table.insert().values(
                account_type="foretagskonto",
                status="pending",
                name="Chef Pending",
                email=functions.hash_value(functions.normalize_email("pending@example.com")),
                personnummer=None,
            )
        )

    assert functions.supervisor_exists("chef@example.com") is True
    assert functions.get_supervisor_name_by_hash(email_hash) == "Chef Accounts"

    pending_hash = functions.hash_value(functions.normalize_email("pending@example.com"))
    assert functions.check_pending_supervisor_hash(pending_hash) is True


# <!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
