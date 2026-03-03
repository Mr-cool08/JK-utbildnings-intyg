# Copyright (c) Liam Suorsa and Mika Suorsa
import functions
import functions.database as database_module


def test_cutover_mode_accounts_only_without_fallback(empty_db, monkeypatch):
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("ACCOUNTS_CUTOVER_MODE", "accounts_cutover")
    monkeypatch.setenv("USE_LEGACY_READ_FALLBACK", "false")

    email_hash = functions.hash_value(functions.normalize_email("endastkonto@example.com"))
    pnr_hash = functions.hash_value(functions.normalize_personnummer("9001011234"))

    with empty_db.begin() as conn:
        conn.execute(
            functions.accounts_table.insert().values(
                account_type="standard",
                status="active",
                name="Kontonamn",
                email=email_hash,
                personnummer=pnr_hash,
            )
        )

    assert functions.check_user_exists("endastkonto@example.com") is True
    assert functions.get_username("endastkonto@example.com") == "Kontonamn"


def test_cutover_mode_emergency_fallback_to_legacy(empty_db, monkeypatch):
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("ACCOUNTS_CUTOVER_MODE", "accounts_cutover")
    monkeypatch.setenv("USE_LEGACY_READ_FALLBACK", "true")

    email_hash = functions.hash_value(functions.normalize_email("legacyonly@example.com"))

    with empty_db.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Legacy Endast",
                email=email_hash,
                password=functions.hash_password("hemligt123"),
                personnummer=functions.hash_value(functions.normalize_personnummer("8801011234")),
            )
        )

    assert functions.check_user_exists("legacyonly@example.com") is True
    assert functions.get_username("legacyonly@example.com") == "Legacy Endast"


def test_cutover_mode_increments_mismatch_metric_on_fallback(empty_db, monkeypatch):
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("ACCOUNTS_CUTOVER_MODE", "accounts_cutover")
    monkeypatch.setenv("USE_LEGACY_READ_FALLBACK", "true")

    email_hash = functions.hash_value(functions.normalize_email("metric@example.com"))

    with empty_db.begin() as conn:
        conn.execute(
            functions.supervisors_table.insert().values(
                name="Legacy Chef",
                email=email_hash,
                password=functions.hash_password("hemligt123"),
            )
        )

    assert functions.supervisor_exists("metric@example.com") is True
    metrics = database_module.get_accounts_mismatch_metrics()
    assert metrics.get("supervisor_exists", 0) >= 1


def test_cutover_default_is_safe_legacy(empty_db, monkeypatch):
    monkeypatch.setenv("DEV_MODE", "false")
    monkeypatch.delenv("ACCOUNTS_CUTOVER_MODE", raising=False)
    monkeypatch.setenv("USE_LEGACY_READ_FALLBACK", "false")

    email_hash = functions.hash_value(functions.normalize_email("safe@example.com"))
    with empty_db.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Safe Legacy",
                email=email_hash,
                password=functions.hash_password("hemligt123"),
                personnummer=functions.hash_value(functions.normalize_personnummer("7001011234")),
            )
        )

    assert functions.check_user_exists("safe@example.com") is True
    assert functions.get_username("safe@example.com") == "Safe Legacy"


# <!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
