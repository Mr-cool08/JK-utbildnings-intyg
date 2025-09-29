import os
import sys

import pytest

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import functions  # noqa: E402


def test_normalize_personnummer():
    assert functions.normalize_personnummer("19900101-1234") == "9001011234"
    assert functions.normalize_personnummer("199001011234") == "9001011234"
    assert functions.normalize_personnummer("9001011234") == "9001011234"
    with pytest.raises(ValueError):
        functions.normalize_personnummer("123")


def test_admin_and_user_create_flow(empty_db, monkeypatch):
    email = "new@example.com"
    username = "New"
    personnummer = "19900101-1234"

    assert functions.admin_create_user(email, username, personnummer)

    with empty_db.connect() as conn:
        pending_row = conn.execute(functions.pending_users_table.select()).first()
    assert pending_row is not None
    assert pending_row.email == functions.hash_value(email)
    assert pending_row.email_plain == functions.normalize_email(email)
    assert pending_row.username == username

    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user("secret", pnr_hash)
    assert functions.check_user_exists(email)

    with empty_db.connect() as conn:
        pending_after = conn.execute(functions.pending_users_table.select()).first()
        user_row = conn.execute(
            functions.users_table.select().where(
                functions.users_table.c.personnummer == pnr_hash
            )
        ).first()

    assert pending_after is None
    assert user_row is not None
    assert user_row.email_plain == functions.normalize_email(email)

    functions.verify_certificate.cache_clear()
    assert functions.verify_certificate(personnummer)

    def fail_get_engine():
        raise AssertionError("verify_certificate should use cached value")

    monkeypatch.setattr(functions, "get_engine", fail_get_engine)
    assert functions.verify_certificate(personnummer)
