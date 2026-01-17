# Copyright (c) Liam Suorsa
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import functions  # noqa: E402


def test_check_pending_user_hash_missing(empty_db):
    assert not functions.check_pending_user_hash("missinghash")


def test_admin_create_user_single_pdf(empty_db):
    email = "user@example.com"
    username = "User"
    pnr = "19900101-1234"
    assert functions.admin_create_user(email, username, pnr)
    with empty_db.connect() as conn:
        row = conn.execute(functions.pending_users_table.select()).first()
    assert row.email == functions.hash_value(email)
    assert row.username == username


def test_check_password_user_nonexistent(empty_db):
    assert not functions.check_password_user("no@example.com", "secret")


def test_get_username_nonexistent(empty_db):
    assert functions.get_username("no@example.com") is None


def test_create_database_creates_tables(empty_db):
    with empty_db.connect() as conn:
        for table in [functions.pending_users_table, functions.users_table, functions.user_pdfs_table]:
            result = conn.execute(table.select().limit(0))
            assert result is not None


def test_verify_certificate_not_found(empty_db):
    functions.verify_certificate.cache_clear()
    assert not functions.verify_certificate("19900101-1234")


def test_user_create_user_no_pending(empty_db):
    pnr_hash = functions.hash_value("9001011234")
    assert not functions.user_create_user("pass", pnr_hash)

