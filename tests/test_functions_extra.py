import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import pytest

import functions  # noqa: E402


def test_normalize_email_trims_and_lowercases():
    assert functions.normalize_email("  User@Example.COM  ") == "user@example.com"


def test_normalize_email_rejects_newlines():
    with pytest.raises(ValueError):
        functions.normalize_email("user@example.com\n")


def test_hash_value_deterministic():
    h1 = functions.hash_value("hello")
    h2 = functions.hash_value("hello")
    h3 = functions.hash_value("world")
    assert h1 == h2
    assert h1 != h3


def test_hash_password_verify():
    hashed = functions.hash_password("s3cret")
    assert functions.verify_password(hashed, "s3cret")
    assert not functions.verify_password(hashed, "wrong")


def test_check_pending_user_and_hash(empty_db):
    functions.admin_create_user("e@example.com", "User", "19900101-1234")
    assert functions.check_pending_user("19900101-1234")
    pnr_hash = functions.hash_value("9001011234")
    assert functions.check_pending_user_hash(pnr_hash)
    assert not functions.check_pending_user("20000101-1234")


def test_admin_create_user_duplicate(empty_db):
    with empty_db.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Existing",
                email=functions.hash_value("exist@example.com"),
                password=functions.hash_password("secret"),
                personnummer=functions.hash_value("9001011234"),
            )
        )
    assert not functions.admin_create_user("exist@example.com", "Existing", "19900101-1234")


def test_check_personnummer_password(empty_db):
    with empty_db.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Test",
                email=functions.hash_value("test@example.com"),
                password=functions.hash_password("secret"),
                personnummer=functions.hash_value("9001011234"),
            )
        )
    assert functions.check_personnummer_password("19900101-1234", "secret")
    assert not functions.check_personnummer_password("19900101-1234", "wrong")


def test_get_user_info(empty_db):
    with empty_db.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Info",
                email=functions.hash_value("info@example.com"),
                password=functions.hash_password("pass"),
                personnummer=functions.hash_value("9001011234"),
            )
        )
    user = functions.get_user_info("19900101-1234")
    assert user is not None
    assert user.username == "Info"
    assert user.email == functions.hash_value("info@example.com")


def test_user_create_user_fails_if_exists(empty_db):
    pnr_hash = functions.hash_value("9001011234")
    with empty_db.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Existing",
                email=functions.hash_value("exist@example.com"),
                password=functions.hash_password("secret"),
                personnummer=pnr_hash,
            )
        )
    assert not functions.user_create_user("newpass", pnr_hash)


def test_hash_value_uniqueness_stress():
    values = {functions.hash_value(f"value{i}") for i in range(200)}
    assert len(values) == 200


def test_check_password_user_and_get_username(empty_db):
    email = "tester@example.com"
    username = "Tester"
    password = "s3cret"

    with empty_db.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username=username,
                email=functions.hash_value(email),
                password=functions.hash_password(password),
                personnummer=functions.hash_value("9001011234"),
            )
        )

    assert functions.check_password_user(email, password)
    assert not functions.check_password_user(email, "wrong")
    assert functions.get_username(email) == username


def test_get_username_by_personnummer_hash(empty_db):
    pnr_hash = functions.hash_value("9001011234")
    with empty_db.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="PersonnummerNamn",
                email=functions.hash_value("hash@example.com"),
                password=functions.hash_password("hemligt"),
                personnummer=pnr_hash,
            )
        )

    assert (
        functions.get_username_by_personnummer_hash(pnr_hash)
        == "PersonnummerNamn"
    )
    assert functions.get_username_by_personnummer_hash("saknas") is None
