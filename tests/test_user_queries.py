import os
import sys

# Ensure project root on path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import functions  # noqa: E402


def test_verify_certificate_existing_user(empty_db):
    with empty_db.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Test",
                email=functions.hash_value("user@example.com"),
                password=functions.hash_password("secret"),
                personnummer=functions.hash_value("9001011234"),
            )
        )
    functions.verify_certificate.cache_clear()
    assert functions.verify_certificate("199001011234")
    assert functions.verify_certificate("9001011234")


def test_check_user_exists(empty_db):
    email = "tester@example.com"
    with empty_db.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Tester",
                email=functions.hash_value(email),
                password=functions.hash_password("pass"),
                personnummer=functions.hash_value("9001011234"),
            )
        )
    assert functions.check_user_exists(email)
    assert not functions.check_user_exists("unknown@example.com")
