import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import functions  # noqa: E402


def test_check_user_exists(empty_db):
    email = "exists@example.com"
    with empty_db.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Exists",
                email=functions.hash_value(email),
                password=functions.hash_password("pass"),
                personnummer=functions.hash_value("199001011234"),
            )
        )

    assert functions.check_user_exists(email)
    assert not functions.check_user_exists("missing@example.com")


def test_user_create_user_success(empty_db):
    email = "new@example.com"
    username = "NewUser"
    personnummer = "19900101-1234"

    assert functions.admin_create_user(email, username, personnummer)

    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user("secret", pnr_hash)

    with empty_db.connect() as conn:
        pending = conn.execute(
            functions.pending_users_table.select().where(
                functions.pending_users_table.c.personnummer == pnr_hash
            )
        ).first()
        user_row = conn.execute(
            functions.users_table.select().where(
                functions.users_table.c.personnummer == pnr_hash
            )
        ).first()

    assert pending is None
    assert user_row is not None
    assert user_row.email == functions.hash_value(email)
    assert user_row.username == username
    assert functions.check_user_exists(email)
