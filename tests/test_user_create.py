import functions


def test_user_create_hashes_password(empty_db):
    pnr_hash = functions.hash_value("9001011234")
    with empty_db.begin() as conn:
        conn.execute(
            functions.pending_users_table.insert().values(
                email=functions.hash_value("user@example.com"),
                email_plain="user@example.com",
                username="User",
                personnummer=pnr_hash,
            )
        )

    assert functions.user_create_user("mypassword", pnr_hash)

    with empty_db.connect() as conn:
        row = conn.execute(
            functions.users_table.select().where(
                functions.users_table.c.personnummer == pnr_hash
            )
        ).first()
    assert row is not None
    assert functions.verify_password(row.password, "mypassword")
