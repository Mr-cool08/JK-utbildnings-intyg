import app
import functions


def test_create_user_route_moves_pending_user_and_orgnr(empty_db):
    personnummer = "19900101-1234"
    personnummer_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    with empty_db.begin() as conn:
        conn.execute(
            functions.pending_users_table.insert().values(
                username="User",
                email=functions.hash_value(functions.normalize_email("user@example.com")),
                personnummer=personnummer_hash,
                orgnr_normalized="5569668337",
            )
        )

    with app.app.test_client() as client:
        response = client.get(f"/create_user/{personnummer_hash}")
        assert response.status_code == 200
        assert "Skapa konto" in response.get_data(as_text=True)

        response = client.post(
            f"/create_user/{personnummer_hash}",
            data={"password": "newpass12", "confirm": "newpass12"},
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/login")

    with empty_db.connect() as conn:
        user_row = conn.execute(
            functions.users_table.select().where(
                functions.users_table.c.personnummer == personnummer_hash
            )
        ).first()
        pending_row = conn.execute(
            functions.pending_users_table.select().where(
                functions.pending_users_table.c.personnummer == personnummer_hash
            )
        ).first()

    assert user_row is not None
    assert user_row.orgnr_normalized == "5569668337"
    assert pending_row is None


# Copyright (c) Liam Suorsa and Mika Suorsa
