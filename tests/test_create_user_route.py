import app
import functions


def test_create_user_route_moves_pending_user(empty_db):
    functions.admin_create_user("user@example.com", "User", "19900101-1234")
    pnr_hash = functions.hash_value(functions.normalize_personnummer("19900101-1234"))

    with app.app.test_client() as client:
        resp = client.get(f"/create_user/{pnr_hash}")
        assert resp.status_code == 200
        assert "Skapa konto" in resp.get_data(as_text=True)

        resp = client.post(f"/create_user/{pnr_hash}", data={"password": "newpass"})
        assert resp.status_code == 302

    with empty_db.connect() as conn:
        user_row = conn.execute(
            functions.users_table.select().where(
                functions.users_table.c.personnummer == pnr_hash
            )
        ).first()
        pending_row = conn.execute(
            functions.pending_users_table.select().where(
                functions.pending_users_table.c.personnummer == pnr_hash
            )
        ).first()

    assert user_row is not None
    assert pending_row is None
