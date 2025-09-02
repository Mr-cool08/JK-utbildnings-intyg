import sqlite3
import app
import functions


def test_create_user_route_moves_pending_user(empty_db):
    functions.admin_create_user("user@example.com", "User", "19900101-1234", "doc.pdf")
    pnr_hash = functions.hash_value("199001011234")

    with app.app.test_client() as client:
        resp = client.get(f"/create_user/{pnr_hash}")
        assert resp.status_code == 200
        assert "Skapa konto" in resp.get_data(as_text=True)

        resp = client.post(f"/create_user/{pnr_hash}", data={"password": "newpass"})
        assert resp.status_code == 302

    conn = sqlite3.connect(empty_db)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM users WHERE personnummer = ?", (pnr_hash,))
    assert cursor.fetchone() is not None
    cursor.execute("SELECT 1 FROM pending_users WHERE personnummer = ?", (pnr_hash,))
    assert cursor.fetchone() is None
    conn.close()
