import app
import functions


def _admin_client():
    client = app.app.test_client()
    with client.session_transaction() as session:
        session["admin_logged_in"] = True
        session["admin_username"] = "säkerhetstest"
    return client


def test_wildcard_search_is_escaped(empty_db):
    engine = empty_db
    with engine.begin() as conn:
        conn.execute(
            functions.pending_users_table.insert(),
            [
                {
                    "username": "Anna",
                    "email": functions.hash_value("anna@example.com"),
                    "personnummer": functions.hash_value(
                        functions.normalize_personnummer("19900101-9999")
                    ),
                },
                {
                    "username": "Bo",
                    "email": functions.hash_value("bo@example.com"),
                    "personnummer": functions.hash_value(
                        functions.normalize_personnummer("19900202-9999")
                    ),
                },
            ],
        )

    with _admin_client() as client:
        all_rows = client.get("/admin/advanced/api/rows/pending_users")
        assert all_rows.status_code == 200
        total = len(all_rows.get_json()["rows"])
        assert total == 2

        response = client.get(
            "/admin/advanced/api/rows/pending_users",
            query_string={"sok": "%"},
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "success"
        assert data["rows"] == []

        # Kontrollera att en vanlig sökning fortfarande fungerar.
        normal_response = client.get(
            "/admin/advanced/api/rows/pending_users",
            query_string={"sok": "anna"},
        )
        assert normal_response.status_code == 200
        rows = normal_response.get_json()["rows"]
        assert len(rows) == 1
        assert rows[0]["username"] == "Anna"
