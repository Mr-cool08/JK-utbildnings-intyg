import app
import functions
import pytest


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(functions, "DB_PATH", str(db_path))
    functions.create_database()


def test_db_endpoint_requires_password():
    with app.app.test_client() as client:
        resp = client.get("/db")
        assert resp.status_code == 403


def test_db_endpoint_allows_view_and_modify(monkeypatch):
    monkeypatch.setenv("DB_ADMIN_PASSWORD", "secret")
    headers = {"X-DB-PASSWORD": "secret"}
    with app.app.test_client() as client:
        resp = client.get("/db", headers=headers)
        assert resp.status_code == 200
        assert resp.get_json()["users"] == []

        resp = client.post(
            "/db",
            json={
                "operation": "insert",
                "table": "users",
                "values": {
                    "username": "u",
                    "email": "e",
                    "password": "p",
                    "personnummer": "p",
                },
            },
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.get_json()["rowcount"] == 1

        resp = client.post(
            "/db",
            json={
                "operation": "select",
                "table": "users",
                "filters": {"email": "e"},
            },
            headers=headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert len(data["rows"]) == 1
        assert data["rows"][0]["email"] == "e"
