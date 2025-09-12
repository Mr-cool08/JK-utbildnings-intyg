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
    with app.app.test_client() as client:
        resp = client.get("/db", headers={"X-DB-PASSWORD": "secret"})
        assert resp.status_code == 200
        assert resp.get_json()["users"] == []
        sql = (
            "INSERT INTO users (username, email, password, personnummer) "
            "VALUES ('u', 'e', 'p', 'p')"
        )
        resp = client.post(
            "/db", json={"sql": sql}, headers={"X-DB-PASSWORD": "secret"}
        )
        assert resp.status_code == 200
        resp = client.get("/db", headers={"X-DB-PASSWORD": "secret"})
        data = resp.get_json()
        assert len(data["users"]) == 1
