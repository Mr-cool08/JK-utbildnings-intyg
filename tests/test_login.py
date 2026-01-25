# Copyright (c) Liam Suorsa
import pytest
import app


def _login(client, personnummer: str, password: str):
    with client.session_transaction() as sess:
        sess["csrf_token"] = "test-token"
    return client.post(
        "/login",
        data={
            "personnummer": personnummer,
            "password": password,
            "csrf_token": "test-token",
        },
    )


@pytest.mark.parametrize("pnr_input", ["9001011234", "900101-1234", "199001011234"])
def test_login_success(user_db, pnr_input):
    with app.app.test_client() as client:
        response = _login(client, pnr_input, "secret")
        assert response.status_code == 302


def test_login_failure(user_db):
    with app.app.test_client() as client:
        response = _login(client, "9001011234", "wrong")
        assert response.status_code == 401


def test_login_requires_csrf(user_db):
    with app.app.test_client() as client:
        response = client.post(
            "/login",
            data={"personnummer": "9001011234", "password": "secret"},
        )
        assert response.status_code == 400
        assert "formuläret" in response.text.lower()
