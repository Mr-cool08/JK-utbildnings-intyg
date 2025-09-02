import pytest
import app


@pytest.mark.parametrize("pnr_input", ["199001011234", "19900101-1234", "900101-1234"])
def test_login_success(user_db, pnr_input):
    with app.app.test_client() as client:
        response = client.post("/login", data={"personnummer": pnr_input, "password": "secret"})
        assert response.status_code == 302


def test_login_failure(user_db):
    with app.app.test_client() as client:
        response = client.post("/login", data={"personnummer": "199001011234", "password": "wrong"})
        assert response.status_code == 401
