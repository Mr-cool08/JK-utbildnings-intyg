from status_service.app import app


def test_pytest_route_returns_success_message(monkeypatch):
    def fake_pytest_main():
        return 0

    monkeypatch.setattr("status_service.app.pytest.main", fake_pytest_main)

    app.testing = True
    with app.test_client() as client:
        response = client.get("/pytest")

    assert response.status_code == 200
    assert response.get_data(as_text=True) == "Pytest klart: lyckades."


def test_pytest_route_returns_failure_message(monkeypatch):
    def fake_pytest_main():
        return 2

    monkeypatch.setattr("status_service.app.pytest.main", fake_pytest_main)

    app.testing = True
    with app.test_client() as client:
        response = client.get("/pytest")

    assert response.status_code == 200
    assert response.get_data(as_text=True) == "Pytest klart: misslyckades (2)."
