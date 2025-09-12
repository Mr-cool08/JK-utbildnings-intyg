import app


def test_debug_endpoint_returns_404_when_disabled():
    app.app.debug = False
    with app.app.test_client() as client:
        response = client.get("/debug")
        assert response.status_code == 404


def test_debug_endpoint_returns_info_when_enabled():
    app.app.debug = True
    with app.app.test_client() as client:
        response = client.get("/debug")
        assert response.status_code == 200
        data = response.get_json()
        assert data["debug"] is True
    app.app.debug = False
