# Copyright (c) Liam Suorsa and Mika Suorsa
import app


def test_custom_404_page():
    with app.app.test_client() as client:
        response = client.get("/this-page-does-not-exist")
        assert response.status_code == 404
        assert b"Sidan du letade efter" in response.data
