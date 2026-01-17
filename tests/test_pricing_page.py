# Copyright (c) Liam Suorsa
import app


def _client():
    client = app.app.test_client()
    return client


def test_pricing_page_loads(empty_db):
    with _client() as client:
        response = client.get('/pris')
        assert response.status_code == 200
        body = response.data.decode('utf-8')
        assert 'Prislista' in body
        assert '690 kr' in body


def test_home_page_links_pricing(empty_db):
    with _client() as client:
        response = client.get('/')
        assert response.status_code == 200
        body = response.data.decode('utf-8')
        assert '/pris' in body
