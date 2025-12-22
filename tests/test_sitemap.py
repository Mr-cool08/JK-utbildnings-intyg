import app


def _client():
    client = app.app.test_client()
    return client


def test_sitemap_xml_is_public(empty_db):
    with _client() as client:
        response = client.get('/sitemap.xml')

    assert response.status_code == 200
    assert response.mimetype == 'application/xml'

    body = response.data.decode('utf-8')
    assert 'https://www.utbildningsintyg.se/' in body
    assert '/ansok/standardkonto' in body
    assert '/ansok/foretagskonto' in body

    assert '/admin' not in body
    assert '/dashboard' not in body
    assert '/create_user' not in body
