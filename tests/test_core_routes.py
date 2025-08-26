
def test_home_page(client):
    resp = client.get('/')
    assert resp.status_code == 200
    assert b'Welcome' in resp.data
    assert resp.headers['Content-Type'].startswith('text/html')

def test_license_page(client):
    resp = client.get('/license')
    assert resp.status_code == 200
    assert resp.headers['Content-Type'].startswith('text/html')
