import importlib
import wsgi

def test_get_ssl_context_none(monkeypatch):
    monkeypatch.delenv("CLOUDFLARE_CERT_PATH", raising=False)
    monkeypatch.delenv("CLOUDFLARE_KEY_PATH", raising=False)
    importlib.reload(wsgi)
    assert wsgi.get_ssl_context() is None


def test_get_ssl_context_with_paths(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_CERT_PATH", "/tmp/cert.pem")
    monkeypatch.setenv("CLOUDFLARE_KEY_PATH", "/tmp/key.pem")
    importlib.reload(wsgi)
    assert wsgi.get_ssl_context() == ("/tmp/cert.pem", "/tmp/key.pem")
