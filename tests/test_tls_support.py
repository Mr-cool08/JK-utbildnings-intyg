import importlib
import wsgi


def test_get_ssl_context_none(monkeypatch, tmp_path):
    monkeypatch.delenv("CLOUDFLARE_CERT_PATH", raising=False)
    monkeypatch.delenv("CLOUDFLARE_KEY_PATH", raising=False)
    importlib.reload(wsgi)
    monkeypatch.setattr(wsgi, "DEFAULT_CERT_PATH", str(tmp_path / "missing_cert.pem"))
    monkeypatch.setattr(wsgi, "DEFAULT_KEY_PATH", str(tmp_path / "missing_key.pem"))
    assert wsgi.get_ssl_context() is None


def test_get_ssl_context_with_paths(monkeypatch, tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("cert")
    key.write_text("key")
    monkeypatch.setenv("CLOUDFLARE_CERT_PATH", str(cert))
    monkeypatch.setenv("CLOUDFLARE_KEY_PATH", str(key))
    importlib.reload(wsgi)
    assert wsgi.get_ssl_context() == (str(cert), str(key))


def test_get_ssl_context_default_paths(monkeypatch, tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("cert")
    key.write_text("key")
    monkeypatch.delenv("CLOUDFLARE_CERT_PATH", raising=False)
    monkeypatch.delenv("CLOUDFLARE_KEY_PATH", raising=False)
    importlib.reload(wsgi)
    monkeypatch.setattr(wsgi, "DEFAULT_CERT_PATH", str(cert))
    monkeypatch.setattr(wsgi, "DEFAULT_KEY_PATH", str(key))
    assert wsgi.get_ssl_context() == (str(cert), str(key))


def test_default_paths_constants():
    importlib.reload(wsgi)
    assert wsgi.DEFAULT_CERT_PATH == "/home/client_52_3/cert.pem"
    assert wsgi.DEFAULT_KEY_PATH == "/home/client_52_3/key.pem"

