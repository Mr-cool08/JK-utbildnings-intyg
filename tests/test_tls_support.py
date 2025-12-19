import importlib
import wsgi


def test_get_ssl_context_none(monkeypatch, tmp_path):
    monkeypatch.delenv("TLS_CERT", raising=False)
    monkeypatch.delenv("TLS_KEY", raising=False)
    monkeypatch.delenv("TLS_CERT_PATH", raising=False)
    monkeypatch.delenv("TLS_KEY_PATH", raising=False)
    importlib.reload(wsgi)
    monkeypatch.setattr(wsgi, "DEFAULT_CERT_PATH", str(tmp_path / "missing_cert.pem"))
    monkeypatch.setattr(wsgi, "DEFAULT_KEY_PATH", str(tmp_path / "missing_key.pem"))
    assert wsgi.get_ssl_context() is None


def test_get_ssl_context_with_env(monkeypatch, tmp_path):
    cert_content = "cert"
    key_content = "key"
    monkeypatch.setenv("TLS_CERT", cert_content)
    monkeypatch.setenv("TLS_KEY", key_content)
    monkeypatch.delenv("TLS_CERT_PATH", raising=False)
    monkeypatch.delenv("TLS_KEY_PATH", raising=False)
    importlib.reload(wsgi)
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    monkeypatch.setattr(wsgi, "DEFAULT_CERT_PATH", str(cert))
    monkeypatch.setattr(wsgi, "DEFAULT_KEY_PATH", str(key))
    result = wsgi.get_ssl_context()
    assert result == (str(cert), str(key))
    assert cert.read_text() == cert_content
    assert key.read_text() == key_content


def test_get_ssl_context_default_paths(monkeypatch, tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("cert")
    key.write_text("key")
    monkeypatch.delenv("TLS_CERT", raising=False)
    monkeypatch.delenv("TLS_KEY", raising=False)
    monkeypatch.delenv("TLS_CERT_PATH", raising=False)
    monkeypatch.delenv("TLS_KEY_PATH", raising=False)
    importlib.reload(wsgi)
    monkeypatch.setattr(wsgi, "DEFAULT_CERT_PATH", str(cert))
    monkeypatch.setattr(wsgi, "DEFAULT_KEY_PATH", str(key))
    assert wsgi.get_ssl_context() == (str(cert), str(key))


def test_get_ssl_context_with_explicit_paths(monkeypatch, tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("cert")
    key.write_text("key")
    monkeypatch.setenv("TLS_CERT_PATH", str(cert))
    monkeypatch.setenv("TLS_KEY_PATH", str(key))
    monkeypatch.delenv("TLS_CERT", raising=False)
    monkeypatch.delenv("TLS_KEY", raising=False)
    importlib.reload(wsgi)
    assert wsgi.get_ssl_context() == (str(cert), str(key))


def test_default_paths_constants():
    importlib.reload(wsgi)
    assert wsgi.DEFAULT_CERT_PATH == "/etc/nginx/certs/server.crt"
    assert wsgi.DEFAULT_KEY_PATH == "/etc/nginx/certs/server.key"

