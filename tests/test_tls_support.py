# Copyright (c) Liam Suorsa and Mika Suorsa
import importlib
import wsgi



def test_get_ssl_context_default_paths(monkeypatch, tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("cert")
    key.write_text("key")
    monkeypatch.delenv("TLS_CERT", raising=False)
    monkeypatch.delenv("TLS_KEY", raising=False)
    monkeypatch.delenv("ORIGIN_CERT_PATH", raising=False)
    monkeypatch.delenv("ORIGIN_KEY_PATH", raising=False)
    importlib.reload(wsgi)
    monkeypatch.setattr(wsgi, "DEFAULT_CERT_PATH", str(cert))
    monkeypatch.setattr(wsgi, "DEFAULT_KEY_PATH", str(key))
    assert wsgi.get_ssl_context() == (str(cert), str(key))


def test_get_ssl_context_with_explicit_paths(monkeypatch, tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("cert")
    key.write_text("key")
    monkeypatch.setenv("ORIGIN_CERT_PATH", str(cert))
    monkeypatch.setenv("ORIGIN_KEY_PATH", str(key))
    monkeypatch.delenv("TLS_CERT", raising=False)
    monkeypatch.delenv("TLS_KEY", raising=False)
    importlib.reload(wsgi)
    assert wsgi.get_ssl_context() == (str(cert), str(key))


def test_default_paths_constants():
    importlib.reload(wsgi)
    assert wsgi.DEFAULT_CERT_PATH == "/etc/ssl/cloudflare/origin.crt"
    assert wsgi.DEFAULT_KEY_PATH == "/etc/ssl/cloudflare/origin.key"
