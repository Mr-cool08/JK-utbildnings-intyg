"""Regression checks: the app runs HTTP and shared Traefik owns TLS."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_wsgi_delegates_https_without_cert_handling():
    wsgi = (ROOT / "wsgi.py").read_text(encoding="utf-8")
    assert "app = application" in wsgi
    assert "application.run(" in wsgi
    assert "ssl_context=" not in wsgi
    for obsolete in ("get_ssl_context", "TLS_CERT", "TLS_KEY", "ORIGIN_CERT_PATH", "ORIGIN_KEY_PATH"):
        assert obsolete not in wsgi


def test_app_example_env_has_no_tls_secrets_or_domain_routing():
    env = (ROOT / ".example.env").read_text(encoding="utf-8")
    for obsolete in (
        "ORIGIN_CERT_PATH", "ORIGIN_KEY_PATH", "TLS_CERT=", "TLS_KEY=",
        "TLS_DOMAINS=", "APP_UPSTREAM=",
    ):
        assert obsolete not in env
    assert "PREFERRED_URL_SCHEME=https" in env
    assert "SESSION_COOKIE_SECURE=true" in env
    assert "TRUSTED_PROXY_COUNT=1" in env
