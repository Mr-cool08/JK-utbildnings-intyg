from flask import request
from markupsafe import escape
from werkzeug.middleware.proxy_fix import ProxyFix

import app
import functions


def test_proxy_fix_applied_and_headers_respected(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "1")
    functions.reset_engine()

    proxy_app = app.create_app()
    assert isinstance(proxy_app.wsgi_app, ProxyFix)

    def _probe() -> dict[str, str]:
        return {
            "scheme": str(escape(request.scheme)),
            "remote_addr": str(escape(request.remote_addr or "")),
            "host": str(escape(request.host)),
            "port": str(escape(request.environ["SERVER_PORT"])),
        }

    proxy_app.add_url_rule("/proxy-test", view_func=_probe)

    response = proxy_app.test_client().get(
        "/proxy-test",
        headers={
            "X-Forwarded-Proto": "https",
            "X-Forwarded-For": "203.0.113.7",
            "X-Forwarded-Host": "exempel.se",
            "X-Forwarded-Port": "8443",
        },
    )

    data = response.get_json()
    assert data == {
        "scheme": "https",
        "remote_addr": "203.0.113.7",
        "host": "exempel.se:8443",
        "port": "8443",
    }
