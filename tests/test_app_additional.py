import logging

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

import app


def test_trusted_proxy_hops_handles_defaults_and_invalid(caplog):
    original_propagate = app.logger.propagate
    app.logger.propagate = True
    caplog.set_level(logging.WARNING, logger="app")

    assert app._trusted_proxy_hops(None) == 1
    assert app._trusted_proxy_hops("   ") == 1

    try:
        invalid = app._trusted_proxy_hops("abc")
        assert invalid == 1
        assert "Ogiltigt värde" in caplog.text

        negative = app._trusted_proxy_hops("-2")
        assert negative == 0
        assert "kan inte vara negativt" in caplog.text
    finally:
        app.logger.propagate = original_propagate


def test_configure_proxy_fix_applies_when_positive(monkeypatch):
    flask_app = Flask(__name__)
    original_wsgi = flask_app.wsgi_app
    monkeypatch.setattr(app, "_trusted_proxy_hops", lambda raw: 2)

    app._configure_proxy_fix(flask_app)

    assert isinstance(flask_app.wsgi_app, ProxyFix)
    assert flask_app.wsgi_app is not original_wsgi


def test_configure_proxy_fix_disabled_when_zero(monkeypatch):
    flask_app = Flask(__name__)
    original_wsgi = flask_app.wsgi_app
    monkeypatch.setattr(app, "_trusted_proxy_hops", lambda raw: 0)

    app._configure_proxy_fix(flask_app)

    assert not isinstance(flask_app.wsgi_app, ProxyFix)


def test_enable_debug_mode_sets_handlers_and_creates_user(monkeypatch):
    root_logger = logging.getLogger()
    original_level = root_logger.level
    original_handlers = list(root_logger.handlers)
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    created = {}
    monkeypatch.setattr(app.functions, "create_test_user", lambda: created.setdefault("called", True))

    functions_logger = logging.getLogger("app_test_functions_logger")
    for handler in list(functions_logger.handlers):
        functions_logger.removeHandler(handler)
    functions_logger.setLevel(logging.WARNING)
    monkeypatch.setattr(app.functions, "logger", functions_logger)

    flask_app = Flask(__name__)
    for handler in list(flask_app.logger.handlers):
        flask_app.logger.removeHandler(handler)

    try:
        app._enable_debug_mode(flask_app)

        assert created.get("called") is True
        assert any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers)
        assert any(isinstance(h, logging.StreamHandler) for h in flask_app.logger.handlers)
        assert any(isinstance(h, logging.StreamHandler) for h in functions_logger.handlers)
        assert functions_logger.level == logging.DEBUG
    finally:
        for handler in list(root_logger.handlers):
            root_logger.removeHandler(handler)
        for handler in original_handlers:
            root_logger.addHandler(handler)
        root_logger.setLevel(original_level)


def test_create_app_enables_demo_mode(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "0")
    monkeypatch.setenv("secret_key", "demo-secret")
    monkeypatch.setenv("ENABLE_DEMO_MODE", "true")
    monkeypatch.setenv("DEMO_USER_EMAIL", "demo@example.com")
    monkeypatch.setenv("DEMO_USER_NAME", "Demo")
    monkeypatch.setenv("DEMO_USER_PERSONNUMMER", "199001012222")
    monkeypatch.setenv("DEMO_USER_PASSWORD", "DemoLos1!")
    monkeypatch.setenv("DEMO_SUPERVISOR_EMAIL", "boss@example.com")
    monkeypatch.setenv("DEMO_SUPERVISOR_NAME", "Chef")
    monkeypatch.setenv("DEMO_SUPERVISOR_PASSWORD", "BossLos1!")
    monkeypatch.setenv("DEMO_SUPERVISOR_ORGNR", "5560160000")

    calls = {"create_db": 0, "ensure": None, "scheduler": False}
    monkeypatch.setattr(app.functions, "create_database", lambda: calls.__setitem__("create_db", calls["create_db"] + 1))

    def fake_ensure_demo_data(**kwargs):
        calls["ensure"] = kwargs

    monkeypatch.setattr(app.functions, "ensure_demo_data", fake_ensure_demo_data)
    monkeypatch.setattr(app, "_start_demo_reset_scheduler", lambda app_obj, defaults: calls.__setitem__("scheduler", True))

    demo_app = app.create_app()

    assert calls["create_db"] == 1
    assert calls["ensure"] is not None
    assert calls["scheduler"] is True
    assert demo_app.config["IS_DEMO"] is True
    assert demo_app.config["DEMO_DEFAULTS"]["user_email"] == "demo@example.com"
    assert demo_app.secret_key == "demo-secret"


def test_debug_clear_session_requires_debug(monkeypatch):
    app.app.secret_key = "test-secret"
    monkeypatch.setattr(app.app, "debug", False)

    client = app.app.test_client()
    response = client.get("/debug/clear-session")

    assert response.status_code == 404


def test_debug_clear_session_clears_session_in_debug(monkeypatch):
    app.app.secret_key = "test-secret"
    monkeypatch.setattr(app.app, "debug", True)

    client = app.app.test_client()
    with client.session_transaction() as sess:
        sess["keep"] = "nope"

    response = client.get("/debug/clear-session")

    assert response.status_code == 302
    with client.session_transaction() as sess:
        assert "keep" not in sess
