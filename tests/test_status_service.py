import contextlib
import logging
from datetime import timedelta
from urllib import error

from status_service import status_checks


def test_format_uptime_includes_swedish_units():
    uptime = timedelta(days=1, hours=2, minutes=3, seconds=4)

    result = status_checks.format_uptime(uptime)

    assert "dagar" in result
    assert "timmar" in result
    assert "minuter" in result


def test_build_status_uses_dependency_overrides(monkeypatch):
    def fake_ssl():
        return {"status": "OK", "details": "Test"}

    def fake_db():
        return {"status": "Inte konfigurerad", "details": "Test"}

    def fake_nginx():
        return {"status": "Fel", "details": "Test"}

    monkeypatch.setattr(status_checks, "check_ssl_status", fake_ssl)
    monkeypatch.setattr(status_checks, "check_database_status", fake_db)
    monkeypatch.setattr(status_checks, "check_nginx_status", fake_nginx)
    monkeypatch.setattr(status_checks, "get_http_check_targets", lambda: [])
    monkeypatch.setattr(status_checks, "get_country_availability", lambda: [])

    status = status_checks.build_status(now=status_checks.START_TIME + 5)

    assert status["checks"]["ssl"]["status"] == "OK"
    assert status["checks"]["database"]["status"] == "Inte konfigurerad"
    assert status["checks"]["nginx"]["status"] == "Fel"
    assert "sekunder" in status["uptime"]


def test_get_country_availability_parses_entries(monkeypatch):
    monkeypatch.setenv("STATUS_COUNTRY_AVAILABILITY", "Sverige=OK,Norge=Fel,Finland:Okänd")

    result = status_checks.get_country_availability()

    assert result == [
        {"name": "Sverige", "status": "OK"},
        {"name": "Norge", "status": "Fel"},
        {"name": "Finland", "status": "Okänd"},
    ]


def test_get_http_check_targets_includes_extras(monkeypatch):
    monkeypatch.setenv("STATUS_MAIN_URL", "https://huvudsida.test/health")
    monkeypatch.setenv("STATUS_DEMO_URL", "https://demo.test/health")
    monkeypatch.setenv(
        "STATUS_EXTRA_HTTP_CHECKS",
        "API|https://api.test/health,CDN|https://cdn.test/status",
    )

    targets = status_checks.get_http_check_targets()

    assert targets == [
        {"name": "Huvudsidan", "url": "https://huvudsida.test/health"},
        {"name": "Demosidan", "url": "https://demo.test/health"},
        {"name": "API", "url": "https://api.test/health"},
        {"name": "CDN", "url": "https://cdn.test/status"},
    ]


def test_check_ssl_status_handles_connection_refused(monkeypatch, caplog):
    def fake_connection(*_args, **_kwargs):
        raise ConnectionRefusedError(111, "Connection refused")

    monkeypatch.setattr(
        status_checks.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(None, None, None, None, ("host", 443))],
    )
    monkeypatch.setattr(status_checks.socket, "create_connection", fake_connection)

    with caplog.at_level(logging.WARNING):
        result = status_checks.check_ssl_status()

    assert result == {"status": "Fel", "details": "Anslutning nekades"}
    assert "kunde inte ansluta" in caplog.text


def test_check_ssl_status_tries_multiple_addresses(monkeypatch):
    addresses = [
        (None, None, None, None, ("first", 443)),
        (None, None, None, None, ("second", 443)),
    ]

    def fake_connection(address, *_args, **_kwargs):
        if address == ("first", 443):
            raise ConnectionRefusedError(111, "Connection refused")
        return contextlib.nullcontext()

    class DummyContext:
        minimum_version = None

        def wrap_socket(self, *_args, **_kwargs):
            return contextlib.nullcontext()

    monkeypatch.setattr(status_checks.socket, "getaddrinfo", lambda *_args, **_kwargs: addresses)
    monkeypatch.setattr(status_checks.socket, "create_connection", fake_connection)
    monkeypatch.setattr(status_checks.ssl, "create_default_context", lambda: DummyContext())

    result = status_checks.check_ssl_status()

    assert result == {"status": "OK", "details": "TLS-handshake lyckades"}


def test_check_http_status_handles_connection_refused(monkeypatch, caplog):
    def fake_urlopen(*_args, **_kwargs):
        raise error.URLError(ConnectionRefusedError(111, "Connection refused"))

    monkeypatch.setattr(status_checks.request, "urlopen", fake_urlopen)

    with caplog.at_level(logging.WARNING):
        result = status_checks.check_http_status("Test", "http://test")

    assert result == {"name": "Test", "status": "Fel", "details": "Anslutning nekades"}
    assert "kunde inte ansluta" in caplog.text
