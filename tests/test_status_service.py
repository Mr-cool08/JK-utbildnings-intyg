# Copyright (c) Liam Suorsa and Mika Suorsa
import logging
from datetime import timedelta
from urllib import error

from status_service import status_checks
from status_service import app as status_app


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

    def fake_traefik():
        return {"status": "Fel", "details": "Test"}

    monkeypatch.setattr(status_checks, "check_ssl_status", fake_ssl)
    monkeypatch.setattr(status_checks, "check_database_status", fake_db)
    monkeypatch.setattr(status_checks, "check_traefik_status", fake_traefik)
    monkeypatch.setattr(status_checks, "get_http_check_targets", lambda: [])
    monkeypatch.setattr(status_checks, "get_country_availability", lambda: [])

    status = status_checks.build_status(now=status_checks.START_TIME + 5)

    assert status["checks"]["ssl"]["status"] == "OK"
    assert status["checks"]["database"]["status"] == "Inte konfigurerad"
    assert status["checks"]["traefik"]["status"] == "Fel"
    assert status["checks"]["nginx"]["status"] == "Fel"
    assert "sekunder" in status["uptime"]


def test_resolve_proxy_target_prefers_traefik_and_handles_invalid_port(monkeypatch, caplog):
    monkeypatch.setenv("STATUS_NGINX_HOST", "nginx-service")
    monkeypatch.setenv("STATUS_NGINX_PORT", "8081")
    monkeypatch.setenv("STATUS_TRAEFIK_HOST", "traefik-service")
    monkeypatch.setenv("STATUS_TRAEFIK_PORT", "notint")

    captured = {}

    def fake_check_tcp(host, port, timeout=2):
        _ = timeout
        captured["host"] = host
        captured["port"] = port
        return True

    monkeypatch.setattr(status_checks, "check_tcp", fake_check_tcp)

    with caplog.at_level(logging.WARNING):
        status_checks.check_traefik_status()

    assert captured["host"] == "traefik-service"
    assert captured["port"] == 80
    assert "STATUS_TRAEFIK_PORT" in caplog.text


def test_get_country_availability_parses_entries(monkeypatch):
    monkeypatch.setenv("STATUS_COUNTRY_AVAILABILITY", "Sverige=OK,Norge=Fel,Finland:Okänd")

    result = status_checks.get_country_availability()

    assert result == [
        {"name": "Sverige", "status": "OK"},
        {"name": "Norge", "status": "Fel"},
        {"name": "Finland", "status": "Okänd"},
    ]


def test_get_http_check_targets_is_hardcoded_for_primary_site():
    targets = status_checks.get_http_check_targets()

    assert targets == [
        {
            "name": "Huvudsidan",
            "url": "https://utbildningsintyg.se/health",
            "fallback_url": "http://app:80/health",
            "fallback_host_header": "utbildningsintyg.se",
        }
    ]


def test_check_ssl_status_handles_connection_refused(monkeypatch, caplog):
    def fake_urlopen(*_args, **_kwargs):
        raise error.URLError(ConnectionRefusedError(111, "Connection refused"))

    monkeypatch.setattr(status_checks.request, "urlopen", fake_urlopen)

    with caplog.at_level(logging.WARNING):
        result = status_checks.check_ssl_status()

    assert result == {"status": "Fel", "details": "Anslutning nekades"}
    assert "kunde inte ansluta" in caplog.text


def test_check_ssl_status_uses_hardcoded_primary_url(monkeypatch):

    class DummyResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    class DummyContext:
        minimum_version = None

    def fake_urlopen(req, timeout=0, context=None):
        assert req.full_url == "https://utbildningsintyg.se/health"
        assert timeout == 4
        assert context is not None
        return DummyResponse()

    monkeypatch.setattr(status_checks.ssl, "create_default_context", lambda: DummyContext())
    monkeypatch.setattr(status_checks.request, "urlopen", fake_urlopen)

    result = status_checks.check_ssl_status()

    assert result == {"status": "OK", "details": "TLS + HTTP 200"}


def test_check_ssl_status_returns_error_for_http_error(monkeypatch):

    class DummyContext:
        minimum_version = None

    def fake_urlopen(*_args, **_kwargs):
        raise error.HTTPError(
            url="https://utbildningsintyg.se/health",
            code=503,
            msg="Service unavailable",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setattr(status_checks.ssl, "create_default_context", lambda: DummyContext())
    monkeypatch.setattr(status_checks.request, "urlopen", fake_urlopen)

    result = status_checks.check_ssl_status()

    assert result == {"status": "Fel", "details": "TLS + HTTP 503"}


def test_check_http_status_handles_connection_refused(monkeypatch, caplog):
    def fake_urlopen(*_args, **_kwargs):
        raise error.URLError(ConnectionRefusedError(111, "Connection refused"))

    monkeypatch.setattr(status_checks.request, "urlopen", fake_urlopen)

    with caplog.at_level(logging.WARNING):
        result = status_checks.check_http_status("Test", "http://test")

    assert result == {"name": "Test", "status": "Fel", "details": "Anslutning nekades"}
    assert "kunde inte ansluta" in caplog.text


def test_check_http_status_uses_fallback_url(monkeypatch):
    calls = []

    class DummyResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(req, timeout=0):
        calls.append((req.full_url, req.headers.get("Host"), timeout))
        if req.full_url == "https://utbildningsintyg.se/health":
            raise error.URLError(ConnectionRefusedError(111, "Connection refused"))
        return DummyResponse()

    monkeypatch.setattr(status_checks.request, "urlopen", fake_urlopen)

    result = status_checks.check_http_status(
        "Huvudsidan",
        "https://utbildningsintyg.se/health",
        fallback_url="http://app:80/health",
        fallback_host_header="utbildningsintyg.se",
    )

    assert result["status"] == "OK"
    assert calls[0][0] == "https://utbildningsintyg.se/health"
    assert calls[1][0] == "http://app:80/health"
    assert calls[1][1] == "utbildningsintyg.se"


def test_check_ssl_status_uses_internal_fallback_url(monkeypatch):

    class DummyContext:
        minimum_version = None

    class DummyResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    calls = []

    def fake_urlopen(req, timeout=0, context=None):
        calls.append((req.full_url, req.headers.get("Host"), timeout, context))
        if req.full_url == "https://utbildningsintyg.se/health":
            raise error.URLError(ConnectionRefusedError(111, "Connection refused"))
        return DummyResponse()

    monkeypatch.setattr(status_checks.ssl, "create_default_context", lambda: DummyContext())
    monkeypatch.setattr(status_checks.request, "urlopen", fake_urlopen)

    result = status_checks.check_ssl_status()

    assert result == {"status": "OK", "details": "TLS + HTTP 200 (intern kontroll)"}
    assert calls[1][0] == "http://app:80/health"
    assert calls[1][1] == "utbildningsintyg.se"

def test_get_load_average_handles_missing_support(monkeypatch, caplog):
    def raise_os_error():
        raise OSError("unsupported")

    monkeypatch.setattr(status_checks.os, "getloadavg", raise_os_error, raising=False)

    with caplog.at_level(logging.WARNING):
        result = status_checks.get_load_average()

    assert result == {"status": "Inte tillgänglig", "details": "Inte tillgänglig"}
    assert "Systemlast kunde inte läsas" in caplog.text


def test_summarize_latency_handles_empty_input():
    result = status_checks.summarize_latency([])

    assert result == {"status": "Inte tillgänglig", "details": "Inga mätningar"}


def test_build_latency_series_skips_invalid_items():
    http_checks = [
        {"name": "Test", "response_time_ms": 120, "status": "OK", "details": "HTTP 200"},
        "not-a-dict",
    ]

    series = status_checks.build_latency_series(http_checks)

    assert series == [
        {
            "label": "Test",
            "value": 120,
            "status": "OK",
            "details": "HTTP 200",
        }
    ]




def test_check_http_status_handles_timeout_error(monkeypatch, caplog):
    def fake_urlopen(*_args, **_kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(status_checks.request, "urlopen", fake_urlopen)

    with caplog.at_level(logging.WARNING):
        result = status_checks.check_http_status("Test", "http://test")

    assert result == {"name": "Test", "status": "Fel", "details": "Timeout"}
    assert "nådde timeout" in caplog.text


def test_check_http_status_handles_timeout_inside_url_error(monkeypatch, caplog):
    def fake_urlopen(*_args, **_kwargs):
        raise error.URLError(TimeoutError("timed out"))

    monkeypatch.setattr(status_checks.request, "urlopen", fake_urlopen)

    with caplog.at_level(logging.WARNING):
        result = status_checks.check_http_status("Test", "http://test")

    assert result == {"name": "Test", "status": "Fel", "details": "Timeout"}
    assert "nådde timeout" in caplog.text

def test_check_http_status_handles_http_error(monkeypatch, caplog):
    class FakeResponse:
        def __init__(self, status):
            self.status = status

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(*_args, **_kwargs):
        return FakeResponse(503)

    monkeypatch.setattr(status_checks.request, "urlopen", fake_urlopen)

    with caplog.at_level(logging.WARNING):
        result = status_checks.check_http_status("Test", "http://test")

    assert result["status"] == "Fel"
    assert result["details"] == "HTTP 503"
    assert "response_time_ms" in result
    assert "serverfel" in caplog.text


def test_check_http_status_treats_client_error_as_reachable(monkeypatch):
    def fake_urlopen(*_args, **_kwargs):
        raise error.HTTPError(
            url="http://test",
            code=404,
            msg="Not found",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setattr(status_checks.request, "urlopen", fake_urlopen)

    result = status_checks.check_http_status("Test", "http://test")

    assert result["status"] == "Nåbar"
    assert result["details"] == "HTTP 404"


def test_check_ssl_status_treats_client_error_as_reachable(monkeypatch):
    class DummyContext:
        minimum_version = None

    def fake_urlopen(*_args, **_kwargs):
        raise error.HTTPError(
            url="https://utbildningsintyg.se/health",
            code=404,
            msg="Not found",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setattr(status_checks.ssl, "create_default_context", lambda: DummyContext())
    monkeypatch.setattr(status_checks.request, "urlopen", fake_urlopen)

    result = status_checks.check_ssl_status()

    assert result == {"status": "OK", "details": "TLS + HTTP 404"}


def test_check_tcp_returns_false_on_error(monkeypatch, caplog):
    def fake_connection(*_args, **_kwargs):
        raise OSError("connection failed")

    monkeypatch.setattr(status_checks.socket, "create_connection", fake_connection)

    with caplog.at_level(logging.WARNING):
        result = status_checks.check_tcp("localhost", 1234, timeout=0.1)

    assert result is False


def test_get_cpu_and_ram_procent_handle_exceptions(monkeypatch, caplog):
    def raise_exception(*_args, **_kwargs):
        raise Exception("boom")

    monkeypatch.setattr(status_checks.psutil, "cpu_percent", raise_exception)
    monkeypatch.setattr(status_checks.psutil, "virtual_memory", raise_exception)

    with caplog.at_level(logging.WARNING):
        cpu_result = status_checks.get_cpu_procent()
        ram_result = status_checks.get_ram_procent()

    assert cpu_result == {"status": "Inte tillgänglig", "details": "Inte tillgänglig"}
    assert ram_result == {"status": "Inte tillgänglig", "details": "Inte tillgänglig"}
    assert "kunde inte läsas" in caplog.text


def test_get_display_timestamp_uses_stockholm_timezone(monkeypatch):
    monkeypatch.delenv("APP_TIMEZONE", raising=False)
    captured = {}

    def fake_zoneinfo(name):
        captured["timezone"] = name
        return "tz-object"

    class FakeNow:
        def strftime(self, fmt):
            captured["format"] = fmt
            return "2026-01-01 12:00:00 CET"

    class FakeDateTime:
        @staticmethod
        def now(tz):
            captured["tz"] = tz
            return FakeNow()

    monkeypatch.setattr(status_app, "ZoneInfo", fake_zoneinfo)
    monkeypatch.setattr(status_app, "datetime", FakeDateTime)

    result = status_app.get_display_timestamp()

    assert result == "2026-01-01 12:00:00 CET"
    assert captured["timezone"] == "Europe/Stockholm"
    assert captured["tz"] == "tz-object"
    assert captured["format"] == "%Y-%m-%d %H:%M:%S %Z"
