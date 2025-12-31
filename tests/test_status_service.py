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


def test_get_http_check_targets_defaults_to_internal_services(monkeypatch):
    monkeypatch.delenv("STATUS_MAIN_URL", raising=False)
    monkeypatch.delenv("STATUS_DEMO_URL", raising=False)
    monkeypatch.delenv("STATUS_EXTRA_HTTP_CHECKS", raising=False)

    targets = status_checks.get_http_check_targets()

    assert targets == [
        {"name": "Huvudsidan", "url": "http://app/health"},
        {"name": "Demosidan", "url": "http://app_demo/health"},
    ]


def test_check_ssl_status_handles_connection_refused(monkeypatch, caplog):
    def fake_connection(*_args, **_kwargs):
        raise ConnectionRefusedError(111, "Connection refused")

    monkeypatch.setattr(status_checks.socket, "create_connection", fake_connection)

    with caplog.at_level(logging.WARNING):
        result = status_checks.check_ssl_status()

    assert result == {"status": "Fel", "details": "Anslutning nekades"}
    assert "kunde inte ansluta" in caplog.text


def test_check_http_status_handles_connection_refused(monkeypatch, caplog):
    def fake_urlopen(*_args, **_kwargs):
        raise error.URLError(ConnectionRefusedError(111, "Connection refused"))

    monkeypatch.setattr(status_checks.request, "urlopen", fake_urlopen)

    with caplog.at_level(logging.WARNING):
        result = status_checks.check_http_status("Test", "http://test")

    assert result == {"name": "Test", "status": "Fel", "details": "Anslutning nekades"}
    assert "kunde inte ansluta" in caplog.text

def test_get_load_average_handles_missing_support(monkeypatch, caplog):
    def raise_os_error():
        raise OSError("unsupported")

    monkeypatch.setattr(status_checks.os, "getloadavg", raise_os_error)

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
    assert "oväntad statuskod" in caplog.text


def test_check_tcp_returns_false_on_error(monkeypatch, caplog):
    def fake_connection(*_args, **_kwargs):
        raise OSError("connection failed")

    monkeypatch.setattr(status_checks.socket, "create_connection", fake_connection)

    with caplog.at_level(logging.ERROR):
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
