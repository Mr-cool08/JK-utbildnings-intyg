from datetime import timedelta

from status_service import status_checks


def test_format_uptime_includes_swedish_units():
    uptime = timedelta(days=1, hours=2, minutes=3, seconds=4)

    result = status_checks.format_uptime(uptime)

    assert "dagar" in result
    assert "timmar" in result
    assert "minuter" in result


def test_build_status_uses_dependency_overrides(monkeypatch):
    def fake_ssl():
        return "OK"

    def fake_db():
        return "Inte konfigurerad"

    def fake_nginx():
        return "Fel"

    monkeypatch.setattr(status_checks, "check_ssl_status", fake_ssl)
    monkeypatch.setattr(status_checks, "check_database_status", fake_db)
    monkeypatch.setattr(status_checks, "check_nginx_status", fake_nginx)

    status = status_checks.build_status(now=status_checks.START_TIME + 5)

    assert status["ssl"] == "OK"
    assert status["database"] == "Inte konfigurerad"
    assert status["nginx"] == "Fel"
    assert "sekunder" in status["uptime"]
