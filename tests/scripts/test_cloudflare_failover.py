import json

import pytest

import scripts.failover.cloudflare_failover as cf
from scripts.failover.cloudflare_failover import (
    HealthState,
    determine_target,
    parse_hostname,
    should_use_fallback,
)


class _FakeResponse:
    def __init__(self, payload=None, status_code=200):
        self._payload = payload or {"success": True}
        self._status_code = status_code

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return json.dumps(self._payload).encode("utf-8")

    def getcode(self):
        return self._status_code


def test_parse_hostname_supports_full_url():
    assert parse_hostname("https://jk-utbildnings-intyg.onrender.com") == (
        "jk-utbildnings-intyg.onrender.com"
    )


def test_parse_hostname_keeps_plain_host():
    assert parse_hostname("utbildningsintyg.se") == "utbildningsintyg.se"


def test_should_use_fallback_when_main_down():
    assert should_use_fallback(HealthState(main_ok=False, traefik_ok=True))


def test_should_use_fallback_when_traefik_down():
    assert should_use_fallback(HealthState(main_ok=True, traefik_ok=False))


def test_determine_target_uses_primary_only_when_both_ok():
    assert determine_target(
        HealthState(main_ok=True, traefik_ok=True),
        "utbildningsintyg.se",
        "jk-utbildnings-intyg.onrender.com",
    ) == ("utbildningsintyg.se", "primary")


def test_determine_target_uses_fallback_when_any_check_fails():
    assert determine_target(
        HealthState(main_ok=False, traefik_ok=True),
        "utbildningsintyg.se",
        "jk-utbildnings-intyg.onrender.com",
    ) == ("jk-utbildnings-intyg.onrender.com", "failover")


def test_http_ok_rejects_non_http_scheme():
    assert cf.http_ok("ftp://example.org/health", 2.0) is False


def test_update_dns_record_omits_proxied_when_missing(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout=20):
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        return _FakeResponse({"success": True})

    monkeypatch.setattr(cf, "urlopen", fake_urlopen)

    cf.update_dns_record(
        api_token="token",
        zone_id="zone",
        record_id="record",
        record={"type": "A", "name": "example.org", "ttl": 120},
        target="1.2.3.4",
        timeout_seconds=20.0,
    )

    assert "proxied" not in captured["payload"]


def test_update_dns_record_rejects_unsupported_record_type():
    with pytest.raises(RuntimeError):
        cf.update_dns_record(
            api_token="token",
            zone_id="zone",
            record_id="record",
            record={"type": "TXT", "name": "example.org", "ttl": 120},
            target="hello",
            timeout_seconds=20.0,
        )

def test_parse_positive_timeout_uses_default_when_invalid(monkeypatch):
    monkeypatch.setenv("FAILOVER_HTTP_TIMEOUT_SECONDS", "abc")
    assert cf.parse_positive_timeout("FAILOVER_HTTP_TIMEOUT_SECONDS", 8.0) == 8.0


def test_parse_positive_timeout_uses_default_when_non_positive(monkeypatch):
    monkeypatch.setenv("FAILOVER_HTTP_TIMEOUT_SECONDS", "0")
    assert cf.parse_positive_timeout("FAILOVER_HTTP_TIMEOUT_SECONDS", 8.0) == 8.0


def test_parse_positive_timeout_accepts_valid_value(monkeypatch):
    monkeypatch.setenv("FAILOVER_HTTP_TIMEOUT_SECONDS", "3.5")
    assert cf.parse_positive_timeout("FAILOVER_HTTP_TIMEOUT_SECONDS", 8.0) == 3.5

# Copyright (c) Liam Suorsa and Mika Suorsa
