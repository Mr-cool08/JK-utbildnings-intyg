from scripts.failover.cloudflare_failover import (
    HealthState,
    determine_target,
    parse_hostname,
    should_use_fallback,
)


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

# Copyright (c) Liam Suorsa and Mika Suorsa
