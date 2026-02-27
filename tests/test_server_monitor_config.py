from pathlib import Path


def test_server_monitor_service_exists_in_compose_files():
    dev_compose = Path("docker-compose.yml").read_text(encoding="utf-8")
    prod_compose = Path("docker-compose.prod.yml").read_text(encoding="utf-8")

    assert "server_monitor:" in dev_compose
    assert "server_monitor:" in prod_compose
    assert "CRITICAL_ALERTS_EMAIL" in dev_compose
    assert "CRITICAL_ALERTS_EMAIL" in prod_compose


def test_prod_compose_routes_mta_sts_via_app_service():
    prod_compose = Path("docker-compose.prod.yml").read_text(encoding="utf-8")

    assert "mta_sts:" not in prod_compose
    assert "Host(`mta-sts.utbildningsintyg.se`) && Path(`/.well-known/mta-sts.txt`)" in prod_compose
    assert "traefik.http.routers.app-mta-sts.middlewares=security-headers@file" in prod_compose


def test_mta_sts_policy_file_has_expected_content():
    policy_content = Path("deploy/mta-sts/.well-known/mta-sts.txt").read_text(encoding="utf-8")

    assert policy_content == (
        "version: STSv1\n"
        "mode: testing\n"
        "mx: webmail.internetport.se\n"
        "max_age: 86400\n"
    )


def test_monitor_thresholds_are_configured():
    monitor_script = Path("services/server_monitor/monitor.py").read_text(encoding="utf-8")

    assert "DISK_THRESHOLDS = [50, 60, 75, 95, 100]" in monitor_script
    assert "RAM_THRESHOLD = 80" in monitor_script
    assert "CPU_THRESHOLD = 90" in monitor_script
    assert "Nattlig ClamAV-rapport" in monitor_script


def test_collect_container_resource_usage_guards_none_stats():
    monitor_script = Path("services/server_monitor/monitor.py").read_text(encoding="utf-8")

    assert 'stats.get("blkio_stats", {}).get("io_service_bytes_recursive") or []' in monitor_script
    assert 'stats.get("networks") or {}' in monitor_script


def test_send_email_handles_smtp_timeouts_gracefully():
    monitor_script = Path("services/server_monitor/monitor.py").read_text(encoding="utf-8")

    assert "except (smtplib.SMTPException, TimeoutError, OSError) as exc:" in monitor_script
    assert 'logger.error("Kunde inte skicka e-postvarning: %s", str(exc))' in monitor_script


# Copyright (c) Liam Suorsa and Mika Suorsa
