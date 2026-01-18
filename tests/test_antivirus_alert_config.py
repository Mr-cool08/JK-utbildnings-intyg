from pathlib import Path


def test_antivirus_alert_env_is_configured():
    entrypoint = Path("services/antivirus/entrypoint.sh").read_text(encoding="utf-8")
    run_scan = Path("services/antivirus/run_scan.sh").read_text(encoding="utf-8")

    assert "smtp_server" in entrypoint
    assert "smtp_user" in entrypoint
    assert "CRITICAL_ALERTS_EMAIL" in entrypoint

    assert "CRITICAL_ALERTS_EMAIL" in run_scan
    assert "send_alert_email" in run_scan


# Copyright (c) Liam Suorsa
