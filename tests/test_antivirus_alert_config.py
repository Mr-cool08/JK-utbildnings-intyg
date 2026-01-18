from pathlib import Path


def test_antivirus_alert_env_is_configured():
    entrypoint = Path("services/antivirus/entrypoint.sh").read_text(encoding="utf-8")
    run_scan = Path("services/antivirus/run_scan.sh").read_text(encoding="utf-8")

    assert "ALERT_EMAIL_TO" in entrypoint
    assert "ALERT_EMAIL_FROM" in entrypoint
    assert "ALERT_SMTP_HOST" in entrypoint

    assert "ALERT_EMAIL_TO" in run_scan
    assert "send_alert_email" in run_scan


# Copyright (c) Liam Suorsa
