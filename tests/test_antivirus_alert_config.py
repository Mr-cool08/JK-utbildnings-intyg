from pathlib import Path


def test_antivirus_alert_env_is_configured():
    entrypoint = Path("services/antivirus/entrypoint.sh").read_text(encoding="utf-8")
    run_scan = Path("services/antivirus/run_scan.sh").read_text(encoding="utf-8")

    assert "SMTP_SERVER" in entrypoint
    assert "SMTP_USER" in entrypoint
    assert "CRITICAL_ALERTS_EMAIL" in entrypoint

    assert "CRITICAL_ALERTS_EMAIL" in run_scan
    assert "send_alert_email" in run_scan


def test_antivirus_send_alert_email_command_present():
    run_scan = Path("services/antivirus/run_scan.sh").read_text(encoding="utf-8")

    assert 'mail -s "${ALERT_EMAIL_SUBJECT}"' in run_scan
    assert '-r "${SMTP_USER}"' in run_scan
    assert '"${CRITICAL_ALERTS_EMAIL}"' in run_scan
    assert '[ -z "${SMTP_SERVER}" ]' in run_scan
    assert '[ -z "${SMTP_USER}" ]' in run_scan
    assert '[ -z "${SMTP_PASSWORD}" ]' in run_scan
    assert 'awk \'/ FOUND$/ {print "- " $0}\'' in run_scan


def test_antivirus_does_not_copy_or_move_infected_files():
    run_scan = Path("services/antivirus/run_scan.sh").read_text(encoding="utf-8")

    assert "--copy=" not in run_scan
    assert "--move=" not in run_scan
    assert "ignoreras. Inga filer flyttas eller kopieras." in run_scan


# Copyright (c) Liam Suorsa and Mika Suorsa
