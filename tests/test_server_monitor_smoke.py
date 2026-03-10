import datetime as dt
import importlib.util
import logging
import sys
import types
from pathlib import Path


def _load_monitor_module(monkeypatch, **env):
    for key, value in env.items():
        monkeypatch.setenv(key, str(value))

    fake_docker = types.ModuleType("docker")
    fake_docker.DockerClient = object
    fake_docker.from_env = lambda: None
    monkeypatch.setitem(sys.modules, "docker", fake_docker)

    module_path = Path("services/server_monitor/monitor.py")
    spec = importlib.util.spec_from_file_location("server_monitor_for_tests", module_path)
    module = importlib.util.module_from_spec(spec)
    if spec.loader is None:
        raise AssertionError("Kunde inte ladda monitor-modulen.")
    spec.loader.exec_module(module)
    return module


def test_parse_smoke_targets_supports_named_and_unnamed_entries(monkeypatch):
    module = _load_monitor_module(monkeypatch)

    targets = module.parse_smoke_targets(
        "Hälsa=https://utbildningsintyg.se/health,https://status.utbildningsintyg.se"
    )

    assert targets == [
        ("Hälsa", "https://utbildningsintyg.se/health"),
        ("https://status.utbildningsintyg.se", "https://status.utbildningsintyg.se"),
    ]


def test_run_smoke_tests_records_daily_results(monkeypatch):
    module = _load_monitor_module(
        monkeypatch,
        MONITOR_SMOKE_TEST_TARGETS="Hälsa=https://a.test,Status=https://b.test",
    )
    module.DAILY_SMOKE_RESULTS.clear()

    responses = [
        {"name": "Hälsa", "url": "https://a.test", "ok": True, "details": "HTTP 200", "duration_seconds": 0.01},
        {"name": "Status", "url": "https://b.test", "ok": False, "details": "HTTP 503", "duration_seconds": 0.02},
    ]

    def _fake_run(name, url):
        for item in responses:
            if item["name"] == name:
                return item
        raise AssertionError("Okänt smoke-mål.")

    monkeypatch.setattr(module, "run_smoke_check", _fake_run)
    now = dt.datetime(2026, 3, 8, 10, 30, 0)

    summary = module.run_smoke_tests(now=now)

    assert summary["total_checks"] == 2
    assert summary["passed_checks"] == 1
    assert summary["failed_checks"] == 1
    assert summary["all_ok"] is False

    day_entries = module.DAILY_SMOKE_RESULTS[now.date()]
    assert len(day_entries) == 1
    assert day_entries[0]["failed_checks"] == 1


def test_maybe_run_smoke_tests_respects_interval(monkeypatch):
    module = _load_monitor_module(
        monkeypatch,
        MONITOR_SMOKE_TESTS_INTERVAL_SECONDS="300",
        MONITOR_SMOKE_TEST_TARGETS="Hälsa=https://a.test",
    )

    calls = []

    def _fake_run(now=None):
        calls.append(now)
        return {
            "passed_checks": 1,
            "total_checks": 1,
            "failed_checks": 0,
            "all_ok": True,
            "checks": [],
        }

    monkeypatch.setattr(module, "run_smoke_tests", _fake_run)
    module.LAST_SMOKE_RUN_AT = dt.datetime(2026, 3, 8, 10, 0, 0)

    module.maybe_run_smoke_tests(now=dt.datetime(2026, 3, 8, 10, 3, 0))
    module.maybe_run_smoke_tests(now=dt.datetime(2026, 3, 8, 10, 6, 0))

    assert len(calls) == 1
    assert calls[0] == dt.datetime(2026, 3, 8, 10, 6, 0)


def test_weekly_smoke_report_is_sent_once_and_contains_daily_rows(monkeypatch):
    module = _load_monitor_module(
        monkeypatch,
        MONITOR_SMOKE_TEST_TARGETS="Hälsa=https://a.test",
        MONITOR_SMOKE_WEEKLY_REPORT_WEEKDAY="6",
        MONITOR_SMOKE_WEEKLY_REPORT_HOUR="9",
        MONITOR_SMOKE_WEEKLY_REPORT_MINUTE="0",
    )
    module.DAILY_SMOKE_RESULTS.clear()
    module.LAST_SMOKE_WEEKLY_REPORT_ID = None

    report_now = dt.datetime(2026, 3, 8, 9, 0, 0)
    for days_back in range(7):
        day = report_now.date() - dt.timedelta(days=days_back)
        module.DAILY_SMOKE_RESULTS[day] = [
            {
                "timestamp": f"{day.isoformat()}T08:00:00",
                "checks": [{"name": "Hälsa", "ok": True}],
                "total_checks": 1,
                "passed_checks": 1,
                "failed_checks": 0,
                "all_ok": True,
            }
        ]

    sent_messages = []

    def _fake_send_email(subject, body, attachments):
        sent_messages.append({"subject": subject, "body": body, "attachments": attachments})

    monkeypatch.setattr(module, "send_email", _fake_send_email)

    module.maybe_send_weekly_smoke_report(now=report_now)
    module.maybe_send_weekly_smoke_report(now=report_now)

    assert len(sent_messages) == 1
    first_message = sent_messages[0]
    assert "Veckorapport: smoke-tester vecka" in first_message["subject"]
    assert "- 2026-03-08:" in first_message["body"]
    assert "- 2026-03-02:" in first_message["body"]
    assert first_message["attachments"] == []


def test_run_smoke_check_includes_exception_type_in_details(monkeypatch):
    module = _load_monitor_module(monkeypatch)

    def _fake_urlopen(*_args, **_kwargs):
        raise TimeoutError("begäran tog för lång tid")

    monkeypatch.setattr(module.url_request, "urlopen", _fake_urlopen)

    result = module.run_smoke_check("Huvudsidan", "https://utbildningsintyg.se/health")

    assert result["ok"] is False
    assert "TimeoutError" in result["details"]
    assert "begäran tog för lång tid" in result["details"]


def test_maybe_run_smoke_tests_logs_failure_details(monkeypatch):
    module = _load_monitor_module(monkeypatch, MONITOR_SMOKE_TEST_TARGETS="Hälsa=https://a.test")
    module.LAST_SMOKE_RUN_AT = None
    captured = {}

    def _fake_run_smoke_tests(now=None):
        return {
            "passed_checks": 0,
            "total_checks": 1,
            "failed_checks": 1,
            "all_ok": False,
            "checks": [
                {
                    "name": "Hälsa",
                    "url": "https://a.test",
                    "ok": False,
                    "details": "HTTP 503",
                    "duration_seconds": 0.123,
                }
            ],
        }

    def _fake_warning(message, *args):
        captured["message"] = message
        captured["args"] = args

    monkeypatch.setattr(module, "run_smoke_tests", _fake_run_smoke_tests)
    monkeypatch.setattr(module.logger, "warning", _fake_warning)

    module.maybe_run_smoke_tests(now=dt.datetime(2026, 3, 8, 10, 0, 0))

    rendered_log = captured["message"] % captured["args"]
    assert "Hälsa (https://a.test): HTTP 503 efter 0.123s" in rendered_log
    assert "detaljer:" in rendered_log


def test_build_heartbeat_log_message_includes_metrics_and_schedule(monkeypatch):
    module = _load_monitor_module(
        monkeypatch,
        MONITOR_SMOKE_TEST_TARGETS="Hälsa=https://a.test",
    )
    module.LAST_SMOKE_RUN_AT = dt.datetime(2026, 3, 8, 10, 0, 0)

    message = module.build_heartbeat_log_message(
        now=dt.datetime(2026, 3, 8, 10, 5, 0),
        disk_percent=12.3,
        ram_percent=45.6,
        cpu_percent=78.9,
    )

    assert "Heartbeat: övervakning aktiv 2026-03-08T10:05:00" in message
    assert "disk 12.30%" in message
    assert "RAM 45.60%" in message
    assert "CPU 78.90%" in message
    assert "smoke: 1 mål, nästa tidigast 2026-03-08T10:30:00" in message


def test_resolve_fallback_log_level_handles_invalid_values(monkeypatch):
    module = _load_monitor_module(monkeypatch)

    assert module._resolve_fallback_log_level("DEBUG") == logging.DEBUG
    assert module._resolve_fallback_log_level("warning") == logging.WARNING
    assert module._resolve_fallback_log_level("inte_en_niva") == logging.INFO
    assert module._resolve_fallback_log_level("") == logging.INFO
    assert module._resolve_fallback_log_level(None) == logging.INFO


def test_configure_fallback_logging_sets_console_handler_and_level(monkeypatch):
    module = _load_monitor_module(monkeypatch)
    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_level = root_logger.level
    try:
        root_logger.handlers = []
        root_logger.setLevel(logging.NOTSET)
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")

        configured_logger = module.configure_fallback_logging("jk.test.monitor")

        assert configured_logger.name == "jk.test.monitor"
        assert root_logger.level == logging.DEBUG
        assert any(
            isinstance(handler, logging.StreamHandler)
            for handler in root_logger.handlers
        )
    finally:
        for handler in list(root_logger.handlers):
            try:
                handler.close()
            except Exception:
                pass
        root_logger.handlers = original_handlers
        root_logger.setLevel(original_level)


# Copyright (c) Liam Suorsa and Mika Suorsa
