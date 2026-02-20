# Copyright (c) Liam Suorsa
import logging
from datetime import datetime, timezone

from functions import logging as logging_utils


def test_configure_module_logger_inits_without_root_handlers():
    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_level = root_logger.level
    try:
        root_logger.handlers = []
        root_logger.setLevel(logging.NOTSET)

        logger = logging_utils.configure_module_logger("jk.test")

        assert logger.handlers == root_logger.handlers
        assert len(logger.handlers) == 1
        assert logger.propagate is False
        assert logger.level == logging.INFO
    finally:
        root_logger.handlers = original_handlers
        root_logger.setLevel(original_level)


def test_configure_module_logger_reuses_existing_handlers():
    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_level = root_logger.level
    try:
        handler = logging.StreamHandler()
        root_logger.handlers = [handler]
        root_logger.setLevel(logging.WARNING)

        logger = logging_utils.configure_module_logger("jk.reuse")
        second_call_logger = logging_utils.configure_module_logger("jk.reuse")

        assert logger is second_call_logger
        assert logger.handlers == [handler]
        assert logger.propagate is False
        assert getattr(logger, "_jk_configured", False) is True
    finally:
        root_logger.handlers = original_handlers
        root_logger.setLevel(original_level)


def test_app_timezone_formatter_uses_stockholm_by_default(monkeypatch):
    monkeypatch.delenv("APP_TIMEZONE", raising=False)
    formatter = logging_utils.AppTimezoneFormatter("%(asctime)s")
    record = logging.LogRecord(
        name="jk.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="Hej",
        args=(),
        exc_info=None,
    )
    record.created = datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc).timestamp()

    rendered = formatter.formatTime(record)

    assert rendered.startswith("2025-01-01T13:00:00")


def test_app_timezone_formatter_falls_back_to_stockholm_for_invalid_timezone(monkeypatch):
    monkeypatch.setenv("APP_TIMEZONE", "Mars/Olympus")
    formatter = logging_utils.AppTimezoneFormatter("%(asctime)s")
    record = logging.LogRecord(
        name="jk.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="Hej",
        args=(),
        exc_info=None,
    )
    record.created = datetime(2025, 6, 1, 12, 0, tzinfo=timezone.utc).timestamp()

    rendered = formatter.formatTime(record)

    assert rendered.startswith("2025-06-01T14:00:00")


def test_configure_root_logging_uses_first_available_env_var(monkeypatch):
    monkeypatch.setenv("STATUS_LOG_LEVEL", "warning")
    monkeypatch.delenv("LOG_LEVEL", raising=False)

    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_level = root_logger.level
    try:
        root_logger.handlers = []
        root_logger.setLevel(logging.NOTSET)

        logging_utils.configure_root_logging(level_env_vars=("STATUS_LOG_LEVEL", "LOG_LEVEL"))

        assert root_logger.level == logging.WARNING
    finally:
        for handler in list(root_logger.handlers):
            try:
                handler.close()
            except Exception:
                pass
        root_logger.handlers = original_handlers
        root_logger.setLevel(original_level)


def test_bootstrap_logging_returns_configured_module_logger(monkeypatch):
    monkeypatch.setenv("STATUS_LOG_LEVEL", "error")

    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_level = root_logger.level
    target_logger = logging.getLogger("jk.bootstrap")
    original_target_handlers = list(target_logger.handlers)
    original_target_level = target_logger.level
    original_target_propagate = target_logger.propagate
    had_config_flag = hasattr(target_logger, "_jk_configured")
    original_config_flag = getattr(target_logger, "_jk_configured", False)

    try:
        root_logger.handlers = []
        root_logger.setLevel(logging.NOTSET)
        target_logger.handlers = []
        target_logger.setLevel(logging.NOTSET)
        target_logger.propagate = True
        if had_config_flag:
            delattr(target_logger, "_jk_configured")

        logger = logging_utils.bootstrap_logging(
            "jk.bootstrap",
            level_env_vars=("STATUS_LOG_LEVEL", "LOG_LEVEL"),
        )

        assert logger is target_logger
        assert logger.propagate is False
        assert logger.level == logging.ERROR
        assert root_logger.level == logging.ERROR
        assert len(logger.handlers) >= 1
    finally:
        for handler in list(root_logger.handlers):
            try:
                handler.close()
            except Exception:
                pass
        root_logger.handlers = original_handlers
        root_logger.setLevel(original_level)
        target_logger.handlers = original_target_handlers
        target_logger.setLevel(original_target_level)
        target_logger.propagate = original_target_propagate
        if had_config_flag:
            setattr(target_logger, "_jk_configured", original_config_flag)
        elif hasattr(target_logger, "_jk_configured"):
            delattr(target_logger, "_jk_configured")
