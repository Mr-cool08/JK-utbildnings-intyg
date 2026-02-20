# Root logging bootstrap used by all services.

from __future__ import annotations

import logging
import os
from typing import Iterable, Sequence

from functions.logging.formatters import JsonFormatter, TextFormatter

_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_VALID_FORMATS = {"text", "json"}
_VALID_TIMEZONES = {"UTC", "LOCAL"}


def _resolve_log_level(level_env_vars: Sequence[str]) -> int:
    for env_var in level_env_vars:
        value = os.getenv(env_var)
        if value:
            normalized = value.strip().upper()
            if normalized in _VALID_LOG_LEVELS:
                return getattr(logging, normalized)
    return logging.INFO


def _resolve_log_format() -> str:
    value = os.getenv("LOG_FORMAT", "text").strip().lower()
    return value if value in _VALID_FORMATS else "text"


def _resolve_timezone_mode() -> str:
    value = os.getenv("LOG_TIMEZONE", "UTC").strip().upper()
    return value if value in _VALID_TIMEZONES else "UTC"


def _build_standard_handlers(log_format: str, timezone_mode: str) -> list[logging.Handler]:
    formatter: logging.Formatter
    if log_format == "json":
        formatter = JsonFormatter(timezone_mode=timezone_mode)
    else:
        formatter = TextFormatter(timezone_mode=timezone_mode)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    return [console_handler]


def configure_root_logging(level_env_vars: Sequence[str] = ("LOG_LEVEL",), force: bool = False) -> None:
    """Configure root logger once per process.

    Uses environment variables:
    - LOG_LEVEL (default INFO)
    - LOG_FORMAT (text|json, default text)
    - LOG_TIMEZONE (UTC|LOCAL, default UTC)
    """

    root = logging.getLogger()
    already_configured = getattr(root, "_jk_root_bootstrapped", False)
    if already_configured and root.handlers and not force:
        root.setLevel(_resolve_log_level(level_env_vars))
        return

    for handler in list(root.handlers):
        root.removeHandler(handler)

    level = _resolve_log_level(level_env_vars)
    log_format = _resolve_log_format()
    timezone_mode = _resolve_timezone_mode()

    for handler in _build_standard_handlers(log_format=log_format, timezone_mode=timezone_mode):
        root.addHandler(handler)

    root.setLevel(level)
    setattr(root, "_jk_root_bootstrapped", True)


def configure_module_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if getattr(logger, "_jk_configured", False):
        return logger

    root_logger = logging.getLogger()
    handlers: Iterable[logging.Handler]
    if root_logger.handlers:
        handlers = root_logger.handlers
    else:
        configure_root_logging(force=True)
        handlers = root_logger.handlers

    for handler in handlers:
        logger.addHandler(handler)

    if logger.level == logging.NOTSET:
        logger.setLevel(root_logger.level or logging.INFO)

    logger.propagate = False
    setattr(logger, "_jk_configured", True)
    return logger


def bootstrap_logging(module_name: str, level_env_vars: Sequence[str] = ("LOG_LEVEL",)) -> logging.Logger:
    configure_root_logging(level_env_vars=level_env_vars)
    return configure_module_logger(module_name)


# Copyright (c) Liam Suorsa
