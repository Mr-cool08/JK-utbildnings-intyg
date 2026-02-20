# Copyright (c) Liam Suorsa
# Helpers for consistent logging configuration across the project.

from __future__ import annotations

import logging
import os
import threading
from functools import lru_cache
from datetime import datetime, timedelta, timezone, tzinfo
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Iterable, Mapping, Sequence, Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MASK_PLACEHOLDER = "***"

_TZ_WARNING_STATE = threading.local()


class AppTimezoneFormatter(logging.Formatter):
    # Formattera loggtider i applikationens tidszon (standard: Europe/Stockholm).

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        timezone_name = os.getenv("APP_TIMEZONE", "Europe/Stockholm").strip() or "Europe/Stockholm"
        zone = _resolve_timezone(timezone_name)

        dt = datetime.fromtimestamp(record.created, zone)
        if datefmt:
            return dt.strftime(datefmt)
        return dt.isoformat(timespec="seconds")


@lru_cache(maxsize=None)
def _resolve_timezone(timezone_name: str) -> tzinfo:
    # Resolve timezone and gracefully handle environments without tzdata.
    try:
        return ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        if timezone_name != "Europe/Stockholm":
            logger = logging.getLogger(__name__)
            if not getattr(_TZ_WARNING_STATE, "active", False):
                _TZ_WARNING_STATE.active = True
                try:
                    logger.warning(
                        "Tidszonen %s kunde inte laddas eftersom tzdata saknas; använder Europe/Stockholm som fallback.",
                        timezone_name,
                    )
                finally:
                    _TZ_WARNING_STATE.active = False
            return _resolve_timezone("Europe/Stockholm")
        return _StockholmFallbackTimezone()


class _StockholmFallbackTimezone(tzinfo):
    # A timezone fallback for Europe/Stockholm when IANA timezone data is unavailable.

    def utcoffset(self, dt):
        return timedelta(hours=1) + self.dst(dt)

    def tzname(self, dt):
        dst_offset = self.dst(dt)
        if dst_offset != timedelta(0):
            return "CEST"
        return "CET"

    def dst(self, dt):
        if dt is None:
            return timedelta(0)

        utc_candidate = (dt.replace(tzinfo=None) - timedelta(hours=1)).replace(tzinfo=timezone.utc)
        if _is_stockholm_summer_time(utc_candidate):
            return timedelta(hours=1)
        return timedelta(0)


def _is_stockholm_summer_time(dt_utc: datetime) -> bool:
    # Stockholm follows CET/CEST and changes at 01:00 UTC.
    year = dt_utc.year
    dst_start_day = _last_sunday_of_month(year, 3)
    dst_end_day = _last_sunday_of_month(year, 10)

    dst_start = datetime(year, 3, dst_start_day, 1, 0, tzinfo=timezone.utc)
    dst_end = datetime(year, 10, dst_end_day, 1, 0, tzinfo=timezone.utc)
    return dst_start <= dt_utc < dst_end


def _last_sunday_of_month(year: int, month: int) -> int:
    # Return the day number of the last Sunday in a month.
    next_year = year + 1 if month == 12 else year
    next_month_value = 1 if month == 12 else month + 1
    next_month = datetime(next_year, next_month_value, 1)
    last_day = next_month - timedelta(days=1)
    return last_day.day - ((last_day.weekday() + 1) % 7)


def configure_module_logger(name: str) -> logging.Logger:
    # Return a module logger configured to avoid duplicate log output.
    logger = logging.getLogger(name)
    if getattr(logger, "_jk_configured", False):
        return logger

    root_logger = logging.getLogger()
    handlers: Iterable[logging.Handler]
    if root_logger.handlers:
        handlers = root_logger.handlers
    else:
        handler = logging.StreamHandler()
        handler.setFormatter(AppTimezoneFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        root_logger.addHandler(handler)
        handlers = (handler,)

    for handler in handlers:
        logger.addHandler(handler)

    if logger.level == logging.NOTSET:
        logger.setLevel(root_logger.level or logging.INFO)

    logger.propagate = False
    setattr(logger, "_jk_configured", True)
    return logger


_SENSITIVE_KEYS = {
    "password",
    "pass",
    "passwd",
    "token",
    "secret",
    "authorization",
    "cookie",
    "set-cookie",
    "database_url",
    "postgres_password",
    "secret_key",
    "smtp_password",
    "api_key",
    "apikey",
    "key",
}


def mask_sensitive_data(data: Any) -> Any:
    # Mask sensitive fields in dicts/lists to avoid leaking secrets to logs.
    if isinstance(data, Mapping):
        masked: dict[Any, Any] = {}
        for key, value in data.items():
            key_str = str(key).lower()
            if key_str in _SENSITIVE_KEYS:
                masked[key] = "***"
            else:
                masked[key] = mask_sensitive_data(value)
        return masked
    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray)):
        return [mask_sensitive_data(item) for item in data]
    return data


def mask_headers(headers: Mapping[str, str]) -> dict[str, str]:
    # Mask sensitive headers for logging.
    masked: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in _SENSITIVE_KEYS:
            masked[key] = "***"
        else:
            masked[key] = value
    return masked


def _resolve_log_level(level_env_vars: Sequence[str]) -> str:
    # Resolve log level from the first configured environment variable.
    for env_var in level_env_vars:
        value = os.getenv(env_var)
        if value:
            return value.upper()
    return "INFO"


def configure_root_logging(level_env_vars: Sequence[str] = ("LOG_LEVEL",)) -> None:
    # Configure root logging with console + rotating file handler.
    log_level = _resolve_log_level(level_env_vars)
    log_dir = os.getenv("LOG_DIR", "logs")
    default_log_file = os.path.join(log_dir, "app.log")
    log_file = os.getenv("LOG_FILE", default_log_file)
    max_bytes = int(os.getenv("LOG_MAX_BYTES", str(5 * 1024 * 1024)))
    backup_count = int(os.getenv("LOG_BACKUP_COUNT", "5"))

    root = logging.getLogger()
    os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
    formatter = AppTimezoneFormatter("%(asctime)s %(levelname)s %(module)s %(funcName)s: %(message)s")
    has_stream_handler = any(
        isinstance(handler, logging.StreamHandler) for handler in root.handlers
    )
    has_file_handler = any(
        isinstance(handler, RotatingFileHandler)
        and getattr(handler, "baseFilename", None) == os.path.abspath(log_file)
        for handler in root.handlers
    )

    if not has_stream_handler:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        root.addHandler(console_handler)

    if not has_file_handler:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    root.setLevel(log_level)

    # Attach email handler for ERROR and CRITICAL level logs
    try:
        from functions.notifications.critical_events import EmailErrorHandler
        has_email_handler = any(
            isinstance(handler, EmailErrorHandler) for handler in root.handlers
        )
        if not has_email_handler:
            email_handler = EmailErrorHandler()
            email_handler.setFormatter(formatter)
            root.addHandler(email_handler)
    except Exception:
        # Silently fail if email handler can't be attached (e.g., during early initialization)
        pass


def bootstrap_logging(
    module_name: str,
    level_env_vars: Sequence[str] = ("LOG_LEVEL",),
) -> logging.Logger:
    # Configure root logging and return a configured module logger.
    configure_root_logging(level_env_vars=level_env_vars)
    return configure_module_logger(module_name)


def _iter_configured_loggers() -> Iterable[logging.Logger]:
    root = logging.getLogger()
    yield root
    manager = logging.Logger.manager
    for logger in manager.loggerDict.values():
        if isinstance(logger, logging.PlaceHolder):
            continue
        if isinstance(logger, logging.Logger):
            yield logger


def collect_log_attachments() -> list[tuple[str, bytes]]:
    # Collect log files from all configured loggers.
    paths: set[str] = set()
    for logger in _iter_configured_loggers():
        for handler in logger.handlers:
            path = getattr(handler, "baseFilename", None)
            if path:
                paths.add(path)

    attachments: list[tuple[str, bytes]] = []
    for path in sorted(paths):
        try:
            with open(path, "rb") as fh:
                content = fh.read()
            attachments.append((Path(path).name, content))
        except Exception:
            continue
    return attachments


def mask_hash(value: str, prefix: int = 10) -> str:
    # Return a shortened representation of a hash value for logging.
    if not value:
        return MASK_PLACEHOLDER

    trimmed = value[:prefix]
    return f"{trimmed}…" if len(value) > prefix else trimmed


def mask_personnummer(value: str) -> str:
    # Mask all but the last four digits of a personnummer for logging.
    digits = "".join(ch for ch in value if ch.isdigit())
    if not digits:
        return MASK_PLACEHOLDER

    tail = digits[-4:]
    return f"{MASK_PLACEHOLDER}{tail}"


def mask_email(value: str) -> str:
    # Mask the local part of an email address for logging purposes.
    if not value or "@" not in value:
        return MASK_PLACEHOLDER

    local, domain = value.split("@", 1)
    if not local:
        return f"{MASK_PLACEHOLDER}@{domain}"

    return f"{local[0]}***@{domain}"
