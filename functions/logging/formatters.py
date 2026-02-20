# Logging formatters with env-controlled format and timezone.

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from functions.logging.context import get_correlation_id, get_request_id


class AppTimezoneFormatter(logging.Formatter):
    # Backward compatible formatter that follows APP_TIMEZONE (default Europe/Stockholm).

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:  # noqa: N802
        timezone_name = os.getenv("APP_TIMEZONE", "Europe/Stockholm").strip() or "Europe/Stockholm"
        try:
            zone = ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError:
            zone = ZoneInfo("Europe/Stockholm")

        dt = datetime.fromtimestamp(record.created, zone)
        if datefmt:
            return dt.strftime(datefmt)
        return dt.isoformat(timespec="seconds")


class BaseTimezoneFormatter(logging.Formatter):
    def __init__(self, fmt: str | None = None, timezone_mode: str = "UTC") -> None:
        super().__init__(fmt=fmt)
        self.timezone_mode = timezone_mode.upper().strip() or "UTC"

    def _resolve_timestamp(self, created: float) -> datetime:
        if self.timezone_mode == "LOCAL":
            return datetime.fromtimestamp(created).astimezone()
        return datetime.fromtimestamp(created, tz=timezone.utc)

    def format_time_iso(self, created: float) -> str:
        return self._resolve_timestamp(created).isoformat(timespec="seconds")

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:  # noqa: N802
        dt = self._resolve_timestamp(record.created)
        if datefmt:
            return dt.strftime(datefmt)
        return dt.isoformat(timespec="seconds")


class TextFormatter(BaseTimezoneFormatter):
    def __init__(self, timezone_mode: str = "UTC") -> None:
        super().__init__(
            fmt="%(asctime)s %(levelname)s %(name)s request_id=%(request_id)s correlation_id=%(correlation_id)s %(message)s",
            timezone_mode=timezone_mode,
        )

    def format(self, record: logging.LogRecord) -> str:
        if not hasattr(record, "request_id"):
            record.request_id = get_request_id() or "-"
        if not hasattr(record, "correlation_id"):
            record.correlation_id = get_correlation_id() or "-"
        return super().format(record)


class JsonFormatter(BaseTimezoneFormatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.format_time_iso(record.created),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": get_request_id(),
            "correlation_id": get_correlation_id(),
            "module": record.module,
            "line": record.lineno,
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


# Copyright (c) Liam Suorsa
