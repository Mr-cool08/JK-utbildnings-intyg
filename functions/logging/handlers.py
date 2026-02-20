# Logging handlers for application bootstrap.

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler

from functions.logging.formatters import JsonFormatter, TextFormatter


def build_standard_handlers(log_format: str, timezone_mode: str) -> list[logging.Handler]:
    handlers: list[logging.Handler] = []
    formatter: logging.Formatter
    if log_format == "json":
        formatter = JsonFormatter(timezone_mode=timezone_mode)
    else:
        formatter = TextFormatter(timezone_mode=timezone_mode)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    handlers.append(console_handler)

    log_dir = os.getenv("LOG_DIR", "logs")
    log_file = os.getenv("LOG_FILE", os.path.join(log_dir, "app.log"))
    max_bytes = int(os.getenv("LOG_MAX_BYTES", str(5 * 1024 * 1024)))
    backup_count = int(os.getenv("LOG_BACKUP_COUNT", "5"))

    os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
    file_handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
    file_handler.setFormatter(formatter)
    handlers.append(file_handler)

    return handlers


# Copyright (c) Liam Suorsa
