# Copyright (c) Liam Suorsa
# Public API for logging bootstrap + masking helpers.

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from functions.logging.bootstrap import bootstrap_logging, configure_module_logger, configure_root_logging
from functions.logging.context import (
    ensure_operation_id,
    get_correlation_id,
    get_request_id,
    set_correlation_id,
    set_request_id,
)
from functions.logging.formatters import AppTimezoneFormatter

MASK_PLACEHOLDER = "***"

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
    if isinstance(data, Mapping):
        masked: dict[Any, Any] = {}
        for key, value in data.items():
            key_str = str(key).lower()
            if key_str in _SENSITIVE_KEYS:
                masked[key] = MASK_PLACEHOLDER
            else:
                masked[key] = mask_sensitive_data(value)
        return masked
    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray)):
        return [mask_sensitive_data(item) for item in data]
    return data


def mask_headers(headers: Mapping[str, str]) -> dict[str, str]:
    masked: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in _SENSITIVE_KEYS:
            masked[key] = MASK_PLACEHOLDER
        else:
            masked[key] = value
    return masked


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
        except OSError:
            continue
    return attachments


def mask_hash(value: str, prefix: int = 10) -> str:
    if not value:
        return MASK_PLACEHOLDER
    trimmed = value[:prefix]
    return f"{trimmed}…" if len(value) > prefix else trimmed


def mask_personnummer(value: str) -> str:
    digits = "".join(ch for ch in value if ch.isdigit())
    if not digits:
        return MASK_PLACEHOLDER
    return f"{MASK_PLACEHOLDER}{digits[-4:]}"


def mask_email(value: str) -> str:
    if not value or "@" not in value:
        return MASK_PLACEHOLDER
    local, domain = value.split("@", 1)
    if not local:
        return f"{MASK_PLACEHOLDER}@{domain}"
    return f"{local[0]}***@{domain}"
