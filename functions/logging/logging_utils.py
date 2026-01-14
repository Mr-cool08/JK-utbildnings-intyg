# Helpers for consistent logging configuration across the project.

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

MASK_PLACEHOLDER = "***"


def configure_module_logger(name: str) -> logging.Logger:
    # Return a module logger configured to avoid duplicate log output.

    # The application runs under different WSGI servers depending on the
    # environment (development Flask server, gunicorn, tests, etc.).  Several of
    # these set up their own handlers on the root logger which can result in the
    # same log record being emitted multiple times when module loggers propagate
    # to the root.

    # This helper reuses the root handlers but disables propagation on the module
    # logger so that each log record is handled exactly once, regardless of how
    # many handlers the root logger has.  If no root handlers exist we create a
    # simple ``StreamHandler`` so logs are still visible during local execution.

    logger = logging.getLogger(name)
    if getattr(logger, "_jk_configured", False):
        return logger

    root_logger = logging.getLogger()
    handlers: Iterable[logging.Handler]
    if root_logger.handlers:
        handlers = root_logger.handlers
    else:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
        root_logger.addHandler(handler)
        handlers = (handler,)

    for handler in handlers:
        logger.addHandler(handler)

    if logger.level == logging.NOTSET:
        logger.setLevel(root_logger.level or logging.INFO)

    logger.propagate = False
    setattr(logger, "_jk_configured", True)
    return logger


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
    """Return a shortened representation of a hash value for logging."""

    if not value:
        return MASK_PLACEHOLDER

    trimmed = value[:prefix]
    return f"{trimmed}…" if len(value) > prefix else trimmed


def mask_personnummer(value: str) -> str:
    """Mask all but the last four digits of a personnummer for logging."""

    digits = "".join(ch for ch in value if ch.isdigit())
    if not digits:
        return MASK_PLACEHOLDER

    tail = digits[-4:]
    return f"{MASK_PLACEHOLDER}{tail}"


def mask_email(value: str) -> str:
    """Mask the local part of an email address for logging purposes."""

    if not value or "@" not in value:
        return MASK_PLACEHOLDER

    local, domain = value.split("@", 1)
    if not local:
        return f"{MASK_PLACEHOLDER}@{domain}"

    return f"{local[0]}***@{domain}"
