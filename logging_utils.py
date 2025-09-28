 # Helpers for consistent logging configuration across the project.

from __future__ import annotations

import logging
from typing import Iterable


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
