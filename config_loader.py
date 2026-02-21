# Copyright (c) Liam Suorsa and Mika Suorsa
# Utilities for loading environment variables from configuration files.

from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Iterable

from dotenv import load_dotenv


logger = logging.getLogger(__name__)


def _as_bool(value: str | None) -> bool:
    # Tolka strängar som booleska värden.
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "on", "ja", "yes"}


def _log_dev_mode_status() -> None:
    # Logga om DEV_MODE är aktiverat för utvecklingsrelaterad felsökning.
    raw = os.getenv("DEV_MODE")
    if raw is None or raw.strip() == "":
        return

    dev_mode = _as_bool(raw)
    normalized = "true" if dev_mode else "false"
    logger.info("DEV_MODE är %s och styr utvecklingsrelaterade flaggor.", normalized)


def _resolve_unique_paths(paths: Iterable[str | os.PathLike[str] | None]) -> list[Path]:
    # Return a list of unique, expanded ``Path`` objects from ``paths``.

    resolved_paths: list[Path] = []
    seen: set[Path] = set()

    for raw in paths:
        if not raw:
            continue

        # Expand user home explicitly using HOME when available so tests that
        # monkeypatch HOME on Windows behave deterministically. Fallback to
        # Path.expanduser() for other cases (including ~user patterns).
        raw_str = str(raw)
        if raw_str.startswith("~"):
            home = os.environ.get("HOME")
            if home:
                # Replace the initial '~' with the HOME env var content
                # Keep the remainder of the path intact (including any leading slash).
                path = Path(home + raw_str[1:])
            else:
                path = Path(raw_str).expanduser()
        else:
            path = Path(raw_str).expanduser()
        try:
            canonical = path.resolve()
        except FileNotFoundError:
            canonical = path

        if canonical in seen:
            continue

        seen.add(canonical)
        resolved_paths.append(path)

    return resolved_paths


def load_environment() -> None:
    # Load environment variables from available configuration files.

    app_root = Path(__file__).resolve().parent
    candidates = _resolve_unique_paths(
        (
            os.getenv("CONFIG_PATH"),
            Path("/config/.env"),
            app_root / ".env",
        )
    )

    loaded = False
    for path in candidates:
        if path.is_file():
            load_dotenv(path, override=False)
            loaded = True

    if not loaded:
        load_dotenv(override=False)

    _log_loaded_configuration()
    _log_dev_mode_status()


def _mask_sensitive_data(values: dict[str, str | None]) -> dict[str, str | None]:
    # Maska känsliga konfigurationsvärden i loggar.
    sensitive = {
        "DATABASE_URL",
        "POSTGRES_PASSWORD",
        "SECRET_KEY",
        "SMTP_PASSWORD",
    }
    masked: dict[str, str | None] = {}
    for key, value in values.items():
        if key in sensitive and value is not None:
            masked[key] = "***"
        else:
            masked[key] = value
    return masked


def _log_loaded_configuration() -> None:
    # Logga konfigurationsvärden som är säkra att visa i loggar.
    keys = [
        "DEV_MODE",
        "ENABLE_DEMO_MODE",
        "DEMO_SITE_URL",
        "TRUSTED_PROXY_COUNT",
        "DATABASE_URL",
        "POSTGRES_HOST",
        "POSTGRES_DB",
        "STATUS_MAIN_URL",
        "STATUS_DEMO_URL",
        "LOG_LEVEL",
        "LOG_FILE",
    ]
    values = {key: os.getenv(key) for key in keys if os.getenv(key) is not None}
    logger.debug("Laddade konfigurationsvärden: %s", _mask_sensitive_data(values))
