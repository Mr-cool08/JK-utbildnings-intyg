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


def _apply_dev_mode_defaults() -> None:
    # Synka utvecklingsinställningar med DEV_MODE för konsekvent konfiguration.
    raw = os.getenv("DEV_MODE")
    if raw is None or raw.strip() == "":
        return

    dev_mode = _as_bool(raw)
    normalized = "true" if dev_mode else "false"
    for key in ("FLASK_DEBUG", "ENABLE_DEMO_MODE", "ENABLE_LOCAL_TEST_DB"):
        current_value = os.getenv(key)
        if current_value is None or current_value.strip() == "":
            os.environ[key] = normalized
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

    _apply_dev_mode_defaults()
