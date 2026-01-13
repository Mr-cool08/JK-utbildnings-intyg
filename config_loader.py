# Utilities for loading environment variables from configuration files.

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from dotenv import load_dotenv


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
            Path("/config/stack.env"),
            app_root / "stack.env",
        )
    )

    loaded = False
    for path in candidates:
        if path.is_file():
            load_dotenv(path, override=False)
            loaded = True

    if not loaded:
        load_dotenv(override=False)
