from __future__ import annotations

import os


_DEV_MODE_TRUTHY = frozenset({"true"})


def _dev_mode_enabled() -> bool:
    return os.getenv("DEV_MODE", "").strip().lower() in _DEV_MODE_TRUTHY


__all__ = ["_DEV_MODE_TRUTHY", "_dev_mode_enabled"]


# Copyright (c) Liam Suorsa and Mika Suorsa
