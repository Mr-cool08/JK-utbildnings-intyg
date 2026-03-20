# package marker for scripts

DEV_MODE_ENABLED_VALUES = frozenset({"true", "1", "yes"})


def is_dev_mode_enabled(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in DEV_MODE_ENABLED_VALUES


# Copyright (c) Liam Suorsa and Mika Suorsa
