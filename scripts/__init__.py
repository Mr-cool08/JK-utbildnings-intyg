# package marker for scripts

def is_dev_mode_enabled(value: str | None) -> bool:
    value = (value or "").strip().lower()
    return value == "true"


# Copyright (c) Liam Suorsa and Mika Suorsa
