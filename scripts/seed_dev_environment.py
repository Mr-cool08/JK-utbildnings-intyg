# Copyright (c) Liam Suorsa and Mika Suorsa
from __future__ import annotations

import os
import sys

import functions
from functions.requests import as_bool

from scripts.validate_dev_environment import validate_dev_environment


def _required_env(env_name: str) -> str:
    value = (os.getenv(env_name) or "").strip()
    if value:
        return value
    raise RuntimeError(f"{env_name} måste vara satt och inte tom.")


def _load_seed_defaults() -> dict[str, str]:
    company_name = _required_env("DEV_COMPANY_NAME")
    return {
        "user_email": _required_env("DEV_PRIVATE_USER_EMAIL"),
        "user_name": _required_env("DEV_PRIVATE_USER_NAME"),
        "user_personnummer": _required_env("DEV_PRIVATE_USER_PERSONNUMMER"),
        "user_password": _required_env("DEV_PRIVATE_USER_PASSWORD"),
        "supervisor_email": _required_env("DEV_COMPANY_EMAIL"),
        "supervisor_name": company_name,
        "supervisor_password": _required_env("DEV_COMPANY_PASSWORD"),
        "supervisor_orgnr": _required_env("DEV_COMPANY_ORGNR"),
    }


def seed_dev_environment() -> dict[str, str]:
    if not as_bool(os.getenv("DEV_MODE")):
        raise RuntimeError("DEV_MODE måste vara true för att seedscriptet ska få köras.")

    errors = validate_dev_environment()
    if errors:
        joined = " | ".join(errors)
        raise RuntimeError(f"Utvecklingsmiljön kunde inte seedas: {joined}")

    functions.reset_engine()
    functions.create_database()
    seed_defaults = _load_seed_defaults()
    functions.ensure_demo_data(**seed_defaults)
    return seed_defaults


def main() -> int:
    try:
        seed_defaults = seed_dev_environment()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "Utvecklingsmiljön är seedad med syntetiska konton för "
        f"{seed_defaults['user_email']} och {seed_defaults['supervisor_email']}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# Copyright (c) Liam Suorsa and Mika Suorsa
