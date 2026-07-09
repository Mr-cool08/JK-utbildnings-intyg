# Copyright (c) Liam Suorsa and Mika Suorsa
from __future__ import annotations

import os
import sys
from urllib.parse import urlparse

from functions.requests import as_bool


REQUIRED_DEV_VARIABLES = (
    "DEV_ADMIN_USERNAME",
    "DEV_ADMIN_PASSWORD",
    "DEV_PRIVATE_USER_NAME",
    "DEV_PRIVATE_USER_EMAIL",
    "DEV_PRIVATE_USER_PERSONNUMMER",
    "DEV_PRIVATE_USER_PASSWORD",
    "DEV_COMPANY_NAME",
    "DEV_COMPANY_EMAIL",
    "DEV_COMPANY_ORGNR",
    "DEV_COMPANY_PASSWORD",
)

FORBIDDEN_DEV_SMTP_VARIABLES = (
    "smtp_server",
    "smtp_user",
    "smtp_password",
    "SMTP_SERVER",
    "SMTP_USER",
    "SMTP_PASSWORD",
)


def _append_missing_value_error(errors: list[str], env_name: str) -> None:
    errors.append(f"{env_name} måste vara satt och inte tom.")


def _validate_database_url(database_url: str, errors: list[str]) -> None:
    cleaned_url = (database_url or "").strip()
    if not cleaned_url:
        errors.append("DATABASE_URL måste vara satt i utvecklingsmiljön.")
        return

    parsed = urlparse(cleaned_url)
    scheme = (parsed.scheme or "").lower()

    if scheme.startswith("sqlite"):
        if cleaned_url == "sqlite:///:memory:":
            errors.append(
                "DATABASE_URL får inte använda SQLite i minnet i den publika utvecklingsmiljön."
            )
        return

    if "postgres" in scheme:
        host = (parsed.hostname or "").strip().lower()
        if host != "postgres_dev":
            errors.append(
                "DATABASE_URL får bara peka på postgres_dev eller en separat SQLite-fil i utvecklingsmiljön."
            )
        return

    errors.append("DATABASE_URL måste använda SQLite eller PostgreSQL i utvecklingsmiljön.")


def validate_dev_environment() -> list[str]:
    errors: list[str] = []

    if (os.getenv("APP_ENV") or "").strip().lower() != "development":
        errors.append("APP_ENV måste vara satt till development.")

    if not as_bool(os.getenv("DEV_MODE")):
        errors.append("DEV_MODE måste vara true i utvecklingsmiljön.")

    if not as_bool(os.getenv("DISABLE_EMAILS")):
        errors.append("DISABLE_EMAILS måste vara true i utvecklingsmiljön.")

    if not ((os.getenv("SECRET_KEY") or "").strip() or (os.getenv("secret_key") or "").strip()):
        errors.append("SECRET_KEY eller secret_key måste vara satt i utvecklingsmiljön.")

    if (os.getenv("HASH_SALT") or "").strip() in {"", "static_salt"}:
        errors.append("HASH_SALT måste vara satt till ett separat devvärde.")

    _validate_database_url(os.getenv("DATABASE_URL", ""), errors)

    for env_name in REQUIRED_DEV_VARIABLES:
        if not (os.getenv(env_name) or "").strip():
            _append_missing_value_error(errors, env_name)

    for env_name in FORBIDDEN_DEV_SMTP_VARIABLES:
        if (os.getenv(env_name) or "").strip():
            errors.append(
                f"{env_name} får inte vara satt i utvecklingsmiljön eftersom riktig e-post är förbjuden."
            )

    return errors


def main() -> int:
    errors = validate_dev_environment()
    if not errors:
        print("Utvecklingsmiljön är validerad.")
        return 0

    print("Utvecklingsmiljön stoppades av säkerhetsvakter:", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

# Copyright (c) Liam Suorsa and Mika Suorsa
