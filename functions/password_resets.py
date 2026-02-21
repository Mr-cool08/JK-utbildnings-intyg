# Copyright (c) Liam Suorsa and Mika Suorsa
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from sqlalchemy import insert, select, update

from functions.database import (
    pending_users_table,
    password_resets_table,
    supervisor_password_resets_table,
    supervisors_table,
    users_table,
    get_engine,
)
from functions.hashing import (
    _hash_personnummer,
    hash_password,
    hash_value,
    normalize_email,
)
from functions.logging import configure_module_logger, mask_hash
from functions.users import verify_certificate


logger = configure_module_logger(__name__)
logger.setLevel(logging.DEBUG)


def _hash_token(token: str) -> str:
    return hash_value(token)


def create_password_reset_token(personnummer: str, email: str) -> str:
    # Skapa ett återställningstoken för en användare.
    personnummer_hash = _hash_personnummer(personnummer)
    normalized_email = normalize_email(email)
    email_hash = hash_value(normalized_email)

    with get_engine().begin() as conn:
        row = conn.execute(
            select(users_table.c.email).where(users_table.c.personnummer == personnummer_hash)
        ).first()
        if not row:
            pending = conn.execute(
                select(pending_users_table.c.email).where(
                    pending_users_table.c.personnummer == personnummer_hash
                )
            ).first()
            if pending and pending.email == email_hash:
                logger.warning(
                    "Kunde inte skapa återställningstoken för %s: kontot är inte aktiverat",
                    mask_hash(personnummer_hash),
                )
                raise ValueError("Kontot är inte aktiverat ännu.")
        if not row or row.email != email_hash:
            logger.warning(
                "Kunde inte skapa återställningstoken för %s: uppgifter matchar inte",
                mask_hash(personnummer_hash),
            )
            raise ValueError("Uppgifterna matchar inget aktivt standardkonto.")

        token = secrets.token_urlsafe(32)
        token_hash = _hash_token(token)
        conn.execute(
            insert(password_resets_table).values(
                personnummer=personnummer_hash,
                email=email_hash,
                token_hash=token_hash,
            )
        )

    logger.info("Skapade återställningstoken för %s", mask_hash(personnummer_hash))
    return token


def create_supervisor_password_reset_token(email: str) -> str:
    # Skapa ett återställningstoken för ett företagskonto.
    normalized_email = normalize_email(email)
    email_hash = hash_value(normalized_email)

    with get_engine().begin() as conn:
        row = conn.execute(
            select(supervisors_table.c.email).where(supervisors_table.c.email == email_hash)
        ).first()
        if not row:
            logger.warning(
                "Kunde inte skapa återställningstoken för företagskonto %s: saknas",
                mask_hash(email_hash),
            )
            raise ValueError("Angiven e-post matchar inget aktivt företagskonto.")

        token = secrets.token_urlsafe(32)
        token_hash = _hash_token(token)
        conn.execute(
            insert(supervisor_password_resets_table).values(
                email=email_hash,
                token_hash=token_hash,
            )
        )

    logger.info(
        "Skapade återställningstoken för företagskonto %s",
        mask_hash(email_hash),
    )
    return token


def get_password_reset(token: str) -> Optional[Dict[str, Any]]:
    # Hämta metadata för ett återställningstoken.
    token_hash = _hash_token(token)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(
                password_resets_table.c.personnummer,
                password_resets_table.c.email,
                password_resets_table.c.created_at,
                password_resets_table.c.used_at,
            ).where(password_resets_table.c.token_hash == token_hash)
        ).first()
    if not row:
        return None
    return {
        "personnummer": row.personnummer,
        "email": row.email,
        "created_at": row.created_at,
        "used_at": row.used_at,
    }


def get_supervisor_password_reset(token: str) -> Optional[Dict[str, Any]]:
    # Hämta metadata för ett företagskonto-återställningstoken.
    token_hash = _hash_token(token)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(
                supervisor_password_resets_table.c.email,
                supervisor_password_resets_table.c.created_at,
                supervisor_password_resets_table.c.used_at,
            ).where(supervisor_password_resets_table.c.token_hash == token_hash)
        ).first()
    if not row:
        return None
    return {
        "email": row.email,
        "created_at": row.created_at,
        "used_at": row.used_at,
    }


def reset_password_with_token(token: str, new_password: str) -> bool:
    # Återställ lösenordet för det angivna tokenet.
    token_hash = _hash_token(token)
    now = datetime.now(timezone.utc)
    with get_engine().begin() as conn:
        row = conn.execute(
            select(
                password_resets_table.c.personnummer,
                password_resets_table.c.used_at,
                password_resets_table.c.created_at,
            ).where(password_resets_table.c.token_hash == token_hash)
        ).first()
        if not row:
            logger.warning("Okänt återställningstoken användes")
            return False
        if row.used_at is not None:
            logger.warning("Förbrukat återställningstoken användes igen")
            return False

        created_at = row.created_at
        if created_at and created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        if created_at and now - created_at > timedelta(days=2):
            logger.warning("Utgånget återställningstoken för %s", row.personnummer)
            return False

        conn.execute(
            update(users_table)
            .where(users_table.c.personnummer == row.personnummer)
            .values(password=hash_password(new_password))
        )
        conn.execute(
            update(password_resets_table)
            .where(password_resets_table.c.token_hash == token_hash)
            .values(used_at=now)
        )

    verify_certificate.cache_clear()
    logger.info("Lösenord återställt för %s", row.personnummer)
    return True


def reset_supervisor_password_with_token(token: str, new_password: str) -> bool:
    # Återställ lösenordet för ett företagskonto med angivet token.
    token_hash = _hash_token(token)
    now = datetime.now(timezone.utc)
    with get_engine().begin() as conn:
        row = conn.execute(
            select(
                supervisor_password_resets_table.c.email,
                supervisor_password_resets_table.c.used_at,
                supervisor_password_resets_table.c.created_at,
            ).where(supervisor_password_resets_table.c.token_hash == token_hash)
        ).first()
        if not row:
            logger.warning("Okänt företagskonto-återställningstoken användes")
            return False
        if row.used_at is not None:
            logger.warning("Förbrukat företagskonto-återställningstoken användes igen")
            return False

        created_at = row.created_at
        if created_at and created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        if created_at and now - created_at > timedelta(days=2):
            logger.warning(
                "Utgånget företagskonto-återställningstoken för %s",
                row.email,
            )
            return False

        conn.execute(
            update(supervisors_table)
            .where(supervisors_table.c.email == row.email)
            .values(password=hash_password(new_password))
        )
        conn.execute(
            update(supervisor_password_resets_table)
            .where(supervisor_password_resets_table.c.token_hash == token_hash)
            .values(used_at=now)
        )

    logger.info("Lösenord återställt för företagskonto %s", row.email)
    return True
