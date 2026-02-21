# Copyright (c) Liam Suorsa and Mika Suorsa
from __future__ import annotations

from sqlalchemy import insert

from functions.database import admin_audit_log_table, get_engine
from functions.logging import configure_module_logger


logger = configure_module_logger(__name__)


def log_admin_action(admin: str, action: str, details: str) -> None:
    # Spara en revisionspost för administratörsåtgärder.
    admin_name = admin or "okänd"
    trimmed_details = details.strip()
    with get_engine().begin() as conn:
        conn.execute(
            insert(admin_audit_log_table).values(
                admin=admin_name,
                action=action,
                details=trimmed_details[:1000],
            )
        )
    logger.info("Admin %s utförde %s: %s", admin_name, action, trimmed_details)
