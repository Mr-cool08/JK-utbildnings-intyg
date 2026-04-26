# Copyright (c) Liam Suorsa and Mika Suorsa
from __future__ import annotations

from sqlalchemy import insert

from functions.database import admin_audit_log_table, get_engine
from functions.logging import configure_module_logger


logger = configure_module_logger(__name__)


def log_admin_action(admin: str | None, action: str, details: str | None) -> None:
    # Spara en revisionspost för administratörsåtgärder.
    admin_name = admin or "okänd"
    truncated_details = (details or "").strip()[:1000]
    with get_engine().begin() as conn:
        conn.execute(
            insert(admin_audit_log_table).values(
                admin=admin_name,
                action=action,
                details=truncated_details,
            )
        )
    logger.info("Admin %s utförde %s: %s", admin_name, action, truncated_details)
