from __future__ import annotations

from typing import Any, Dict, List, Optional

from sqlalchemy import delete, insert, select

from functions.db.engine import get_engine
from functions.db.schema import (
    supervisor_connections_table,
    supervisor_link_requests_table,
    supervisors_table,
    users_table,
)
from functions.logging.logging_utils import configure_module_logger, mask_hash
from functions.security.hashing import (
    _hash_personnummer,
    _is_valid_hash,
    hash_value,
    normalize_email,
)

logger = configure_module_logger(__name__)


def list_supervisor_connections(email_hash: str) -> List[Dict[str, Any]]:
    # Return connected users for the given supervisor hash.
    if not _is_valid_hash(email_hash):
        raise ValueError("Ogiltig hash för e-post.")
    with get_engine().connect() as conn:
        rows = conn.execute(
            select(
                supervisor_connections_table.c.user_personnummer,
                users_table.c.username,
            )
            .select_from(
                supervisor_connections_table.join(
                    users_table,
                    supervisor_connections_table.c.user_personnummer
                    == users_table.c.personnummer,
                )
            )
            .where(supervisor_connections_table.c.supervisor_email == email_hash)
            .order_by(users_table.c.username.asc())
        )

        return [
            {
                "personnummer_hash": row.user_personnummer,
                "username": row.username,
            }
            for row in rows
        ]


def supervisor_has_access(supervisor_email_hash: str, personnummer_hash: str) -> bool:
    # Return True if supervisor has access to the given user.
    if not _is_valid_hash(supervisor_email_hash):
        logger.warning("Avvisade ogiltig hash för e-post")
        return False
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return False
    with get_engine().connect() as conn:
        row = conn.execute(
            select(supervisor_connections_table.c.id).where(
                supervisor_connections_table.c.supervisor_email
                == supervisor_email_hash,
                supervisor_connections_table.c.user_personnummer
                == personnummer_hash,
            )
        ).first()
    return row is not None


def supervisor_remove_connection(
    supervisor_email_hash: str, personnummer_hash: str
) -> bool:
    # Remove a connection between supervisor and user.
    if not _is_valid_hash(supervisor_email_hash):
        logger.warning("Avvisade ogiltig hash för e-post")
        return False
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return False
    with get_engine().begin() as conn:
        result = conn.execute(
            delete(supervisor_connections_table).where(
                supervisor_connections_table.c.supervisor_email
                == supervisor_email_hash,
                supervisor_connections_table.c.user_personnummer
                == personnummer_hash,
            )
        )
    return result.rowcount > 0


def list_user_supervisor_connections(personnummer_hash: str) -> List[Dict[str, str]]:
    # Return connected supervisors for a given user hash.
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return []
    with get_engine().connect() as conn:
        rows = conn.execute(
            select(
                supervisor_connections_table.c.supervisor_email,
                supervisors_table.c.name,
            )
            .select_from(
                supervisor_connections_table.join(
                    supervisors_table,
                    supervisor_connections_table.c.supervisor_email
                    == supervisors_table.c.email,
                )
            )
            .where(supervisor_connections_table.c.user_personnummer == personnummer_hash)
            .order_by(supervisors_table.c.name.asc())
        )
        return [
            {"supervisor_email": row.supervisor_email, "supervisor_name": row.name}
            for row in rows
        ]


def list_user_link_requests(personnummer_hash: str) -> List[Dict[str, str]]:
    # Return pending supervisor link requests for a user.
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return []
    with get_engine().connect() as conn:
        rows = conn.execute(
            select(
                supervisor_link_requests_table.c.supervisor_email,
                supervisors_table.c.name,
            )
            .select_from(
                supervisor_link_requests_table.join(
                    supervisors_table,
                    supervisor_link_requests_table.c.supervisor_email
                    == supervisors_table.c.email,
                )
            )
            .where(supervisor_link_requests_table.c.user_personnummer == personnummer_hash)
            .order_by(supervisors_table.c.name.asc())
        )
        return [
            {"supervisor_email": row.supervisor_email, "supervisor_name": row.name}
            for row in rows
        ]


def create_supervisor_link_request(
    supervisor_email_hash: str, personnummer: str
) -> tuple[bool, str]:
    # Create a link request from a supervisor to a user.
    if not _is_valid_hash(supervisor_email_hash):
        logger.warning("Avvisade ogiltig hash för e-post")
        return False, "invalid_supervisor"
    pnr_hash = _hash_personnummer(personnummer)

    with get_engine().begin() as conn:
        supervisor_row = conn.execute(
            select(supervisors_table.c.id).where(
                supervisors_table.c.email == supervisor_email_hash
            )
        ).first()
        if not supervisor_row:
            logger.warning(
                "Supervisor %s not found for link request",
                mask_hash(supervisor_email_hash),
            )
            return False, "missing_supervisor"

        user_row = conn.execute(
            select(users_table.c.id).where(users_table.c.personnummer == pnr_hash)
        ).first()
        if not user_row:
            logger.warning(
                "User %s not found for link request from %s",
                mask_hash(pnr_hash),
                mask_hash(supervisor_email_hash),
            )
            return False, "missing_user"

        existing_connection = conn.execute(
            select(supervisor_connections_table.c.id).where(
                supervisor_connections_table.c.supervisor_email
                == supervisor_email_hash,
                supervisor_connections_table.c.user_personnummer == pnr_hash,
            )
        ).first()
        if existing_connection:
            return False, "already_connected"

        existing_request = conn.execute(
            select(supervisor_link_requests_table.c.id).where(
                supervisor_link_requests_table.c.supervisor_email
                == supervisor_email_hash,
                supervisor_link_requests_table.c.user_personnummer == pnr_hash,
            )
        ).first()
        if existing_request:
            return False, "already_requested"

        conn.execute(
            insert(supervisor_link_requests_table).values(
                supervisor_email=supervisor_email_hash,
                user_personnummer=pnr_hash,
            )
        )

    logger.info(
        "Supervisor %s requested link with %s",
        mask_hash(supervisor_email_hash),
        mask_hash(pnr_hash),
    )
    return True, "created"


def user_accept_link_request(
    personnummer_hash: str, supervisor_email_hash: str
) -> bool:
    # Accept a supervisor link request and create the connection.
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return False
    if not _is_valid_hash(supervisor_email_hash):
        logger.warning("Avvisade ogiltig hash för e-post")
        return False

    with get_engine().begin() as conn:
        request_row = conn.execute(
            select(supervisor_link_requests_table.c.id).where(
                supervisor_link_requests_table.c.supervisor_email
                == supervisor_email_hash,
                supervisor_link_requests_table.c.user_personnummer
                == personnummer_hash,
            )
        ).first()
        if not request_row:
            return False

        existing_connection = conn.execute(
            select(supervisor_connections_table.c.id).where(
                supervisor_connections_table.c.supervisor_email
                == supervisor_email_hash,
                supervisor_connections_table.c.user_personnummer
                == personnummer_hash,
            )
        ).first()
        if not existing_connection:
            conn.execute(
                insert(supervisor_connections_table).values(
                    supervisor_email=supervisor_email_hash,
                    user_personnummer=personnummer_hash,
                )
            )

        conn.execute(
            delete(supervisor_link_requests_table).where(
                supervisor_link_requests_table.c.id == request_row.id
            )
        )
    return True


def user_reject_link_request(
    personnummer_hash: str, supervisor_email_hash: str
) -> bool:
    # Reject a supervisor link request.
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return False
    if not _is_valid_hash(supervisor_email_hash):
        logger.warning("Avvisade ogiltig hash för e-post")
        return False
    with get_engine().begin() as conn:
        result = conn.execute(
            delete(supervisor_link_requests_table).where(
                supervisor_link_requests_table.c.supervisor_email
                == supervisor_email_hash,
                supervisor_link_requests_table.c.user_personnummer
                == personnummer_hash,
            )
        )
    return result.rowcount > 0


def user_remove_supervisor_connection(
    personnummer_hash: str, supervisor_email_hash: str
) -> bool:
    # Remove a supervisor connection from the user side.
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return False
    if not _is_valid_hash(supervisor_email_hash):
        logger.warning("Avvisade ogiltig hash för e-post")
        return False
    with get_engine().begin() as conn:
        result = conn.execute(
            delete(supervisor_connections_table).where(
                supervisor_connections_table.c.supervisor_email
                == supervisor_email_hash,
                supervisor_connections_table.c.user_personnummer
                == personnummer_hash,
            )
        )
    return result.rowcount > 0


def admin_link_supervisor_to_user(
    supervisor_email: str, personnummer: str
) -> tuple[bool, str]:
    # Create a connection between a supervisor and a user.
    #
    # Returns a tuple (success, reason). ``reason`` is ``'created'`` when the
    # connection was stored, or one of ``'missing_supervisor'``, ``'missing_user'``
    # or ``'exists'`` for error cases.
    normalized_email = normalize_email(supervisor_email)
    email_hash = hash_value(normalized_email)
    pnr_hash = _hash_personnummer(personnummer)

    with get_engine().begin() as conn:
        supervisor_row = conn.execute(
            select(supervisors_table.c.id).where(
                supervisors_table.c.email == email_hash
            )
        ).first()
        if not supervisor_row:
            logger.warning("Supervisor %s not found for linking", mask_hash(email_hash))
            return False, "missing_supervisor"

        user_row = conn.execute(
            select(users_table.c.id).where(users_table.c.personnummer == pnr_hash)
        ).first()
        if not user_row:
            logger.warning(
                "User %s not found when linking supervisor %s",
                mask_hash(pnr_hash),
                mask_hash(email_hash),
            )
            return False, "missing_user"

        existing = conn.execute(
            select(supervisor_connections_table.c.id).where(
                supervisor_connections_table.c.supervisor_email == email_hash,
                supervisor_connections_table.c.user_personnummer == pnr_hash,
            )
        ).first()
        if existing:
            logger.info(
                "Supervisor %s already connected to %s",
                mask_hash(email_hash),
                mask_hash(pnr_hash),
            )
            return False, "exists"

        conn.execute(
            insert(supervisor_connections_table).values(
                supervisor_email=email_hash,
                user_personnummer=pnr_hash,
            )
        )
        conn.execute(
            delete(supervisor_link_requests_table).where(
                supervisor_link_requests_table.c.supervisor_email == email_hash,
                supervisor_link_requests_table.c.user_personnummer == pnr_hash,
            )
        )

    logger.info(
        "Supervisor %s connected to user %s",
        mask_hash(email_hash),
        mask_hash(pnr_hash),
    )
    return True, "created"


def get_supervisor_overview(email_hash: str) -> Optional[Dict[str, Any]]:
    # Return supervisor info together with connected users.
    if not _is_valid_hash(email_hash):
        raise ValueError("Ogiltig hash för e-post.")
    with get_engine().connect() as conn:
        supervisor_row = conn.execute(
            select(supervisors_table.c.name).where(
                supervisors_table.c.email == email_hash
            )
        ).first()
        if not supervisor_row:
            return None

        connections = conn.execute(
            select(
                supervisor_connections_table.c.user_personnummer,
                users_table.c.username,
            )
            .select_from(
                supervisor_connections_table.join(
                    users_table,
                    supervisor_connections_table.c.user_personnummer
                    == users_table.c.personnummer,
                )
            )
            .where(supervisor_connections_table.c.supervisor_email == email_hash)
            .order_by(users_table.c.username.asc())
        )

        return {
            "name": supervisor_row.name,
            "email_hash": email_hash,
            "connections": [
                {
                    "personnummer_hash": row.user_personnummer,
                    "username": row.username,
                }
                for row in connections
            ],
        }
