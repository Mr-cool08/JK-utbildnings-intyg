# Copyright (c) Liam Suorsa and Mika Suorsa
from sqlalchemy import select

import functions
import functions.database as database_module


def test_accounts_migration_version_and_table_created(empty_db):
    engine = empty_db

    with engine.begin() as conn:
        version = conn.execute(
            select(functions.schema_migrations_table.c.version).where(
                functions.schema_migrations_table.c.version
                == "0010_add_accounts_table"
            )
        ).scalar_one_or_none()

        accounts_count = conn.execute(
            select(functions.accounts_table.c.id)
        ).fetchall()

    assert version == "0010_add_accounts_table"
    assert accounts_count == []


def test_accounts_backfill_maps_legacy_rows(empty_db):
    engine = empty_db
    with engine.begin() as conn:
        user_id = conn.execute(
            functions.users_table.insert().values(
                username="Aktiv användare",
                email="user@example.com",
                password="hashed-user",
                personnummer="pnr-user",
            )
        ).inserted_primary_key[0]

        pending_user_id = conn.execute(
            functions.pending_users_table.insert().values(
                username="Väntande användare",
                email="pending@example.com",
                personnummer="pnr-pending",
            )
        ).inserted_primary_key[0]

        supervisor_id = conn.execute(
            functions.supervisors_table.insert().values(
                name="Aktiv chef",
                email="supervisor@example.com",
                password="hashed-supervisor",
            )
        ).inserted_primary_key[0]

        pending_supervisor_id = conn.execute(
            functions.pending_supervisors_table.insert().values(
                name="Väntande chef",
                email="pending-supervisor@example.com",
            )
        ).inserted_primary_key[0]

        counts = database_module._backfill_accounts_table(conn)

        rows = conn.execute(
            select(
                functions.accounts_table.c.account_type,
                functions.accounts_table.c.status,
                functions.accounts_table.c.name,
                functions.accounts_table.c.email,
                functions.accounts_table.c.password,
                functions.accounts_table.c.personnummer,
                functions.accounts_table.c.source_table,
                functions.accounts_table.c.source_id,
            )
        ).fetchall()

    by_source = {(row.source_table, row.source_id): row for row in rows}

    assert counts["users"] == 1
    assert counts["pending_users"] == 1
    assert counts["supervisors"] == 1
    assert counts["pending_supervisors"] == 1
    assert counts["collisions"] == 0

    active_user = by_source[("users", user_id)]
    assert active_user.account_type == "standard"
    assert active_user.status == "active"
    assert active_user.password == "hashed-user"
    assert active_user.personnummer == "pnr-user"

    pending_user = by_source[("pending_users", pending_user_id)]
    assert pending_user.account_type == "standard"
    assert pending_user.status == "pending"
    assert pending_user.password is None
    assert pending_user.personnummer == "pnr-pending"

    active_supervisor = by_source[("supervisors", supervisor_id)]
    assert active_supervisor.account_type == "foretagskonto"
    assert active_supervisor.status == "active"
    assert active_supervisor.password == "hashed-supervisor"
    assert active_supervisor.personnummer is None

    pending_supervisor = by_source[("pending_supervisors", pending_supervisor_id)]
    assert pending_supervisor.account_type == "foretagskonto"
    assert pending_supervisor.status == "pending"
    assert pending_supervisor.password is None
    assert pending_supervisor.personnummer is None


def test_accounts_backfill_is_idempotent_and_logs_collisions(empty_db):
    engine = empty_db
    with engine.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Användare",
                email="same@example.com",
                password="hashed",
                personnummer="pnr-1",
            )
        )
        conn.execute(
            functions.pending_supervisors_table.insert().values(
                name="Chef",
                email="same@example.com",
            )
        )

        first_counts = database_module._backfill_accounts_table(conn)
        second_counts = database_module._backfill_accounts_table(conn)

        total_rows = conn.execute(
            select(functions.accounts_table.c.id)
        ).fetchall()

    assert first_counts["users"] == 1
    assert first_counts["pending_supervisors"] == 1
    assert first_counts["collisions"] == 1

    assert second_counts["users"] == 0
    assert second_counts["pending_supervisors"] == 0
    assert second_counts["collisions"] == 1
    assert len(total_rows) == 2


# <!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
