from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import os
from queue import Queue
import re
from threading import Barrier, Event
import time
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, func, insert, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.engine.url import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import NullPool

import functions.database as database_module
from services.external_private_provisioning import _advisory_identity_locks


pytestmark = pytest.mark.postgres

_SCHEMA_PATTERN = re.compile(r"^external_provisioning_test_[0-9a-f]{32}$")
_TEST_TABLES = (
    database_module.external_provisioning_requests_table,
    database_module.external_provisioning_nonces_table,
    database_module.private_account_activation_tokens_table,
    database_module.user_pdfs_table,
)


@dataclass(frozen=True)
class PostgreSQLTestContext:
    engine: Engine
    schema: str


@pytest.fixture(scope="session")
def postgres_test_context() -> PostgreSQLTestContext:
    raw_url = os.getenv("POSTGRES_TEST_DATABASE_URL", "").strip()
    if not raw_url:
        pytest.skip("POSTGRES_TEST_DATABASE_URL saknas.")

    url = make_url(raw_url)
    if not url.get_backend_name().startswith("postgresql"):
        pytest.fail("POSTGRES_TEST_DATABASE_URL måste använda PostgreSQL.")
    database_name = url.database or ""
    if not database_name.endswith("_test"):
        pytest.fail(
            "POSTGRES_TEST_DATABASE_URL måste peka på en databas vars namn "
            "slutar med _test."
        )

    schema = f"external_provisioning_test_{uuid4().hex}"
    assert _SCHEMA_PATTERN.fullmatch(schema)
    admin_engine = create_engine(
        url,
        future=True,
        poolclass=NullPool,
    )
    quoted_schema = admin_engine.dialect.identifier_preparer.quote(schema)
    schema_created = False
    test_engine: Engine | None = None

    try:
        if not admin_engine.dialect.name.startswith("postgresql"):
            pytest.fail("Testmotorn måste använda PostgreSQL.")
        with admin_engine.begin() as conn:
            conn.exec_driver_sql(f"CREATE SCHEMA {quoted_schema}")
        schema_created = True

        test_engine = create_engine(
            url,
            future=True,
            poolclass=NullPool,
            connect_args={"options": f"-csearch_path={schema}"},
        )
        with test_engine.begin() as conn:
            current_schema = conn.execute(
                select(func.current_schema())
            ).scalar_one()
            assert current_schema == schema
            for table in _TEST_TABLES:
                table.create(bind=conn)

        yield PostgreSQLTestContext(test_engine, schema)
    finally:
        if test_engine is not None:
            test_engine.dispose()
        if schema_created:
            with admin_engine.begin() as conn:
                conn.exec_driver_sql(
                    f"DROP SCHEMA {quoted_schema} CASCADE"
                )
        admin_engine.dispose()


def _race_unique_inserts(
    engine: Engine,
    table,
    rows: list[dict[str, object]],
) -> None:
    barrier = Barrier(len(rows))

    def insert_row(values: dict[str, object]) -> tuple[str, int]:
        backend_pid = -1
        try:
            with engine.begin() as conn:
                conn.exec_driver_sql("SET LOCAL lock_timeout = '10s'")
                backend_pid = int(
                    conn.execute(select(func.pg_backend_pid())).scalar_one()
                )
                barrier.wait(timeout=10)
                conn.execute(insert(table).values(**values))
            return "inserted", backend_pid
        except IntegrityError:
            return "conflict", backend_pid

    with ThreadPoolExecutor(max_workers=len(rows)) as executor:
        futures = [executor.submit(insert_row, row) for row in rows]
        results = [future.result(timeout=15) for future in futures]

    assert sorted(status for status, _pid in results) == [
        "conflict",
        "inserted",
    ]
    backend_pids = {pid for _status, pid in results}
    assert -1 not in backend_pids
    assert len(backend_pids) == len(rows)


def _row_count(engine: Engine, table) -> int:
    with engine.connect() as conn:
        return int(
            conn.execute(
                select(func.count()).select_from(table)
            ).scalar_one()
        )


def _assert_advisory_lock_serialization(
    context: PostgreSQLTestContext,
) -> None:
    holder_ready = Event()
    release_holder = Event()
    waiter_ready = Event()
    waiter_acquired = Event()
    waiter_pid_queue: Queue[int] = Queue(maxsize=1)
    identity = f"{context.schema}:same-person"

    def hold_lock() -> int:
        with context.engine.begin() as conn:
            conn.exec_driver_sql("SET LOCAL statement_timeout = '15s'")
            backend_pid = int(
                conn.execute(select(func.pg_backend_pid())).scalar_one()
            )
            _advisory_identity_locks(conn, [identity])
            holder_ready.set()
            if not release_holder.wait(timeout=10):
                raise AssertionError(
                    "Testet frigav inte advisory lock inom tidsgränsen."
                )
        return backend_pid

    def wait_for_lock() -> int:
        if not holder_ready.wait(timeout=10):
            raise AssertionError(
                "Första anslutningen tog inte advisory lock."
            )
        with context.engine.begin() as conn:
            conn.exec_driver_sql("SET LOCAL lock_timeout = '10s'")
            backend_pid = int(
                conn.execute(select(func.pg_backend_pid())).scalar_one()
            )
            waiter_pid_queue.put(backend_pid)
            waiter_ready.set()
            _advisory_identity_locks(conn, [identity])
            waiter_acquired.set()
        return backend_pid

    observed_waiting_lock = False
    with ThreadPoolExecutor(max_workers=2) as executor:
        holder_future = executor.submit(hold_lock)
        waiter_future = executor.submit(wait_for_lock)
        try:
            assert holder_ready.wait(timeout=10)
            assert waiter_ready.wait(timeout=10)
            observed_waiter_pid = waiter_pid_queue.get(timeout=10)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                with context.engine.connect() as observer:
                    waiting_locks = int(
                        observer.execute(
                            text(
                                """
                                SELECT COUNT(*)
                                FROM pg_locks
                                WHERE pid = :pid
                                  AND locktype = 'advisory'
                                  AND NOT granted
                                """
                            ),
                            {
                                "pid": observed_waiter_pid,
                            },
                        ).scalar_one()
                    )
                if waiting_locks == 1:
                    observed_waiting_lock = True
                    break
                time.sleep(0.05)
        finally:
            release_holder.set()

        holder_pid = holder_future.result(timeout=15)
        waiter_pid = waiter_future.result(timeout=15)

    assert observed_waiting_lock
    assert waiter_acquired.is_set()
    assert waiter_pid == observed_waiter_pid
    assert holder_pid != waiter_pid


def test_postgres_unique_constraints_and_advisory_lock_serialization(
    postgres_test_context: PostgreSQLTestContext,
) -> None:
    engine = postgres_test_context.engine
    now = datetime.now(timezone.utc)

    _race_unique_inserts(
        engine,
        database_module.external_provisioning_requests_table,
        [
            {
                "key_id": "partner-a",
                "idempotency_key_hash": "a" * 64,
                "request_fingerprint": fingerprint,
                "state": "processing",
            }
            for fingerprint in ("b" * 64, "c" * 64)
        ],
    )
    _race_unique_inserts(
        engine,
        database_module.external_provisioning_nonces_table,
        [
            {
                "key_id": "partner-a",
                "nonce_hash": "d" * 64,
                "expires_at": now + timedelta(hours=24),
            },
            {
                "key_id": "partner-a",
                "nonce_hash": "d" * 64,
                "expires_at": now + timedelta(hours=25),
            },
        ],
    )
    _race_unique_inserts(
        engine,
        database_module.user_pdfs_table,
        [
            {
                "personnummer": "e" * 64,
                "filename": filename,
                "content": content,
                "content_sha256": "f" * 64,
            }
            for filename, content in (
                ("first.pdf", b"%PDF-first"),
                ("second.pdf", b"%PDF-second"),
            )
        ],
    )
    _race_unique_inserts(
        engine,
        database_module.private_account_activation_tokens_table,
        [
            {
                "pending_user_personnummer": "1" * 64,
                "provisioning_request_id": request_id,
                "token_hash": "2" * 64,
                "expires_at": now + timedelta(hours=48),
            }
            for request_id in (1, 2)
        ],
    )

    assert _row_count(
        engine,
        database_module.external_provisioning_requests_table,
    ) == 1
    assert _row_count(
        engine,
        database_module.external_provisioning_nonces_table,
    ) == 1
    assert _row_count(engine, database_module.user_pdfs_table) == 1
    assert _row_count(
        engine,
        database_module.private_account_activation_tokens_table,
    ) == 1

    _assert_advisory_lock_serialization(postgres_test_context)


# Copyright (c) Liam Suorsa and Mika Suorsa
