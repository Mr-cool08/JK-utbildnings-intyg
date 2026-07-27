import hashlib

import pytest
from sqlalchemy import create_engine, event, insert, inspect, select, text
from sqlalchemy.exc import IntegrityError

import functions.database as database_module


MIGRATION_VERSION = "0023_external_private_provisioning"
PREVIOUS_MIGRATION_VERSION = "0022_fix_supervisor_connections_created_at_default"
SECURITY_TABLES = {
    "external_provisioning_requests",
    "external_provisioning_nonces",
    "private_account_activation_tokens",
}


def _create_0022_database(engine, pdf_rows=()):
    with engine.begin() as conn:
        database_module.schema_migrations_table.create(bind=conn)
        conn.execute(
            insert(database_module.schema_migrations_table).values(
                version=PREVIOUS_MIGRATION_VERSION
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE user_pdfs (
                    id INTEGER PRIMARY KEY,
                    personnummer TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    content BLOB NOT NULL,
                    categories TEXT DEFAULT '' NOT NULL,
                    note TEXT DEFAULT '' NOT NULL,
                    expires_on DATE,
                    last_expiry_reminder_month TEXT,
                    last_expiry_reminder_sent_at DATETIME,
                    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
                )
                """
            )
        )
        for row_id, personnummer, filename, content in pdf_rows:
            conn.execute(
                text(
                    """
                    INSERT INTO user_pdfs (
                        id,
                        personnummer,
                        filename,
                        content
                    ) VALUES (
                        :id,
                        :personnummer,
                        :filename,
                        :content
                    )
                    """
                ),
                {
                    "id": row_id,
                    "personnummer": personnummer,
                    "filename": filename,
                    "content": content,
                },
            )


def _run_migration_0023(monkeypatch, engine):
    monkeypatch.setattr(
        database_module,
        "MIGRATIONS",
        [
            (
                MIGRATION_VERSION,
                database_module._migration_0023_external_private_provisioning,
            )
        ],
    )
    database_module.run_migrations(engine)


def _unique_column_sets(inspector, table_name):
    unique_columns = {
        tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints(table_name)
    }
    unique_columns.update(
        tuple(index["column_names"])
        for index in inspector.get_indexes(table_name)
        if index["unique"]
    )
    return unique_columns


def _index_column_sets(inspector, table_name):
    return {
        tuple(index["column_names"])
        for index in inspector.get_indexes(table_name)
    }


def test_migration_0023_creates_security_schema_and_keeps_it_out_of_table_registry(
    monkeypatch,
):
    engine = create_engine("sqlite:///:memory:", future=True)
    _create_0022_database(engine)

    _run_migration_0023(monkeypatch, engine)

    inspector = inspect(engine)
    assert SECURITY_TABLES <= set(inspector.get_table_names())
    expected_columns = {
        "external_provisioning_requests": {
            "id",
            "key_id",
            "idempotency_key_hash",
            "request_fingerprint",
            "state",
            "http_status",
            "response_body",
            "mail_status",
            "attempt_count",
            "locked_at",
            "last_attempt_at",
            "completed_at",
            "personnummer_hash",
            "pdf_content_sha256",
            "pdf_id",
            "account_state",
            "created_at",
            "updated_at",
        },
        "external_provisioning_nonces": {
            "id",
            "key_id",
            "nonce_hash",
            "expires_at",
            "created_at",
        },
        "private_account_activation_tokens": {
            "id",
            "pending_user_personnummer",
            "provisioning_request_id",
            "token_hash",
            "created_at",
            "expires_at",
            "used_at",
            "revoked_at",
            "superseded_at",
        },
    }
    for table_name, column_names in expected_columns.items():
        assert column_names == {
            column["name"] for column in inspector.get_columns(table_name)
        }

    user_pdf_columns = {
        column["name"]: column for column in inspector.get_columns("user_pdfs")
    }
    assert user_pdf_columns["content_sha256"]["nullable"] is True
    assert user_pdf_columns["content_sha256"]["type"].length == 64

    assert (
        "key_id",
        "idempotency_key_hash",
    ) in _unique_column_sets(inspector, "external_provisioning_requests")
    assert (
        "key_id",
        "nonce_hash",
    ) in _unique_column_sets(inspector, "external_provisioning_nonces")
    assert ("token_hash",) in _unique_column_sets(
        inspector,
        "private_account_activation_tokens",
    )
    assert (
        "personnummer",
        "content_sha256",
    ) in _unique_column_sets(inspector, "user_pdfs")

    request_check_constraints = {
        constraint["name"]: constraint["sqltext"]
        for constraint in inspector.get_check_constraints(
            "external_provisioning_requests"
        )
    }
    assert "ck_external_provisioning_requests_state" in request_check_constraints
    for state in database_module.EXTERNAL_PROVISIONING_STATES:
        assert state in request_check_constraints[
            "ck_external_provisioning_requests_state"
        ]

    assert {
        ("state",),
        ("locked_at",),
        ("personnummer_hash",),
    } <= _index_column_sets(inspector, "external_provisioning_requests")
    assert {("expires_at",)} <= _index_column_sets(
        inspector,
        "external_provisioning_nonces",
    )
    assert {
        ("pending_user_personnummer",),
        ("provisioning_request_id",),
        ("expires_at",),
    } <= _index_column_sets(inspector, "private_account_activation_tokens")

    with engine.connect() as conn:
        applied_versions = set(
            conn.execute(
                select(database_module.schema_migrations_table.c.version)
            ).scalars()
        )
    assert MIGRATION_VERSION in applied_versions
    assert SECURITY_TABLES.isdisjoint(database_module.TABLE_REGISTRY)


def test_migration_0023_backfills_content_hashes_in_batches(monkeypatch):
    first_pdf = b"%PDF-1.4\nfirst certificate"
    second_pdf = b"%PDF-1.4\nsecond certificate"
    engine = create_engine("sqlite:///:memory:", future=True)
    statements = []
    event.listen(
        engine,
        "before_cursor_execute",
        lambda _conn, _cursor, statement, _parameters, _context, _many: (
            statements.append(statement)
        ),
    )
    _create_0022_database(
        engine,
        [
            (1, "person-a", "first.pdf", first_pdf),
            (2, "person-a", "second.pdf", second_pdf),
            (3, "person-b", "same-content-other-person.pdf", first_pdf),
        ],
    )
    monkeypatch.setenv("EXTERNAL_PROVISIONING_HASH_BACKFILL_BATCH_SIZE", "1")

    _run_migration_0023(monkeypatch, engine)

    with engine.connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT id, content_sha256
                FROM user_pdfs
                ORDER BY id
                """
            )
        ).all()

    assert rows == [
        (1, hashlib.sha256(first_pdf).hexdigest()),
        (2, hashlib.sha256(second_pdf).hexdigest()),
        (3, hashlib.sha256(first_pdf).hexdigest()),
    ]
    batch_selects = [
        statement
        for statement in statements
        if "content_sha256 IS NULL" in statement
        and "LIMIT" in statement
    ]
    assert batch_selects
    assert all(
        "user_pdfs.content" not in statement.split("FROM", 1)[0]
        for statement in batch_selects
    )


def test_migration_0023_preserves_and_inventories_existing_duplicate_pdfs(
    monkeypatch,
):
    duplicate_pdf = b"%PDF-1.4\nexisting duplicate"
    distinct_pdf = b"%PDF-1.4\ndistinct"
    warnings = []
    engine = create_engine("sqlite:///:memory:", future=True)
    _create_0022_database(
        engine,
        [
            (1, "person-a", "canonical.pdf", duplicate_pdf),
            (2, "person-a", "duplicate-one.pdf", duplicate_pdf),
            (3, "person-a", "duplicate-two.pdf", duplicate_pdf),
            (4, "person-a", "distinct.pdf", distinct_pdf),
            (5, "person-b", "same-content-other-person.pdf", duplicate_pdf),
        ],
    )

    def _record_warning(message, *args):
        warnings.append(message % args)

    monkeypatch.setattr(database_module.logger, "warning", _record_warning)
    _run_migration_0023(monkeypatch, engine)

    with engine.connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT id, filename, content_sha256
                FROM user_pdfs
                ORDER BY id
                """
            )
        ).all()

    duplicate_hash = hashlib.sha256(duplicate_pdf).hexdigest()
    assert rows == [
        (1, "canonical.pdf", duplicate_hash),
        (2, "duplicate-one.pdf", None),
        (3, "duplicate-two.pdf", None),
        (4, "distinct.pdf", hashlib.sha256(distinct_pdf).hexdigest()),
        (5, "same-content-other-person.pdf", duplicate_hash),
    ]
    assert len(rows) == 5
    assert sum("inventerade duplicerad PDF" in warning for warning in warnings) == 2
    assert any(
        "inventerade 2 befintliga PDF-dubbletter" in warning for warning in warnings
    )


def test_migration_0023_enforces_uniqueness_for_new_hashed_pdf_rows(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    _create_0022_database(engine)
    _run_migration_0023(monkeypatch, engine)
    content_hash = hashlib.sha256(b"%PDF-1.4\nnew certificate").hexdigest()

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO user_pdfs (
                    personnummer,
                    filename,
                    content,
                    content_sha256
                ) VALUES (
                    'person-a',
                    'first.pdf',
                    x'25504446',
                    :content_hash
                )
                """
            ),
            {"content_hash": content_hash},
        )

    with pytest.raises(IntegrityError):
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO user_pdfs (
                        personnummer,
                        filename,
                        content,
                        content_sha256
                    ) VALUES (
                        'person-a',
                        'duplicate.pdf',
                        x'25504446',
                        :content_hash
                    )
                    """
                ),
                {"content_hash": content_hash},
            )

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO user_pdfs (
                    personnummer,
                    filename,
                    content,
                    content_sha256
                ) VALUES (
                    'person-b',
                    'same-hash-other-person.pdf',
                    x'25504446',
                    :content_hash
                )
                """
            ),
            {"content_hash": content_hash},
        )

    with engine.connect() as conn:
        stored_rows = conn.execute(
            text(
                """
                SELECT personnummer, content_sha256
                FROM user_pdfs
                WHERE content_sha256 = :content_hash
                ORDER BY personnummer
                """
            ),
            {"content_hash": content_hash},
        ).all()

    assert stored_rows == [
        ("person-a", content_hash),
        ("person-b", content_hash),
    ]


# Copyright (c) Liam Suorsa and Mika Suorsa
