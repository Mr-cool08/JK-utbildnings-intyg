from __future__ import annotations

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    func,
)

metadata = MetaData()

pending_users_table = Table(
    "pending_users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String, nullable=False),
    Column("email", String, nullable=False),
    Column("personnummer", String, nullable=False, unique=True),
)

users_table = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String, nullable=False),
    Column("email", String, nullable=False, unique=True),
    Column("password", String, nullable=False),
    Column("personnummer", String, nullable=False, unique=True),
)

user_pdfs_table = Table(
    "user_pdfs",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("personnummer", String, nullable=False, index=True),
    Column("filename", String, nullable=False),
    Column("content", LargeBinary, nullable=False),
    Column("categories", String, nullable=False, server_default=""),
    Column(
        "uploaded_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
)

pending_supervisors_table = Table(
    "pending_supervisors",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String, nullable=False),
    Column("email", String, nullable=False, unique=True),
    Column(
        "created_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
)

supervisors_table = Table(
    "supervisors",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String, nullable=False),
    Column("email", String, nullable=False, unique=True),
    Column("password", String, nullable=False),
    Column(
        "created_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
)

supervisor_connections_table = Table(
    "supervisor_connections",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("supervisor_email", String, nullable=False, index=True),
    Column("user_personnummer", String, nullable=False, index=True),
    Column(
        "created_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
    UniqueConstraint(
        "supervisor_email",
        "user_personnummer",
        name="uq_supervisor_connections_pair",
    ),
)

supervisor_link_requests_table = Table(
    "supervisor_link_requests",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("supervisor_email", String, nullable=False, index=True),
    Column("user_personnummer", String, nullable=False, index=True),
    Column(
        "created_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
    UniqueConstraint(
        "supervisor_email",
        "user_personnummer",
        name="uq_supervisor_link_requests_pair",
    ),
)

password_resets_table = Table(
    "password_resets",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("personnummer", String, nullable=False, index=True),
    Column("email", String, nullable=False),
    Column("token_hash", String, nullable=False, unique=True),
    Column(
        "created_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
    Column("used_at", DateTime(timezone=True)),
)

admin_audit_log_table = Table(
    "admin_audit_log",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("admin", String, nullable=False),
    Column("action", String, nullable=False),
    Column("details", String, nullable=False),
    Column(
        "created_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
)

schema_migrations_table = Table(
    "schema_migrations",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("version", String, nullable=False, unique=True),
    Column(
        "applied_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
)

companies_table = Table(
    "companies",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String, nullable=False),
    Column("orgnr", String, nullable=False, unique=True, index=True),
    Column("invoice_address", String),
    Column("invoice_contact", String),
    Column("invoice_reference", String),
    Column(
        "created_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
    Column(
        "updated_at",
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    ),
)

application_requests_table = Table(
    "application_requests",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("account_type", String, nullable=False),
    Column("name", String, nullable=False),
    Column("email", String, nullable=False),
    Column("orgnr_normalized", String, nullable=False, index=True),
    Column("company_name", String, nullable=False),
    Column("invoice_address", String),
    Column("invoice_contact", String),
    Column("invoice_reference", String),
    Column("comment", String),
    Column("status", String, nullable=False, server_default="pending"),
    Column("reviewed_by", String),
    Column("reviewed_at", DateTime(timezone=True)),
    Column("decision_reason", String),
    Column(
        "created_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
    Column(
        "updated_at",
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    ),
)

company_users_table = Table(
    "company_users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("company_id", Integer, nullable=True, index=True),
    Column("role", String, nullable=False),
    Column("name", String, nullable=False),
    Column("email", String, nullable=False, unique=True),
    Column("created_via_application_id", Integer, index=True),
    Column(
        "created_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
    Column(
        "updated_at",
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    ),
)

TABLE_REGISTRY: dict[str, Table] = {
    table.name: table
    for table in (
        pending_users_table,
        users_table,
        user_pdfs_table,
        pending_supervisors_table,
        supervisors_table,
        supervisor_connections_table,
        supervisor_link_requests_table,
        password_resets_table,
        admin_audit_log_table,
        schema_migrations_table,
        companies_table,
        application_requests_table,
        company_users_table,
    )
}
