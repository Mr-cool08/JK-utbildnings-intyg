from __future__ import annotations

import importlib
import logging as std_logging

from sqlalchemy import create_engine

from config_loader import load_environment
from functions.app_paths import APP_ROOT
from functions.logging.logging_utils import configure_module_logger

load_environment()

logger = configure_module_logger(__name__)
logger.setLevel(std_logging.DEBUG)

from functions.applications.requests import (  # noqa: E402
    _clean_optional_text,
    approve_application_request,
    create_application_request,
    get_application_request,
    list_application_requests,
    list_companies_for_invoicing,
    reject_application_request,
)
from functions.db.engine import (  # noqa: E402
    _build_engine,
    _is_truthy,
    create_database,
    get_engine,
    reset_engine,
)
from functions.db.schema import (  # noqa: E402
    admin_audit_log_table,
    application_requests_table,
    companies_table,
    company_users_table,
    password_resets_table,
    pending_supervisors_table,
    pending_users_table,
    schema_migrations_table,
    supervisor_connections_table,
    supervisor_link_requests_table,
    supervisors_table,
    user_pdfs_table,
    users_table,
)
from functions.demo.data import (  # noqa: E402
    DEMO_PDF_DEFINITIONS,
    create_test_user,
    ensure_demo_data,
    reset_demo_database,
)
from functions.pdf.storage import (  # noqa: E402
    delete_user_pdf,
    get_pdf_content,
    get_pdf_metadata,
    get_user_pdfs,
    store_pdf_blob,
    update_pdf_categories,
)
from functions.security.hashing import (  # noqa: E402
    hash_password,
    hash_value,
    normalize_email,
    normalize_orgnr,
    normalize_personnummer,
    validate_orgnr,
    verify_password,
)
from functions.security.password_reset import (  # noqa: E402
    create_password_reset_token,
    get_password_reset,
    reset_password_with_token,
)
from functions.admin.audit import log_admin_action  # noqa: E402
from functions.admin.tables import (  # noqa: E402
    create_table_row,
    delete_table_row,
    fetch_table_rows,
    get_table_schema,
    update_table_row,
)
from functions.users.accounts import (  # noqa: E402
    admin_create_supervisor,
    admin_create_user,
    check_password_user,
    check_pending_supervisor_hash,
    check_pending_user,
    check_pending_user_hash,
    check_personnummer_password,
    check_user_exists,
    get_supervisor_email_hash,
    get_supervisor_login_details_for_orgnr,
    get_supervisor_name_by_hash,
    get_user_info,
    get_username,
    get_username_by_personnummer_hash,
    supervisor_activate_account,
    supervisor_exists,
    user_create_user,
    verify_certificate,
    verify_supervisor_credentials,
)
from functions.users.supervisor_links import (  # noqa: E402
    admin_link_supervisor_to_user,
    create_supervisor_link_request,
    get_supervisor_overview,
    list_supervisor_connections,
    list_user_link_requests,
    list_user_supervisor_connections,
    supervisor_has_access,
    supervisor_remove_connection,
    user_accept_link_request,
    user_reject_link_request,
    user_remove_supervisor_connection,
)

__all__ = [
    "APP_ROOT",
    "DEMO_PDF_DEFINITIONS",
    "_build_engine",
    "_clean_optional_text",
    "_is_truthy",
    "admin_audit_log_table",
    "admin_create_supervisor",
    "admin_create_user",
    "admin_link_supervisor_to_user",
    "application_requests_table",
    "approve_application_request",
    "check_password_user",
    "check_pending_supervisor_hash",
    "check_pending_user",
    "check_pending_user_hash",
    "check_personnummer_password",
    "check_user_exists",
    "companies_table",
    "company_users_table",
    "create_application_request",
    "create_database",
    "create_engine",
    "create_password_reset_token",
    "create_table_row",
    "create_test_user",
    "delete_table_row",
    "delete_user_pdf",
    "ensure_demo_data",
    "fetch_table_rows",
    "get_application_request",
    "get_engine",
    "get_password_reset",
    "get_pdf_content",
    "get_pdf_metadata",
    "get_supervisor_email_hash",
    "get_supervisor_login_details_for_orgnr",
    "get_supervisor_name_by_hash",
    "get_supervisor_overview",
    "get_table_schema",
    "get_user_info",
    "get_user_pdfs",
    "get_username",
    "get_username_by_personnummer_hash",
    "hash_password",
    "hash_value",
    "list_application_requests",
    "list_companies_for_invoicing",
    "list_supervisor_connections",
    "list_user_link_requests",
    "list_user_supervisor_connections",
    "log_admin_action",
    "normalize_email",
    "normalize_orgnr",
    "normalize_personnummer",
    "password_resets_table",
    "pending_supervisors_table",
    "pending_users_table",
    "reject_application_request",
    "reset_demo_database",
    "reset_engine",
    "reset_password_with_token",
    "schema_migrations_table",
    "store_pdf_blob",
    "supervisor_activate_account",
    "supervisor_connections_table",
    "supervisor_exists",
    "supervisor_has_access",
    "supervisor_link_requests_table",
    "supervisor_remove_connection",
    "supervisors_table",
    "update_pdf_categories",
    "update_table_row",
    "user_accept_link_request",
    "user_create_user",
    "user_pdfs_table",
    "user_reject_link_request",
    "user_remove_supervisor_connection",
    "users_table",
    "validate_orgnr",
    "verify_certificate",
    "verify_password",
    "verify_supervisor_credentials",
]
