from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional

from sqlalchemy import select, update

from functions.app_paths import APP_ROOT
from functions.applications.requests import _ensure_company
from functions.db.engine import create_database, get_engine, reset_engine
from functions.db.schema import (
    company_users_table,
    pending_supervisors_table,
    pending_users_table,
    supervisors_table,
    user_pdfs_table,
    users_table,
)
from functions.logging.logging_utils import configure_module_logger
from functions.pdf.storage import store_pdf_blob, _serialize_categories
from functions.security.hashing import (
    hash_password,
    hash_value,
    normalize_email,
    normalize_personnummer,
    validate_orgnr,
)
from functions.users.accounts import (
    admin_create_user,
    supervisor_activate_account,
    user_create_user,
    verify_certificate,
)
from functions.users.supervisor_links import admin_link_supervisor_to_user

logger = configure_module_logger(__name__)


def create_test_user() -> None:
    # Populate the database with a simple test user.
    email = "test@example.com"
    username = "Test User"
    personnummer = "9001011234"
    if not admin_create_user(email, username, personnummer):
        return
    pnr_hash = hash_value(normalize_personnummer(personnummer))
    user_create_user("password", pnr_hash)


def ensure_demo_data(
    *,
    user_email: str,
    user_name: str,
    user_personnummer: str,
    user_password: str,
    supervisor_email: str,
    supervisor_name: str,
    supervisor_password: str,
    supervisor_orgnr: Optional[str] = None,
) -> None:
    # Skapa eller uppdatera demodata för företagskonto och standardkonto.
    try:
        normalized_pnr = normalize_personnummer(user_personnummer)
    except ValueError:
        logger.error("Ogiltigt personnummer för demoanvändare: %s", user_personnummer)
        return

    try:
        normalized_user_email = normalize_email(user_email)
    except ValueError:
        logger.error("Ogiltig e-postadress för demoanvändare: %s", user_email)
        return

    try:
        normalized_supervisor_email = normalize_email(supervisor_email)
    except ValueError:
        logger.error("Ogiltig e-postadress för demoföretagskonto: %s", supervisor_email)
        return

    try:
        normalized_orgnr = validate_orgnr(supervisor_orgnr) if supervisor_orgnr else None
    except ValueError:
        logger.error(
            "Ogiltigt organisationsnummer för demoföretagskonto: %s", supervisor_orgnr
        )
        normalized_orgnr = None

    pnr_hash = hash_value(normalized_pnr)
    user_email_hash = hash_value(normalized_user_email)
    supervisor_email_hash = hash_value(normalized_supervisor_email)

    engine = get_engine()

    user_created = False
    user_updated = False
    with engine.begin() as conn:
        existing_user = conn.execute(
            select(users_table.c.id).where(users_table.c.personnummer == pnr_hash)
        ).first()
        if existing_user:
            conn.execute(
                update(users_table)
                .where(users_table.c.personnummer == pnr_hash)
                .values(
                    username=user_name,
                    email=user_email_hash,
                    password=hash_password(user_password),
                )
            )
            user_updated = True
            logger.info("Demodata: uppdaterade demoanvändare")
        else:
            conn.execute(
                pending_users_table.delete().where(
                    pending_users_table.c.personnummer == pnr_hash
                )
            )
            conn.execute(
                pending_users_table.delete().where(
                    pending_users_table.c.email == user_email_hash
                )
            )
            conn.execute(
                pending_users_table.insert().values(
                    username=user_name,
                    email=user_email_hash,
                    personnummer=pnr_hash,
                )
            )
            user_created = True
            logger.info("Demodata: skapade pending-demoanvändare")

    if user_created:
        if user_create_user(user_password, pnr_hash):
            logger.info("Demodata: demoanvändare aktiverad")
        else:
            logger.warning("Demodata: demoanvändare kunde inte aktiveras")
    elif user_updated:
        verify_certificate.cache_clear()

    supervisor_created = False
    with engine.begin() as conn:
        existing_supervisor = conn.execute(
            select(supervisors_table.c.id).where(
                supervisors_table.c.email == supervisor_email_hash
            )
        ).first()
        if existing_supervisor:
            conn.execute(
                update(supervisors_table)
                .where(supervisors_table.c.email == supervisor_email_hash)
                .values(
                    name=supervisor_name,
                    password=hash_password(supervisor_password),
                )
            )
            logger.info("Demodata: uppdaterade demoföretagskonto")
        else:
            conn.execute(
                pending_supervisors_table.delete().where(
                    pending_supervisors_table.c.email == supervisor_email_hash
                )
            )
            conn.execute(
                pending_supervisors_table.insert().values(
                    name=supervisor_name,
                    email=supervisor_email_hash,
                )
            )
            supervisor_created = True
            logger.info("Demodata: skapade pending-demoföretagskonto")

    if supervisor_created:
        try:
            if supervisor_activate_account(supervisor_email_hash, supervisor_password):
                logger.info("Demodata: demoföretagskonto aktiverat")
            else:
                logger.warning("Demodata: demoföretagskonto kunde inte aktiveras")
        except ValueError:
            logger.exception("Demodata: lösenordet för demoföretagskontot är ogiltigt")

    if normalized_orgnr:
        with engine.begin() as conn:
            try:
                company_id, created_company, company_name = _ensure_company(
                    conn,
                    normalized_orgnr,
                    supervisor_name,
                    invoice_address="Demovägen 1, 123 45 Demo",
                    invoice_contact=supervisor_name,
                    invoice_reference="DEMOKONTO",
                )
            except ValueError:
                logger.exception(
                    "Demodata: kunde inte skapa företag för organisationsnummer %s",
                    normalized_orgnr,
                )
            else:
                if created_company:
                    logger.info(
                        "Demodata: skapade demoföretag %s (%s)",
                        company_name,
                        normalized_orgnr,
                    )
                existing_company_user = conn.execute(
                    select(company_users_table.c.id).where(
                        company_users_table.c.email == normalized_supervisor_email
                    )
                ).first()
                if existing_company_user:
                    conn.execute(
                        update(company_users_table)
                        .where(company_users_table.c.email == normalized_supervisor_email)
                        .values(
                            company_id=company_id,
                            role="foretagskonto",
                            name=supervisor_name,
                            email=normalized_supervisor_email,
                        )
                    )
                    logger.info(
                        "Demodata: uppdaterade demoföretagskonto för %s",
                        normalized_orgnr,
                    )
                else:
                    conn.execute(
                        company_users_table.insert().values(
                            company_id=company_id,
                            role="foretagskonto",
                            name=supervisor_name,
                            email=normalized_supervisor_email,
                        )
                    )
                    logger.info(
                        "Demodata: kopplade demoföretag %s till företagskonto",
                        normalized_orgnr,
                    )

    linked, reason = admin_link_supervisor_to_user(
        normalized_supervisor_email, normalized_pnr
    )
    if linked:
        logger.info("Demodata: kopplade företagskonto och demoanvändare")
    elif reason != "exists":
        logger.warning(
            "Demodata: kunde inte koppla företagskonto och demoanvändare (%s)", reason
        )

    _ensure_demo_pdfs(pnr_hash)


def reset_demo_database(demo_defaults: Dict[str, str]) -> bool:
    # Rensa demodatabasen och återställ standardinnehållet.
    #
    # Funktionen är endast avsedd att användas i demoläge där en lokal
    # SQLite-databas nyttjas. Om databasen inte är SQLite eller körs i minnet
    # görs ingen återställning.
    engine = get_engine()
    url = engine.url

    if url.get_backend_name() != "sqlite":
        logger.info("Demodatabasen hoppades över eftersom bakänden inte är SQLite")
        return False

    database = url.database or ""
    if database in ("", ":memory:"):
        logger.info("Demodatabasen hoppades över eftersom SQLite körs i minnet")
        return False

    reset_engine()

    try:
        Path(database).unlink(missing_ok=True)
    except OSError:
        logger.exception("Demodatabasen kunde inte tas bort")
        return False

    create_database()
    ensure_demo_data(**demo_defaults)

    logger.info("Demodatabasen har rensats och återställts till standarddata")
    return True


DEMO_PDF_DEFINITIONS = [
    {
        "filename": "Kompetensintyg_Demoanvandare.pdf",
        "path": Path(APP_ROOT)
        / "demo_assets"
        / "pdfs"
        / "Kompetensintyg_Demoanvandare.pdf",
        "categories": ["fallskydd", "heta-arbeten"],
    },
    {
        "filename": "Utbildningsbevis_Demoanvandare.pdf",
        "path": Path(APP_ROOT)
        / "demo_assets"
        / "pdfs"
        / "Utbildningsbevis_Demoanvandare.pdf",
        "categories": ["lift"],
    },
]


def _ensure_demo_pdfs(personnummer_hash: str) -> None:
    # Säkerställ att demoanvändaren har exempel-PDF:er uppladdade.
    with get_engine().begin() as conn:
        existing = conn.execute(
            select(user_pdfs_table.c.filename).where(
                user_pdfs_table.c.personnummer == personnummer_hash
            )
        )
        existing_filenames = {row.filename for row in existing}

    for pdf in DEMO_PDF_DEFINITIONS:
        path = pdf["path"]
        filename = pdf["filename"]
        if not path.is_file():
            logger.warning("Demodata: kunde inte hitta demopdf %s", path)
            continue

        content = path.read_bytes()
        categories_serialized = _serialize_categories(pdf.get("categories"))

        if filename in existing_filenames:
            with get_engine().begin() as conn:
                conn.execute(
                    update(user_pdfs_table)
                    .where(user_pdfs_table.c.personnummer == personnummer_hash)
                    .where(user_pdfs_table.c.filename == filename)
                    .values(content=content, categories=categories_serialized)
                )
            logger.info("Demodata: uppdaterade demopdf %s", filename)
        else:
            store_pdf_blob(personnummer_hash, filename, content, pdf.get("categories"))
            existing_filenames.add(filename)
