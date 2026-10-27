# Copyright (c) Liam Suorsa and Mika Suorsa
from datetime import date, timedelta
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import app
import functions
from functions import demo as demo_module
from sqlalchemy import func, select, text


DEMO_PARAMS = dict(
    user_email="demo.anvandare@example.com",
    user_name="Demoanvändare",
    user_personnummer="199001011234",
    user_password="DemoLösenord1!",
    supervisor_email="demo.foretagskonto@example.com",
    supervisor_name="Demoföretagskonto",
    supervisor_password="DemoForetagskonto1!",
    supervisor_orgnr="5569668337",
)


def test_ensure_demo_data_creates_accounts(empty_db, monkeypatch):
    today = date(2026, 10, 22)

    class FixedDate(date):
        @classmethod
        def today(cls):
            return today

    monkeypatch.setattr(demo_module, "date", FixedDate)
    functions.ensure_demo_data(**DEMO_PARAMS)

    assert functions.check_personnummer_password(
        DEMO_PARAMS["user_personnummer"], DEMO_PARAMS["user_password"]
    )
    assert functions.verify_supervisor_credentials(
        DEMO_PARAMS["supervisor_email"], DEMO_PARAMS["supervisor_password"]
    )

    details = functions.get_supervisor_login_details_for_orgnr(
        DEMO_PARAMS["supervisor_orgnr"]
    )
    assert details is not None
    assert details["email"] == functions.normalize_email(DEMO_PARAMS["supervisor_email"])

    with empty_db.connect() as conn:
        connection_row = conn.execute(
            select(
                functions.supervisor_connections_table.c.supervisor_email,
                functions.supervisor_connections_table.c.user_personnummer,
            )
        ).first()

    assert connection_row is not None

    normalized = functions.normalize_personnummer(DEMO_PARAMS["user_personnummer"])
    pnr_hash = functions.hash_value(normalized)
    pdfs = functions.get_user_pdfs(pnr_hash)

    filenames = {pdf["filename"] for pdf in pdfs}
    expected = {item["filename"] for item in functions.DEMO_PDF_DEFINITIONS}
    assert expected.issubset(filenames)
    expiry_dates = {pdf["filename"]: pdf["expires_on"] for pdf in pdfs}
    assert expiry_dates == {
        "demo-arbetsmiljo-grund.pdf": app._add_months_to_date(today, 6),
        "demo-hlr.pdf": today + timedelta(days=14),
        "demo-hlr-utgatt.pdf": today - timedelta(days=30),
    }

    demo_dir = Path(functions.APP_ROOT) / "demo_assets" / "pdfs"
    with empty_db.connect() as conn:
        stored = {
            row.filename: row.content
            for row in conn.execute(
                select(
                    functions.user_pdfs_table.c.filename,
                    functions.user_pdfs_table.c.content,
                )
            )
        }

    for definition in functions.DEMO_PDF_DEFINITIONS:
        filename = definition["filename"]
        assert filename in stored
        source_filename = definition.get("source_filename", filename)
        assert stored[filename] == (demo_dir / source_filename).read_bytes()


def test_demo_expiry_date_uses_calendar_months():
    assert demo_module._demo_expiry_date(
        {"expires_in_months": 6}, date(2025, 8, 31)
    ) == date(2026, 2, 28)


def test_debug_and_demo_modes_seed_missing_certificates_on_startup(
    empty_db, monkeypatch
):
    functions.ensure_demo_data(**DEMO_PARAMS)
    demo_personnummer_hash = functions.hash_value(
        functions.normalize_personnummer(DEMO_PARAMS["user_personnummer"])
    )
    with empty_db.begin() as conn:
        conn.execute(
            functions.user_pdfs_table.delete().where(
                functions.user_pdfs_table.c.personnummer == demo_personnummer_hash
            )
        )
        conn.execute(
            functions.user_pdfs_table.insert().values(
                personnummer=demo_personnummer_hash,
                filename="mitt-eget-intyg.pdf",
                content=b"mitt eget innehall",
                categories="arbetsmiljo-sakerhet",
                note="",
                expires_on=None,
            )
        )

    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("ENABLE_DEMO_MODE", "true")
    monkeypatch.setenv("DEMO_USER_PERSONNUMMER", DEMO_PARAMS["user_personnummer"])
    monkeypatch.setenv("DEMO_USER_EMAIL", DEMO_PARAMS["user_email"])
    monkeypatch.setenv("DEMO_USER_NAME", DEMO_PARAMS["user_name"])
    monkeypatch.setenv("DEMO_USER_PASSWORD", DEMO_PARAMS["user_password"])

    app.create_app()
    app.create_app()

    pdfs = functions.get_user_pdfs(demo_personnummer_hash)
    assert {pdf["filename"] for pdf in pdfs} == {
        "demo-arbetsmiljo-grund.pdf",
        "demo-hlr.pdf",
        "demo-hlr-utgatt.pdf",
        "mitt-eget-intyg.pdf",
    }


def test_debug_and_demo_modes_create_demo_user_and_certificates_on_startup(
    empty_db, monkeypatch
):
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("ENABLE_DEMO_MODE", "true")
    monkeypatch.setenv("DEMO_USER_PERSONNUMMER", DEMO_PARAMS["user_personnummer"])
    monkeypatch.setenv("DEMO_USER_EMAIL", DEMO_PARAMS["user_email"])
    monkeypatch.setenv("DEMO_USER_NAME", DEMO_PARAMS["user_name"])
    monkeypatch.setenv("DEMO_USER_PASSWORD", DEMO_PARAMS["user_password"])

    app.create_app()

    assert functions.check_personnummer_password(
        DEMO_PARAMS["user_personnummer"], DEMO_PARAMS["user_password"]
    )
    personnummer_hash = functions.hash_value(
        functions.normalize_personnummer(DEMO_PARAMS["user_personnummer"])
    )
    pdfs = functions.get_user_pdfs(personnummer_hash)
    assert {pdf["filename"] for pdf in pdfs} == {
        "demo-arbetsmiljo-grund.pdf",
        "demo-hlr.pdf",
        "demo-hlr-utgatt.pdf",
    }


def test_debug_startup_does_not_seed_demo_certificates_for_another_account(
    empty_db, monkeypatch
):
    personnummer_hash = functions.hash_value(
        functions.normalize_personnummer(DEMO_PARAMS["user_personnummer"])
    )
    assert functions.admin_create_user(
        "real.user@example.com", "Riktig användare", DEMO_PARAMS["user_personnummer"]
    )
    assert functions.user_create_user("RealUserPassword1!", personnummer_hash)

    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("ENABLE_DEMO_MODE", "true")
    monkeypatch.setenv("DEMO_USER_PERSONNUMMER", DEMO_PARAMS["user_personnummer"])
    monkeypatch.setenv("DEMO_USER_EMAIL", DEMO_PARAMS["user_email"])
    monkeypatch.setenv("DEMO_USER_NAME", DEMO_PARAMS["user_name"])
    monkeypatch.setenv("DEMO_USER_PASSWORD", DEMO_PARAMS["user_password"])

    app.create_app()

    assert functions.get_user_pdfs(personnummer_hash) == []
    user = functions.get_user_info(DEMO_PARAMS["user_personnummer"])
    assert user.email == functions.normalize_email("real.user@example.com")


def test_ensure_demo_user_retries_after_concurrent_creation(monkeypatch):
    calls = []

    def ensure_once(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            raise demo_module.IntegrityError(
                "INSERT", {}, Exception("duplicate account")
            )
        return True

    monkeypatch.setattr(demo_module, "_ensure_demo_user_once", ensure_once)

    assert functions.ensure_demo_user(
        user_email=DEMO_PARAMS["user_email"],
        user_name=DEMO_PARAMS["user_name"],
        user_personnummer=DEMO_PARAMS["user_personnummer"],
        user_password=DEMO_PARAMS["user_password"],
    )
    assert len(calls) == 2


def test_concurrent_demo_user_initialization_adds_certificates_once(empty_db):
    barrier = Barrier(2)

    def initialize():
        barrier.wait()
        return functions.ensure_demo_user(
            user_email=DEMO_PARAMS["user_email"],
            user_name=DEMO_PARAMS["user_name"],
            user_personnummer=DEMO_PARAMS["user_personnummer"],
            user_password=DEMO_PARAMS["user_password"],
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert list(executor.map(lambda _: initialize(), range(2))) == [True, True]

    with empty_db.connect() as conn:
        filenames = conn.execute(
            select(functions.user_pdfs_table.c.filename)
        ).scalars().all()
    assert sorted(filenames) == sorted(
        definition["filename"] for definition in functions.DEMO_PDF_DEFINITIONS
    )


def test_ensure_demo_data_handles_pending_users_without_orgnr_default(empty_db):
    with empty_db.begin() as conn:
        conn.execute(text("DROP TABLE pending_users"))
        conn.execute(
            text(
                """
                CREATE TABLE pending_users (
                    id INTEGER PRIMARY KEY,
                    username VARCHAR NOT NULL,
                    email VARCHAR NOT NULL,
                    personnummer VARCHAR NOT NULL UNIQUE,
                    orgnr_normalized VARCHAR NOT NULL
                )
                """
            )
        )

    functions.ensure_demo_data(**DEMO_PARAMS)

    with empty_db.connect() as conn:
        user = conn.execute(
            select(functions.users_table).where(
                functions.users_table.c.personnummer
                == functions.hash_value(
                    functions.normalize_personnummer(DEMO_PARAMS["user_personnummer"])
                )
            )
        ).first()

    assert user is not None
    assert user.orgnr_normalized == ""


def test_ensure_demo_data_handles_company_users_without_timestamp_defaults(empty_db):
    with empty_db.begin() as conn:
        conn.execute(text("DROP TABLE company_users"))
        conn.execute(
            text(
                """
                CREATE TABLE company_users (
                    id INTEGER PRIMARY KEY,
                    company_id INTEGER,
                    role VARCHAR NOT NULL,
                    name VARCHAR NOT NULL,
                    email VARCHAR NOT NULL,
                    created_via_application_id INTEGER,
                    created_at DATETIME NOT NULL,
                    updated_at DATETIME NOT NULL,
                    UNIQUE (email, role)
                )
                """
            )
        )

    functions.ensure_demo_data(**DEMO_PARAMS)

    with empty_db.connect() as conn:
        company_user = conn.execute(
            select(functions.company_users_table).where(
                functions.company_users_table.c.email
                == functions.normalize_email(DEMO_PARAMS["supervisor_email"]),
                functions.company_users_table.c.role == "foretagskonto",
            )
        ).first()

    assert company_user is not None
    assert company_user.created_at is not None
    assert company_user.updated_at is not None


def test_ensure_demo_data_handles_supervisor_connections_without_timestamp_default(
    empty_db,
):
    with empty_db.begin() as conn:
        conn.execute(text("DROP TABLE supervisor_connections"))
        conn.execute(
            text(
                """
                CREATE TABLE supervisor_connections (
                    id INTEGER PRIMARY KEY,
                    supervisor_email VARCHAR NOT NULL,
                    user_personnummer VARCHAR NOT NULL,
                    created_at DATETIME NOT NULL,
                    UNIQUE (supervisor_email, user_personnummer)
                )
                """
            )
        )

    functions.ensure_demo_data(**DEMO_PARAMS)

    with empty_db.connect() as conn:
        connection = conn.execute(
            select(functions.supervisor_connections_table).where(
                functions.supervisor_connections_table.c.supervisor_email
                == functions.normalize_email(DEMO_PARAMS["supervisor_email"]),
                functions.supervisor_connections_table.c.user_personnummer
                == functions.hash_value(
                    functions.normalize_personnummer(DEMO_PARAMS["user_personnummer"])
                ),
            )
        ).first()

    assert connection is not None
    assert connection.created_at is not None


def test_ensure_demo_data_is_idempotent(empty_db):
    functions.ensure_demo_data(**DEMO_PARAMS)
    functions.ensure_demo_data(**DEMO_PARAMS)

    with empty_db.connect() as conn:
        user_count = conn.execute(
            select(func.count()).select_from(functions.users_table)
        ).scalar_one()
        supervisor_count = conn.execute(
            select(func.count()).select_from(functions.supervisors_table)
        ).scalar_one()
        connection_count = conn.execute(
            select(func.count()).select_from(functions.supervisor_connections_table)
        ).scalar_one()
        pdf_count = conn.execute(
            select(func.count()).select_from(functions.user_pdfs_table)
        ).scalar_one()

    assert user_count == 1
    assert supervisor_count == 1
    assert connection_count == 1
    assert pdf_count == len(functions.DEMO_PDF_DEFINITIONS)


def test_ensure_demo_data_recovers_when_demo_email_conflicts(empty_db):
    demo_personnummer_hash = functions.hash_value(
        functions.normalize_personnummer(DEMO_PARAMS["user_personnummer"])
    )
    conflicting_personnummer_hash = functions.hash_value("9002021234")

    with empty_db.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Gammal Demo",  # nosec - testdata
                email="annan@example.com",
                password=functions.hash_password("GammalDemo1!"),
                personnummer=demo_personnummer_hash,
            )
        )
        conn.execute(
            functions.users_table.insert().values(
                username="Konflikt",  # nosec - testdata
                email=functions.normalize_email(DEMO_PARAMS["user_email"]),
                password=functions.hash_password("Konflikt1!"),
                personnummer=conflicting_personnummer_hash,
            )
        )

    functions.ensure_demo_data(**DEMO_PARAMS)

    with empty_db.connect() as conn:
        rows = conn.execute(
            select(
                functions.users_table.c.username,
                functions.users_table.c.email,
                functions.users_table.c.personnummer,
            )
        ).fetchall()

    assert len(rows) == 1
    assert rows[0].username == DEMO_PARAMS["user_name"]
    assert rows[0].email == functions.normalize_email(DEMO_PARAMS["user_email"])
    assert rows[0].personnummer == demo_personnummer_hash
    assert functions.check_personnummer_password(
        DEMO_PARAMS["user_personnummer"], DEMO_PARAMS["user_password"]
    )


def test_demo_menu_link_points_to_main_domain(monkeypatch):
    monkeypatch.setitem(app.app.config, "IS_DEMO", True)
    client = app.app.test_client()

    response = client.get("/", base_url="https://demo.exempel.se")

    assert response.status_code == 200
    assert b'L\xc3\xa4mna demomilj\xc3\xb6' in response.data
    assert b'href="https://exempel.se"' in response.data


def test_reset_demo_database_recreates_defaults(tmp_path, monkeypatch):
    db_path = tmp_path / "demo-reset.db"
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("ENABLE_DEMO_MODE", "true")
    monkeypatch.setenv("LOCAL_TEST_DB_PATH", str(db_path))
    functions.reset_engine()
    functions.create_database()

    demo_defaults = DEMO_PARAMS.copy()
    functions.ensure_demo_data(**demo_defaults)

    with functions.get_engine().begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Extra",  # nosec - testdata
                email=functions.hash_value("extra@example.com"),
                password=functions.hash_password("ExtraLosen1!"),
                personnummer=functions.hash_value("9002021234"),
            )
        )

    assert db_path.exists()
    assert functions.reset_demo_database(demo_defaults)

    engine = functions.get_engine()
    with engine.connect() as conn:
        user_count = conn.execute(
            select(func.count()).select_from(functions.users_table)
        ).scalar_one()
        pdf_count = conn.execute(
            select(func.count()).select_from(functions.user_pdfs_table)
        ).scalar_one()

    assert user_count == 1
    assert pdf_count == len(functions.DEMO_PDF_DEFINITIONS)
