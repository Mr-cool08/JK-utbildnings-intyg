from pathlib import Path

import functions
from sqlalchemy import func, select


DEMO_PARAMS = dict(
    user_email="demo.anvandare@example.com",
    user_name="Demoanvändare",
    user_personnummer="199001011234",
    user_password="DemoLösenord1!",
    supervisor_email="demo.foretagskonto@example.com",
    supervisor_name="Demoföretagskonto",
    supervisor_password="DemoForetagskonto1!",
    supervisor_orgnr="5560160680",
)


def test_ensure_demo_data_creates_accounts(empty_db):
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
        assert stored[filename] == (demo_dir / filename).read_bytes()


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
