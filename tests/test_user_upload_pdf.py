# Copyright (c) Liam Suorsa
import io

import app
import functions
from course_categories import COURSE_CATEGORIES


def test_user_can_upload_pdf_from_dashboard(user_db):
    pdf_bytes = b"%PDF-1.4 via upload"

    with app.app.test_client() as client:
        client.post(
            "/login",
            data={"personnummer": "9001011234", "password": "secret"},
        )

        client.get("/dashboard")

        with client.session_transaction() as session_data:
            csrf_token = session_data.get("csrf_token")

        response = client.post(
            "/dashboard/ladda-upp",
            data={
                "category": COURSE_CATEGORIES[1][0],
                "certificate": (io.BytesIO(pdf_bytes), "intyg.pdf"),
                "csrf_token": csrf_token,
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    assert response.status_code == 200

    personnummer_hash = functions.hash_value("9001011234")
    with functions.get_engine().connect() as conn:
        row = conn.execute(
            functions.user_pdfs_table.select().where(
                functions.user_pdfs_table.c.personnummer == personnummer_hash
            )
        ).first()

    assert row is not None
    assert row.filename.endswith(".pdf")

    filename, stored_content = functions.get_pdf_content(personnummer_hash, row.id)
    assert filename == row.filename
    assert stored_content == pdf_bytes
