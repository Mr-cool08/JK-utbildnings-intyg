import io

from werkzeug.datastructures import FileStorage

import app
import functions
from course_categories import COURSE_CATEGORIES


def test_save_pdf_for_user(empty_db):
    pdf_bytes = b"%PDF-1.4 test"
    file_storage = FileStorage(
        stream=io.BytesIO(pdf_bytes),
        filename="test.pdf",
        content_type="application/pdf",
    )

    category = COURSE_CATEGORIES[0][0]
    result = app.save_pdf_for_user("19900101-1234", file_storage, [category])
    assert result["id"] > 0
    assert result["categories"] == [category]

    with functions.get_engine().connect() as conn:
        row = conn.execute(
            functions.user_pdfs_table.select().where(
                functions.user_pdfs_table.c.id == result["id"]
            )
        ).first()
    assert row is not None
    assert row.filename == result["filename"]
    assert row.categories == category

    personnummer_hash = functions.hash_value(
        functions.normalize_personnummer("19900101-1234")
    )
    filename, decrypted = functions.get_pdf_content(personnummer_hash, row.id)
    assert filename == result["filename"]
    assert decrypted == pdf_bytes
