import io
import os
import sys

import pytest
import werkzeug

if not hasattr(werkzeug, "__version__"):
    werkzeug.__version__ = "3.0.0"

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import app  # noqa: E402
import functions  # noqa: E402
from app import save_pdf_for_user  # noqa: E402
from course_categories import COURSE_CATEGORIES  # noqa: E402
from werkzeug.datastructures import FileStorage


def _file_storage(data: bytes, filename: str, mimetype: str = "application/pdf") -> FileStorage:
    """Helper to create an in-memory FileStorage object."""
    return FileStorage(stream=io.BytesIO(data), filename=filename, content_type=mimetype)


def test_save_pdf_stores_in_database(empty_db):
    pdf = _file_storage(b"%PDF-1.4 test", "9001011234_resume.pdf")
    category = COURSE_CATEGORIES[0][0]
    result = save_pdf_for_user("9001011234", pdf, [category])

    assert "id" in result and "filename" in result
    assert "9001011234" not in result["filename"]

    pnr_hash = functions.hash_value("9001011234")

    with functions.get_engine().connect() as conn:
        row = conn.execute(
            functions.user_pdfs_table.select().where(
                functions.user_pdfs_table.c.id == result["id"]
            )
        ).first()
    assert row is not None
    assert row.filename == result["filename"]
    assert row.personnummer == pnr_hash

    filename, decrypted = functions.get_pdf_content(pnr_hash, row.id)
    assert filename == result["filename"]
    assert decrypted == b"%PDF-1.4 test"


def test_save_pdf_rejects_invalid_files(empty_db):
    not_pdf = _file_storage(b"not pdf", "doc.pdf")
    category = COURSE_CATEGORIES[0][0]
    with pytest.raises(ValueError):
        save_pdf_for_user("9001011234", not_pdf, [category])
    wrong_mime = _file_storage(b"%PDF-1.4 test", "doc.pdf", mimetype="text/plain")
    with pytest.raises(ValueError):
        save_pdf_for_user("9001011234", wrong_mime, [category])


def test_save_pdf_requires_category(empty_db):
    pdf = _file_storage(b"%PDF-1.4 test", "certificate.pdf")
    with pytest.raises(ValueError):
        save_pdf_for_user("9001011234", pdf, [])


def test_save_pdf_rejects_multiple_categories(empty_db):
    pdf = _file_storage(b"%PDF-1.4 test", "certificate.pdf")
    category_one = COURSE_CATEGORIES[0][0]
    category_two = COURSE_CATEGORIES[1][0]
    with pytest.raises(ValueError):
        save_pdf_for_user("9001011234", pdf, [category_one, category_two])
