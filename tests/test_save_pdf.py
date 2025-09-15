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
from werkzeug.datastructures import FileStorage


def _file_storage(data: bytes, filename: str, mimetype: str = "application/pdf") -> FileStorage:
    """Helper to create an in-memory FileStorage object."""
    return FileStorage(stream=io.BytesIO(data), filename=filename, content_type=mimetype)


def test_save_pdf_stores_in_database(empty_db):
    pdf = _file_storage(b"%PDF-1.4 test", "199001011234_resume.pdf")
    result = save_pdf_for_user("199001011234", pdf)

    assert "id" in result and "filename" in result
    assert "199001011234" not in result["filename"]

    with functions.get_engine().connect() as conn:
        row = conn.execute(
            functions.user_pdfs_table.select().where(
                functions.user_pdfs_table.c.id == result["id"]
            )
        ).first()
    assert row is not None
    assert row.filename == result["filename"]
    assert row.personnummer == functions.hash_value("199001011234")
    assert row.content.startswith(b"%PDF-")


def test_save_pdf_rejects_invalid_files(empty_db):
    not_pdf = _file_storage(b"not pdf", "doc.pdf")
    with pytest.raises(ValueError):
        save_pdf_for_user("199001011234", not_pdf)
    wrong_mime = _file_storage(b"%PDF-1.4 test", "doc.pdf", mimetype="text/plain")
    with pytest.raises(ValueError):
        save_pdf_for_user("199001011234", wrong_mime)
