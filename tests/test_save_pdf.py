import io
import os
import sys
import pytest
import werkzeug

if not hasattr(werkzeug, "__version__"):
    werkzeug.__version__ = "3.0.0"

# Ensure project root on path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import app
from app import save_pdf_for_user, APP_ROOT
from werkzeug.datastructures import FileStorage


def _file_storage(data: bytes, filename: str, mimetype: str = "application/pdf") -> FileStorage:
    """Helper to create an in-memory FileStorage object."""
    return FileStorage(stream=io.BytesIO(data), filename=filename, content_type=mimetype)


def test_save_pdf_removes_personnummer_from_filename(tmp_path, monkeypatch):
    monkeypatch.setitem(app.app.config, "UPLOAD_ROOT", tmp_path)
    pdf = _file_storage(b"%PDF-1.4 test", "199001011234_resume.pdf")
    rel = save_pdf_for_user("199001011234", pdf)
    abs_path = os.path.join(APP_ROOT, rel)
    assert os.path.exists(abs_path)
    assert "199001011234" not in os.path.basename(rel)


def test_save_pdf_rejects_invalid_files(tmp_path, monkeypatch):
    monkeypatch.setitem(app.app.config, "UPLOAD_ROOT", tmp_path)
    not_pdf = _file_storage(b"not pdf", "doc.pdf")
    with pytest.raises(ValueError):
        save_pdf_for_user("199001011234", not_pdf)
    wrong_mime = _file_storage(b"%PDF-1.4 test", "doc.pdf", mimetype="text/plain")
    with pytest.raises(ValueError):
        save_pdf_for_user("199001011234", wrong_mime)
