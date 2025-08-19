import io
import os
import sys

import pytest
from werkzeug.datastructures import FileStorage

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import main


# Tests for normalize_personnummer

def test_normalize_personnummer_valid():
    assert main.normalize_personnummer(" 19900101-1234 ") == "19900101-1234"


def test_normalize_personnummer_invalid():
    with pytest.raises(ValueError):
        main.normalize_personnummer("abc")


# Tests for save_pdf_for_user

def test_save_pdf_for_user(tmp_path, monkeypatch):
    monkeypatch.setitem(main.app.config, "UPLOAD_ROOT", tmp_path)

    pdf_bytes = b"%PDF-1.4 test"
    file_storage = FileStorage(
        stream=io.BytesIO(pdf_bytes),
        filename="test.pdf",
        content_type="application/pdf",
    )

    rel_path = main.save_pdf_for_user("19900101-1234", file_storage)

    abs_path = os.path.abspath(os.path.join(main.APP_ROOT, rel_path))
    assert os.path.exists(abs_path)
    with open(abs_path, "rb") as f:
        assert f.read() == pdf_bytes
