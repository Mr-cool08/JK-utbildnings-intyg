# Copyright (c) Liam Suorsa and Mika Suorsa
import io

import pytest

from PIL import Image
from werkzeug.datastructures import FileStorage

import app
import functions
from course_categories import COURSE_CATEGORIES
from services.pdf_scanner import ScanVerdict


def test_save_pdf_for_user(empty_db):
    pdf_bytes = b"%PDF-1.4 test"
    file_storage = FileStorage(
        stream=io.BytesIO(pdf_bytes),
        filename="test.pdf",
        content_type="application/pdf",
    )

    category = COURSE_CATEGORIES[0][0]
    result = app.pdf.save_pdf_for_user("19900101-1234", file_storage, [category])
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


def test_save_png_converts_to_pdf(empty_db):
    image = Image.new("RGB", (10, 10), (255, 0, 0))
    png_buffer = io.BytesIO()
    image.save(png_buffer, format="PNG")
    png_bytes = png_buffer.getvalue()
    file_storage = FileStorage(
        stream=io.BytesIO(png_bytes),
        filename="bevis.png",
        content_type="image/png",
    )

    category = COURSE_CATEGORIES[0][0]
    result = app.pdf.save_pdf_for_user("19900101-1234", file_storage, [category])

    assert result["filename"].endswith(".pdf")
    personnummer_hash = functions.hash_value(
        functions.normalize_personnummer("19900101-1234")
    )
    filename, decrypted = functions.get_pdf_content(personnummer_hash, result["id"])
    assert filename == result["filename"]
    assert decrypted.startswith(b"%PDF-")
    assert decrypted != png_bytes


def test_save_pdf_rejects_blocked_scan(monkeypatch, empty_db):
    pdf_bytes = b"%PDF-1.4 block"  # nosec - testdata
    personnummer = "19900101-1234"
    category = COURSE_CATEGORIES[0][0]

    def _reject_scan(_content: bytes, _logger=None):
        return ScanVerdict("REJECT", ["JavaScript"])

    monkeypatch.setattr("functions.pdf.service.scan_pdf_bytes", _reject_scan)

    file_storage = FileStorage(
        stream=io.BytesIO(pdf_bytes),
        filename="malicious.pdf",
        content_type="application/pdf",
    )

    with pytest.raises(ValueError):
        app.pdf.save_pdf_for_user(personnummer, file_storage, [category])
