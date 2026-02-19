# Copyright (c) Liam Suorsa
"""Tests for PDF storage helpers in :mod:`functions`."""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

from sqlalchemy import select
from sqlalchemy.exc import OperationalError

import functions
from course_categories import COURSE_CATEGORIES


def _personnummer_hash(personnummer: str) -> str:
    """Return a hashed personnummer suitable for database lookups."""

    normalized = functions.normalize_personnummer(personnummer)
    return functions.hash_value(normalized)


def test_store_pdf_blob_returns_unique_ids(empty_db):
    """Storing multiple PDFs should return unique, increasing identifiers."""

    _ = empty_db  # ensure database is initialized

    pnr_hash = _personnummer_hash("9001011234")
    first_id = functions.store_pdf_blob(
        pnr_hash, "first.pdf", b"%PDF-1.4 first", [COURSE_CATEGORIES[0][0]]
    )
    second_id = functions.store_pdf_blob(
        pnr_hash, "second.pdf", b"%PDF-1.4 second", [COURSE_CATEGORIES[1][0]]
    )

    assert isinstance(first_id, int)
    assert isinstance(second_id, int)
    assert first_id != second_id
    assert second_id > first_id


def test_get_pdf_metadata_returns_expected_information(empty_db):
    """Metadata lookups should include id, filename and timestamp."""

    _ = empty_db

    pnr_hash = _personnummer_hash("9001011234")
    pdf_id = functions.store_pdf_blob(
        pnr_hash, "metadata.pdf", b"%PDF-1.4 metadata", [COURSE_CATEGORIES[0][0]]
    )

    metadata = functions.get_pdf_metadata(pnr_hash, pdf_id)

    assert metadata is not None
    assert metadata["id"] == pdf_id
    assert metadata["filename"] == "metadata.pdf"
    assert isinstance(metadata["uploaded_at"], datetime)
    assert metadata["categories"] == [COURSE_CATEGORIES[0][0]]


def test_get_pdf_metadata_handles_missing_entries(empty_db):
    """Requests for unknown PDFs should gracefully return ``None``."""

    _ = empty_db

    primary_hash = _personnummer_hash("9001011234")
    other_hash = _personnummer_hash("9002024567")
    pdf_id = functions.store_pdf_blob(
        primary_hash, "missing.pdf", b"%PDF-1.4 missing", [COURSE_CATEGORIES[0][0]]
    )

    assert functions.get_pdf_metadata(other_hash, pdf_id) is None
    assert functions.get_pdf_metadata(primary_hash, pdf_id + 100) is None


def test_pdf_content_is_stored_plainly(empty_db):
    """PDF-data ska lagras och hämtas oförändrat."""

    _ = empty_db

    pnr_hash = _personnummer_hash("9001011234")
    original_content = b"%PDF-1.4 utan kryptering"
    pdf_id = functions.store_pdf_blob(
        pnr_hash, "okrypterad.pdf", original_content, [COURSE_CATEGORIES[0][0]]
    )

    with functions.get_engine().connect() as conn:
        query = select(functions.user_pdfs_table.c.content).where(
            functions.user_pdfs_table.c.id == pdf_id
        )
        stored_blob = conn.execute(query).scalar_one()

    assert stored_blob == original_content

    filename, fetched = functions.get_pdf_content(pnr_hash, pdf_id)
    assert filename == "okrypterad.pdf"
    assert fetched == original_content


def test_get_user_pdfs_retries_once_after_operational_error(monkeypatch):
    """Hämtning av användar-PDF:er ska försöka igen vid tillfälligt anslutningsfel."""

    pnr_hash = _personnummer_hash("9001011234")
    expected_uploaded_at = datetime(2026, 1, 1, 12, 30, 0)
    row = SimpleNamespace(
        id=7,
        filename="retry.pdf",
        categories="truck,hlr",
        uploaded_at=expected_uploaded_at,
    )

    state = {"calls": 0}

    class _FailingConnection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, _query):
            state["calls"] += 1
            if state["calls"] == 1:
                raise OperationalError("SELECT 1", {}, Exception("connection lost"))
            return [row]

    class _FakeEngine:
        def __init__(self):
            self.dispose_calls = 0

        def connect(self):
            return _FailingConnection()

        def dispose(self):
            self.dispose_calls += 1

    engine = _FakeEngine()
    monkeypatch.setattr(functions.pdf_storage, "get_engine", lambda: engine)

    pdfs = functions.get_user_pdfs(pnr_hash)

    assert state["calls"] == 2
    assert engine.dispose_calls == 1
    assert pdfs == [
        {
            "id": 7,
            "filename": "retry.pdf",
            "categories": ["truck", "hlr"],
            "uploaded_at": expected_uploaded_at,
            "note": "",
        }
    ]
