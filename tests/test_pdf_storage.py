"""Tests for PDF storage helpers in :mod:`functions`."""

from __future__ import annotations

from datetime import datetime

import functions


def _personnummer_hash(personnummer: str) -> str:
    """Return a hashed personnummer suitable for database lookups."""

    normalized = functions.normalize_personnummer(personnummer)
    return functions.hash_value(normalized)


def test_store_pdf_blob_returns_unique_ids(empty_db):
    """Storing multiple PDFs should return unique, increasing identifiers."""

    _ = empty_db  # ensure database is initialized

    pnr_hash = _personnummer_hash("9001011234")
    first_id = functions.store_pdf_blob(pnr_hash, "first.pdf", b"%PDF-1.4 first")
    second_id = functions.store_pdf_blob(pnr_hash, "second.pdf", b"%PDF-1.4 second")

    assert isinstance(first_id, int)
    assert isinstance(second_id, int)
    assert first_id != second_id
    assert second_id > first_id


def test_get_pdf_metadata_returns_expected_information(empty_db):
    """Metadata lookups should include id, filename and timestamp."""

    _ = empty_db

    pnr_hash = _personnummer_hash("9001011234")
    pdf_id = functions.store_pdf_blob(pnr_hash, "metadata.pdf", b"%PDF-1.4 metadata")

    metadata = functions.get_pdf_metadata(pnr_hash, pdf_id)

    assert metadata is not None
    assert metadata["id"] == pdf_id
    assert metadata["filename"] == "metadata.pdf"
    assert isinstance(metadata["uploaded_at"], datetime)


def test_get_pdf_metadata_handles_missing_entries(empty_db):
    """Requests for unknown PDFs should gracefully return ``None``."""

    _ = empty_db

    primary_hash = _personnummer_hash("9001011234")
    other_hash = _personnummer_hash("9002024567")
    pdf_id = functions.store_pdf_blob(primary_hash, "missing.pdf", b"%PDF-1.4 missing")

    assert functions.get_pdf_metadata(other_hash, pdf_id) is None
    assert functions.get_pdf_metadata(primary_hash, pdf_id + 100) is None

