"""Tests for PDF storage helpers in :mod:`functions`."""

from __future__ import annotations

from datetime import datetime

from cryptography.fernet import Fernet
from sqlalchemy import select

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


def test_pdf_content_is_encrypted_at_rest(empty_db):
    """Stored PDF-data ska krypteras men dekrypteras vid hämtning."""

    _ = empty_db

    pnr_hash = _personnummer_hash("9001011234")
    original_content = b"%PDF-1.4 encrypted"
    pdf_id = functions.store_pdf_blob(
        pnr_hash, "encrypted.pdf", original_content, [COURSE_CATEGORIES[0][0]]
    )

    with functions.get_engine().connect() as conn:
        query = select(functions.user_pdfs_table.c.content).where(
            functions.user_pdfs_table.c.id == pdf_id
        )
        stored_blob = conn.execute(query).scalar_one()

    assert stored_blob != original_content

    filename, decrypted = functions.get_pdf_content(pnr_hash, pdf_id)
    assert filename == "encrypted.pdf"
    assert decrypted == original_content


def test_pdf_key_rotation_allows_decryption_of_old_files(empty_db, monkeypatch):
    """Äldre filer ska kunna dekrypteras när en nyckel roteras."""

    _ = empty_db

    monkeypatch.setenv("PDF_ENCRYPTION_KEYS", "primar,sekundar")
    functions.reset_pdf_encryption_cache()

    pnr_hash = _personnummer_hash("9001011234")
    legacy_content = b"%PDF-1.4 legacy"
    pdf_id = functions.store_pdf_blob(
        pnr_hash, "legacy.pdf", legacy_content, [COURSE_CATEGORIES[0][0]]
    )

    monkeypatch.setenv("PDF_ENCRYPTION_KEYS", "nyprimar,primar,sekundar")
    functions.reset_pdf_encryption_cache()

    filename, decrypted = functions.get_pdf_content(pnr_hash, pdf_id)
    assert filename == "legacy.pdf"
    assert decrypted == legacy_content

    fresh_pdf_id = functions.store_pdf_blob(
        pnr_hash, "fresh.pdf", b"%PDF-1.4 fresh", [COURSE_CATEGORIES[0][0]]
    )
    with functions.get_engine().connect() as conn:
        query = select(functions.user_pdfs_table.c.content).where(
            functions.user_pdfs_table.c.id == fresh_pdf_id
        )
        stored_blob = conn.execute(query).scalar_one()

    assert stored_blob != b"%PDF-1.4 fresh"


def test_decrypts_legacy_fernet_content(empty_db, monkeypatch):
    """Filer krypterade med äldre Fernet-nycklar ska kunna läsas."""

    _ = empty_db

    legacy_key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("PDF_ENCRYPTION_KEYS", legacy_key)
    functions.reset_pdf_encryption_cache()

    pnr_hash = _personnummer_hash("9001011234")
    original = b"%PDF-1.4 legacy-fern"
    fernet = Fernet(legacy_key.encode("ascii"))
    encrypted = fernet.encrypt(original)

    with functions.get_engine().begin() as conn:
        result = conn.execute(
            functions.user_pdfs_table.insert().values(
                personnummer=pnr_hash,
                filename="legacy.pdf",
                content=encrypted,
                categories="",
            )
        )
        pdf_id = result.inserted_primary_key[0]

    filename, decrypted = functions.get_pdf_content(pnr_hash, pdf_id)
    assert filename == "legacy.pdf"
    assert decrypted == original

