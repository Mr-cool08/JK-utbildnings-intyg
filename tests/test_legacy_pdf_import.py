"""Tests covering automatic import of legacy filesystem PDFs."""

from __future__ import annotations

import functions


def _personnummer_hash() -> str:
    normalized = functions.normalize_personnummer("199001011234")
    return functions.hash_value(normalized)


def test_get_user_pdfs_imports_legacy_files(tmp_path, monkeypatch, empty_db):
    """PDFs stored on disk should be imported and listed for the user."""

    _ = empty_db  # ensure database tables exist

    monkeypatch.setattr(functions, "APP_ROOT", str(tmp_path), raising=False)

    pnr_hash = _personnummer_hash()
    legacy_dir = tmp_path / "uploads" / pnr_hash
    legacy_dir.mkdir(parents=True)

    first_pdf = legacy_dir / "legacy.pdf"
    first_pdf.write_bytes(b"%PDF-1.4 legacy")

    pdfs = functions.get_user_pdfs(pnr_hash)
    assert len(pdfs) == 1
    assert pdfs[0]["filename"] == "legacy.pdf"

    content = functions.get_pdf_content(pnr_hash, pdfs[0]["id"])
    assert content is not None
    filename, data = content
    assert filename == "legacy.pdf"
    assert data.startswith(b"%PDF-")

    second_pdf = legacy_dir / "second.pdf"
    second_pdf.write_bytes(b"%PDF-1.4 second")

    pdfs_after_second = functions.get_user_pdfs(pnr_hash)
    assert len(pdfs_after_second) == 2
    filenames = {item["filename"] for item in pdfs_after_second}
    assert filenames == {"legacy.pdf", "second.pdf"}

    second_entry = next(
        pdf for pdf in pdfs_after_second if pdf["filename"] == "second.pdf"
    )
    second_content = functions.get_pdf_content(pnr_hash, second_entry["id"])
    assert second_content is not None
    assert second_content[0] == "second.pdf"
    assert second_content[1].startswith(b"%PDF-")

    pdfs_final = functions.get_user_pdfs(pnr_hash)
    assert len(pdfs_final) == 2
