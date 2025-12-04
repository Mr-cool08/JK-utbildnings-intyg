from __future__ import annotations

import logging
import time
from typing import Sequence

from werkzeug.utils import secure_filename

import functions
from course_categories import normalize_category_slugs
from logging_utils import mask_hash

ALLOWED_MIMES = {"application/pdf"}


def save_pdf_for_user(
    pnr: str,
    file_storage,
    categories: Sequence[str],
    logger: logging.Logger | None = None,
):
    """Validera och spara PDF i databasen för angivet personnummer."""
    logger = logger or logging.getLogger(__name__)
    if file_storage.filename == "":
        logger.error("No file selected for upload")
        raise ValueError("Ingen fil vald.")

    mime = file_storage.mimetype or ""
    if mime not in ALLOWED_MIMES:
        logger.error("Disallowed MIME type %s", mime)
        raise ValueError("Endast PDF tillåts.")

    head = file_storage.stream.read(5)
    file_storage.stream.seek(0)
    if head != b"%PDF-":
        logger.error("File does not appear to be valid PDF")
        raise ValueError("Filen verkar inte vara en giltig PDF.")

    pnr_norm = functions.normalize_personnummer(pnr)
    pnr_hash = functions.hash_value(pnr_norm)
    logger.debug("Saving PDF for person %s", mask_hash(pnr_hash))

    selected_categories = normalize_category_slugs(categories)
    if len(selected_categories) != 1:
        logger.error(
            "Invalid number of categories (%d) for hash %s",
            len(selected_categories),
            mask_hash(pnr_hash),
        )
        raise ValueError("Exakt en kurskategori måste väljas.")

    base = secure_filename(file_storage.filename)
    base = base.replace(pnr_norm, "")
    base = base.lstrip("_- ")
    if not base:
        base = "certificate.pdf"
    # lägg på timestamp för att undvika krockar
    filename = f"{int(time.time())}_{base}"

    file_storage.stream.seek(0)
    content = file_storage.stream.read()
    pdf_id = functions.store_pdf_blob(pnr_hash, filename, content, selected_categories)
    logger.info("Stored PDF for %s as id %s", mask_hash(pnr_hash), pdf_id)
    return {"id": pdf_id, "filename": filename, "categories": selected_categories}
