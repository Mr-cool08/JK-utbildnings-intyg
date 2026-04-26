# Copyright (c) Liam Suorsa and Mika Suorsa
from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import OperationalError

from functions.database import user_pdfs_table, get_engine
from functions.hashing import _hash_personnummer, _is_valid_hash
from functions.logging import configure_module_logger, mask_hash


logger = configure_module_logger(__name__)

_PDF_QUERY_MAX_ATTEMPTS = 2
_PDF_QUERY_RETRY_DELAY_SECONDS = 0.1


def _serialize_categories(categories: Sequence[str] | None) -> str:
    if not categories:
        return ""
    cleaned: List[str] = []
    seen: set[str] = set()
    for category in categories:
        value = category.strip()
        if value and value not in seen:
            cleaned.append(value)
            seen.add(value)
    return ",".join(cleaned)


def _deserialize_categories(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    return [part for part in raw.split(",") if part]


def _run_pdf_query_with_retry(
    personnummer_hash: str,
    action: str,
    operation: Callable[[Any], Any],
) -> Any:
    # Läsoperationer kan säkert upprepas vid tillfälliga DB/IO-fel.
    # Skrivoperationerna längre ned använder inte _run_pdf_query_with_retry för
    # att undvika dubbla bieffekter om en uppdatering eller insättning redan hann genomföras.
    engine = get_engine()
    for attempt in range(1, _PDF_QUERY_MAX_ATTEMPTS + 1):
        try:
            with engine.connect() as conn:
                return operation(conn)
        except OperationalError:
            if attempt == _PDF_QUERY_MAX_ATTEMPTS:
                raise
            logger.warning(
                "Databasanslutningen tappades vid %s för %s. Försöker igen.",
                action,
                mask_hash(personnummer_hash),
            )
            engine.dispose()
            time.sleep(_PDF_QUERY_RETRY_DELAY_SECONDS * attempt)


def delete_user_pdf(personnummer: str, pdf_id: int) -> bool:
    # Ta bort en PDF kopplad till en användares personnummer.
    personnummer_hash = _hash_personnummer(personnummer)
    with get_engine().begin() as conn:
        result = conn.execute(
            delete(user_pdfs_table).where(
                user_pdfs_table.c.personnummer == personnummer_hash,
                user_pdfs_table.c.id == pdf_id,
            )
        )
    deleted = result.rowcount > 0
    if deleted:
        logger.info("PDF %s raderades för %s", pdf_id, mask_hash(personnummer_hash))
    else:
        logger.warning("PDF %s kunde inte raderas för %s", pdf_id, mask_hash(personnummer_hash))
    return deleted


def update_pdf_categories(personnummer: str, pdf_id: int, categories: Sequence[str]) -> bool:
    # Uppdatera kategorierna för en PDF.
    personnummer_hash = _hash_personnummer(personnummer)
    serialized = _serialize_categories(categories)
    with get_engine().begin() as conn:
        result = conn.execute(
            update(user_pdfs_table)
            .where(
                user_pdfs_table.c.personnummer == personnummer_hash,
                user_pdfs_table.c.id == pdf_id,
            )
            .values(categories=serialized)
        )
    updated = result.rowcount > 0
    if updated:
        logger.info(
            "PDF %s fick nya kategorier %s för %s",
            pdf_id,
            serialized,
            mask_hash(personnummer_hash),
        )
    else:
        logger.warning(
            "PDF %s kunde inte uppdateras för %s",
            pdf_id,
            mask_hash(personnummer_hash),
        )
    return updated


def store_pdf_blob(
    personnummer_hash: str,
    filename: str,
    content: bytes,
    categories: Sequence[str] | None = None,
    note: str = "",
) -> int:
    # Store a PDF for the hashed personnummer and return its database id.
    with get_engine().begin() as conn:
        result = conn.execute(
            insert(user_pdfs_table).values(
                personnummer=personnummer_hash,
                filename=filename,
                content=content,
                categories=_serialize_categories(categories),
                note=note,
            )
        )
        pdf_id = result.inserted_primary_key[0]
    logger.info(
        "Sparade PDF %s för %s med id %s",
        filename,
        mask_hash(personnummer_hash),
        pdf_id,
    )
    return int(pdf_id)


def get_user_pdfs(personnummer_hash: str) -> List[Dict[str, Any]]:
    # Return metadata for all PDFs belonging to ``personnummer_hash``.
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return []

    query = (
        select(
            user_pdfs_table.c.id,
            user_pdfs_table.c.filename,
            user_pdfs_table.c.categories,
            user_pdfs_table.c.uploaded_at,
            user_pdfs_table.c.note,
        )
        .where(user_pdfs_table.c.personnummer == personnummer_hash)
        .order_by(
            user_pdfs_table.c.uploaded_at.desc(),
            user_pdfs_table.c.id.desc(),
        )
    )

    rows = _run_pdf_query_with_retry(
        personnummer_hash,
        "hämtning av PDF-lista",
        lambda conn: conn.execute(query).fetchall(),
    )
    return [
        {
            "id": row.id,
            "filename": row.filename,
            "categories": _deserialize_categories(row.categories),
            "uploaded_at": row.uploaded_at,
            "note": getattr(row, "note", "") or "",
        }
        for row in rows
    ]


def get_pdf_metadata(personnummer_hash: str, pdf_id: int) -> Optional[Dict[str, Any]]:
    # Return metadata for a single PDF without loading its content.
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return None
    query = select(
        user_pdfs_table.c.id,
        user_pdfs_table.c.filename,
        user_pdfs_table.c.categories,
        user_pdfs_table.c.uploaded_at,
        user_pdfs_table.c.note,
    ).where(
        user_pdfs_table.c.personnummer == personnummer_hash,
        user_pdfs_table.c.id == pdf_id,
    )
    row = _run_pdf_query_with_retry(
        personnummer_hash,
        "hämtning av PDF-metadata",
        lambda conn: conn.execute(query).first(),
    )
    if not row:
        return None
    return {
        "id": row.id,
        "filename": row.filename,
        "categories": _deserialize_categories(row.categories),
        "uploaded_at": row.uploaded_at,
        "note": getattr(row, "note", "") or "",
    }


def get_pdf_content(personnummer_hash: str, pdf_id: int) -> Optional[Tuple[str, bytes]]:
    # Return the filename and binary content for ``pdf_id``.
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return None
    query = select(
        user_pdfs_table.c.filename,
        user_pdfs_table.c.content,
    ).where(
        user_pdfs_table.c.personnummer == personnummer_hash,
        user_pdfs_table.c.id == pdf_id,
    )
    row = _run_pdf_query_with_retry(
        personnummer_hash,
        "hämtning av PDF-innehåll",
        lambda conn: conn.execute(query).first(),
    )
    if not row:
        return None
    return row.filename, row.content
