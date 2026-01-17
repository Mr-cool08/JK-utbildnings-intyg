# Copyright (c) Liam Suorsa
from __future__ import annotations

import base64
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import Column, LargeBinary, String, bindparam, delete, func, insert, or_, select, update

from functions.database import TABLE_REGISTRY, get_engine


def _get_table(table_name: str):
    table = TABLE_REGISTRY.get(table_name)
    if table is None:
        raise ValueError("Okänd tabell")
    return table


def get_table_schema(table_name: str) -> List[Dict[str, Any]]:
    table = _get_table(table_name)
    schema: List[Dict[str, Any]] = []
    for column in table.c:
        schema.append(
            {
                "name": column.name,
                "type": type(column.type).__name__,
                "nullable": bool(column.nullable),
                "primary_key": column.primary_key,
            }
        )
    return schema


def _encode_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _decode_value(column: Column, raw_value: Any) -> Any:
    if raw_value is None:
        return None
    if isinstance(column.type, LargeBinary):
        if raw_value == "":
            return b""
        if isinstance(raw_value, str):
            try:
                return base64.b64decode(raw_value.encode("ascii"))
            except Exception as exc:  # pragma: no cover - defensiv kontroll
                raise ValueError("Ogiltig binärdata") from exc
        raise ValueError("Ogiltig binärdata")
    return raw_value


def fetch_table_rows(
    table_name: str, search: Optional[str] = None, limit: int = 100
) -> List[Dict[str, Any]]:
    table = _get_table(table_name)
    stmt = select(table)
    if search:
        # Skydda mot SQL-injektion genom att behandla wildcard-tecken som
        # vanliga tecken och använda parametrar.
        escaped = (
            search.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        )
        pattern = f"%{escaped}%"
        parameter = bindparam("search_term", value=pattern)
        conditions = []
        for column in table.c:
            if isinstance(column.type, String):
                conditions.append(func.lower(column).like(parameter, escape="\\"))
        if conditions:
            stmt = stmt.where(or_(*conditions))
    stmt = stmt.order_by(table.c.id.asc()).limit(limit)
    with get_engine().connect() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [{key: _encode_value(value) for key, value in row.items()} for row in rows]


def create_table_row(table_name: str, values: Dict[str, Any]) -> Dict[str, Any]:
    table = _get_table(table_name)
    prepared: Dict[str, Any] = {}
    for column in table.c:
        if column.name in values and not column.primary_key:
            prepared[column.name] = _decode_value(column, values[column.name])
    if not prepared:
        raise ValueError("Inga giltiga kolumner angavs")
    with get_engine().begin() as conn:
        result = conn.execute(insert(table).values(**prepared))
        new_id = None
        if "id" in table.c:
            new_id = result.inserted_primary_key[0]
        if new_id is None:
            return prepared
        row = conn.execute(select(table).where(table.c.id == new_id)).mappings().first()
    return {key: _encode_value(value) for key, value in row.items()}


def update_table_row(table_name: str, row_id: int, values: Dict[str, Any]) -> bool:
    table = _get_table(table_name)
    assignments: Dict[str, Any] = {}
    for column in table.c:
        if column.primary_key:
            continue
        if column.name in values:
            assignments[column.name] = _decode_value(column, values[column.name])
    if not assignments:
        raise ValueError("Inga fält att uppdatera")
    with get_engine().begin() as conn:
        result = conn.execute(
            update(table).where(table.c.id == row_id).values(**assignments)
        )
    return result.rowcount > 0


def delete_table_row(table_name: str, row_id: int) -> bool:
    table = _get_table(table_name)
    with get_engine().begin() as conn:
        result = conn.execute(delete(table).where(table.c.id == row_id))
    return result.rowcount > 0
