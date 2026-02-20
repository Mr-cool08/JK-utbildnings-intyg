# Utilities for request/correlation context in logs.

from __future__ import annotations

from contextvars import ContextVar
from uuid import uuid4

_REQUEST_ID: ContextVar[str | None] = ContextVar("request_id", default=None)
_CORRELATION_ID: ContextVar[str | None] = ContextVar("correlation_id", default=None)


def get_request_id() -> str | None:
    return _REQUEST_ID.get()


def set_request_id(value: str | None) -> None:
    _REQUEST_ID.set(value)


def get_correlation_id() -> str | None:
    return _CORRELATION_ID.get()


def set_correlation_id(value: str | None) -> None:
    _CORRELATION_ID.set(value)


def ensure_operation_id() -> str:
    operation_id = get_correlation_id()
    if operation_id:
        return operation_id
    operation_id = uuid4().hex
    set_correlation_id(operation_id)
    return operation_id


# Copyright (c) Liam Suorsa
