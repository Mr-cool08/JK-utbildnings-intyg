"""Dekoratorer för inloggnings- och rollkontroller."""

from __future__ import annotations

from functools import wraps
from typing import Callable, TypeVar, cast

from flask import abort, redirect, request, session, url_for

from .roles import ALL_ROLES, ROLE_SUPERVISOR, ROLE_USER

F = TypeVar("F", bound=Callable[..., object])


def _current_role() -> str | None:
    role = session.get("current_role")
    if role in ALL_ROLES:
        return cast(str, role)
    if session.get("supervisor_logged_in"):
        return ROLE_SUPERVISOR
    if session.get("user_logged_in"):
        return ROLE_USER
    return None


def get_current_role() -> str | None:
    """Returnera aktuell roll från sessionen."""

    return _current_role()


def login_required(func: F) -> F:
    """Säkerställ att någon typ av konto är inloggat."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        role = _current_role()
        if role is None:
            if request.blueprint == "supervisor" or request.path.startswith("/foretag"):
                return redirect(url_for("supervisor_login"))
            return redirect(url_for("login"))
        return cast(object, func(*args, **kwargs))

    return cast(F, wrapper)


def role_required(role: str) -> Callable[[F], F]:
    """Returnera en dekorator som kräver angiven roll."""

    if role not in ALL_ROLES:
        raise ValueError(f"Ogiltig roll: {role}")

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs):
            current = _current_role()
            if current is None:
                if role == ROLE_SUPERVISOR:
                    return redirect(url_for("supervisor_login"))
                return redirect(url_for("login"))
            if current != role:
                abort(403)
            return cast(object, func(*args, **kwargs))

        return cast(F, wrapper)

    return decorator


__all__ = ["get_current_role", "login_required", "role_required"]
