from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import call, Mock

import config_loader


def test_resolve_unique_paths_skips_empty_entries() -> None:
    result = config_loader._resolve_unique_paths([None, "", None])
    assert result == []


def test_resolve_unique_paths_expands_user_home(monkeypatch, tmp_path) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))

    paths = config_loader._resolve_unique_paths(["~/.config/test.env"])

    assert paths == [fake_home / ".config" / "test.env"]


def test_resolve_unique_paths_ignores_duplicates(tmp_path) -> None:
    first = tmp_path / "first.env"
    first.write_text("data", encoding="utf-8")
    duplicate = Path(str(first))
    second = tmp_path / "second.env"
    second.write_text("more", encoding="utf-8")

    paths = config_loader._resolve_unique_paths([first, duplicate, second, str(second)])

    assert paths == [first, second]


def test_load_environment_loads_existing_candidates(monkeypatch, tmp_path) -> None:
    first = tmp_path / "first.env"
    first.write_text("A=1", encoding="utf-8")
    second = tmp_path / "second.env"
    second.write_text("B=2", encoding="utf-8")

    fake_loader: Mock = Mock()
    monkeypatch.setattr(config_loader, "load_dotenv", fake_loader)
    monkeypatch.setattr(
        config_loader,
        "_resolve_unique_paths",
        lambda _: [first, second],
    )

    config_loader.load_environment()

    assert fake_loader.call_args_list == [
        call(first, override=False),
        call(second, override=False),
    ]


def test_load_environment_uses_fallback_when_missing(monkeypatch, tmp_path) -> None:
    missing = tmp_path / "missing.env"

    fake_loader: Mock = Mock()
    monkeypatch.setattr(config_loader, "load_dotenv", fake_loader)
    monkeypatch.setattr(config_loader, "_resolve_unique_paths", lambda _: [missing])

    config_loader.load_environment()

    assert fake_loader.call_args_list == [call(override=False)]


def test_load_environment_does_not_override_demo_mode(monkeypatch) -> None:
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.delenv("ENABLE_DEMO_MODE", raising=False)

    fake_loader: Mock = Mock()
    monkeypatch.setattr(config_loader, "load_dotenv", fake_loader)
    monkeypatch.setattr(config_loader, "_resolve_unique_paths", lambda _: [])

    config_loader.load_environment()

    assert "ENABLE_DEMO_MODE" not in os.environ
