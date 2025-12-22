# Tests for the manage_compose script.

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path


def _load_module():
    module_path = Path(__file__).resolve().parents[1] / "scripts" / "manage_compose.py"
    spec = importlib.util.spec_from_file_location("manage_compose", module_path)
    module = importlib.util.module_from_spec(spec)
    if spec.loader is None:
        raise AssertionError("Kunde inte ladda manage_compose-modulen.")
    spec.loader.exec_module(module)
    return module


def test_build_compose_args_includes_expected_flags():
    module = _load_module()
    args = module.build_compose_args("docker-compose.yml", "./.env", "demo")

    assert args == [
        "-f",
        "docker-compose.yml",
        "--env-file",
        "./.env",
        "--project-name",
        "demo",
    ]


def test_default_compose_file_uses_repo_root():
    module = _load_module()
    root = Path(module.__file__).resolve().parents[1]
    prod_file = root / "docker-compose.prod.yml"
    expected = prod_file if prod_file.is_file() else root / "docker-compose.yml"

    assert module.default_compose_file() == str(expected)


def test_run_compose_action_cycle_orders_commands():
    module = _load_module()
    calls: list[tuple[list[str], bool]] = []

    def fake_runner(cmd, check):
        calls.append((list(cmd), check))
        return subprocess.CompletedProcess(cmd, 0)

    module.run_compose_action(["-f", "docker-compose.yml"], "cycle", runner=fake_runner)

    assert calls == [
        (["docker", "compose", "-f", "docker-compose.yml", "down", "--remove-orphans"], True),
        (["git", "pull"], True),
        (["docker", "compose", "-f", "docker-compose.yml", "up", "-d", "--build"], True),
    ]


def test_select_action_returns_none_for_exit():
    module = _load_module()

    def fake_input(prompt):
        return "6"

    assert module.select_action(fake_input) is None


def test_run_compose_action_git_pull_runs_git():
    module = _load_module()
    calls: list[tuple[list[str], bool]] = []

    def fake_runner(cmd, check):
        calls.append((list(cmd), check))
        return subprocess.CompletedProcess(cmd, 0)

    module.run_compose_action(["-f", "docker-compose.yml"], "git-pull", runner=fake_runner)

    assert calls == [(["git", "pull"], True)]


def test_run_menu_executes_selected_action():
    module = _load_module()
    calls: list[str] = []

    def fake_input(prompt):
        return "1"

    def fake_runner(cmd, check):
        calls.append(" ".join(cmd))
        return subprocess.CompletedProcess(cmd, 0)

    result = module.run_menu(["-f", "docker-compose.yml"], input_func=fake_input, runner=fake_runner)

    assert result == 0
    assert calls == ["docker compose -f docker-compose.yml stop"]
