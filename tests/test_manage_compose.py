# Copyright (c) Liam Suorsa
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
    args = module.build_compose_args("docker-compose.prod.yml", "./.env", "demo")

    assert args == [
        "-f",
        "docker-compose.prod.yml",
        "--env-file",
        "./.env",
        "--project-name",
        "demo",
    ]


def test_default_compose_file_uses_repo_root():
    module = _load_module()
    root = Path(module.__file__).resolve().parents[1]
    prod_file = root / "docker-compose.prod.yml"
    expected = prod_file if prod_file.is_file() else root / "docker-compose.prod.yml"

    assert module.default_compose_file() == str(expected)


def test_default_compose_file_falls_back_to_standard_file(tmp_path):
    module = _load_module()
    module.repo_root = lambda: tmp_path

    standard = tmp_path / "docker-compose.yml"
    standard.write_text("services: {}\n")

    assert module.default_compose_file() == str(standard)


def test_build_venv_command_raises_clear_error(tmp_path):
    module = _load_module()

    try:
        module._build_venv_command(
            tmp_path,
            unix_executable="pytest",
            windows_executable="pytest.exe",
        )
    except FileNotFoundError as exc:
        assert str(exc) == "Kunde inte hitta pytest i venv/.venv-katalogen."
    else:
        raise AssertionError("Förväntade FileNotFoundError när pytest saknas.")


def test_run_compose_action_cycle_orders_commands():
    module = _load_module()
    events: list[dict[str, object]] = []

    module.build_pytest_command = lambda root: ["venv/bin/pytest"]
    module.install_requirements = lambda root, runner: events.append(
        {"event": "install", "root": root}
    )
    module._ensure_compose_volumes = lambda *args, **kwargs: events.append(
        {"event": "ensure"}
    )

    def fake_runner(cmd, check, **kwargs):
        events.append(
            {
                "event": "cmd",
                "cmd": list(cmd),
                "check": check,
                "cwd": kwargs.get("cwd"),
            }
        )
        return subprocess.CompletedProcess(cmd, 0)

    module.run_compose_action(["-f", "docker-compose.yml"], "cycle", runner=fake_runner)

    repo_root = Path(module.__file__).resolve().parents[1]

    assert events == [
        {"event": "cmd", "cmd": ["git", "pull"], "check": True, "cwd": None},
        {"event": "cmd", "cmd": ["sudo", "apt", "update"], "check": True, "cwd": None},
        {"event": "cmd", "cmd": ["sudo", "apt", "upgrade", "-y"], "check": True, "cwd": None},

        {
            "event": "cmd",
            "cmd": ["docker", "compose", "-f", "docker-compose.yml", "stop"],
            "check": True,
            "cwd": None,
        },

        {"event": "install", "root": repo_root},

        {"event": "cmd", "cmd": ["venv/bin/pytest", "-n", "auto"], "check": True, "cwd": repo_root},

        {"event": "cmd", "cmd": ["docker", "system", "df"], "check": True, "cwd": None},

        {
            "event": "cmd",
            "cmd": ["docker", "compose", "-f", "docker-compose.yml", "build", "--no-cache"],
            "check": True,
            "cwd": None,
        },

        {"event": "ensure"},

        {
            "event": "cmd",
            "cmd": [
                "docker",
                "compose",
                "-f",
                "docker-compose.yml",
                "up",
                "-d",
                "--remove-orphans",
                "--renew-anon-volumes",
            ],
            "check": True,
            "cwd": None,
        },

        {"event": "cmd", "cmd": ["docker", "image", "prune", "-a"], "check": True, "cwd": None},
        {"event": "cmd", "cmd": ["docker", "builder", "prune"], "check": True, "cwd": None},
        {"event": "cmd", "cmd": ["docker", "system", "prune", "-a"], "check": True, "cwd": None},
    ]

def test_run_compose_action_build_up_orders_commands():
    module = _load_module()
    events: list[dict[str, object]] = []

    module._ensure_compose_volumes = lambda *args, **kwargs: events.append(
        {"event": "ensure"}
    )

    def fake_runner(cmd, check, **kwargs):
        events.append(
            {
                "event": "cmd",
                "cmd": list(cmd),
                "check": check,
                "cwd": kwargs.get("cwd"),
            }
        )
        return subprocess.CompletedProcess(cmd, 0)

    module.run_compose_action(["-f", "docker-compose.yml"], "build-up", runner=fake_runner)

    assert events == [
        {
            "event": "cmd",
            "cmd": ["docker", "compose", "-f", "docker-compose.yml", "build"],
            "check": True,
            "cwd": None,
        },
        {"event": "ensure"},
        {
            "event": "cmd",
            "cmd": ["docker", "compose", "-f", "docker-compose.yml", "up", "-d"],
            "check": True,
            "cwd": None,
        },
    ]


def test_select_action_returns_none_for_exit():
    module = _load_module()

    def fake_input(prompt):
        return "9"

    assert module.select_action(fake_input) is None


def test_run_compose_action_git_pull_runs_git():
    module = _load_module()
    calls: list[tuple[list[str], bool]] = []

    def fake_runner(cmd, check, **kwargs):
        calls.append((list(cmd), check))
        return subprocess.CompletedProcess(cmd, 0)

    module.run_compose_action(["-f", "docker-compose.yml"], "git-pull", runner=fake_runner)

    assert calls == [(["git", "pull"], True)]


def test_build_pytest_command_uses_repo_venv(tmp_path):
    module = _load_module()
    pytest_path = tmp_path / "venv" / "bin" / "pytest"
    pytest_path.parent.mkdir(parents=True)
    pytest_path.write_text("#!/bin/sh\n")

    assert module.build_pytest_command(tmp_path) == [str(pytest_path)]


def test_run_compose_action_pytest_uses_repo_root():
    module = _load_module()
    calls: list[dict[str, object]] = []

    module.build_pytest_command = lambda root: ["venv/bin/pytest"]

    def fake_runner(cmd, check, **kwargs):
        calls.append(
            {
                "cmd": list(cmd),
                "check": check,
                "cwd": kwargs.get("cwd"),
            }
        )
        return subprocess.CompletedProcess(cmd, 0)

    module.run_compose_action(["-f", "docker-compose.yml"], "pytest", runner=fake_runner)

    repo_root = Path(module.__file__).resolve().parents[1]

    assert calls == [{"cmd": ["venv/bin/pytest", "-n", "auto"], "check": True, "cwd": repo_root}]


def test_build_pip_command_uses_repo_venv(tmp_path):
    module = _load_module()
    pip_path = tmp_path / "venv" / "bin" / "pip"
    pip_path.parent.mkdir(parents=True)
    pip_path.write_text("#!/bin/sh\n")

    assert module.build_pip_command(tmp_path) == [str(pip_path)]


def test_find_requirements_files_ignores_virtualenv_paths(tmp_path):
    module = _load_module()
    root_requirements = tmp_path / "requirements.txt"
    service_requirements = tmp_path / "service" / "requirements.txt"
    venv_requirements = tmp_path / "venv" / "requirements.txt"

    root_requirements.write_text("flask\n")
    service_requirements.parent.mkdir(parents=True)
    service_requirements.write_text("requests\n")
    venv_requirements.parent.mkdir(parents=True)
    venv_requirements.write_text("pytest\n")

    assert module.find_requirements_files(tmp_path) == [
        root_requirements,
        service_requirements,
    ]


def test_install_requirements_runs_pip_for_all_files(tmp_path):
    module = _load_module()
    requirements_one = tmp_path / "requirements.txt"
    requirements_two = tmp_path / "service" / "requirements.txt"
    requirements_one.write_text("flask\n")
    requirements_two.parent.mkdir(parents=True)
    requirements_two.write_text("requests\n")

    module.build_pip_command = lambda root: ["venv/bin/pip"]
    calls: list[dict[str, object]] = []

    def fake_runner(cmd, check, **kwargs):
        calls.append({"cmd": list(cmd), "check": check, "cwd": kwargs.get("cwd")})
        return subprocess.CompletedProcess(cmd, 0)

    module.install_requirements(tmp_path, runner=fake_runner)

    assert calls == [
        {
            "cmd": ["venv/bin/pip", "install", "-r", str(requirements_one)],
            "check": True,
            "cwd": tmp_path,
        },
        {
            "cmd": ["venv/bin/pip", "install", "-r", str(requirements_two)],
            "check": True,
            "cwd": tmp_path,
        },
    ]


def test_run_compose_action_prune_volumes_runs_docker_volume_prune():
    module = _load_module()
    calls: list[tuple[list[str], bool]] = []

    def fake_runner(cmd, check, **kwargs):
        calls.append((list(cmd), check))
        return subprocess.CompletedProcess(cmd, 0)

    module.run_compose_action(["-f", "docker-compose.yml"], "prune-volumes", runner=fake_runner)

    assert calls == [(["docker", "volume", "prune", "--force"], True)]


def test_run_compose_action_system_df_runs_docker_system_df():
    module = _load_module()
    calls: list[tuple[list[str], bool]] = []

    def fake_runner(cmd, check, **kwargs):
        calls.append((list(cmd), check))
        return subprocess.CompletedProcess(cmd, 0)

    module.run_compose_action(["-f", "docker-compose.yml"], "system-df", runner=fake_runner)

    assert calls == [(["docker", "system", "df"], True)]


def test_run_compose_action_up_ensures_volumes_first():
    module = _load_module()
    events: list[dict[str, object]] = []

    module._ensure_compose_volumes = lambda *args, **kwargs: events.append(
        {"event": "ensure"}
    )

    def fake_runner(cmd, check, **kwargs):
        events.append(
            {
                "event": "cmd",
                "cmd": list(cmd),
                "check": check,
            }
        )
        return subprocess.CompletedProcess(cmd, 0)

    module.run_compose_action(["-f", "docker-compose.yml"], "up", runner=fake_runner)

    assert events == [
        {"event": "ensure"},
        {"event": "cmd", "cmd": ["docker", "compose", "-f", "docker-compose.yml", "up", "-d"], "check": True},
    ]


def test_ensure_compose_volumes_creates_missing_volume():
    module = _load_module()
    calls: list[list[str]] = []

    def fake_runner(cmd, check, **kwargs):
        calls.append(list(cmd))
        if cmd[:4] == ["docker", "compose", "-f", "docker-compose.yml"]:
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout='{"volumes": {"env_data": {}}}',
                stderr="",
            )
        if cmd[:3] == ["docker", "volume", "inspect"]:
            raise subprocess.CalledProcessError(1, cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    module._ensure_compose_volumes(
        ["-f", "docker-compose.yml", "--project-name", "demo"],
        runner=fake_runner,
    )

    assert calls == [
        ["docker", "compose", "-f", "docker-compose.yml", "--project-name", "demo", "config", "--format", "json"],
        ["docker", "volume", "inspect", "demo_env_data"],
        ["docker", "volume", "create", "demo_env_data"],
    ]


def test_ensure_compose_volumes_recreates_missing_mountpoint(tmp_path):
    module = _load_module()
    calls: list[list[str]] = []
    missing_mount = tmp_path / "missing"

    def fake_runner(cmd, check, **kwargs):
        calls.append(list(cmd))
        if cmd[:4] == ["docker", "compose", "-f", "docker-compose.yml"]:
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout='{"volumes": {"env_data": {}}}',
                stderr="",
            )
        if cmd[:3] == ["docker", "volume", "inspect"]:
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=f'[{{"Mountpoint": "{missing_mount}"}}]',
                stderr="",
            )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    module._ensure_compose_volumes(
        ["-f", "docker-compose.yml", "--project-name", "demo"],
        runner=fake_runner,
    )

    assert calls == [
        ["docker", "compose", "-f", "docker-compose.yml", "--project-name", "demo", "config", "--format", "json"],
        ["docker", "volume", "inspect", "demo_env_data"],
        ["docker", "volume", "rm", "demo_env_data"],
        ["docker", "volume", "create", "demo_env_data"],
    ]


def test_ensure_volume_present_handles_in_use_volume(capsys, tmp_path):
    module = _load_module()
    calls: list[list[str]] = []
    missing_mount = tmp_path / "missing"

    def fake_runner(cmd, check, **kwargs):
        calls.append(list(cmd))
        if cmd[:3] == ["docker", "volume", "inspect"]:
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=f'[{{"Mountpoint": "{missing_mount}"}}]',
                stderr="",
            )
        if cmd[:3] == ["docker", "volume", "rm"]:
            raise subprocess.CalledProcessError(1, cmd, stderr="volume is in use")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    result = module._ensure_volume_present("demo_env_data", runner=fake_runner)

    assert result is False
    assert calls == [
        ["docker", "volume", "inspect", "demo_env_data"],
        ["docker", "volume", "rm", "demo_env_data"],
    ]
    captured = capsys.readouterr()
    assert "Varning: Kunde inte ta bort Docker-volymen" in captured.err


def test_run_menu_executes_selected_action():
    module = _load_module()
    calls: list[str] = []

    def fake_input(prompt):
        return "1"

    def fake_runner(cmd, check, **kwargs):
        calls.append(" ".join(cmd))
        return subprocess.CompletedProcess(cmd, 0)

    result = module.run_menu(["-f", "docker-compose.yml"], input_func=fake_input, runner=fake_runner)

    assert result == 0
    assert calls == ["docker compose -f docker-compose.yml stop"]
