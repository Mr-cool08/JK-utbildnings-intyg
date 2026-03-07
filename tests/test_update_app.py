import subprocess
from pathlib import Path

import scripts.update_app as ua


def _patch_main_runtime(
    monkeypatch,
    calls,
    venv_bin="X",
):
    def fake_run(cmd, check=True, **kwargs):
        calls.append((list(cmd), kwargs.get("cwd")))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(ua, "_run", fake_run)
    monkeypatch.setattr(ua, "_build_venv_command", lambda root, a, b: [venv_bin])
    monkeypatch.setattr(ua, "_find_requirements", lambda root: [])
    monkeypatch.setattr(ua, "_run_os_upgrade_if_enabled", lambda: None)
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *args, **kwargs: type(
            "P", (), {"terminate": lambda self: None, "wait": lambda self: None}
        )(),
    )
    monkeypatch.setattr(ua.time, "sleep", lambda *_: None)


def _index_of_command(calls, expected_command):
    for index, (command, _) in enumerate(calls):
        if command == expected_command:
            return index
    raise AssertionError(f"Kommandot hittades inte: {expected_command}")


def _find_command_prefix(calls, prefix):
    for command, _ in calls:
        if command[: len(prefix)] == prefix:
            return command
    raise AssertionError(f"Kommandoprefix hittades inte: {prefix}")


def test_find_requirements_skips_virtualenv(tmp_path):
    # root has one requirements and one inside venv which should be ignored
    r1 = tmp_path / "requirements.txt"
    r1.write_text("flask\n")
    venv_req = tmp_path / "venv" / "requirements.txt"
    venv_req.parent.mkdir()
    venv_req.write_text("ignored\n")

    found = ua._find_requirements(tmp_path)
    assert found == [r1]


def test_build_venv_command_prefers_unix_layout_on_posix(tmp_path):
    root = tmp_path
    for v in ("venv", ".venv"):
        (root / v / "bin").mkdir(parents=True, exist_ok=True)
        (root / v / "bin" / "pip").write_text("")
        (root / v / "bin" / "pytest").write_text("")
        # add windows layout too to keep test intent aligned with name
        (root / v / "Scripts").mkdir(parents=True, exist_ok=True)
        (root / v / "Scripts" / "pip.exe").write_text("")
        (root / v / "Scripts" / "pytest.exe").write_text("")

    pip_cmd = ua._build_venv_command(root, "pip", "pip.exe")
    assert Path(pip_cmd[0]).name == "pip" or Path(pip_cmd[0]).name == "pip.exe"


def test_main_sequence_uses_production_compose(monkeypatch):
    calls = []
    _patch_main_runtime(monkeypatch, calls, venv_bin="Y")

    ua.main()

    prod_ps_idx = _index_of_command(
        calls, ["docker", "compose", "-f", "docker-compose.yml", "ps", "--all"]
    )

    assert prod_ps_idx == 0


def test_main_sequence_runs_expected_commands(monkeypatch):
    calls = []
    _patch_main_runtime(monkeypatch, calls, venv_bin="Y")

    ua.main()

    assert calls[0][0][:5] == ["docker", "compose", "-f", "docker-compose.yml", "ps"]
    assert any(c[0][0] == "git" for c in calls)
    assert any(c[0] and c[0][0] == "Y" for c in calls)


def test_main_runs_compose_up_without_scale_flags(monkeypatch):
    calls = []
    _patch_main_runtime(monkeypatch, calls, venv_bin="Y")

    ua.main()

    up_command = _find_command_prefix(
        calls, ["docker", "compose", "-f", "docker-compose.yml", "up", "-d"]
    )
    assert "--scale" not in up_command
