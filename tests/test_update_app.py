import subprocess
from pathlib import Path

import scripts.update_app as ua


def _patch_main_runtime(monkeypatch, calls, venv_bin="X", dev_mode=False):
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
    monkeypatch.setattr(ua, "_dev_mode_enabled", lambda: dev_mode)


def _index_of_command(calls, expected_command):
    for index, (command, _) in enumerate(calls):
        if command == expected_command:
            return index
    raise AssertionError(f"Kommandot hittades inte: {expected_command}")


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
    assert Path(pip_cmd[0]).name == "pip"


def test_main_sequence_includes_failover_compose(monkeypatch):
    calls = []
    _patch_main_runtime(monkeypatch, calls, venv_bin="X", dev_mode=False)

    ua.main()

    prod_ps_idx = _index_of_command(
        calls, ["docker", "compose", "-f", "docker-compose.prod.yml", "ps", "--all"]
    )
    failover_up_build_idx = _index_of_command(
        calls,
        ["docker", "compose", "-f", "docker-compose.failover.yml", "up", "-d", "--build"],
    )
    failover_up_idx = _index_of_command(
        calls,
        ["docker", "compose", "-f", "docker-compose.failover.yml", "up", "-d"],
    )

    assert prod_ps_idx < failover_up_build_idx < failover_up_idx


def test_main_sequence_dev_mode_uses_dev_compose(monkeypatch):
    calls = []
    _patch_main_runtime(monkeypatch, calls, venv_bin="Y", dev_mode=True)

    ua.main()

    dev_ps_idx = _index_of_command(
        calls, ["docker", "compose", "-f", "docker-compose.yml", "ps", "--all"]
    )
    failover_up_build_idx = _index_of_command(
        calls,
        ["docker", "compose", "-f", "docker-compose.failover.yml", "up", "-d", "--build"],
    )

    assert dev_ps_idx < failover_up_build_idx
    assert any(command and command[0] == "git" for command, _ in calls)
    assert any(command and command[0] == "Y" for command, _ in calls)
