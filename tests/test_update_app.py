import subprocess
from pathlib import Path

import scripts.update_app as ua


def _patch_main_runtime(
    monkeypatch,
    calls,
    venv_bin="X",
    dev_mode=False,
    busy_ports=None,
):
    def fake_run(cmd, check=True, **kwargs):
        calls.append((list(cmd), kwargs.get("cwd")))
        return subprocess.CompletedProcess(cmd, 0)

    busy = set(busy_ports or [])
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
    monkeypatch.setattr(ua, "_dev_mode_enabled", lambda root: dev_mode)
    monkeypatch.setattr(ua, "_port_in_use", lambda port: port in busy)


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


def test_main_sequence_dev_mode(monkeypatch, tmp_path):
    # same sequence but compose file remains production even in dev mode
    calls = []
    _patch_main_runtime(monkeypatch, calls, venv_bin="Y", dev_mode=True, busy_ports=[])

    ua.main()

    prod_ps_idx = _index_of_command(
        calls, ["docker", "compose", "-f", "docker-compose.yml", "ps", "--all"]
    )

    assert prod_ps_idx == 0


def test_main_sequence_dev_mode_uses_dev_compose(monkeypatch):
    calls = []
    _patch_main_runtime(monkeypatch, calls, venv_bin="Y", dev_mode=True, busy_ports=[])

    ua.main()

    assert calls[0][0][:5] == ["docker", "compose", "-f", "docker-compose.yml", "ps"]
    assert any(c[0][0] == "git" for c in calls)
    assert any(c[0] and c[0][0] == "Y" for c in calls)


def test_dev_mode_enabled_reads_dotenv_when_env_missing(monkeypatch, tmp_path):
    monkeypatch.delenv("DEV_MODE", raising=False)
    (tmp_path / ".env").write_text("DEV_MODE=true\n")

    assert ua._dev_mode_enabled(tmp_path) is True


def test_dev_port_scales_when_dev_mode_off():
    scales = ua._dev_port_scales(False)
    assert scales == [
        "--scale",
        "dev_main_port=0",
        "--scale",
        "dev_demo_port=0",
        "--scale",
        "dev_status_port=0",
    ]


def test_dev_port_scales_only_for_busy_ports(monkeypatch):
    monkeypatch.setattr(ua, "_port_in_use", lambda port: port in {80, 8000})

    scales = ua._dev_port_scales(True)
    assert scales == [
        "--scale",
        "dev_main_port=0",
        "--scale",
        "dev_status_port=0",
    ]


def test_main_scales_busy_dev_ports_on_up(monkeypatch):
    calls = []
    _patch_main_runtime(monkeypatch, calls, venv_bin="Y", dev_mode=True, busy_ports={80})

    ua.main()

    up_command = _find_command_prefix(
        calls, ["docker", "compose", "-f", "docker-compose.yml", "up", "-d"]
    )
    assert "--scale" in up_command
    assert "dev_main_port=0" in up_command
    assert "dev_demo_port=0" not in up_command
    assert "dev_status_port=0" not in up_command


def test_main_scales_all_dev_ports_when_dev_mode_off(monkeypatch):
    calls = []
    _patch_main_runtime(monkeypatch, calls, venv_bin="Y", dev_mode=False)

    ua.main()

    up_command = _find_command_prefix(
        calls, ["docker", "compose", "-f", "docker-compose.yml", "up", "-d"]
    )
    assert "dev_main_port=0" in up_command
    assert "dev_demo_port=0" in up_command
    assert "dev_status_port=0" in up_command
