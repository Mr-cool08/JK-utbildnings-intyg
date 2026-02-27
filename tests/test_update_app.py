import subprocess
import sys
import time
from pathlib import Path

import pytest

import scripts.update_app as ua


def test_find_requirements_skips_virtualenv(tmp_path):
    # root has one requirements and one inside venv which should be ignored
    r1 = tmp_path / "requirements.txt"
    r1.write_text("flask\n")
    venv_req = tmp_path / "venv" / "requirements.txt"
    venv_req.parent.mkdir()
    venv_req.write_text("ignored\n")

    found = ua._find_requirements(tmp_path)
    assert found == [r1]


def test_build_venv_command_prefers_windows_and_unix(tmp_path, monkeypatch):
    # simulate a windows-like layout on non-windows
    root = tmp_path
    for v in ("venv", ".venv"):
        (root / v / "bin").mkdir(parents=True, exist_ok=True)
        (root / v / "bin" / "pip").write_text("")
        (root / v / "bin" / "pytest").write_text("")
    # should find the unix version on posix
    pip_cmd = ua._build_venv_command(root, "pip", "pip.exe")
    # path may use backslashes on Windows; just ensure the basename is correct
    assert Path(pip_cmd[0]).name == "pip"


def test_main_sequence(monkeypatch, tmp_path):
    # verify that main invokes the expected steps in order (production)
    calls = []

    def fake_run(cmd, check=True, **kwargs):
        calls.append((list(cmd), kwargs.get("cwd")))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(ua, "_run", fake_run)
    monkeypatch.setattr(ua, "_build_venv_command", lambda root, a, b: ["X"])
    monkeypatch.setattr(ua, "_find_requirements", lambda root: [])
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: type("P", (), {"terminate": lambda self: None, "wait": lambda self: None})())

    # force dev mode off
    monkeypatch.setattr(ua, "_dev_mode_enabled", lambda: False)

    ua.main()

    assert calls[0][0][:5] == ["docker", "compose", "-f", "docker-compose.prod.yml", "ps"]
    assert any(c[0][0] == "git" for c in calls)
    assert any(c[0] == ["X"] for c in calls)


def test_main_sequence_dev_mode(monkeypatch, tmp_path):
    # same sequence but dev mode should switch compose file
    calls = []

    def fake_run(cmd, check=True, **kwargs):
        calls.append((list(cmd), kwargs.get("cwd")))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(ua, "_run", fake_run)
    monkeypatch.setattr(ua, "_build_venv_command", lambda root, a, b: ["Y"])
    monkeypatch.setattr(ua, "_find_requirements", lambda root: [])
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: type("P", (), {"terminate": lambda self: None, "wait": lambda self: None})())

    monkeypatch.setattr(ua, "_dev_mode_enabled", lambda: True)

    ua.main()

    assert calls[0][0][:5] == ["docker", "compose", "-f", "docker-compose.yml", "ps"]
    assert any(c[0][0] == "git" for c in calls)
    assert any(c[0] == ["Y"] for c in calls)
