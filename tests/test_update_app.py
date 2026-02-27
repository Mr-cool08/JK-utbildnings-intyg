import subprocess
from pathlib import Path

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



def test_get_valid_postgres_public_port_defaults_when_missing(monkeypatch):
    monkeypatch.delenv("POSTGRES_PUBLIC_PORT", raising=False)

    assert ua._get_valid_postgres_public_port() == "15432"


def test_get_valid_postgres_public_port_defaults_when_invalid(monkeypatch, capsys):
    monkeypatch.setenv("POSTGRES_PUBLIC_PORT", "154321")

    assert ua._get_valid_postgres_public_port() == "15432"
    assert "mellan 1 och 65535" in capsys.readouterr().out


def test_get_valid_postgres_public_port_accepts_valid_value(monkeypatch):
    monkeypatch.setenv("POSTGRES_PUBLIC_PORT", "5432")

    assert ua._get_valid_postgres_public_port() == "5432"


def test_main_sequence(monkeypatch, tmp_path):
    # verify that main invokes the expected steps in order (production)
    calls = []

    def fake_run(cmd, check=True, **kwargs):
        calls.append((list(cmd), kwargs.get("cwd"), kwargs.get("env")))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(ua, "_run", fake_run)
    monkeypatch.setattr(ua, "_build_venv_command", lambda root, a, b: ["X"])
    monkeypatch.setattr(ua, "_find_requirements", lambda root: [])
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: type("P", (), {"terminate": lambda self: None, "wait": lambda self: None})())
    monkeypatch.setattr(ua, "_dev_mode_enabled", lambda: False)
    monkeypatch.setenv("POSTGRES_PUBLIC_PORT", "5432")

    ua.main()

    compose_calls = [c for c in calls if c[0][:3] == ["docker", "compose", "-f"]]
    assert compose_calls
    assert any(c[0][:6] == ["docker", "compose", "-f", "docker-compose.prod.yml", "ps", "--all"] for c in compose_calls)
    assert all(c[2]["POSTGRES_PUBLIC_PORT"] == "5432" for c in compose_calls)
    assert any(c[0][0] == "git" for c in calls)
    assert any(c[0] and c[0][0] == "X" for c in calls)


def test_main_sequence_dev_mode(monkeypatch, tmp_path):
    # same sequence but dev mode should switch compose file
    calls = []

    def fake_run(cmd, check=True, **kwargs):
        calls.append((list(cmd), kwargs.get("cwd"), kwargs.get("env")))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(ua, "_run", fake_run)
    monkeypatch.setattr(ua, "_build_venv_command", lambda root, a, b: ["Y"])
    monkeypatch.setattr(ua, "_find_requirements", lambda root: [])
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: type("P", (), {"terminate": lambda self: None, "wait": lambda self: None})())

    monkeypatch.setattr(ua, "_dev_mode_enabled", lambda: True)
    monkeypatch.setenv("POSTGRES_PUBLIC_PORT", "99999")

    ua.main()

    compose_calls = [c for c in calls if c[0][:3] == ["docker", "compose", "-f"]]
    assert compose_calls
    assert any(c[0][:6] == ["docker", "compose", "-f", "docker-compose.yml", "ps", "--all"] for c in compose_calls)
    assert all(c[2]["POSTGRES_PUBLIC_PORT"] == "15432" for c in compose_calls)
    assert any(c[0][0] == "git" for c in calls)
    assert any(c[0] and c[0][0] == "Y" for c in calls)
