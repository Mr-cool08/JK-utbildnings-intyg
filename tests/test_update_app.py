import json
import subprocess
from pathlib import Path

import scripts.update_app as ua


def _patch_main_runtime(
    monkeypatch,
    calls,
    venv_bin="X",
    cron_marker=None,
    compose_services=None,
):
    if compose_services is None:
        compose_services = (
            "traefik",
            "app",
            "expiry_reminder",
            "postgres",
        )

    def fake_run(cmd, check=True, **kwargs):
        calls.append((list(cmd), kwargs.get("cwd")))
        if list(cmd) == [
            "docker",
            "compose",
            "-f",
            "docker-compose.yml",
            "config",
            "--format",
            "json",
        ]:
            services = {service_name: {} for service_name in compose_services}
            return subprocess.CompletedProcess(cmd, 0, json.dumps({"services": services}), "")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(ua, "_run", fake_run)
    monkeypatch.setattr(ua, "_build_venv_command", lambda root, a, b: [venv_bin])
    monkeypatch.setattr(ua, "_find_requirements", lambda root: [])
    monkeypatch.setattr(ua, "_run_os_upgrade_if_enabled", lambda: None)
    if cron_marker is None:
        monkeypatch.setattr(ua, "_ensure_expiry_reminder_cron", lambda root: None)
    else:
        monkeypatch.setattr(
            ua,
            "_ensure_expiry_reminder_cron",
            lambda root: calls.append(([cron_marker], root)),
        )
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


def test_build_pytest_environment_overrides_conflicting_env(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@postgres:5432/testdb")
    monkeypatch.setenv("DEV_MODE", "false")
    monkeypatch.setenv("ENABLE_DEMO_MODE", "true")
    monkeypatch.delenv("DISABLE_EMAILS", raising=False)

    env = ua._build_pytest_environment(tmp_path)

    assert env["DATABASE_URL"] == "sqlite:///:memory:"
    assert env["DEV_MODE"] == "true"
    assert env["ENABLE_DEMO_MODE"] == "false"
    assert env["DISABLE_EMAILS"] == "true"
    assert env["secret_key"] == "test-secret-key"
    assert Path(env["LOG_FILE"]).parent == tmp_path / ".pytest_tmp" / "logs"
    assert (tmp_path / ".pytest_tmp" / "logs").is_dir()


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


def test_main_runs_pytest_with_deterministic_test_env(monkeypatch):
    calls = []

    def fake_run(cmd, check=True, **kwargs):
        calls.append(
            {
                "cmd": list(cmd),
                "cwd": kwargs.get("cwd"),
                "env": kwargs.get("env"),
            }
        )
        if list(cmd) == [
            "docker",
            "compose",
            "-f",
            "docker-compose.yml",
            "config",
            "--format",
            "json",
        ]:
            services = {
                "traefik": {},
                "app": {},
                "expiry_reminder": {},
                "postgres": {},
            }
            return subprocess.CompletedProcess(
                cmd,
                0,
                json.dumps({"services": services}),
                "",
            )
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(ua, "_run", fake_run)
    monkeypatch.setattr(ua, "_build_venv_command", lambda root, a, b: ["Y"])
    monkeypatch.setattr(ua, "_find_requirements", lambda root: [])
    monkeypatch.setattr(ua, "_run_os_upgrade_if_enabled", lambda: None)
    monkeypatch.setattr(ua, "_ensure_expiry_reminder_cron", lambda root: None)
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *args, **kwargs: type(
            "P", (), {"terminate": lambda self: None, "wait": lambda self: None}
        )(),
    )
    monkeypatch.setattr(ua.time, "sleep", lambda *_: None)
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@postgres:5432/testdb")
    monkeypatch.setenv("DEV_MODE", "false")

    ua.main()

    pytest_call = next(call for call in calls if call["cmd"] == ["Y", "-n", "auto", "-q"])

    assert pytest_call["env"] is not None
    assert pytest_call["env"]["DATABASE_URL"] == "sqlite:///:memory:"
    assert pytest_call["env"]["DEV_MODE"] == "true"
    assert pytest_call["env"]["ENABLE_DEMO_MODE"] == "false"
    assert pytest_call["env"]["DISABLE_EMAILS"] == "true"


def test_main_runs_compose_up_without_scale_flags(monkeypatch):
    calls = []
    _patch_main_runtime(monkeypatch, calls, venv_bin="Y")

    ua.main()

    up_command = _find_command_prefix(
        calls, ["docker", "compose", "-f", "docker-compose.yml", "up", "-d"]
    )
    assert "--scale" not in up_command


def test_build_compose_up_command_excludes_expiry_reminder(monkeypatch, tmp_path):
    def fake_run(cmd, check=True, **kwargs):
        assert list(cmd) == [
            "docker",
            "compose",
            "-f",
            "docker-compose.yml",
            "config",
            "--format",
            "json",
        ]
        return subprocess.CompletedProcess(
            cmd,
            0,
            json.dumps(
                {
                    "services": {
                        "traefik": {},
                        "app": {},
                        "expiry_reminder": {},
                        "postgres": {},
                    }
                }
            ),
            "",
        )

    monkeypatch.setattr(ua, "_run", fake_run)

    command = ua._build_compose_up_command(tmp_path, {"POSTGRES_PUBLIC_PORT": "1543"})

    assert command == [
        "docker",
        "compose",
        "-f",
        "docker-compose.yml",
        "up",
        "-d",
        "traefik",
        "app",
        "postgres",
    ]


def test_build_expiry_reminder_cron_line_uses_env_schedule(monkeypatch):
    monkeypatch.setenv("CERTIFICATE_EXPIRY_REMINDER_CRON_SCHEDULE", "15 */6 * * *")

    cron_line = ua._build_expiry_reminder_cron_line(Path("/srv/jk-utbildnings-intyg"))

    assert cron_line.startswith(
        "15 */6 * * * cd /srv/jk-utbildnings-intyg && docker compose "
    )


def test_ensure_expiry_reminder_cron_adds_entry_when_missing(monkeypatch):
    installed_crontabs = []

    def fake_run(cmd, check=False, **kwargs):
        if list(cmd) == ["crontab", "-l"]:
            return subprocess.CompletedProcess(cmd, 1, "", "no crontab for user")
        if list(cmd) == ["crontab", "-"]:
            installed_crontabs.append(kwargs["input"])
            return subprocess.CompletedProcess(cmd, 0, "", "")
        raise AssertionError(f"Oväntat kommando: {cmd}")

    monkeypatch.setattr(ua.os, "name", "posix")
    monkeypatch.setattr(ua, "_command_exists", lambda command: command == "crontab")
    monkeypatch.setattr(ua.subprocess, "run", fake_run)

    ua._ensure_expiry_reminder_cron(Path("/srv/jk utbildningsintyg"))

    assert len(installed_crontabs) == 1
    assert (
        "0 7 1 * * cd '/srv/jk utbildningsintyg' && docker compose "
        "-f docker-compose.yml run --rm expiry_reminder"
    ) in installed_crontabs[0]
    assert installed_crontabs[0].count(ua.EXPIRY_REMINDER_CRON_MARKER) == 1


def test_ensure_expiry_reminder_cron_reads_schedule_from_project_env(
    monkeypatch,
    tmp_path,
):
    installed_crontabs = []
    monkeypatch.delenv("CERTIFICATE_EXPIRY_REMINDER_CRON_SCHEDULE", raising=False)
    (tmp_path / ".env").write_text(
        "CERTIFICATE_EXPIRY_REMINDER_CRON_SCHEDULE=30 6 * * *\n",
        encoding="utf-8",
    )

    def fake_run(cmd, check=False, **kwargs):
        if list(cmd) == ["crontab", "-l"]:
            return subprocess.CompletedProcess(cmd, 1, "", "no crontab for user")
        if list(cmd) == ["crontab", "-"]:
            installed_crontabs.append(kwargs["input"])
            return subprocess.CompletedProcess(cmd, 0, "", "")
        raise AssertionError(f"Oväntat kommando: {cmd}")

    monkeypatch.setattr(ua.os, "name", "posix")
    monkeypatch.setattr(ua, "_command_exists", lambda command: command == "crontab")
    monkeypatch.setattr(ua.subprocess, "run", fake_run)

    ua._ensure_expiry_reminder_cron(tmp_path)

    assert len(installed_crontabs) == 1
    assert ua._build_expiry_reminder_cron_line(tmp_path) in installed_crontabs[0]


def test_ensure_expiry_reminder_cron_does_not_add_duplicate_entry(monkeypatch):
    existing_cron = (
        ua._build_expiry_reminder_cron_line(Path("/srv/jk-utbildnings-intyg")) + "\n"
    )

    def fake_run(cmd, check=False, **kwargs):
        if list(cmd) == ["crontab", "-l"]:
            return subprocess.CompletedProcess(cmd, 0, existing_cron, "")
        if list(cmd) == ["crontab", "-"]:
            raise AssertionError("Cron ska inte installeras en gång till.")
        raise AssertionError(f"Oväntat kommando: {cmd}")

    monkeypatch.setattr(ua.os, "name", "posix")
    monkeypatch.setattr(ua, "_command_exists", lambda command: command == "crontab")
    monkeypatch.setattr(ua.subprocess, "run", fake_run)

    ua._ensure_expiry_reminder_cron(Path("/srv/jk-utbildnings-intyg"))


def test_main_ensures_expiry_reminder_cron_after_compose_up(monkeypatch):
    calls = []
    _patch_main_runtime(monkeypatch, calls, venv_bin="Y", cron_marker="cron-ensure")

    ua.main()

    up_index = _index_of_command(
        calls,
        [
            "docker",
            "compose",
            "-f",
            "docker-compose.yml",
            "up",
            "-d",
            "traefik",
            "app",
            "postgres",
        ],
    )
    cron_index = _index_of_command(calls, ["cron-ensure"])
    assert cron_index == up_index + 1
