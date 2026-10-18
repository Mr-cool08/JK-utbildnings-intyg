import json
import subprocess
from pathlib import Path

import pytest

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
    monkeypatch.setattr(ua, "_preflight_fail2ban", lambda root, env: [])
    monkeypatch.setattr(ua, "_activate_fail2ban", lambda root, env, addresses: None)
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
    monkeypatch.delenv("DISABLE_EMAILS", raising=False)

    env = ua._build_pytest_environment(tmp_path)

    assert env["DATABASE_URL"] == "sqlite:///:memory:"
    assert env["DEV_MODE"] == "true"
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
    monkeypatch.setattr(ua, "_preflight_fail2ban", lambda root, env: [])
    monkeypatch.setattr(ua, "_activate_fail2ban", lambda root, env, addresses: None)

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
                        "fail2ban": {},
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
    project_root = Path("/srv/jk utbildningsintyg")

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

    ua._ensure_expiry_reminder_cron(project_root)

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
    project_root = Path("/srv/jk-utbildnings-intyg")
    existing_cron = ua._build_expiry_reminder_cron_line(project_root) + "\n"

    def fake_run(cmd, check=False, **kwargs):
        if list(cmd) == ["crontab", "-l"]:
            return subprocess.CompletedProcess(cmd, 0, existing_cron, "")
        if list(cmd) == ["crontab", "-"]:
            raise AssertionError("Cron ska inte installeras en gång till.")
        raise AssertionError(f"Oväntat kommando: {cmd}")

    monkeypatch.setattr(ua.os, "name", "posix")
    monkeypatch.setattr(ua, "_command_exists", lambda command: command == "crontab")
    monkeypatch.setattr(ua.subprocess, "run", fake_run)

    ua._ensure_expiry_reminder_cron(project_root)


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



def test_fail2ban_access_is_idempotent_and_preserves_existing_addresses(tmp_path):
    env = {"SSH_CONNECTION": "203.0.113.7 50000 192.0.2.1 2222"}
    ua._prepare_fail2ban_access(tmp_path, env)
    path = tmp_path / "deploy/fail2ban/ssh-access.local"
    original = path.read_bytes()
    ua._prepare_fail2ban_access(tmp_path, env)
    assert path.read_bytes() == original
    ua._prepare_fail2ban_access(
        tmp_path, {"SSH_CONNECTION": "2001:db8::7 50001 2001:db8::1 2222"}
    )
    content = path.read_text(encoding="utf-8")
    assert "203.0.113.7/32" in content
    assert "2001:db8::7/128" in content
    assert "port = 2222" in content


@pytest.mark.parametrize("env", [
    {},
    {"SSH_CONNECTION": "felaktigt"},
    {"SSH_CONNECTION": "ingen-ip 50000 192.0.2.1 22"},
    {"FAIL2BAN_ADMIN_IPS": "203.0.113.7", "FAIL2BAN_SSH_PORTS": "0"},
    {"FAIL2BAN_ADMIN_IPS": "127.0.0.1", "FAIL2BAN_SSH_PORTS": "22"},
])
def test_fail2ban_missing_or_invalid_access_does_not_write_file(tmp_path, env):
    with pytest.raises(ValueError):
        ua._prepare_fail2ban_access(tmp_path, env)
    assert not (tmp_path / "deploy/fail2ban/ssh-access.local").exists()


def test_fail2ban_existing_access_supports_unattended_updates(tmp_path):
    env = {"FAIL2BAN_ADMIN_IPS": "203.0.113.7 2001:db8::7", "FAIL2BAN_SSH_PORTS": "22,2222"}
    expected = ua._prepare_fail2ban_access(tmp_path, env)
    assert ua._prepare_fail2ban_access(tmp_path, {}) == expected


def test_fail2ban_rejects_overrides_that_disable_protection(tmp_path):
    path = tmp_path / "deploy/fail2ban/ssh-access.local"
    path.parent.mkdir(parents=True)
    content = "[sshd]\nenabled = false\nignoreip = 203.0.113.7\nport = 22\n"
    path.write_text(content)
    with pytest.raises(ValueError):
        ua._prepare_fail2ban_access(tmp_path, {})
    assert path.read_text() == content


def test_fail2ban_preflight_uses_no_daemon_and_never_stops_services(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(ua, "_run", lambda cmd, **kw: calls.append(cmd))
    ua._preflight_fail2ban(tmp_path, {"SSH_CONNECTION": "203.0.113.7 50000 192.0.2.1 22"})
    assert len(calls) == 2
    assert calls[0] == ua._compose_command("config", "--quiet")
    assert calls[1][-1] == "test -s /var/log/host/auth.log && fail2ban-client -t"
    assert "--no-deps" in calls[1]
    assert "stop" not in calls[1]


@pytest.mark.parametrize("failure", [None, "up", "maxretry", "ignoreip"])
def test_fail2ban_activation_verifies_and_stops_only_fail2ban_on_failure(
    monkeypatch, tmp_path, failure
):
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        if "up" in cmd and failure == "up":
            raise subprocess.TimeoutExpired(cmd, 210)
        output = {
            "maxretry": "5", "findtime": "600", "bantime": "3600",
            "ignoreip": (
                "These IP addresses/networks are ignored:\n"
                "|- 127.0.0.0/8\n|- ::1\n`- 203.0.113.7"
            ),
        }.get(cmd[-1], "")
        if cmd[-1] == failure:
            output = "0"
        return subprocess.CompletedProcess(cmd, 0, output, "")

    monkeypatch.setattr(ua, "_run", run)
    if failure:
        with pytest.raises((RuntimeError, subprocess.TimeoutExpired)):
            ua._activate_fail2ban(tmp_path, {}, ["203.0.113.7/32"])
        assert calls[-1] == ua._compose_command("stop", "-t", "30", "fail2ban")
    else:
        ua._activate_fail2ban(tmp_path, {}, ["203.0.113.7/32"])
        assert not any("stop" in cmd for cmd in calls)
    assert "--wait" in calls[0]
    assert all("fail2ban" in cmd for cmd in calls)


def test_fail2ban_only_skips_all_general_update_steps(monkeypatch):
    calls = []
    monkeypatch.setattr(ua, "_load_project_environment", lambda root: None)
    monkeypatch.setattr(
        ua, "_preflight_fail2ban", lambda root, env: calls.append("preflight") or []
    )
    monkeypatch.setattr(
        ua, "_activate_fail2ban", lambda root, env, addresses: calls.append("activate")
    )
    monkeypatch.setattr(
        ua, "_run", lambda *args, **kwargs: pytest.fail("Övriga tjänster får inte påverkas")
    )
    ua.main(fail2ban_only=True)
    assert calls == ["preflight", "activate"]


def test_main_preflight_failure_prevents_stopping_services(monkeypatch):
    calls = []
    _patch_main_runtime(monkeypatch, calls)

    def fail(root, env):
        raise RuntimeError("Konfigurationen är felaktig")

    monkeypatch.setattr(ua, "_preflight_fail2ban", fail)
    with pytest.raises(RuntimeError):
        ua.main()
    assert not any("stop" in cmd or "up" in cmd for cmd, _ in calls)
    assert any("pull" in cmd for cmd, _ in calls)


# Copyright (c) Liam Suorsa and Mika Suorsa
