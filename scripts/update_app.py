#!/usr/bin/env python3
"""Helper script for performing an update workflow.

This script is intentionally self-contained and does **not** import from
``scripts.manage_compose``; all of the steps listed in the README have
been implemented inline so the module can be invoked independently.

The sequence executed by :func:`main` is:

1. display current Docker container status
3. pause five seconds and optionally run OS package update/upgrade
4. display Docker storage usage
5. git pull to fetch updates
6. locate virtualenv commands
7. install Python requirements found in the repo tree
8. run the test suite with pytest
9. pull latest images and validate Fail2ban with SSH access exceptions
10. stop main compose containers
11. rebuild and bring up the main compose services without cache; verify Fail2ban
13. display live ``docker stats`` for sixty seconds
14. run a series of ``docker prune`` commands to clean up space

Most shell steps are executed via :func:`_run`. If a command fails,
underlying exceptions such as ``subprocess.CalledProcessError`` and
``OSError`` (or other standard exceptions) can bubble up to :func:`main`.
"""

from __future__ import annotations

import argparse
import configparser
import ipaddress
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
import tempfile
from pathlib import Path
from typing import Iterable, List

from dotenv import load_dotenv

COMPOSE_FILE = "docker-compose.yml"
COMPOSE_UP_EXCLUDED_SERVICES = frozenset({"expiry_reminder", "fail2ban"})
DEFAULT_EXPIRY_REMINDER_CRON_SCHEDULE = "0 7 1 * *"
EXPIRY_REMINDER_CRON_MARKER = "# jk-utbildnings-intyg expiry_reminder"


# --- helpers ----------------------------------------------------------------


def _build_venv_command(root: Path, unix_exe: str, win_exe: str) -> list[str]:
    """Return the full path to an executable inside the project's venv."""

    venv_dirs = ("venv", ".venv")
    if sys.platform.startswith("win"):
        layout = (("Scripts", win_exe), ("bin", unix_exe))
    else:
        layout = (("bin", unix_exe), ("Scripts", win_exe))

    for v in venv_dirs:
        for folder, exe in layout:
            candidate = root / v / folder / exe
            if candidate.is_file():
                return [str(candidate)]
    raise FileNotFoundError(f"Could not locate {unix_exe} in a venv directory.")


def _find_requirements(root: Path) -> List[Path]:
    """Recursively locate all ``requirements.txt`` files, excluding venvs."""

    excluded = {".git", "venv", ".venv", "__pycache__"}
    reqs: List[Path] = []
    for p in root.rglob("requirements.txt"):
        if any(part in excluded for part in p.parts):
            continue
        reqs.append(p)
    return sorted(reqs)


def _run(cmd: Iterable[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command and raise on failure."""

    print("$", " ".join(cmd))
    return subprocess.run(list(cmd), check=True, **kwargs)


def _compose_command(*args: str) -> list[str]:
    """Build a docker compose command for the main compose file."""

    return ["docker", "compose", "-f", COMPOSE_FILE, *args]


def _get_valid_postgres_public_port(default: str = "1543") -> str:
    """Return a valid host port for the postgres compose mapping."""

    raw = os.getenv("POSTGRES_PUBLIC_PORT")
    if not raw:
        return default

    try:
        port = int(raw)
    except ValueError:
        print(
            f"Ogiltigt värde i POSTGRES_PUBLIC_PORT, använder standardport {default}."
        )
        return default

    if 1 <= port <= 65535:
        return str(port)

    print(
        f"POSTGRES_PUBLIC_PORT måste vara mellan 1 och 65535, använder standardport {default}."
    )
    return default


def _command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def _build_compose_up_command(root: Path, compose_env: dict[str, str]) -> list[str]:
    """Build a compose up command that excludes one-shot reminder services."""

    result = _run(
        _compose_command("config", "--format", "json"),
        cwd=root,
        env=compose_env,
        capture_output=True,
        text=True,
    )
    output = (result.stdout or "").strip()
    if not output:
        raise RuntimeError("Kunde inte lasa docker compose-konfigurationen.")

    config = json.loads(output)
    services = list((config.get("services") or {}).keys())
    # Behåll produktionsproxyn om DEV_MODE inte uttryckligen är true.
    dev_mode = compose_env.get("DEV_MODE") == "true"
    excluded_services = COMPOSE_UP_EXCLUDED_SERVICES | {
        "traefik" if dev_mode else "dev_http"
    }
    filtered_services = [
        service
        for service in services
        if service not in excluded_services
    ]
    if not filtered_services:
        raise RuntimeError("Inga docker compose-tjanster kunde startas.")

    if dev_mode and "dev_http" not in filtered_services:
        # Ett explicit tjänstenamn aktiverar dess profil utan fler dev-tjänster.
        filtered_services.append("dev_http")
    return _compose_command("up", "-d", *filtered_services)


def _load_project_environment(root: Path) -> None:
    env_paths = ("/config/.env", os.path.join(str(root), ".env"))
    for env_path in env_paths:
        if os.path.isfile(env_path):
            load_dotenv(env_path, override=False)


def _build_pytest_environment(root: Path) -> dict[str, str]:
    """Build a deterministic environment for pytest runs."""

    log_dir = root / ".pytest_tmp" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env.update(
        {
            "DATABASE_URL": "sqlite:///:memory:",
            "DEV_MODE": "true",
            "DISABLE_EMAILS": "true",
            "LOG_FILE": os.fspath(log_dir / "pytest.log"),
            "admin_username": "test_admin",
            "admin_password": "test_password_123",
            "secret_key": "test-secret-key",
        }
    )
    return env


def _get_expiry_reminder_cron_schedule() -> str:
    schedule = (
        os.getenv(
            "CERTIFICATE_EXPIRY_REMINDER_CRON_SCHEDULE",
            DEFAULT_EXPIRY_REMINDER_CRON_SCHEDULE,
        ).strip()
        or DEFAULT_EXPIRY_REMINDER_CRON_SCHEDULE
    )
    if len(schedule.split()) != 5:
        raise ValueError(
            "CERTIFICATE_EXPIRY_REMINDER_CRON_SCHEDULE måste vara ett cron-uttryck med fem fält."
        )
    return schedule


def _build_expiry_reminder_cron_line(root: Path) -> str:
    project_root = shlex.quote(root.as_posix())
    schedule = _get_expiry_reminder_cron_schedule()
    return (
        f"{schedule} cd {project_root} && docker compose "
        f"-f {COMPOSE_FILE} run --rm expiry_reminder "
        f"{EXPIRY_REMINDER_CRON_MARKER}"
    )


def _ensure_expiry_reminder_cron(root: Path) -> None:
    _load_project_environment(root)
    if os.name == "nt":
        print("Hoppar över cron för utgångspåminnelser: cron stöds inte på Windows.")
        return

    if not _command_exists("crontab"):
        print(
            "Hoppar över cron för utgångspåminnelser: crontab finns inte installerat."
        )
        return

    result = subprocess.run(
        ["crontab", "-l"],
        capture_output=True,
        check=False,
        text=True,
    )

    if result.returncode == 0:
        current_crontab = result.stdout
    elif result.returncode == 1 and not result.stdout.strip():
        current_crontab = ""
    else:
        raise subprocess.CalledProcessError(
            result.returncode,
            result.args,
            output=result.stdout,
            stderr=result.stderr,
        )

    cron_line = _build_expiry_reminder_cron_line(root)
    existing_lines = current_crontab.splitlines()
    if any(
        EXPIRY_REMINDER_CRON_MARKER in line or line.strip() == cron_line
        for line in existing_lines
    ):
        print("Cron för utgångspåminnelser finns redan.")
        return

    updated_lines = [*existing_lines, cron_line]
    updated_crontab = "\n".join(updated_lines).rstrip("\n") + "\n"
    subprocess.run(
        ["crontab", "-"],
        check=True,
        input=updated_crontab,
        text=True,
    )
    print("Lade till cron för utgångspåminnelser.")


def _os_upgrade_enabled() -> bool:
    raw = os.getenv("ENABLE_OS_UPGRADE") or os.getenv("CHECK_OS_UPDATES")
    if not raw:
        return False
    return raw.strip().lower() in {"1", "true", "on", "ja", "yes"}


def _run_os_upgrade_if_enabled() -> None:
    if not _os_upgrade_enabled():
        print("OS-uppdatering är avstängd. Sätt ENABLE_OS_UPGRADE=true för att aktivera.")
        return

    apt_get_available = _command_exists("apt-get")
    sudo_available = _command_exists("sudo")
    if not apt_get_available:
        print("Hoppar över OS-uppdatering: apt-get finns inte i miljön.")
        return

    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        if not sudo_available:
            print("Hoppar över OS-uppdatering: kräver root eller sudo -n utan prompt.")
            return

        _run(
            [
                "bash",
                "-lc",
                "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update && "
                "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get upgrade -y "
                "-o Dpkg::Options::=--force-confdef "
                "-o Dpkg::Options::=--force-confold",
            ]
        )
        return

    _run(
        [
            "bash",
            "-lc",
            "DEBIAN_FRONTEND=noninteractive apt-get update && "
            "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y "
            "-o Dpkg::Options::=--force-confdef "
            "-o Dpkg::Options::=--force-confold",
        ]
    )


# --- workflow ---------------------------------------------------------------
def _prepare_fail2ban_access(root: Path, env: dict[str, str]) -> list[str]:
    """Preserve existing access exceptions and include the current SSH client."""
    path = root / "deploy/fail2ban/ssh-access.local"
    config = configparser.ConfigParser(interpolation=None)
    if path.exists():
        config.read(path, encoding="utf-8")
    if config.defaults() or any(section != "sshd" for section in config.sections()):
        raise ValueError("Åtkomstfilen får endast innehålla sektionen [sshd].")
    if not config.has_section("sshd"):
        config.add_section("sshd")
    if set(config["sshd"]) - {"ignoreip", "port"}:
        raise ValueError("Åtkomstfilen får endast ange ignoreip och port.")
    addresses = config.get("sshd", "ignoreip", fallback="").split()
    addresses += env.get("FAIL2BAN_ADMIN_IPS", "").split()
    connection = env.get("SSH_CONNECTION", "").split()
    port = env.get("FAIL2BAN_SSH_PORTS") or config.get("sshd", "port", fallback="")
    if connection:
        if len(connection) != 4:
            raise ValueError("SSH_CONNECTION måste innehålla fyra fält.")
        addresses.append(str(ipaddress.ip_address(connection[0])))
        if not port:
            port = connection[3]
    networks = [ipaddress.ip_network(value, strict=False) for value in addresses]
    if not any(not network.is_loopback for network in networks):
        raise ValueError(
            "Administrationsadress saknas. Bevara SSH_CONNECTION via sudo eller "
            "ange FAIL2BAN_ADMIN_IPS och FAIL2BAN_SSH_PORTS."
        )
    ports = port.split(",")
    if not all(value.isdecimal() and 1 <= int(value) <= 65535 for value in ports):
        raise ValueError("SSH-portarna måste vara kommaseparerade tal mellan 1 och 65535.")
    addresses = list(dict.fromkeys(["127.0.0.0/8", "::1/128", *map(str, networks)]))
    config["sshd"]["ignoreip"] = " ".join(addresses)
    config["sshd"]["port"] = ",".join(str(int(value)) for value in ports)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
            config.write(stream)
            stream.write("\n# Copyright (c) Liam Suorsa and Mika Suorsa\n")
        temporary.chmod(0o600)
        temporary.replace(path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    print("SSH-undantagen har sparats. Befintliga administrationsadresser behålls.")
    return addresses


def _preflight_fail2ban(root: Path, env: dict[str, str]) -> list[str]:
    addresses = _prepare_fail2ban_access(root, env)
    _run(_compose_command("config", "--quiet"), cwd=root, env=env)
    _run(
        _compose_command(
            "run", "--rm", "--no-deps", "--pull", "never",
            "fail2ban", "sh", "-c",
            "test -s /var/log/host/auth.log && fail2ban-client -t",
        ),
        cwd=root, env=env,
    )
    return addresses


def _activate_fail2ban(root: Path, env: dict[str, str], addresses: list[str]) -> None:
    """Start only Fail2ban and stop it if runtime verification fails."""
    try:
        _run(
            _compose_command(
                "up", "-d", "--no-deps", "--pull", "never", "--force-recreate",
                "--wait", "--wait-timeout", "180", "fail2ban",
            ),
            cwd=root, env=env, timeout=210,
        )
        for setting, expected in (("maxretry", "5"), ("findtime", "600"), ("bantime", "3600")):
            result = _run(
                _compose_command("exec", "-T", "fail2ban", "fail2ban-client",
                                 "get", "sshd", setting),
                cwd=root, env=env, capture_output=True, text=True, timeout=15,
            )
            if result.stdout.strip() != expected:
                raise RuntimeError(f"Fel värde för sshd/{setting}: förväntade {expected}.")
        # Kontrollera att varje undantag faktiskt finns i den körande jailen.
        result = _run(
            _compose_command("exec", "-T", "fail2ban", "fail2ban-client",
                             "get", "sshd", "ignoreip"),
            cwd=root, env=env, capture_output=True, text=True, timeout=15,
        )
        active = set()
        for token in result.stdout.split():
            try:
                active.add(ipaddress.ip_network(token, strict=False))
            except ValueError:
                continue
        if not all(ipaddress.ip_network(value, strict=False) in active for value in addresses):
            raise RuntimeError("SSH-undantagen saknas i den körande jailen.")
        _run(
            _compose_command("exec", "-T", "fail2ban", "fail2ban-client", "status", "sshd"),
            cwd=root, env=env, timeout=15,
        )
    except (Exception, KeyboardInterrupt):
        print("Verifieringen misslyckades. Stoppar endast Fail2ban för att skydda SSH-åtkomsten.")
        try:
            _run(
                _compose_command("stop", "-t", "30", "fail2ban"),
                cwd=root, env=env, timeout=45,
            )
        except Exception as error:
            print(
                "Kunde inte stoppa Fail2ban. Använd serverkonsolen för att "
                f"kontrollera SSH-reglerna: {error}"
            )
        raise
    print("Fail2ban är healthy: SSH-jail och åtkomstundantag har verifierats.")


def main(*, fail2ban_only: bool = False) -> None:
    root = Path(__file__).resolve().parent.parent
    _load_project_environment(root)
    compose_env = os.environ.copy()
    compose_env["POSTGRES_PUBLIC_PORT"] = _get_valid_postgres_public_port()

    if fail2ban_only:
        addresses = _preflight_fail2ban(root, compose_env)
        _activate_fail2ban(root, compose_env, addresses)
        return


    # 1. container status
    _run(_compose_command("ps", "--all"), cwd=root, env=compose_env)


    # 3. wait and optionally update OS packages
    time.sleep(5)
    _run_os_upgrade_if_enabled()

    # 4. storage stats
    _run(["docker", "system", "df"])

    # 5. git pull
    _run(["git", "pull"], cwd=root)

    # 6. prepare venv commands
    pip_cmd = _build_venv_command(root, "pip", "pip.exe")
    pytest_cmd = [*_build_venv_command(root, "pytest", "pytest.exe"), "-n", "auto", "-q"]

    # 7. install requirements
    reqs = _find_requirements(root)
    if not reqs:
        print("No requirements files found.")
    else:
        for r in reqs:
            print(f"Installing {r.relative_to(root)}")
            _run([*pip_cmd, "install", "-r", str(r)], cwd=root)

    # 8. run pytest
    _run([*pytest_cmd], cwd=root, env=_build_pytest_environment(root))

    # 8.5 pull images
    _run(_compose_command("pull"), cwd=root, env=compose_env)

    # Validera den hämtade imagen innan några tjänster stoppas.
    addresses = _preflight_fail2ban(root, compose_env)

    # 8. stop containers
    _run(_compose_command("stop"), cwd=root, env=compose_env)

    # 9. rebuild & up without cache
    _run(_compose_command("build", "--no-cache"), cwd=root, env=compose_env)
    _run(_build_compose_up_command(root, compose_env), cwd=root, env=compose_env)
    _ensure_expiry_reminder_cron(root)
    _activate_fail2ban(root, compose_env, addresses)

    # 13. show stats for 60 seconds
    proc = subprocess.Popen(["docker", "stats", "--all"], cwd=root)
    try:
        time.sleep(60)
    finally:
        proc.terminate()
        proc.wait()

    # 14. prune docker data
    _run(["docker", "image", "prune", "-a", "-f"])
    _run(["docker", "builder", "prune", "-f"])
    _run(["docker", "system", "prune", "-a", "-f"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Uppdatera applikationen och verifiera Fail2ban.")
    parser.add_argument(
        "--fail2ban-only", action="store_true",
        help="Förbered och verifiera endast Fail2ban, utan övriga uppdateringssteg.",
    )
    main(fail2ban_only=parser.parse_args().fail2ban_only)

# Copyright (c) Liam Suorsa and Mika Suorsa
