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
9. stop main compose containers
10. pull latest images
11. rebuild and bring up the main compose services without cache
13. display live ``docker stats`` for sixty seconds
14. run a series of ``docker prune`` commands to clean up space

Most shell steps are executed via :func:`_run`. If a command fails,
underlying exceptions such as ``subprocess.CalledProcessError`` and
``OSError`` (or other standard exceptions) can bubble up to :func:`main`.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable, List

from dotenv import load_dotenv

COMPOSE_FILE = "docker-compose.yml"
COMPOSE_UP_EXCLUDED_SERVICES = frozenset({"expiry_reminder"})
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


def _get_valid_postgres_public_port(default: str = "15432") -> str:
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
    filtered_services = [
        service
        for service in services
        if service not in COMPOSE_UP_EXCLUDED_SERVICES
    ]
    if not filtered_services:
        raise RuntimeError("Inga docker compose-tjanster kunde startas.")

    return _compose_command("up", "-d", *filtered_services)


def _load_project_environment(root: Path) -> None:
    env_paths = ("/config/.env", os.path.join(str(root), ".env"))
    for env_path in env_paths:
        if os.path.isfile(env_path):
            load_dotenv(env_path, override=False)


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
def main() -> None:
    root = Path(__file__).resolve().parent.parent
    _load_project_environment(root)
    compose_env = os.environ.copy()
    compose_env["POSTGRES_PUBLIC_PORT"] = _get_valid_postgres_public_port()


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
    _run([*pytest_cmd], cwd=root)

    # 8. stop containers
    _run(_compose_command("stop"), cwd=root, env=compose_env)

    # 8.5 pull images
    _run(_compose_command("pull"), cwd=root, env=compose_env)

    # 9. rebuild & up without cache
    _run(_compose_command("build", "--no-cache"), cwd=root, env=compose_env)
    _run(_build_compose_up_command(root, compose_env), cwd=root, env=compose_env)
    _ensure_expiry_reminder_cron(root)

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
    main()

# Copyright (c) Liam Suorsa and Mika Suorsa
