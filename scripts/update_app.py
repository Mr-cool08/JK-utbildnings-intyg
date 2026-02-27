#!/usr/bin/env python3
"""Helper script for performing an update workflow.

This script is intentionally self-contained and does **not** import from
``scripts.manage_compose``; all of the steps listed in the README have
been implemented inline so the module can be invoked independently.

The sequence executed by :func:`main` is:

1. display current Docker container status
2. ensure the standalone failover cron service is running
3. pause five seconds and optionally run OS package update/upgrade
4. display Docker storage usage
5. git pull to fetch updates
6. locate virtualenv commands
7. install Python requirements found in the repo tree
8. run the test suite with pytest
9. stop main compose containers
10. pull latest images
11. rebuild and bring up the main compose services without cache
12. rebuild and re-deploy the standalone failover cron service
13. display live ``docker stats`` for sixty seconds
14. run a series of ``docker prune`` commands to clean up space

Most shell steps are executed via :func:`_run`. If a command fails,
underlying exceptions such as ``subprocess.CalledProcessError`` and
``OSError`` (or other standard exceptions) can bubble up to :func:`main`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable, List


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


def _run(cmd: Iterable[str], **kwargs) -> None:
    """Run a command and raise on failure."""

    print("$", " ".join(cmd))
    subprocess.run(list(cmd), check=True, **kwargs)


def _command_exists(command: str) -> bool:
    return shutil.which(command) is not None


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
                "DEBIAN_FRONTEND=noninteractive sudo -n apt-get update && "
                "DEBIAN_FRONTEND=noninteractive sudo -n apt-get upgrade -y "
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


def _dev_mode_enabled() -> bool:
    raw = os.getenv("DEV_MODE")
    if not raw:
        return False
    return raw.strip().lower() in {"1", "true", "on", "ja", "yes"}


def main() -> None:
    root = Path(__file__).resolve().parent.parent

    def compose(*args: str) -> list[str]:
        # choose compose file based on DEV_MODE flag
        file = "docker-compose.yml" if _dev_mode_enabled() else "docker-compose.prod.yml"
        return ["docker", "compose", "-f", file, *args]

    def failover_compose(*args: str) -> list[str]:
        # failover service must stay independent and always on
        return ["docker", "compose", "-f", "docker-compose.failover.yml", *args]

    # 1. container status
    _run(compose("ps", "--all"), cwd=root)

    # 2. keep independent failover running during the full update
    _run(failover_compose("up", "-d"), cwd=root)

    # 3. wait and optionally update OS packages
    time.sleep(5)
    _run_os_upgrade_if_enabled()

    # 4. storage stats
    _run(["docker", "system", "df"])

    # 5. git pull
    _run(["git", "pull"], cwd=root)

    # 6. prepare venv commands
    pip_cmd = _build_venv_command(root, "pip", "pip.exe")
    pytest_cmd = [*_build_venv_command(root, "pytest", "pytest.exe"), "-n", "auto"]

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

    # 9. stop only main containers
    _run(compose("stop"), cwd=root)

    # 10. pull images
    _run(compose("pull"), cwd=root)

    # 11. rebuild & up without cache
    _run(compose("build", "--no-cache"), cwd=root)
    _run(compose("up", "-d"), cwd=root)

    # 12. rebuild and enforce failover service after repository update
    _run(failover_compose("up", "-d", "--build"), cwd=root)

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
