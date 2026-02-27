#!/usr/bin/env python3
"""Helper script for performing an update workflow.

This script is intentionally self-contained and does **not** import from
``scripts.manage_compose``; all of the steps listed in the README have
been implemented inline so the module can be invoked independently.

The sequence executed by :func:`main` is:

1. display current Docker container status
2. pause five seconds
3. display Docker storage usage
4. git pull to fetch updates
5. locate virtualenv commands
6. install Python requirements found in the repo tree
7. run the test suite with pytest
8. stop all compose containers
9. pull latest images
10. rebuild and bring up the compose services without cache
11. display live ``docker stats`` for ten seconds
12. run a series of ``docker prune`` commands to clean up space

All output is written to stdout and errors raise ``RuntimeError``.  This
module deliberately avoids any external dependencies other than the
standard library so it can run on minimal environments.
"""

from __future__ import annotations

import os
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


# --- workflow ---------------------------------------------------------------



# utilities for dev mode

def _dev_mode_enabled() -> bool:
    raw = os.getenv("DEV_MODE")
    if not raw:
        return False
    return raw.strip().lower() in {"1", "true", "on", "ja", "yes"}


def main() -> None:
    root = Path(__file__).resolve().parent.parent

    def compose(*args: str) -> list[str]:
        # helper to build a compose command choosing file based on DEV_MODE
        file = "docker-compose.yml" if _dev_mode_enabled() else "docker-compose.prod.yml"
        return ["docker", "compose", "-f", file, *args]

    # 1. container status
    _run(compose("ps", "--all"), cwd=root)

    # 2. wait 5s
    time.sleep(5)

    # 3. storage stats
    _run(["docker", "system", "df"])

    # 4. git pull
    _run(["git", "pull"], cwd=root)

    # 5. prepare venv commands
    pip_cmd = _build_venv_command(root, "pip", "pip.exe")
    pytest_cmd = _build_venv_command(root, "pytest", "pytest.exe")

    # 6. install requirements
    reqs = _find_requirements(root)
    if not reqs:
        print("No requirements files found.")
    else:
        for r in reqs:
            print(f"Installing {r.relative_to(root)}")
            _run([*pip_cmd, "install", "-r", str(r)], cwd=root)

    # 7. run pytest
    _run([*pytest_cmd], cwd=root)

    # 8. stop containers
    _run(compose("stop"), cwd=root)

    # 8.5 pull images
    _run(compose("pull"), cwd=root)

    # 9. rebuild & up without cache
    _run(compose("build", "--no-cache"), cwd=root)
    _run(compose("up", "-d"), cwd=root)

    # 10. show stats for 10 seconds
    proc = subprocess.Popen(["docker", "stats", "--all"], cwd=root)
    try:
        time.sleep(10)
    finally:
        proc.terminate()
        proc.wait()

    # 11. prune docker data
    _run(["docker", "image", "prune", "-a", "-f"])
    _run(["docker", "builder", "prune", "-f"])
    _run(["docker", "system", "prune", "-a", "-f"])


if __name__ == "__main__":
    main()

# Copyright (c) Liam Suorsa and Mika Suorsa
