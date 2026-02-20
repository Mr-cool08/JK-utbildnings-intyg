#!/usr/bin/env python3
# Copyright (c) Liam Suorsa
# Script to stop, update, and start Docker Compose services.

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable, Sequence

# Configure logging with email notifications for ERROR and CRITICAL logs
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
try:
    from functions.logging import bootstrap_logging
    from config_loader import load_environment
    load_environment()
    logger = bootstrap_logging(__name__)
except Exception:
    # Fallback if functions module not available
    logger = logging.getLogger(__name__)



class ActionError(RuntimeError):
    pass


def repo_root() -> Path:
    # Resolve the repository root directory from this script location.
    return Path(__file__).resolve().parents[1]


def default_compose_file() -> str:
    # Select a sensible default compose file if available.
    root = repo_root()

    # Prefer production compose if it exists, otherwise fall back to standard compose.
    prod_file = root / "docker-compose.prod.yml"
    if prod_file.is_file():
        return str(prod_file)

    standard_file = root / "docker-compose.yml"
    if standard_file.is_file():
        return str(standard_file)

    # Last resort: keep the production path as default.
    return str(prod_file)


def default_project_name() -> str:
    # Use a stable project name to avoid duplicate prefixed volumes.
    name = repo_root().name.lower()
    name = re.sub(r"[^a-z0-9_-]+", "-", name).strip("-")
    return name or "jk-utbildnings-intyg"


def _run_and_capture(cmd: list[str]) -> tuple[bool, str]:
    """Run a command and return (success, stdout+stderr)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        out = "".join([proc.stdout or "", proc.stderr or ""]).strip()
        return (proc.returncode == 0, out)
    except Exception as e:
        return (False, str(e))


def _gather_statuses(compose_args: Sequence[str]) -> str:
    """Collect container and basic server statuses for notification."""
    parts: list[str] = []

    # Container status via docker compose ps
    cmd = ["docker", "compose", *compose_args, "ps", "--all"]
    ok, out = _run_and_capture(cmd)
    parts.append("== Containers (docker compose ps) ==")
    parts.append(out if out else "<no output or docker not available>")

    # Server status: uname, uptime, df -h /, free -h (best-effort)
    try:
        import platform

        parts.append("\n== Server Info ==")
        parts.append(f"Platform: {platform.platform()}")

        ok, out = _run_and_capture(["uptime"])  # may fail on Windows
        parts.append("Uptime: " + (out if ok and out else "<unavailable>"))

        ok, out = _run_and_capture(["df", "-h", "/"])  # may fail on Windows
        parts.append("Disk: " + (out if ok and out else "<unavailable>"))

        ok, out = _run_and_capture(["free", "-h"])  # may fail on some systems
        parts.append("Memory: " + (out if ok and out else "<unavailable>"))
    except Exception as e:
        parts.append(f"Server status unavailable: {e}")

    return "\n".join(parts)


def _run_docker_system_df(
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    # Run docker system df to show disk usage.
    runner(["docker", "system", "df"], check=True)


def _run_docker_prune_commands(
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    # Run docker prune commands to clean up unused data.
    runner(["docker", "image", "prune", "-a"], check=True)
    runner(["docker", "builder", "prune"], check=True)
    runner(["docker", "system", "prune", "-a"], check=True)


def _build_venv_command(
    root: Path,
    unix_executable: str,
    windows_executable: str,
) -> list[str]:
    # Build a command path from venv or .venv directories.
    venv_directories = ("venv", ".venv")
    if sys.platform.startswith("win"):
        layout = (("Scripts", windows_executable), ("bin", unix_executable))
    else:
        layout = (("bin", unix_executable), ("Scripts", windows_executable))

    for venv_dir in venv_directories:
        for folder, executable in layout:
            candidate = root / venv_dir / folder / executable
            if candidate.is_file():
                return [str(candidate)]

    raise FileNotFoundError(
        f"Kunde inte hitta {unix_executable} i venv/.venv-katalogen."
    )


def build_pytest_command(root: Path) -> list[str]:
    # Build the pytest command using the venv in the repository root.
    return _build_venv_command(
        root,
        unix_executable="pytest",
        windows_executable="pytest.exe",
    )


def build_pip_command(root: Path) -> list[str]:
    # Build the pip command using the venv in the repository root.
    return _build_venv_command(
        root,
        unix_executable="pip",
        windows_executable="pip.exe",
    )


def find_requirements_files(root: Path) -> list[Path]:
    # Find all requirements.txt files in the repository, excluding virtual env folders.
    requirements_files: list[Path] = []
    excluded_directories = {
        ".git",
        "venv",
        ".venv",
        "__pycache__",
    }

    for path in root.rglob("requirements.txt"):
        if any(part in excluded_directories for part in path.parts):
            continue
        requirements_files.append(path)

    return sorted(requirements_files)


def install_requirements(
    root: Path,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    # Install all requirements.txt files found in the repository.
    pip_cmd = build_pip_command(root)
    requirements_files = find_requirements_files(root)
    if not requirements_files:
        print("Inga requirements.txt-filer hittades.")
        return

    for requirements_file in requirements_files:
        relative_path = requirements_file.relative_to(root)
        print(f"Installerar beroenden från: {relative_path}")
        runner([*pip_cmd, "install", "-r", str(requirements_file)], check=True, cwd=root)


def send_notification(action: str, details: str = "") -> None:
    """Send email notification about compose action (if configured)."""
    try:
        # Add repo root to path to import services
        sys.path.insert(0, str(repo_root()))
        from services import email as email_service

        action_labels = {
            "stop": "Docker Compose tjänsterna stoppades",
            "pull": "Docker bilder uppdaterades",
            "up": "Docker Compose tjänsterna startades",
            "build-up": "Docker Compose tjänsterna byggdes och startades",
            "cycle": "Docker Compose tjänsterna startades om (cycle)",
            "git-pull": "Git uppdatering genomfördes",
            "prune-volumes": "Oanvända Docker-volymer togs bort",
        }

        event_type = "compose_action"
        title = action_labels.get(action, f"Docker Compose åtgärd: {action}")

        # Log critical event which will trigger email notification via logging handler
        details_msg = f"Åtgärd: {title}\nDetaljer: {details}" if details else title
        logger.critical("Docker Compose action: %s\n%s", event_type, details_msg)
    except Exception:
        # Silently fail if email module isn't available
        pass


def build_compose_args(
    compose_file: str | None,
    env_file: str | None,
    project_name: str | None,
) -> list[str]:
    # Build docker compose arguments from provided settings.
    args: list[str] = []
    if compose_file:
        args.extend(["-f", compose_file])
    if env_file:
        args.extend(["--env-file", env_file])
    if project_name:
        args.extend(["--project-name", project_name])
    return args



def run_compose_command(
    compose_args: Sequence[str],
    command: Iterable[str],
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    # Execute a docker compose command.
    cmd = ["docker", "compose", *compose_args, *command]
    runner(cmd, check=True)


def _get_project_name(compose_args: Sequence[str]) -> str | None:
    # Resolve the docker compose project name from args.
    for index, value in enumerate(compose_args):
        if value in {"--project-name", "-p"} and index + 1 < len(compose_args):
            return compose_args[index + 1]
    return None


def _load_compose_config(
    compose_args: Sequence[str],
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict:
    # Load docker compose config as JSON.
    cmd = ["docker", "compose", *compose_args, "config", "--format", "json"]
    result = runner(cmd, check=True, capture_output=True, text=True)
    output = (result.stdout or "").strip()
    if not output:
        raise ActionError("Kunde inte läsa docker compose-konfigurationen.")
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise ActionError("Kunde inte tolka docker compose-konfigurationen.") from exc


def _resolve_volume_name(
    volume_key: str,
    volume_spec: dict,
    project_name: str | None,
) -> str:
    # Determine the resolved docker volume name.
    name = None
    if isinstance(volume_spec, dict):
        name = volume_spec.get("name")
    if name:
        return str(name)
    if project_name:
        return f"{project_name}_{volume_key}"
    return volume_key


def _inspect_volume(
    volume_name: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict | None:
    # Inspect a docker volume and return its metadata if available.
    try:
        result = runner(
            ["docker", "volume", "inspect", volume_name],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError:
        return None
    output = (result.stdout or "").strip()
    if not output:
        return None
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        # Hantera ogiltiga backslash-sekvenser i vissa miljöer (t.ex. Windows).
        try:
            data = json.loads(output.replace("\\", "\\\\"))
        except json.JSONDecodeError:
            return None
    if isinstance(data, list) and data:
        return data[0]
    return None


def _ensure_volume_present(
    volume_name: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> bool:
    # Ensure a docker volume exists and has a valid mountpoint.
    info = _inspect_volume(volume_name, runner=runner)
    if not info:
        print(f"Skapar Docker-volym: {volume_name}")
        runner(["docker", "volume", "create", volume_name], check=True)
        return True
    mountpoint = info.get("Mountpoint")
    if mountpoint and os.path.exists(mountpoint):
        return False
    print(f"Återskapar Docker-volym: {volume_name}")
    try:
        runner(["docker", "volume", "rm", volume_name], check=True)
    except subprocess.CalledProcessError as exc:
        print(
            "Varning: Kunde inte ta bort Docker-volymen eftersom den används. "
            "Hoppar över återskapning.",
            file=sys.stderr,
        )
        return False
    runner(["docker", "volume", "create", volume_name], check=True)
    return True


def _ensure_compose_volumes(
    compose_args: Sequence[str],
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    # Ensure all volumes from docker compose config exist before starting services.
    config = _load_compose_config(compose_args, runner=runner)
    volumes = config.get("volumes", {}) or {}
    if not volumes:
        return
    project_name = _get_project_name(compose_args)
    print("Säkerställer att Docker-volymer finns...")
    for volume_key, volume_spec in volumes.items():
        if isinstance(volume_spec, dict) and volume_spec.get("external") is True:
            # Hoppa över externa volymer som hanteras utanför compose.
            continue
        volume_name = _resolve_volume_name(volume_key, volume_spec, project_name)
        _ensure_volume_present(volume_name, runner=runner)


def run_compose_action(
    compose_args: Sequence[str],
    action: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    notify: bool = True,
) -> None:
    # Run a single compose action.

    if action == "stop":
        print("Stoppar Docker Compose-tjänsterna...")
        try:
            run_compose_command(compose_args, ["stop"], runner)
        except subprocess.CalledProcessError as exc:
            raise ActionError(
                "Ett fel uppstod när Docker Compose-tjänsterna skulle stoppas."
            ) from exc
        print("Klar.")
        if notify:
            send_notification("stop")
        return

    if action == "pull":
        print("Hämtar senaste Docker-bilderna...")
        try:
            run_compose_command(compose_args, ["pull"], runner)
        except subprocess.CalledProcessError as exc:
            raise ActionError("Ett fel uppstod när Docker-bilderna skulle hämtas.") from exc
        print("Klar.")
        if notify:
            send_notification("pull")
        return

    if action == "git-pull":
        print("Hämtar senaste ändringarna med git pull...")
        try:
            runner(["git", "pull"], check=True)
        except subprocess.CalledProcessError as exc:
            raise ActionError("Ett fel uppstod när git pull kördes.") from exc
        print("Klar.")
        if notify:
            send_notification("git-pull")
        return

    if action == "pytest":
        print("Kör pytest (parallellt)...")
        pytest_cmd = build_pytest_command(repo_root())
        try:
            runner([*pytest_cmd, "-n", "auto"], check=True, cwd=repo_root())
        except subprocess.CalledProcessError as exc:
            raise ActionError("Ett fel uppstod när pytest kördes.") from exc
        print("Klar.")
        return

    if action == "up":
        print("Startar Docker Compose-tjänsterna...")
        try:
            _ensure_compose_volumes(compose_args, runner=runner)
            run_compose_command(compose_args, ["up", "-d"], runner)
        except subprocess.CalledProcessError as exc:
            raise ActionError(
                "Ett fel uppstod när Docker Compose-tjänsterna skulle startas."
            ) from exc
        print("Klar.")
        if notify:
            send_notification("up")
        return

    if action == "build-up":
        print("Bygger om Docker Compose-tjänsterna...")
        try:
            run_compose_command(compose_args, ["build"], runner)
        except subprocess.CalledProcessError as exc:
            raise ActionError(
                "Ett fel uppstod när Docker Compose-tjänsterna skulle byggas."
            ) from exc
        print("Startar Docker Compose-tjänsterna...")
        try:
            _ensure_compose_volumes(compose_args, runner=runner)
            run_compose_command(compose_args, ["up", "-d"], runner)
        except subprocess.CalledProcessError as exc:
            raise ActionError(
                "Ett fel uppstod när Docker Compose-tjänsterna skulle startas."
            ) from exc
        print("Klar.")
        if notify:
            send_notification("build-up")
        return

    if action == "cycle":
        # Notify that cycle is starting
        if notify:
            try:
                send_notification("cycle", "Startar fullständig omstart av alla tjänster")
            except Exception:
                pass

        print("Stoppar Docker Compose-tjänsterna...")
        try:
            print("Hämtar senaste ändringarna med git pull...")
            runner(["git", "pull"], check=True)
            
            print("Uppdaterar systemet...")
            runner(["sudo", "apt", "update"], check=True)
            runner(["sudo", "apt", "upgrade", "-y"], check=True)
            
            # Använd stop för att undvika att volymer tas bort vid omstart.
            run_compose_command(compose_args, ["stop"], runner)

            print("Installerar Python-beroenden...")
            install_requirements(repo_root(), runner=runner)

            print("Kör pytest (parallellt)...")
            pytest_cmd = build_pytest_command(repo_root())
            runner([*pytest_cmd, "-n", "auto"], check=True, cwd=repo_root())

            print("Visar Docker diskstatus...")
            _run_docker_system_df(runner=runner)

            
            print("Bygger om Docker Compose-tjänsterna utan cache...")
            run_compose_command(compose_args, ["build", "--no-cache"], runner)

            print("Startar Docker Compose-tjänsterna...")
            _ensure_compose_volumes(compose_args, runner=runner)
            run_compose_command(
                compose_args,
                ["up", "-d", "--remove-orphans", "--renew-anon-volumes"],
                runner,
            )
            
            
            print("Rensar oanvända Docker-artefakter...")
            _run_docker_prune_commands(runner=runner)

            print("Klar.")
            # Gather statuses and notify with details
            if notify:
                try:
                    status = _gather_statuses(compose_args)
                    send_notification(
                        "cycle",
                        "Fullständig omstart av alla tjänster genomförd\n\n" + status,
                    )
                except Exception:
                    # ignore notification failure
                    pass
            return
        except Exception as exc:
            # Gather available statuses and notify about failure, then re-raise
            try:
                if notify:
                    try:
                        status = _gather_statuses(compose_args)
                    except Exception:
                        status = "<could not gather statuses>"
                    try:
                        send_notification(
                            "cycle",
                            f"Fullständig omstart misslyckades: {exc}\n\n{status}",
                        )
                    except Exception:
                        pass
            finally:
                raise ActionError("Fullständig omstart misslyckades.") from exc

    if action == "prune-volumes":
        print("Tar bort oanvända Docker-volymer...")
        try:
            runner(["docker", "volume", "prune", "--force"], check=True)
        except subprocess.CalledProcessError as exc:
            raise ActionError("Ett fel uppstod när oanvända Docker-volymer togs bort.") from exc
        print("Klar.")
        if notify:
            send_notification("prune-volumes")
        return

    if action == "system-df":
        print("Visar Docker diskstatus...")
        try:
            _run_docker_system_df(runner=runner)
        except subprocess.CalledProcessError as exc:
            raise ActionError(
                "Ett fel uppstod när Docker diskstatus skulle hämtas."
            ) from exc
        print("Klar.")
        return

    raise ValueError("Okänd åtgärd vald.")


def select_action(input_func: Callable[[str], str]) -> str | None:
    # Prompt the user for an action choice.
    menu = (
        "\nVälj en åtgärd:\n"
        "1) Stoppa tjänsterna\n"
        "2) Hämta senaste bilder\n"
        "3) Starta tjänsterna\n"
        "4) Stoppa/ta bort + git pull + pytest + bygg/starta\n"
        "5) Git pull\n"
        "6) Kör pytest\n"
        "7) Visa Docker diskstatus\n"
        "8) Ta bort oanvända volymer\n"
        "9) Avsluta\n"
    )
    print(menu)
    choice = input_func("Ange ditt val (1-9): ").strip()

    mapping = {
        "1": "stop",
        "2": "pull",
        "3": "up",
        "4": "cycle",
        "5": "git-pull",
        "6": "pytest",
        "7": "system-df",
        "8": "prune-volumes",
        "9": None,
    }
    return mapping.get(choice, "invalid")


def run_menu(
    compose_args: Sequence[str],
    input_func: Callable[[str], str] = input,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    notify: bool = True,
) -> int:
    # Run an interactive menu for compose actions.
    while True:
        selection = select_action(input_func)
        if selection is None:
            print("Avslutar.")
            return 0
        if selection == "invalid":
            print("Ogiltigt val. Försök igen.")
            continue
        run_compose_action(compose_args, selection, runner, notify=notify)
        return 0


def parse_args() -> argparse.Namespace:
    # Parse CLI arguments.
    parser = argparse.ArgumentParser(
        description="Stoppa, uppdatera och starta Docker Compose-tjänster.",
    )
    parser.add_argument(
        "-f",
        "--compose-file",
        default=default_compose_file(),
        help="Sökväg till docker compose-filen.",
    )
    parser.add_argument(
        "--env-file",
        help="Valfri env-fil som skickas till docker compose.",
    )
    parser.add_argument(
        "--project-name",
        default=default_project_name(),
        help="Valfritt projektnamn för docker compose.",
    )
    parser.add_argument(
        "--action",
        choices=[
            "stop",
            "pull",
            "up",
            "cycle",
            "git-pull",
            "pytest",
            "prune-volumes",
            "system-df",
        ],
        help="Kör en specifik åtgärd utan meny.",
    )
    parser.add_argument(
        "--no-notify",
        action="store_true",
        help="Skicka inte e-postaviseringar (kräver CRITICAL_ALERTS_EMAIL att vara konfigurerad).",
    )
    return parser.parse_args()


def main() -> int:
    # Entry point for the script.
    args = parse_args()
    compose_args = build_compose_args(
        args.compose_file,
        args.env_file,
        args.project_name,
    )
    notify = not args.no_notify

    try:
        if args.action:
            run_compose_action(compose_args, args.action, notify=notify)
        else:
            return run_menu(compose_args, notify=notify)
    except ActionError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except ValueError:
        print("Ogiltigt val. Försök igen.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
