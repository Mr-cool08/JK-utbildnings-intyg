#!/usr/bin/env python3
# Script to stop, update, and start Docker Compose services.

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable, Sequence


class ActionError(RuntimeError):
    pass


def repo_root() -> Path:
    # Resolve the repository root directory from this script location.
    return Path(__file__).resolve().parents[1]


def default_compose_file() -> str:
    # Select a sensible default compose file if available.
    root = repo_root()
    prod_file = root / "docker-compose.prod.yml"
    if prod_file.is_file():
        return str(prod_file)
    return str(root / "docker-compose.prod.yml")


def github_compose_file() -> Path:
    # Return the compose override for GitHub Actions images.
    return repo_root() / "docker-compose.github.yml"


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


def build_pytest_command(root: Path) -> list[str]:
    # Build the pytest command using the venv in the repository root.
    if sys.platform.startswith("win"):
        pytest_path = root / "venv" / "Scripts" / "pytest.exe"
    else:
        pytest_path = root / "venv" / "bin" / "pytest"
    if not pytest_path.is_file():
        raise FileNotFoundError("Kunde inte hitta pytest i venv-katalogen.")
    return [str(pytest_path)]


def send_notification(action: str, details: str = "") -> None:
    """Send email notification about compose action (if configured)."""
    try:
        # Add repo root to path to import services
        sys.path.insert(0, str(repo_root()))
        from services import email as email_service
        
        action_labels = {
            "stop": "Docker Compose tjänsterna stoppades",
            "pull": "Docker bilder uppdaterades",
            "pull-github": "Docker bilder hämtades från GitHub Actions",
            "up": "Docker Compose tjänsterna startades",
            "cycle": "Docker Compose tjänsterna startades om (cycle)",
            "git-pull": "Git uppdatering genomfördes",
        }
        
        event_type = "compose_action"
        title = action_labels.get(action, f"Docker Compose åtgärd: {action}")
        
        try:
            email_service.send_critical_event_alert(
                event_type,
                f"Åtgärd: {title}\nDetaljer: {details}" if details else title
            )
        except Exception as e:
            # Log but don't fail if email sending fails
            print(f"Varning: Kunde inte skicka avisering: {e}", file=sys.stderr)
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


def build_github_compose_args(compose_args: Sequence[str]) -> list[str]:
    # Add the GitHub Actions override file for image pulls.
    args = list(compose_args)
    github_file = github_compose_file()
    if not github_file.is_file():
        raise ActionError(
            "Kunde inte hitta docker-compose.github.yml för GitHub Actions-bilder."
        )
    args.extend(["-f", str(github_file)])
    return args


def run_compose_command(
    compose_args: Sequence[str],
    command: Iterable[str],
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    # Execute a docker compose command.
    cmd = ["docker", "compose", *compose_args, *command]
    runner(cmd, check=True)


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
            raise ActionError(
                "Ett fel uppstod när Docker-bilderna skulle hämtas."
            ) from exc
        print("Klar.")
        if notify:
            send_notification("pull")
        return
    if action == "pull-github":
        print("Hämtar senaste Docker-bilderna från GitHub Actions...")
        ghcr_repo_url = os.environ.get("GHCR_REPO_URL")
        if ghcr_repo_url:
            print(f"GHCR-länk: {ghcr_repo_url}")
        try:
            compose_args = build_github_compose_args(compose_args)
            run_compose_command(compose_args, ["pull"], runner)
        except subprocess.CalledProcessError as exc:
            raise ActionError(
                "Ett fel uppstod när Docker-bilderna från GitHub Actions skulle hämtas."
            ) from exc
        print("Klar.")
        if notify:
            details = f"GHCR-länk: {ghcr_repo_url}" if ghcr_repo_url else ""
            send_notification("pull-github", details)
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
        print("Kör pytest...")
        pytest_cmd = build_pytest_command(repo_root())
        try:
            runner(pytest_cmd, check=True, cwd=repo_root())
        except subprocess.CalledProcessError as exc:
            raise ActionError("Ett fel uppstod när pytest kördes.") from exc
        print("Klar.")
        return
    if action == "up":
        print("Startar Docker Compose-tjänsterna...")
        try:
            run_compose_command(compose_args, ["up", "-d"], runner)
        except subprocess.CalledProcessError as exc:
            raise ActionError(
                "Ett fel uppstod när Docker Compose-tjänsterna skulle startas."
            ) from exc
        print("Klar.")
        if notify:
            send_notification("up")
        return
    if action == "cycle":
        # Notify that cycle is starting
        if notify:
            try:
                send_notification("cycle", "Startar fullständig omstart av alla tjänster")
            except Exception:
                pass

        print("Stoppar och tar bort Docker Compose-tjänsterna...")
        try:
            run_compose_command(compose_args, ["down", "--remove-orphans"], runner)

            print("Hämtar senaste ändringarna med git pull...")
            runner(["git", "pull"], check=True)

            print("Kör pytest...")
            pytest_cmd = build_pytest_command(repo_root())
            runner(pytest_cmd, check=True, cwd=repo_root())

            print("Bygger om Docker Compose-tjänsterna utan cache...")
            run_compose_command(compose_args, ["build", "--no-cache"], runner)

            print("Startar Docker Compose-tjänsterna...")
            run_compose_command(compose_args, ["up", "-d"], runner)

            print("Klar.")
            # Gather statuses and notify with details
            if notify:
                try:
                    status = _gather_statuses(compose_args)
                    send_notification("cycle", f"Fullständig omstart av alla tjänster genomförd\n\n{status}")
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
                        send_notification("cycle", f"Fullständig omstart misslyckades: {exc}\n\n{status}")
                    except Exception:
                        pass
            finally:
                raise ActionError("Fullständig omstart misslyckades.") from exc
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
        "7) Hämta senaste bilder från GitHub Actions\n"
        "8) Avsluta\n"
    )
    print(menu)
    choice = input_func("Ange ditt val (1-8): ").strip()

    mapping = {
        "1": "stop",
        "2": "pull",
        "3": "up",
        "4": "cycle",
        "5": "git-pull",
        "6": "pytest",
        "7": "pull-github",
        "8": None,
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
        help="Valfritt projektnamn för docker compose.",
    )
    parser.add_argument(
        "--action",
        choices=["stop", "pull", "pull-github", "up", "cycle", "git-pull", "pytest"],
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
