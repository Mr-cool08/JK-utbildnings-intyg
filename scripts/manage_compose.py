#!/usr/bin/env python3
# Script to stop, update, and start Docker Compose services.

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable, Sequence


def repo_root() -> Path:
    # Resolve the repository root directory from this script location.
    return Path(__file__).resolve().parents[1]


def default_compose_file() -> str:
    # Select a sensible default compose file if available.
    root = repo_root()
    prod_file = root / "docker-compose.prod.yml"
    if prod_file.is_file():
        return str(prod_file)
    return str(root / "docker-compose.yml")


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


def run_compose_action(
    compose_args: Sequence[str],
    action: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    # Run a single compose action.
    if action == "stop":
        print("Stoppar Docker Compose-tjänsterna...")
        run_compose_command(compose_args, ["stop"], runner)
        print("Klar.")
        return
    if action == "pull":
        print("Hämtar senaste Docker-bilderna...")
        run_compose_command(compose_args, ["pull"], runner)
        print("Klar.")
        return
    if action == "git-pull":
        print("Hämtar senaste ändringarna med git pull...")
        runner(["git", "pull"], check=True)
        print("Klar.")
        return
    if action == "up":
        print("Startar Docker Compose-tjänsterna...")
        run_compose_command(compose_args, ["up", "-d"], runner)
        print("Klar.")
        return
    if action == "cycle":
        print("Stoppar och tar bort Docker Compose-tjänsterna...")
        run_compose_command(compose_args, ["down", "--remove-orphans"], runner)

        print("Hämtar senaste ändringarna med git pull...")
        runner(["git", "pull"], check=True)

        print("Bygger och startar Docker Compose-tjänsterna...")
        run_compose_command(compose_args, ["up", "-d", "--build"], runner)

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
        "4) Stoppa/ta bort + git pull + bygg/starta\n"
        "5) Git pull\n"
        "6) Avsluta\n"
    )
    print(menu)
    choice = input_func("Ange ditt val (1-6): ").strip()

    mapping = {
        "1": "stop",
        "2": "pull",
        "3": "up",
        "4": "cycle",
        "5": "git-pull",
        "6": None,
    }
    return mapping.get(choice, "invalid")


def run_menu(
    compose_args: Sequence[str],
    input_func: Callable[[str], str] = input,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
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
        run_compose_action(compose_args, selection, runner)
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
        choices=["stop", "pull", "up", "cycle", "git-pull"],
        help="Kör en specifik åtgärd utan meny.",
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
    try:
        if args.action:
            run_compose_action(compose_args, args.action)
        else:
            return run_menu(compose_args)
    except subprocess.CalledProcessError:
        print("Ett fel uppstod när Docker Compose-kommandot kördes.", file=sys.stderr)
        return 1
    except ValueError:
        print("Ogiltigt val. Försök igen.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
