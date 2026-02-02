# Copyright (c) Liam Suorsa
import importlib.util
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from flask import Flask, Response, render_template, stream_with_context

from functions.notifications import critical_events
from status_service.status_checks import build_status

app = Flask(__name__)
logging.basicConfig(level=os.getenv("STATUS_LOG_LEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)


def get_display_timestamp():
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%d %H:%M:%S UTC")


def _looks_like_pytest_root(path):
    if not path or not os.path.isdir(path):
        return False
    return any(
        [
            os.path.isdir(os.path.join(path, "tests")),
            os.path.isfile(os.path.join(path, "pytest.ini")),
            os.path.isfile(os.path.join(path, "pyproject.toml")),
            os.path.isfile(os.path.join(path, "setup.cfg")),
        ]
    )


def _resolve_project_root():
    env_root = os.getenv("STATUS_PROJECT_ROOT")
    if env_root and not os.path.isdir(env_root):
        LOGGER.warning("STATUS_PROJECT_ROOT pekar på en ogiltig katalog: %s", env_root)
        env_root = None

    candidate_paths = []
    if env_root:
        candidate_paths.append(env_root)

    default_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    candidate_paths.append(default_root)

    current = os.path.abspath(os.path.dirname(__file__))
    while True:
        parent = os.path.dirname(current)
        if parent == current:
            break
        candidate_paths.append(parent)
        current = parent

    for path in candidate_paths:
        if _looks_like_pytest_root(path):
            return path

    if env_root:
        LOGGER.warning("STATUS_PROJECT_ROOT saknar pytest-struktur: %s", env_root)
        return env_root

    LOGGER.warning("Kunde inte hitta projektrot, använder arbetskatalogen.")
    return os.getcwd()


def _is_no_tests_output(output_lines):
    combined_output = "".join(output_lines).lower()
    return any(
        token in combined_output
        for token in [
            "collected 0 items",
            "no tests ran",
            "inget test hittades",
        ]
    )


@app.route("/")
def index():
    status = build_status()
    LOGGER.info(
        "Statuskontroll klar. SSL: %s, Databas: %s, Traefik: %s.",
        status["checks"]["ssl"]["status"],
        status["checks"]["database"]["status"],
        status["checks"]["traefik"]["status"],
    )
    return render_template("status.html", status=status, checked_at=get_display_timestamp())


@app.route("/pytest")
def pytest_site():
    LOGGER.info("Startar pytest-körning via status-tjänsten.")
    project_root = _resolve_project_root()

    def generate_output():
        yield "Startar pytest...\n"
        captured_output = []
        if importlib.util.find_spec("pytest") is None:
            message = "Pytest saknas i miljön. Installera pytest och försök igen.\n"
            LOGGER.warning("Pytest saknas i miljön.")
            yield message
            return
        try:
            process = subprocess.Popen(
                [sys.executable, "-m", "pytest"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=project_root,
            )
        except (FileNotFoundError, OSError) as exc:
            LOGGER.exception("Kunde inte starta pytest: %s", exc)
            critical_events.send_critical_event_email(
                event_type="error",
                title="🔴 Pytest kunde inte starta",
                description=(
                    "Pytest-körningen kunde inte startas via status-tjänsten.\n"
                    f"Tidsstämpel: {get_display_timestamp()}"
                ),
                error_message=str(exc),
            )
            yield "Pytest kunde inte starta. Kritisk händelse har skickats.\n"
            return
        if process.stdout is None:
            LOGGER.warning("Pytest saknar stdout-ström.")
            output, _ = process.communicate()
            if output:
                for line in output.splitlines(keepends=True):
                    captured_output.append(line)
                    yield line
            else:
                captured_output.append("Ingen utdata från pytest.\n")
                yield "Ingen utdata från pytest.\n"
        else:
            for line in process.stdout:
                captured_output.append(line)
                yield line
            process.wait()
        LOGGER.info("Pytest-resultat: %s", process.returncode)
        if process.returncode == 0:
            yield "Pytest klart: lyckades.\n"
        elif process.returncode == 5 and _is_no_tests_output(captured_output):
            LOGGER.warning("Pytest hittade inga tester i miljön.")
            yield (
                "Pytest hittade inga tester i den här miljön. "
                "Kontrollera STATUS_PROJECT_ROOT.\n"
            )
        else:
            critical_events.send_critical_event_email(
                event_type="error",
                title="🔴 Pytest misslyckades",
                description=(
                    "Pytest-körningen misslyckades via status-tjänsten.\n"
                    f"Tidsstämpel: {get_display_timestamp()}"
                ),
                error_message="".join(captured_output),
            )
            yield "Pytest misslyckades. Kritisk händelse har skickats.\n"

    return Response(stream_with_context(generate_output()), mimetype="text/plain; charset=utf-8")


if __name__ == "__main__":
    port = int(os.getenv("STATUS_PORT", "80"))
    app.run(host="0.0.0.0", port=port)
